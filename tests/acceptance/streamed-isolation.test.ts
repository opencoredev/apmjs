// A streamed analysis never fails other requests. It is long work in the isolate that also answers installs: the queue
// consumer reads next 16.4.6 (43.7 MB, past what a tarball read whole may be) as a stream in workerd, with the
// registry's own database timings (db-health.ts: 3 s to connect, 8 s a statement, each failure its own request's),
// while other requests to the same isolate read the database and the health check asks it. None of them may be
// answered degraded or fail, the health check may never find the database down, and the isolate may be kept busy no
// longer than by prettier 3.10.1 read whole, which main has always read in the same consumer. npm is a local stand-in;
// the tarballs are read from this machine's corpus (~/.cache/apm-corpus/tgz) and the test is skipped without them.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { getJson, pkgTgz, startRegistry, type Registry } from "./harness";

const clock = Date.parse("2026-11-01T00:00:00Z");
const NEXT = join(homedir(), ".cache", "apm-corpus", "tgz", "next-16.4.6.tgz");
const PRETTIER = join(homedir(), ".cache", "apm-corpus", "tgz", "prettier-3.10.1.tgz");

const Health = z.object({ installs: z.string(), checks: z.object({ database: z.object({ status: z.string(), detail: z.string() }) }) });
const Score = z.object({ grade: z.string(), coverage: z.object({ kind: z.string() }) }).loose();

type Poll = { path: string; status: number; degraded: string | null; ms: number; database?: string };

/**
 * Package answers that were not a plain 200, or said the database was unavailable. The health check answers 503 here
 * whatever the database does (this test sends no queue probe and syncs no block list), so only its database check counts.
 * A request the harness's proxy cut after 10 s (status 0) got no answer of the registry's and is not counted here.
 */
const answeredBadly = (polls: readonly Poll[]): Poll[] => polls.filter((p) => p.degraded !== null || (p.database === undefined && p.status !== 200 && p.status !== 0));

const slowest = (polls: readonly Poll[]): number => Math.max(...polls.map((p) => p.ms));

describe.skipIf(!existsSync(NEXT))("a streamed analysis never fails other requests", () => {
  const served = new Map<string, { version: string; bytes: Uint8Array }>();
  let npm: ReturnType<typeof Bun.serve>;
  let reg: Registry;

  beforeAll(async () => {
    served.set("next", { version: "16.4.6", bytes: new Uint8Array(readFileSync(NEXT)) });

    if (existsSync(PRETTIER)) served.set("prettier", { version: "3.10.1", bytes: new Uint8Array(readFileSync(PRETTIER)) });
    served.set("small-clean", { version: "1.0.0", bytes: pkgTgz({ name: "small-clean", version: "1.0.0", license: "MIT", main: "index.js" }) });

    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const u = new URL(req.url);
        const tar = /^\/([^/]+)\/-\/[^/]+\.tgz$/.exec(u.pathname);
        const name = tar?.[1] ?? decodeURIComponent(u.pathname.slice(1));
        const one = served.get(name);

        if (!one) return Response.json({ error: "Not found" }, { status: 404 });

        if (tar) return new Response(one.bytes, { headers: { "content-length": String(one.bytes.length) } });

        const dist = { tarball: `${npm.url.toString()}${name}/-/${name}-${one.version}.tgz`, integrity: `sha512-${createHash("sha512").update(one.bytes).digest("base64")}` };

        return Response.json({ name, "dist-tags": { latest: one.version }, versions: { [one.version]: { name, version: one.version, main: "index.js", license: "MIT", dist } }, time: { [one.version]: "2026-10-01T00:00:00Z" } });
      },
    });
    // the registry's own database timings
    reg = await startRegistry({ now: () => clock, upstream: npm.url.toString(), upstreamTtlMs: 0 });
    expect(await reg.analysisJob({ name: "small-clean", version: "1.0.0" })).toBe("ack");
  }, 60_000);

  afterAll(async () => {
    await reg?.stop();
    await npm?.stop(true);
  });

  /** Runs `job` while a package answer is asked for every 100 ms and the health check every second. */
  async function beside(job: { name: string; version: string }): Promise<{ answer: "ack" | "retry"; jobMs: number; polls: Poll[] }> {
    const polls: Poll[] = [];
    let done = false;

    const poll = async (path: string): Promise<void> => {
      const t0 = performance.now();
      // the harness's proxy cuts a request it waited on for 10 s: no answer of the registry's, recorded as status 0
      const res = await fetch(`${reg.url}${path}`).catch(() => null);

      if (res === null) {
        polls.push({ path, status: 0, degraded: null, ms: performance.now() - t0 });

        return;
      }

      const text = await res.text();
      const one: Poll = { path, status: res.status, degraded: res.headers.get("x-apm-degraded"), ms: performance.now() - t0 };

      if (path.endsWith("/health")) one.database = Health.parse(JSON.parse(text)).checks.database.status;
      polls.push(one);
    };

    // a package answer (the packument and its stored analyses) every 100 ms, and the health check every second
    const reads = (async () => {
      for (let i = 0; !done; i++) await Promise.all([poll("-/apm/v1/packages/small-clean"), ...(i % 10 === 0 ? [poll("-/apm/v1/health")] : []), Bun.sleep(100)]);
    })();

    const t0 = performance.now();
    const answer = await reg.analysisJob(job);
    const jobMs = performance.now() - t0;

    done = true;
    await reads;
    await poll("-/apm/v1/health");
    process.stdout.write(`[isolation] ${job.name} in ${(jobMs / 1000).toFixed(1)} s beside ${polls.length} requests; slowest answer ${(slowest(polls) / 1000).toFixed(2)} s; health: ${polls.flatMap((p) => (p.database === undefined ? [] : [p.database])).join(",")}\n`);

    return { answer, jobMs, polls };
  }

  /** How long prettier 3.10.1 read whole, as main reads it, kept the isolate from answering, measured just before. */
  let reference: number | null = null;

  test.skipIf(!existsSync(PRETTIER))("for comparison, prettier 3.10.1 read whole, as main reads it", async () => {
    const { answer, polls } = await beside({ name: "prettier", version: "3.10.1" });

    expect(answer).toBe("ack");
    expect(answeredBadly(polls)).toEqual([]);
    expect(polls.filter((p) => p.database !== undefined && p.database !== "up")).toEqual([]);
    reference = slowest(polls);
  }, 300_000);

  test("while next is streamed, every package answer is a plain 200 and the health check finds the database up", async () => {
    const { answer, polls } = await beside({ name: "next", version: "16.4.6" });

    expect(answer).toBe("ack");
    expect(answeredBadly(polls)).toEqual([]);
    expect(polls.filter((p) => p.database !== undefined && p.database !== "up")).toEqual([]);
    // the isolate is kept busy no longer than by a read main already makes (prettier 3.10.1: 11.7 s here, under load)

    if (reference !== null) expect(slowest(polls)).toBeLessThan(reference);
    // and the read it made is v11's: scored, partial, graded P
    const s = await getJson(`${reg.url}-/apm/v1/score/next/16.4.6`);

    expect(s.status, JSON.stringify(s.body)).toBe(200);
    expect(Score.parse(s.body)).toMatchObject({ grade: "P", coverage: { kind: "partial" } });
  }, 300_000);
});
