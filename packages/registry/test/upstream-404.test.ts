// npm's CDN can answer 404 for the tarball of a version its packument lists, for a while right after a publish
// (@firebase/analytics 0.10.26, launch audit 2026-11-18). That is a fetch failure the queue tries again, not a version
// apm can never score; and outcomes stored for it before are dropped (migration 0026), so the next request queues them.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { Effect, Layer, Option } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { SCORER } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { Store } from "../src/db.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { isRetryableTarballStatus, Upstream } from "../src/upstream.ts";

const POOL = new MemoryPool();
const T0 = Date.parse("2026-11-18T00:00:00Z");

/** A tar entry block for one regular file. */
function tarFile(name: string, text: string): Uint8Array[] {
  const data = new TextEncoder().encode(text);
  const h = new Uint8Array(512);

  const put = (s: string, at: number): void => {
    for (let i = 0; i < s.length; i++) h[at + i] = s.charCodeAt(i);
  };

  put(name, 0);
  put("0000644\0", 100);
  put(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
  put("        ", 148);
  put("0", 156);
  put("ustar\0", 257);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148);

  return [h, data, new Uint8Array((512 - (data.length % 512)) % 512)];
}

const parts = [...tarFile("package/package.json", JSON.stringify({ name: "late-cdn", version: "1.0.0", license: "MIT", main: "index.js" })), ...tarFile("package/index.js", "module.exports = 1;\n"), new Uint8Array(1024)];
const tar = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
let at = 0;

for (const p of parts) {
  tar.set(p, at);
  at += p.length;
}

const TGZ = new Uint8Array(gzipSync(tar));
const INTEGRITY = `sha512-${createHash("sha512").update(TGZ).digest("base64")}`;

/** npm as the packument lists late-cdn 1.0.0 and the CDN does not have its tarball yet while `missing` is set. */
function fakeNpm(state: { missing: boolean }) {
  const server: Bun.Server<undefined> = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;

      if (path === "/late-cdn") {
        return Response.json({
          name: "late-cdn",
          "dist-tags": { latest: "1.0.0" },
          versions: { "1.0.0": { name: "late-cdn", version: "1.0.0", dist: { tarball: `${server.url.href}late-cdn/-/late-cdn-1.0.0.tgz`, integrity: INTEGRITY } } },
          time: { "1.0.0": new Date(T0 - 3_600_000).toISOString() },
        });
      }

      if (path === "/late-cdn/-/late-cdn-1.0.0.tgz") return state.missing ? Response.json({ error: "Not found" }, { status: 404 }) : new Response(TGZ);

      return Response.json({ error: "Not found" }, { status: 404 });
    },
  });

  return { url: server.url.href, stop: () => server.stop(true) };
}

const blobs = Layer.succeed(
  Blobs,
  Blobs.of({
    put: () => Effect.void,
    stream: () => Effect.succeed(Option.none()),
    bytes: () => Effect.succeed(Option.none()),
    exists: () => Effect.succeed(false),
    remove: () => Effect.void,
  }),
);

let db: Awaited<ReturnType<typeof freshDatabase>>;
const state = { missing: true };
let npm: ReturnType<typeof fakeNpm>;

const sql = async (text: string, params: readonly unknown[] = []): Promise<unknown[]> => {
  const c = new Client({ connectionString: db.url });

  await c.connect();

  try {
    return (await c.query(text, [...params])).rows;
  } finally {
    await c.end();
  }
};

beforeAll(async () => {
  db = await freshDatabase();
  npm = fakeNpm(state);
});

afterAll(async () => {
  npm.stop();
  await db.drop();
});

const runAt = (now: number) => {
  const base = Layer.mergeAll(Store.postgres(db.url), blobs, Clock.fixed({ now, wallNow: now }), RequestMemory.layer(POOL));
  const layers = Layer.provideMerge(Analysis.layer(null), Layer.provideMerge(Upstream.layer(npm.url, 3_600_000, null), base));

  return Effect.runPromise(Effect.flatMap(Analysis, (a) => a.runJob({ name: "late-cdn", version: "1.0.0" })).pipe(Effect.provide(layers), Effect.scoped));
};

const Outcome = z.array(z.object({ outcome: z.string().nullable(), detail: z.string().nullable(), fetch_failures: z.number() }));

describe("a 404 for a tarball npm lists", () => {
  test("is retryable; the transient statuses still are, and other refusals are not", () => {
    expect([404, 408, 429, 500, 503].map(isRetryableTarballStatus)).toEqual([true, true, true, true, true]);
    expect([400, 401, 403, 410].map(isRetryableTarballStatus)).toEqual([false, false, false, false]);
  });

  test("is a fetch failure the queue tries again, and the version is scored once npm serves it", async () => {
    state.missing = true;
    expect(await runAt(T0)).toBe("retry");
    expect(Outcome.parse(await sql("SELECT outcome, detail, fetch_failures FROM analysis_outcomes WHERE package = 'late-cdn'"))).toEqual([{ outcome: null, detail: null, fetch_failures: 1 }]);

    state.missing = false;
    expect(await runAt(T0 + 30_000)).toBe("stored");
    expect(await sql("SELECT 1 AS one FROM upstream_analysis WHERE package = 'late-cdn' AND scorer = $1", [SCORER])).toEqual([{ one: 1 }]);
  }, 60_000);
});

test("migration 0026 drops the outcomes stored for a 404 and keeps every other", async () => {
  const rows = [
    ["@firebase/analytics", "unavailable", "the upstream answered 404"],
    ["no-sum", "unavailable", "the upstream publishes no checksum for this version"],
    ["gone-410", "unavailable", "the upstream answered 410"],
    ["huge", "too-large", "the tarball is over 32 MiB"],
  ] as const;

  for (const [name, outcome, detail] of rows) await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ($1, '1.0.0', $2, $3, $4, 1)", [name, SCORER, outcome, detail]);
  await sql(readFileSync(join(import.meta.dir, "..", "migrations", "0026_retry_upstream_404.sql"), "utf8"));
  const left = z.array(z.object({ package: z.string() })).parse(await sql("SELECT package FROM analysis_outcomes WHERE package = ANY($1) ORDER BY package", [rows.map((r) => r[0])]));

  expect(left.map((r) => r.package)).toEqual(["gone-410", "huge", "no-sum"]);
});
