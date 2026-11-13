// Criterion 1 of apm-score-v10, the registry's half: a version that can never be scored says why on every surface
// (score endpoint, package answer, resolve for apm add, scan for the Bun scanner) instead of answering 503 "queued, try
// again in a minute" forever, and installs stay refused. A run the platform stopped (CPU limit) stores nothing, so the
// next run reads less and is incomplete, and the one after records that the version cannot be scored.
// npm is a local recording stub; no real host is contacted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addUser, apm, getJson, installedVersion, makeSandbox, pkgTgz, startRegistry, writeConsumer, type Registry } from "./harness";

const clock = Date.parse("2026-11-01T00:00:00Z");

type Served = { bytes: Uint8Array; downloads: number; checksum: boolean; dependencies?: Record<string, string> };

/** One version of the npm stand-in's packument. */
type ServedVersion = { name: string; version: string; main: string; dist: { tarball: string; shasum?: string; integrity?: string }; dependencies?: Record<string, string> };

const ScoreAnswer = z.object({ error: z.string(), pending: z.boolean().optional(), unscorable: z.object({ reason: z.string(), text: z.string() }).optional() });

const PackageAnswer = z.object({
  unscored: z.object({ kind: z.string(), text: z.string() }).nullish(),
  versions: z.array(z.object({ version: z.string(), unscorable: z.string().nullish() })),
});

const ResolveAnswer = z.object({ skipped: z.array(z.object({ version: z.string(), reason: z.string() })) });

const ScanAnswer = z.object({
  advisories: z.array(z.object({ package: z.string(), level: z.string(), description: z.string() })),
  unchecked: z.array(z.object({ package: z.string(), version: z.string(), reason: z.string() })),
});

const Signals = z.object({ score: z.number(), signals: z.array(z.object({ id: z.string(), evidence: z.array(z.string()) })) });
const Starts = z.array(z.object({ starts: z.number(), outcome: z.string().nullable() }));

describe("versions that can never be scored", () => {
  const tarballs = new Map<string, Served>();
  let npm: ReturnType<typeof Bun.serve>;
  let reg: Registry;

  const tgzOf = (name: string, files: Record<string, string>): Uint8Array => pkgTgz({ name, version: "1.0.0", license: "MIT", main: "index.js" }, files);

  beforeAll(async () => {
    // over the 32 MiB download cap: random bytes, which no gzip shrinks
    tarballs.set("over-download", { bytes: new Uint8Array(randomBytes(33 * 1024 * 1024)), downloads: 0, checksum: true });
    // 60 KB compressed, more than 48 MiB once unpacked
    tarballs.set("over-unpack", { bytes: tgzOf("over-unpack", { "index.js": "module.exports = 1;\n", "data.txt": "0".repeat(50 * 1024 * 1024) }), downloads: 0, checksum: true });
    // npm lists no checksum: apm can never check the bytes it would score
    tarballs.set("no-checksum", { bytes: tgzOf("no-checksum", { "index.js": "module.exports = 1;\n" }), downloads: 0, checksum: false });

    // the platform stops a run, then one more: what the next runs do
    for (const name of ["stopped-once", "stopped-twice", "still-running", "limit-dep"]) {
      tarballs.set(name, { bytes: tgzOf(name, { "index.js": "module.exports = require('./lib.js');\n", "lib.js": "module.exports = 2;\n" }), downloads: 0, checksum: true });
    }

    // a clean package whose one dependency apm decides it can never score
    tarballs.set("needs-limit-dep", { bytes: tgzOf("needs-limit-dep", { "index.js": "module.exports = 1;\n" }), downloads: 0, checksum: true, dependencies: { "limit-dep": "^1.0.0" } });

    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const u = new URL(req.url);
        const tar = /^\/([^/]+)\/-\/[^/]+\.tgz$/.exec(u.pathname);
        const served = tarballs.get(tar?.[1] ?? decodeURIComponent(u.pathname.slice(1)));

        if (!served) return Response.json({ error: "Not found" }, { status: 404 });

        if (tar) {
          served.downloads++;

          return new Response(served.bytes);
        }

        const name = decodeURIComponent(u.pathname.slice(1));
        const tarball = `${npm.url.toString()}${name}/-/${name}-1.0.0.tgz`;

        const dist = served.checksum
          ? { tarball, shasum: createHash("sha1").update(served.bytes).digest("hex"), integrity: `sha512-${createHash("sha512").update(served.bytes).digest("base64")}` }
          : { tarball };

        const version: ServedVersion = { name, version: "1.0.0", main: "index.js", dist };

        if (served.dependencies) version.dependencies = served.dependencies;

        return Response.json({
          name,
          "dist-tags": { latest: "1.0.0" },
          versions: { "1.0.0": version },
          time: { "1.0.0": "2026-10-01T00:00:00Z" },
        });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: npm.url.toString(), upstreamTtlMs: 0 });
  });

  afterAll(async () => {
    await reg?.stop();
    await npm?.stop(true);
  });

  /**
   * Every surface's answer for one version that can never be scored, checked against the reason it should give. `token`:
   * the first read is a token caller's, whose request finds out itself (an anonymous one only queues the version).
   */
  async function expectUnscorable(name: string, reason: string, words: string, token?: string): Promise<void> {
    const score = await getJson(`${reg.url}-/apm/v1/score/${name}/1.0.0`, token ? { headers: { authorization: `Bearer ${token}` } } : {});
    const body = ScoreAnswer.parse(score.body);

    // before: 503 with pending: true and "queued for analysis. Try again in a minute", for ever
    expect(score.status, JSON.stringify(score.body)).toBe(422);
    expect(body.pending).toBeUndefined();
    expect(body.unscorable?.reason).toBe(reason);
    expect(body.error).toContain(words);
    expect(body.error).not.toContain("queued");

    // the website's answer: the latest version's reason, and the version row's
    const pkg = PackageAnswer.parse((await getJson(`${reg.url}-/apm/v1/packages/${name}`)).body);

    expect(pkg.unscored?.kind).toBe("unscorable");
    expect(pkg.unscored?.text).toContain(words);
    expect(pkg.versions.find((v) => v.version === "1.0.0")?.unscorable ?? "").toContain(words);

    // apm add: still refused, now with the reason
    const resolve = await getJson(`${reg.url}-/apm/v1/resolve?name=${name}`);

    expect(resolve.status).toBe(422);
    expect(ResolveAnswer.parse(resolve.body).skipped.map((s) => s.reason).join("\n")).toContain(words);

    // the Bun scanner: a fatal advisory with the reason, which blocks in either scanner mode (before: only unchecked,
    // which the default mode lets through with a warning)
    const scan = await getJson(`${reg.url}-/apm/v1/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: [{ name, version: "1.0.0" }] }) });
    const answer = ScanAnswer.parse(scan.body);
    const advisory = answer.advisories.find((a) => a.package === name);

    expect(advisory?.level).toBe("fatal");
    expect(advisory?.description ?? "").toContain(words);
    expect(answer.unchecked.find((u) => u.package === name)).toBeUndefined();
  }

  test("a tarball over the 32 MiB download cap is recorded too large, once, and every surface says so", async () => {
    expect(await reg.analysisJob({ name: "over-download", version: "1.0.0" })).toBe("ack");
    await expectUnscorable("over-download", "too-large", "larger than the 32 MiB apm downloads");

    // decided: the queue does not fetch it again
    const before = tarballs.get("over-download")?.downloads;

    expect(await reg.analysisJob({ name: "over-download", version: "1.0.0" })).toBe("ack");
    expect(tarballs.get("over-download")?.downloads).toBe(before);
  }, 60_000);

  test("a tarball over the 48 MiB unpack cap is recorded on the request that first reads it", async () => {
    // small enough to analyze inline, so a token caller's score request itself finds out
    await expectUnscorable("over-unpack", "too-large", "inflates to more than 48 MB", await addUser(reg, "first-reader"));
  }, 60_000);

  test("a version the upstream lists without a checksum is recorded unavailable", async () => {
    await expectUnscorable("no-checksum", "unavailable", "no checksum", await addUser(reg, "checksum-reader"));
  }, 60_000);

  test("a run the platform stopped is followed by a smaller run that is incomplete, never clean", async () => {
    // what a stopped run leaves: its start counted, nothing stored, and longer ago than any run can take
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ('stopped-once', '1.0.0', 'apm-score-v10', 1, $1)", [clock - 60 * 60_000]);
    expect(await reg.analysisJob({ name: "stopped-once", version: "1.0.0" })).toBe("ack");
    const score = await getJson(`${reg.url}-/apm/v1/score/stopped-once/1.0.0`);

    expect(score.status, JSON.stringify(score.body)).toBe(200);
    const s = Signals.parse(score.body);

    expect(s.signals.find((x) => x.id === "incomplete")?.evidence.join("\n") ?? "").toContain("stopped by the platform's CPU limit");
    expect(s.score).toBeLessThan(70);
  }, 60_000);

  test("after two stopped runs the third records that the version cannot be scored, without analysing", async () => {
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ('stopped-twice', '1.0.0', 'apm-score-v10', 2, $1)", [clock - 60 * 60_000]);
    expect(await reg.analysisJob({ name: "stopped-twice", version: "1.0.0" })).toBe("ack");
    await expectUnscorable("stopped-twice", "analysis-limit", "were stopped by the platform before they finished");
    expect(Starts.parse(await reg.query("SELECT starts, outcome FROM analysis_outcomes WHERE package = 'stopped-twice'"))).toEqual([{ starts: 3, outcome: "analysis-limit" }]);
  }, 60_000);

  test("a run that began a minute ago may still be going: the job comes back later, and nothing is decided", async () => {
    // the queue consumer runs on the system clock (worker.ts), not the test clock
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ('still-running', '1.0.0', 'apm-score-v10', 1, $1)", [Date.now() - 60_000]);
    expect(await reg.analysisJob({ name: "still-running", version: "1.0.0" })).toBe("retry");
    expect(Starts.parse(await reg.query("SELECT starts, outcome FROM analysis_outcomes WHERE package = 'still-running'"))).toEqual([{ starts: 1, outcome: null }]);

    // and while it is not decided, the score endpoint says queued, as before
    const score = await getJson(`${reg.url}-/apm/v1/score/still-running/1.0.0`);

    expect(score.status).toBe(503);
    expect(ScoreAnswer.parse(score.body).pending).toBe(true);
  }, 60_000);

  test("apm add and apm x refuse a package whose dependency apm can never score, naming why", async () => {
    // the root is scored clean by the queue; its dependency is decided analysis-limit
    expect(await reg.analysisJob({ name: "needs-limit-dep", version: "1.0.0" })).toBe("ack");
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ('limit-dep', '1.0.0', 'apm-score-v10', 'analysis-limit', 'two analyses of it were stopped', $1)", [clock]);
    const sb = makeSandbox(reg);
    const app = writeConsumer(mkdtempSync(join(tmpdir(), "apm-unscorable-")), reg, undefined, {});
    const env = { ...sb.env, APM_PENDING_WAIT_MS: "0" };

    for (const args of [["add", "needs-limit-dep"], ["x", "needs-limit-dep"]]) {
      const r = await apm(args, { cwd: app, env, timeoutMs: 60_000 });

      // before: resolve answered 200 with the dependency only unchecked, and apm installed it with a warning
      expect(r.code, r.out).not.toBe(0);
      expect(r.out).toContain("limit-dep@1.0.0 apm cannot score this version: its analysis runs past the registry's limits");
    }

    expect(installedVersion(app, "needs-limit-dep")).toBeNull();
    expect(installedVersion(app, "limit-dep")).toBeNull();
  }, 120_000);
});
