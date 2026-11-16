// Criterion 1 of apm-score-v10, the registry's half: a version that can never be scored says why on every surface
// (score endpoint, package answer, resolve for apm add, scan for the Bun scanner) instead of answering 503 "queued, try
// again in a minute" forever; installs warn about it, and strict mode refuses it. A run the platform stopped (CPU limit) stores nothing, so the
// next run reads less and is incomplete, and the one after records that the version cannot be scored. A tarball over
// the caps a tarball read whole must fit (32 MiB downloaded, 48 MiB unpacked) is no longer one of them: it is read as
// a stream (streamed-analysis.ts) and scored; outcomes are per scorer, so what apm-score-v10 refused for those caps
// decides nothing for apm-score-v11.
// npm is a local recording stub; no real host is contacted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGzip } from "node:zlib";
import { apm, dig, getJson, installedVersion, makeSandbox, pkgTgz, startRegistry, tarHeader, writeConsumer, type Registry } from "./harness";

const clock = Date.parse("2026-11-01T00:00:00Z");

/**
 * A tarball that inflates past the 512 MiB apm-score-v11 reads as a stream (READ.maxUnpackedBytes), so it is still
 * refused as too large: `files`, then `megabytes` MiB of zeros, gzipped a MiB at a time so this test never holds them.
 */
async function inflatesPast(name: string, files: Record<string, string>, megabytes: number): Promise<Uint8Array> {
  const gz = createGzip();
  const out: Buffer[] = [];

  const done = new Promise<void>((resolve, reject) => {
    gz.on("data", (c: Buffer) => out.push(c));
    gz.on("end", resolve);
    gz.on("error", reject);
  });

  const write = (b: Uint8Array) => (gz.write(b) ? Promise.resolve() : new Promise<void>((resolve) => gz.once("drain", resolve)));
  const manifest = JSON.stringify({ name, version: "1.0.0", license: "MIT", main: "index.js" });

  for (const [path, text] of [["package.json", manifest], ...Object.entries(files)] as const) {
    const data = new TextEncoder().encode(text);
    await write(Buffer.concat([tarHeader(`package/${path}`, data.length), data, new Uint8Array((512 - (data.length % 512)) % 512)]));
  }

  await write(tarHeader("package/data.bin", megabytes * 1024 * 1024));
  const mib = new Uint8Array(1024 * 1024);

  for (let i = 0; i < megabytes; i++) await write(mib);
  await write(new Uint8Array(1024));
  gz.end();
  await done;

  return Buffer.concat(out);
}

/** `listed`: the bytes the packument's checksums are of, when they are not the ones served (tampered on the way). */
type Served = { bytes: Uint8Array; downloads: number; checksum: boolean; dependencies?: Record<string, string>; listed?: Uint8Array };

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

  const tgzOf = (name: string, files: Record<string, string | Uint8Array>): Uint8Array => pkgTgz({ name, version: "1.0.0", license: "MIT", main: "index.js" }, files);

  beforeAll(async () => {
    // over the 32 MiB download cap: a native binary of random bytes, which no gzip shrinks, beside a little code
    const addon = new Uint8Array(randomBytes(33 * 1024 * 1024));
    tarballs.set("over-download", { bytes: tgzOf("over-download", { "index.js": "module.exports = require('./lib.js');\n", "lib.js": "module.exports = 2;\n", "prebuilt/addon.node": addon }), downloads: 0, checksum: true });
    // the same size, but npm's checksum names other bytes
    tarballs.set("over-download-tampered", { bytes: tgzOf("over-download-tampered", { "index.js": "module.exports = 1;\n", "prebuilt/addon.node": addon }), downloads: 0, checksum: true, listed: new Uint8Array([1, 2, 3]) });
    // refused by a registry from before streamed reads, for the download cap
    tarballs.set("old-refusal", { bytes: tgzOf("old-refusal", { "index.js": "module.exports = 1;\n" }), downloads: 0, checksum: true });
    // 60 KB compressed, more than 48 MiB once unpacked
    tarballs.set("over-unpack", { bytes: tgzOf("over-unpack", { "index.js": "module.exports = 1;\n", "data.txt": "0".repeat(50 * 1024 * 1024) }), downloads: 0, checksum: true });
    // npm lists no checksum: apm can never check the bytes it would score
    tarballs.set("no-checksum", { bytes: tgzOf("no-checksum", { "index.js": "module.exports = 1;\n" }), downloads: 0, checksum: false });

    // the platform stops a run, then one more: what the next runs do
    for (const name of ["stopped-once", "stopped-twice", "stopped-thrice", "still-running", "limit-dep"]) {
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

        const listed = served.listed ?? served.bytes;

        const dist = served.checksum
          ? { tarball, shasum: createHash("sha1").update(listed).digest("hex"), integrity: `sha512-${createHash("sha512").update(listed).digest("base64")}` }
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

    // apm add --strict: refused, with the reason; by default it installs with a warning that gives the reason
    const resolve = await getJson(`${reg.url}-/apm/v1/resolve?name=${name}&strict=1`);

    expect(resolve.status).toBe(422);
    expect(ResolveAnswer.parse(resolve.body).skipped.map((s) => s.reason).join("\n")).toContain(words);
    const warned = await getJson(`${reg.url}-/apm/v1/resolve?name=${name}`);

    expect(warned.status).toBe(200);
    expect(JSON.stringify(dig(warned.body, "warnings"))).toContain(words);
    expect(dig(warned.body, "warnings", 0, "kind")).toBe("unscorable");

    // the Bun scanner: an advisory with the reason, never only unchecked: warn by default, fatal in strict mode
    for (const strict of [false, true]) {
      const scan = await getJson(`${reg.url}-/apm/v1/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: [{ name, version: "1.0.0" }], strict }) });
      const answer = ScanAnswer.parse(scan.body);
      const advisory = answer.advisories.find((a) => a.package === name);

      expect(advisory?.level).toBe(strict ? "fatal" : "warn");
      expect(advisory?.description ?? "").toContain(words);
      expect(answer.unchecked.find((u) => u.package === name)).toBeUndefined();
    }
  }

  /** The stored score of one version: its answer, which must be 200. */
  async function scoreOf(name: string): Promise<z.infer<typeof Signals>> {
    const score = await getJson(`${reg.url}-/apm/v1/score/${name}/1.0.0`);

    expect(score.status, JSON.stringify(score.body)).toBe(200);

    return Signals.parse(score.body);
  }

  test("a tarball over the 32 MiB download cap is read as a stream and scored in full; its native binary is listed, not read", async () => {
    // on 98decb3: recorded too large ("larger than the 32 MiB apm downloads") and never scored
    expect(tarballs.get("over-download")?.bytes.length ?? 0).toBeGreaterThan(32 * 1024 * 1024);
    expect(await reg.analysisJob({ name: "over-download", version: "1.0.0" })).toBe("ack");
    const s = await scoreOf("over-download");

    expect(s.signals.find((x) => x.id === "incomplete")).toBeUndefined();
    expect(s.score).toBeGreaterThanOrEqual(75);
    // the download's refusal of the size, then one streamed pass: the code fit beside package.json
    expect(tarballs.get("over-download")?.downloads).toBe(2);

    // scored: another delivery fetches nothing (on this test clock it is still inside the run's window, so it is busy)
    await reg.analysisJob({ name: "over-download", version: "1.0.0" });
    expect(tarballs.get("over-download")?.downloads).toBe(2);
  }, 120_000);

  test("a tarball over the 48 MiB unpack cap is read as a stream from the registry's own copy and scored", async () => {
    // on 98decb3: recorded too large ("inflates to more than 48 MB"); its 50 MB data.txt is no code, so nothing is left unread
    expect(await reg.analysisJob({ name: "over-unpack", version: "1.0.0" })).toBe("ack");
    const s = await scoreOf("over-unpack");

    expect(s.signals.find((x) => x.id === "incomplete")).toBeUndefined();
    // downloaded once, checked and kept; the stream read that copy
    expect(tarballs.get("over-unpack")?.downloads).toBe(1);
  }, 120_000);

  test("a streamed tarball that fails its checksum stores nothing and is handed back to retry", async () => {
    expect(await reg.analysisJob({ name: "over-download-tampered", version: "1.0.0" })).toBe("retry");
    const score = await getJson(`${reg.url}-/apm/v1/score/over-download-tampered/1.0.0`);

    // not scored and not refused: queued, as before a run
    expect(score.status).toBe(503);
    expect(ScoreAnswer.parse(score.body).unscorable).toBeUndefined();
    expect(await reg.query("SELECT 1 FROM upstream_analysis WHERE package = 'over-download-tampered'")).toEqual([]);
    expect(Starts.parse(await reg.query("SELECT starts, outcome FROM analysis_outcomes WHERE package = 'over-download-tampered'"))).toEqual([{ starts: 1, outcome: null }]);
  }, 120_000);

  test("a version a registry before apm-score-v11 refused as too large is scored by this scorer's run", async () => {
    // what the old caps wrote (an old Worker may still write it during a deploy): an outcome under apm-score-v10
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ('old-refusal', '1.0.0', 'apm-score-v10', 'too-large', 'the tarball (43.7 MB) is larger than the 32 MiB apm downloads', $1)", [clock]);

    // outcomes are per scorer, so it decides nothing for apm-score-v11: the run reads the tarball and scores it
    expect(await reg.analysisJob({ name: "old-refusal", version: "1.0.0" })).toBe("ack");
    expect((await scoreOf("old-refusal")).signals.find((x) => x.id === "incomplete")).toBeUndefined();
  }, 120_000);

  test("the outcome is bound to the tarball it was decided for: once npm serves other bytes, the website reads the readme again (review of e4f97b2)", async () => {
    const name = "bound-outcome";
    // past what apm-score-v11 reads as a stream: a tarball over the 48 MiB a tarball read whole may inflate to is scored
    // now (above), so this one inflates past 512 MiB
    const big = await inflatesPast(name, { "index.js": "module.exports = 1;\n", "README.md": "# Readable now\n" }, 513);

    tarballs.set(name, { bytes: big, downloads: 0, checksum: true });
    expect(await reg.analysisJob({ name, version: "1.0.0" })).toBe("ack");
    const label = `sha512-${createHash("sha512").update(big).digest("hex")}`;
    const Outcome = z.array(z.object({ outcome: z.string(), digest: z.string().nullable() }));

    expect(Outcome.parse(await reg.query("SELECT outcome, digest FROM analysis_outcomes WHERE package = $1", [name]))).toEqual([{ outcome: "too-large", digest: label }]);
    const Same = z.object({ unscored: z.object({ kind: z.literal("unscorable"), sameTarball: z.boolean() }) });

    expect(Same.parse((await getJson(`${reg.url}-/apm/v1/packages/${name}`)).body).unscored.sameTarball).toBe(true);
    // npm moves 1.0.0 to a smaller tarball: the outcome names other bytes, so the website may not skip the readme,
    // which the registry now serves
    tarballs.set(name, { bytes: tgzOf(name, { "index.js": "module.exports = 1;\n", "README.md": "# Readable now\n" }), downloads: 0, checksum: true });
    expect(Same.parse((await getJson(`${reg.url}-/apm/v1/packages/${name}`)).body).unscored.sameTarball).toBe(false);
    const readme = await getJson(`${reg.url}-/apm/v1/readme/${name}/1.0.0`);

    expect(readme.status).toBe(200);
    expect(JSON.stringify(readme.body)).toContain("Readable now");
  }, 60_000);

  test("a version the upstream lists without a checksum is recorded unavailable", async () => {
    expect(await reg.analysisJob({ name: "no-checksum", version: "1.0.0" })).toBe("ack");
    await expectUnscorable("no-checksum", "unavailable", "no checksum");
  }, 60_000);

  test("a run the platform stopped is run again in full, and stores a complete score", async () => {
    // what a stopped run leaves: its start counted, nothing stored, and longer ago than any run can take. Production,
    // 13 Nov: express 5.3.0's first run shared its isolate with six others, and the memory limit ended them all
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ('stopped-once', '1.0.0', 'apm-score-v11', 1, $1)", [clock - 60 * 60_000]);
    expect(await reg.analysisJob({ name: "stopped-once", version: "1.0.0" })).toBe("ack");
    const score = await getJson(`${reg.url}-/apm/v1/score/stopped-once/1.0.0`);

    expect(score.status, JSON.stringify(score.body)).toBe(200);
    expect(Signals.parse(score.body).signals.find((x) => x.id === "incomplete")).toBeUndefined();
  }, 60_000);

  test("after two stopped runs the next is a smaller run that is incomplete, never clean, and says why first", async () => {
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ('stopped-twice', '1.0.0', 'apm-score-v11', 2, $1)", [clock - 60 * 60_000]);
    expect(await reg.analysisJob({ name: "stopped-twice", version: "1.0.0" })).toBe("ack");
    const score = await getJson(`${reg.url}-/apm/v1/score/stopped-twice/1.0.0`);

    expect(score.status, JSON.stringify(score.body)).toBe(200);
    const s = Signals.parse(score.body);

    expect(s.signals.find((x) => x.id === "incomplete")?.evidence[0]).toBe("2 earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB");
    expect(s.score).toBeLessThan(70);
  }, 60_000);

  test("after three stopped runs the next records that the version cannot be scored, without analysing", async () => {
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ('stopped-thrice', '1.0.0', 'apm-score-v11', 3, $1)", [clock - 60 * 60_000]);
    expect(await reg.analysisJob({ name: "stopped-thrice", version: "1.0.0" })).toBe("ack");
    await expectUnscorable("stopped-thrice", "analysis-limit", "3 analyses of it were stopped by the platform before they finished");
    expect(Starts.parse(await reg.query("SELECT starts, outcome FROM analysis_outcomes WHERE package = 'stopped-thrice'"))).toEqual([{ starts: 4, outcome: "analysis-limit" }]);
  }, 60_000);

  test("a run that began a minute ago may still be going: the job comes back later, and nothing is decided", async () => {
    // the queue consumer runs on the system clock (worker.ts), not the test clock
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ('still-running', '1.0.0', 'apm-score-v11', 1, $1)", [Date.now() - 60_000]);
    expect(await reg.analysisJob({ name: "still-running", version: "1.0.0" })).toBe("retry");
    expect(Starts.parse(await reg.query("SELECT starts, outcome FROM analysis_outcomes WHERE package = 'still-running'"))).toEqual([{ starts: 1, outcome: null }]);

    // and while it is not decided, the score endpoint says queued, as before
    const score = await getJson(`${reg.url}-/apm/v1/score/still-running/1.0.0`);

    expect(score.status).toBe(503);
    expect(ScoreAnswer.parse(score.body).pending).toBe(true);
  }, 60_000);

  test("apm add and apm x warn about a dependency apm can never score, naming why, and install; --strict refuses", async () => {
    // the root is scored clean by the queue; its dependency is decided analysis-limit
    expect(await reg.analysisJob({ name: "needs-limit-dep", version: "1.0.0" })).toBe("ack");
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ('limit-dep', '1.0.0', 'apm-score-v11', 'analysis-limit', 'two analyses of it were stopped', $1)", [clock]);
    const sb = makeSandbox(reg);
    const app = writeConsumer(mkdtempSync(join(tmpdir(), "apm-unscorable-")), reg, undefined, {});
    const env = { ...sb.env, APM_PENDING_WAIT_MS: "0" };

    for (const args of [["add", "needs-limit-dep", "--strict"], ["x", "needs-limit-dep", "--strict"]]) {
      const r = await apm(args, { cwd: app, env, timeoutMs: 60_000 });

      // on 9913a74: resolve answered 200 with the dependency only unchecked, and apm installed it with a warning
      expect(r.code, r.out).not.toBe(0);
      expect(r.out).toContain("limit-dep@1.0.0 apm cannot score this version: its analysis runs past the registry's limits");
    }

    expect(installedVersion(app, "needs-limit-dep")).toBeNull();
    expect(installedVersion(app, "limit-dep")).toBeNull();
    // the default: a warning naming the dependency and the reason, then the install
    const r = await apm(["add", "needs-limit-dep"], { cwd: app, env, timeoutMs: 60_000 });

    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/WARNING.*limit-dep@1\.0\.0.*apm cannot score this version: its analysis runs past the registry's limits/);
    expect(installedVersion(app, "needs-limit-dep")).toBe("1.0.0");
  }, 120_000);
});
