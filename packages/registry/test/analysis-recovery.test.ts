// Criterion 1 of apm-score-v10, the registry's half. A run the platform stops mid-analysis always ends in a stored
// outcome: its record exists before it analyses anything (startAnalysis), the cron sweep (Analysis.recover) requeues
// it, the next run reads less and is incomplete, and after a second stop the version is recorded as one that cannot be
// scored. And no anonymous request analyses anything: its cache misses are queued, and only a signed-in or token
// caller's request analyses at most two versions inline. The store is the real Postgres one; the upstream and the queue
// are recording stubs, and the "platform stop" is a stub that ends the run between its start and its store.
import { describe, expect, test } from "bun:test";
import { Cause, Effect, Exit, Layer } from "effect";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { z } from "zod";
import { Client } from "pg";
import { SCORER } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis, INLINE_ANALYSES, MAX_FAILED_RUNS, RECOVER_PER_SWEEP, RUN_WINDOW_MS, type AnalysisJob, type AnalysisQueue } from "../src/analysis.ts";
import { Clock } from "../src/clock.ts";
import { Store, type VersionRecord } from "../src/db.ts";
import { Upstream, type Probe, type UpstreamPackage } from "../src/upstream.ts";

const T0 = Date.parse("2026-11-12T00:00:00Z");

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

/** `withManifest: false` leaves package.json out, so the analysis reads the packument's manifest instead. */
function tarball(name: string, withManifest = true): Uint8Array {
  const manifest = withManifest ? tarFile("package/package.json", JSON.stringify({ name, version: "1.0.0", license: "MIT", main: "index.js" })) : [];
  const parts = [...manifest, ...tarFile("package/index.js", "module.exports = require('./lib.js');\n"), ...tarFile("package/lib.js", "module.exports = 2;\n"), new Uint8Array(1024)];
  const tar = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;

  for (const p of parts) {
    tar.set(p, at);
    at += p.length;
  }

  return new Uint8Array(gzipSync(tar));
}

function versionOf(name: string, bytes: Uint8Array): VersionRecord {
  return {
    package: name,
    version: "1.0.0",
    manifest: { name, version: "1.0.0", main: "index.js" },
    shasum: createHash("sha1").update(bytes).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
    size: bytes.length,
    tarball_key: "",
    published_at: T0 - 86_400_000,
    seq: 0,
    published_by: "npm",
    deprecated: null,
    status: "active",
    status_reason: null,
    status_at: null,
    status_by: null,
    score: null,
  };
}

/**
 * A packument manifest whose `exports` throws when read, as the analysis overflowing its stack would: what a run that
 * fails with an error it reports looks like to the registry, whatever the cause.
 */
function throwingManifest(name: string): VersionRecord["manifest"] {
  return Object.defineProperty({ name, version: "1.0.0", main: "index.js" }, "exports", {
    enumerable: true,
    get(): never {
      throw new RangeError("Maximum call stack size exceeded.");
    },
  });
}

/**
 * The upstream as a recording stub: one version per package, its tarball served from memory, every download counted.
 * The packages named in `failing` have no package.json in their tarball and a manifest the analysis fails on.
 */
function upstreamStub(names: readonly string[], failing: readonly string[] = []) {
  const bytes = new Map([...names.map((n): [string, Uint8Array] => [n, tarball(n)]), ...failing.map((n): [string, Uint8Array] => [n, tarball(n, false)])]);
  const downloads: string[] = [];

  const pkgOf = (name: string): UpstreamPackage | null => {
    const b = bytes.get(name);

    if (!b) return null;
    const v = versionOf(name, b);

    if (failing.includes(name)) v.manifest = throwingManifest(name);

    return { name, distTags: { latest: "1.0.0" }, description: "", readme: "", maintainers: [], versions: [v], tarballs: new Map() };
  };

  const probeOf = (name: string): Probe => {
    const p = pkgOf(name);

    return p ? { kind: "found", pkg: p } : { kind: "absent" };
  };

  const layer = Layer.succeed(
    Upstream,
    Upstream.of({
      baseUrl: "http://upstream.invalid/",
      scopeExists: () => Effect.succeed("unknown"),
      search: () => Effect.succeed({ kind: "unavailable" }),
      probe: (name) => Effect.succeed(probeOf(name)),
      probeMany: (names) => Effect.succeed(new Map(names.map((n) => [n, probeOf(n)]))),
      listing: () => Effect.succeed({ kind: "unknown" }),
      get: (name) => Effect.succeed(pkgOf(name)),
      tarball: (pkg) =>
        Effect.sync(() => {
          const b = bytes.get(pkg.name);

          downloads.push(pkg.name);

          return b ? { kind: "ok", bytes: b, digest: { algo: "sha512", hex: createHash("sha512").update(b).digest("hex") } } : { kind: "absent" };
        }),
      advisories: () => Effect.succeed({ kind: "unavailable" }),
    }),
  );

  return { layer, downloads, pkgOf };
}

/** A queue that records what it is sent. */
function queueStub() {
  const sent: AnalysisJob[] = [];

  const queue: AnalysisQueue = {
    send: async (job) => {
      sent.push(job);
    },
  };

  return { queue, sent };
}

/** Thrown by the stub that stands for the platform stopping the Worker: nothing the run would do after it happens. */
const STOPPED = "the platform stopped the Worker";

class PlatformStop extends Error {
  constructor() {
    super(STOPPED);
  }
}

/**
 * The real store, except that once `stop.armed` is set, the first write of a result stops the run: the write never
 * happens, and nothing after it reaches the database either (the error handler that would take the start back runs
 * in a Worker that no longer exists).
 */
function stoppingStore(stop: { armed: boolean }) {
  return Layer.effect(
    Store,
    Effect.gen(function* () {
      const real = yield* Store;
      let stopped = false;

      const halt = (): Effect.Effect<never> =>
        Effect.suspend(() => {
          stopped = true;

          return Effect.die(new PlatformStop());
        });

      return Store.of({
        ...real,
        setUpstreamAnalysis: (input) => (stop.armed ? halt() : real.setUpstreamAnalysis(input)),
        setUnscorable: (input) => (stop.armed ? halt() : real.setUnscorable(input)),
        abandonAnalysis: (name, version) => (stopped ? Effect.void : real.abandonAnalysis(name, version)),
      });
    }),
  );
}

type Rig = { url: string; drop: () => Promise<void> };

async function withRig(fn: (rig: Rig, sql: (q: string, p?: unknown[]) => Promise<unknown[]>) => Promise<void>): Promise<void> {
  const db = await freshDatabase();
  const client = new Client({ connectionString: db.url });

  await client.connect();

  try {
    await fn(db, async (q, p = []) => (await client.query(q, p)).rows);
  } finally {
    await client.end();
    await db.drop();
  }
}

function layerFor(input: { url: string; now: number; upstream: Layer.Layer<Upstream>; queue: ReturnType<typeof queueStub>["queue"] | null; stop?: { armed: boolean } }) {
  const store = Store.postgres(input.url);
  const wrapped = input.stop ? Layer.provideMerge(stoppingStore(input.stop), store) : store;
  const base = Layer.mergeAll(wrapped, input.upstream, Clock.fixed({ now: input.now, wallNow: input.now }));

  return Layer.provideMerge(Analysis.layer(input.queue), base);
}

const Outcome = z.array(z.object({ starts: z.number(), started_at: z.coerce.number().nullable(), outcome: z.string().nullable() }));
const Stored = z.array(z.object({ analysis: z.object({ signals: z.array(z.object({ id: z.string(), evidence: z.array(z.string()) })) }) }));

describe("a run the platform stops always ends in a stored outcome", () => {
  test("stopped between start and store: the record is there, the sweep requeues it, the rerun is incomplete", async () => {
    await withRig(async (db, sql) => {
      const up = upstreamStub(["stopped-pkg"]);
      const q = queueStub();
      const stop = { armed: true };
      const pkg = up.pkgOf("stopped-pkg");

      if (!pkg) throw new Error("no package");
      const v = pkg.versions[0];

      if (!v) throw new Error("no version");

      // a token caller's request analyses it inline, and the platform stops the run before it stores anything
      const first = await Effect.runPromiseExit(
        Effect.gen(function* () {
          const a = yield* Analysis;

          yield* a.allowInline(Effect.succeed(true));

          return yield* a.ensure(pkg, v);
        }).pipe(Effect.provide(layerFor({ url: db.url, now: T0, upstream: up.layer, queue: q.queue, stop })), Effect.scoped),
      );

      expect(Exit.isFailure(first) && Cause.pretty(first.cause).includes(STOPPED)).toBe(true);
      // what the stop left: the run's record, nothing stored, nothing queued
      expect(Outcome.parse(await sql("SELECT starts, started_at, outcome FROM analysis_outcomes WHERE package = 'stopped-pkg'"))).toEqual([{ starts: 1, started_at: T0, outcome: null }]);
      expect(await sql("SELECT 1 FROM upstream_analysis WHERE package = 'stopped-pkg'")).toEqual([]);
      expect(q.sent).toEqual([]);

      // a sweep before the run could have ended leaves it alone
      const early = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now: T0 + RUN_WINDOW_MS - 1, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(early).toBe(0);
      expect(q.sent).toEqual([]);

      // the cron's sweep after it must have ended requeues it
      const swept = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now: T0 + RUN_WINDOW_MS + 1, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(swept).toBe(1);
      expect(q.sent).toEqual([{ name: "stopped-pkg", version: "1.0.0" }]);

      // the queue's run reads less and stores an incomplete analysis
      const outcome = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.runJob({ name: "stopped-pkg", version: "1.0.0" })).pipe(Effect.provide(layerFor({ url: db.url, now: T0 + RUN_WINDOW_MS + 2, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(outcome).toBe("stored");
      const [stored] = Stored.parse(await sql("SELECT analysis FROM upstream_analysis WHERE package = 'stopped-pkg' AND scorer = $1", [SCORER]));
      const incomplete = stored?.analysis.signals.find((s) => s.id === "incomplete");

      expect(incomplete?.evidence.join("\n") ?? "").toContain("stopped by the platform");

      // and the sweep has nothing left to do
      const again = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now: T0 + 3 * RUN_WINDOW_MS, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(again).toBe(0);
    });
  }, 120_000);

  test("stopped twice: the sweep requeues each time, and the third run records that it cannot be scored", async () => {
    await withRig(async (db, sql) => {
      const up = upstreamStub(["twice-pkg"]);
      const q = queueStub();
      const job = { name: "twice-pkg", version: "1.0.0" };
      let now = T0;

      for (const round of [1, 2]) {
        const stop = { armed: true };
        const run = await Effect.runPromiseExit(Effect.flatMap(Analysis, (a) => a.runJob(job)).pipe(Effect.provide(layerFor({ url: db.url, now, upstream: up.layer, queue: q.queue, stop })), Effect.scoped));

        expect({ round, stopped: Exit.isFailure(run) }).toEqual({ round, stopped: true });
        now += RUN_WINDOW_MS + 1;
        const swept = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now, upstream: up.layer, queue: q.queue })), Effect.scoped));

        expect({ round, swept }).toEqual({ round, swept: 1 });
        // the claim made for the queue is old enough to be made again by the next sweep
        await sql("UPDATE analysis_jobs SET queued_at = 0 WHERE package = 'twice-pkg'");
      }

      const last = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.runJob(job)).pipe(Effect.provide(layerFor({ url: db.url, now: now + 1, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(last).toBe("unscorable");
      expect(Outcome.parse(await sql("SELECT starts, started_at, outcome FROM analysis_outcomes WHERE package = 'twice-pkg'"))[0]).toMatchObject({ starts: 3, outcome: "analysis-limit" });
      expect(q.sent.length).toBe(2);
    });
  }, 120_000);
});

describe("no anonymous inline analysis", () => {
  test("an anonymous request queues every cache miss and downloads nothing; a signed-in one analyses two, then queues", async () => {
    await withRig(async (db, sql) => {
      const names = ["p1", "p2", "p3", "p4"];
      const up = upstreamStub(names);
      const q = queueStub();

      const request = (signedIn: boolean | null) =>
        Effect.gen(function* () {
          const a = yield* Analysis;

          if (signedIn !== null) yield* a.allowInline(Effect.succeed(signedIn));
          const out: string[] = [];

          for (const n of names) {
            const pkg = up.pkgOf(n);
            const v = pkg?.versions[0];

            if (!pkg || !v) continue;
            const got = yield* a.ensure(pkg, v);

            out.push(got.score ? "scored" : "queued");
          }

          return out;
        }).pipe(Effect.provide(layerFor({ url: db.url, now: T0, upstream: up.layer, queue: q.queue })), Effect.scoped);

      // no grant (an anonymous request), and a cookie that is no session: everything queued, nothing downloaded
      expect(await Effect.runPromise(request(null))).toEqual(["queued", "queued", "queued", "queued"]);
      expect(await Effect.runPromise(request(false))).toEqual(["queued", "queued", "queued", "queued"]);
      expect(up.downloads).toEqual([]);
      expect(q.sent.map((j) => j.name)).toEqual(names);
      expect(await sql("SELECT 1 FROM analysis_outcomes")).toEqual([]);

      // a token or signed-in caller: INLINE_ANALYSES analysed inline, the rest queued
      await sql("DELETE FROM analysis_jobs");
      expect(INLINE_ANALYSES).toBe(2);
      expect(await Effect.runPromise(request(true))).toEqual(["scored", "scored", "queued", "queued"]);
      expect(up.downloads).toEqual(["p1", "p2"]);
    });
  }, 120_000);
});

// Review of d49bf6e, finding 5: a run that failed with an error it reported called abandonAnalysis, which reset its
// start count and its start time and stored nothing, so the sweep never saw it again and the version looked queued
// forever. A failed run now keeps its start counted, and after MAX_FAILED_RUNS the version is stored as incomplete.
describe("a run that fails with an error ends in a stored outcome", () => {
  const Failures = z.array(z.object({ starts: z.number(), failures: z.number(), last_error: z.string().nullable(), started_at: z.coerce.number().nullable(), outcome: z.string().nullable() }));

  test("queued: the first failure is retried, the second stores incomplete naming the error class", async () => {
    await withRig(async (db, sql) => {
      const up = upstreamStub([], ["throws-pkg"]);
      const q = queueStub();
      const job = { name: "throws-pkg", version: "1.0.0" };
      const runAt = (now: number) => Effect.runPromise(Effect.flatMap(Analysis, (a) => a.runJob(job)).pipe(Effect.provide(layerFor({ url: db.url, now, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(MAX_FAILED_RUNS).toBe(2);
      // the queue delivers it again; the failure kept its start and made the run count as ended
      expect(await runAt(T0)).toBe("retry");
      expect(Failures.parse(await sql("SELECT starts, failures, last_error, started_at, outcome FROM analysis_outcomes WHERE package = 'throws-pkg'"))).toEqual([
        { starts: 1, failures: 1, last_error: "RangeError", started_at: T0 - RUN_WINDOW_MS, outcome: null },
      ]);
      expect(await sql("SELECT 1 FROM upstream_analysis WHERE package = 'throws-pkg'")).toEqual([]);

      // the redelivery, 30 s later, fails too: stored as incomplete, below the floor, naming the class only
      expect(await runAt(T0 + 30_000)).toBe("stored");
      const [stored] = Stored.parse(await sql("SELECT analysis FROM upstream_analysis WHERE package = 'throws-pkg' AND scorer = $1", [SCORER]));
      const incomplete = stored?.analysis.signals.find((s) => s.id === "incomplete")?.evidence.join("\n") ?? "";

      expect(incomplete).toContain("RangeError");
      expect(incomplete).not.toContain("Maximum call stack");

      // nothing left for the sweep
      const swept = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now: T0 + 3 * RUN_WINDOW_MS, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(swept).toBe(0);
    });
  }, 120_000);

  test("without a queue redelivery the sweep finds the failed run, and the next failure stores incomplete", async () => {
    await withRig(async (db, sql) => {
      const up = upstreamStub([], ["throws-pkg"]);
      const q = queueStub();
      const job = { name: "throws-pkg", version: "1.0.0" };

      expect(await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.runJob(job)).pipe(Effect.provide(layerFor({ url: db.url, now: T0, upstream: up.layer, queue: q.queue })), Effect.scoped))).toBe("retry");

      // a local registry (no queue): the sweep runs the job itself, and that run is the second failure
      const swept = await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now: T0 + 1, upstream: up.layer, queue: null })), Effect.scoped));

      expect(swept).toBe(1);
      expect(Failures.parse(await sql("SELECT starts, failures, last_error, started_at, outcome FROM analysis_outcomes WHERE package = 'throws-pkg'"))[0]).toMatchObject({ starts: 2, failures: 2 });
      expect(Stored.parse(await sql("SELECT analysis FROM upstream_analysis WHERE package = 'throws-pkg'")).length).toBe(1);
    });
  }, 120_000);

  test("inline: a failed run keeps its start, is queued, and the version stays unscored, never clean", async () => {
    await withRig(async (db, sql) => {
      const up = upstreamStub([], ["throws-pkg"]);
      const q = queueStub();
      const pkg = up.pkgOf("throws-pkg");
      const v = pkg?.versions[0];

      if (!pkg || !v) throw new Error("no package");

      const got = await Effect.runPromise(
        Effect.gen(function* () {
          const a = yield* Analysis;

          yield* a.allowInline(Effect.succeed(true));

          return yield* a.ensure(pkg, v);
        }).pipe(Effect.provide(layerFor({ url: db.url, now: T0, upstream: up.layer, queue: q.queue })), Effect.scoped),
      );

      expect(got.score).toBeNull();
      expect(q.sent).toEqual([{ name: "throws-pkg", version: "1.0.0" }]);
      expect(Failures.parse(await sql("SELECT starts, failures, last_error, started_at, outcome FROM analysis_outcomes WHERE package = 'throws-pkg'"))[0]).toMatchObject({ starts: 1, failures: 1, last_error: "RangeError" });

      // the queued run is the second failure
      expect(await Effect.runPromise(Effect.flatMap(Analysis, (a) => a.runJob({ name: "throws-pkg", version: "1.0.0" })).pipe(Effect.provide(layerFor({ url: db.url, now: T0 + 30_000, upstream: up.layer, queue: q.queue })), Effect.scoped))).toBe("stored");
    });
  }, 120_000);
});

// Review of d49bf6e, finding 6: the sweep took the oldest 200 unfinished rows, and runJob acknowledged a version the
// upstream no longer has without settling its row, so 200 removed versions ahead of one stopped live version were
// picked by every sweep and the live one never was.
describe("versions the upstream no longer has cannot starve the sweep", () => {
  const seed = async (sql: (q: string, p?: unknown[]) => Promise<unknown[]>, live: string): Promise<void> => {
    // 200 removed versions whose runs began first, then the live one, all stopped long ago
    await sql(
      `INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at)
       SELECT 'gone-' || i, '1.0.0', $1, 1, $2::bigint + i FROM generate_series(0, $3::int - 1) AS i`,
      [SCORER, T0 - 10 * RUN_WINDOW_MS, RECOVER_PER_SWEEP],
    );
    await sql("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ($1, '1.0.0', $2, 1, $3)", [live, SCORER, T0 - 5 * RUN_WINDOW_MS]);
  };

  test("no queue: the first sweep settles the removed versions as unavailable, the second scores the live one", async () => {
    await withRig(async (db, sql) => {
      const up = upstreamStub(["live-pkg"]);

      await seed(sql, "live-pkg");
      const sweep = (now: number) => Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now, upstream: up.layer, queue: null })), Effect.scoped));

      expect(await sweep(T0)).toBe(RECOVER_PER_SWEEP);
      expect(await sql("SELECT count(*)::int AS n FROM analysis_outcomes WHERE outcome = 'unavailable'")).toEqual([{ n: RECOVER_PER_SWEEP }]);
      expect(await sweep(T0 + 1)).toBe(1);
      expect(Stored.parse(await sql("SELECT analysis FROM upstream_analysis WHERE package = 'live-pkg'")).length).toBe(1);
      expect(await sweep(T0 + 2)).toBe(0);
    });
  }, 120_000);

  test("with a queue: the second sweep sends the live version, whatever the first one's jobs did", async () => {
    await withRig(async (db, sql) => {
      const up = upstreamStub(["live-pkg"]);
      const q = queueStub();

      await seed(sql, "live-pkg");
      const sweep = (now: number) => Effect.runPromise(Effect.flatMap(Analysis, (a) => a.recover).pipe(Effect.provide(layerFor({ url: db.url, now, upstream: up.layer, queue: q.queue })), Effect.scoped));

      expect(await sweep(T0)).toBe(RECOVER_PER_SWEEP);
      expect(q.sent.some((j) => j.name === "live-pkg")).toBe(false);
      // the jobs were not run yet (a slow queue): the rows the first sweep picked go to the back
      await sweep(T0 + 1);
      expect(q.sent.some((j) => j.name === "live-pkg")).toBe(true);
    });
  }, 120_000);
});
