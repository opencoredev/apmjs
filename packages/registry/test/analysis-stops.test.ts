// Production, 13 Nov, apm-score-v10's first rescoring: seven queue runs shared one isolate and the platform ended them
// all with exceededMemory, two of them after they had stored their analysis. Each kept its start counted, so the next
// delivery of express 5.3.0, axios 1.21.1, eslint 10.14.0, prettier 3.10.1 and tailwindcss 4.3.5 was the smaller re-run
// "after a run the platform's CPU limit stopped", and each stored 39 (incomplete -61). express needs 0.3 s of CPU.
//
// A run cannot learn why the platform ended the one before it, so recovery does not ask: a run that began and stored
// nothing is run again in full, and only after STOPS_BEFORE_RERUN of them does the next read less; one more and the
// version is analysis-limit. The queue consumer runs one invocation at a time (packages/infra, maxConcurrency 1), so
// analyses no longer share an isolate. The store is the real Postgres one; the "platform stop" ends the run where it is
// armed.
import { describe, expect, test } from "bun:test";
import { Effect, Exit, Layer } from "effect";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { z } from "zod";
import { Client } from "pg";
import { SCORER } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis, MAX_FAILED_RUNS, planFor, RUN_WINDOW_MS, STOPS_BEFORE_RERUN, type AnalysisJob } from "../src/analysis.ts";
import { Clock } from "../src/clock.ts";
import { Store, type RunHistory, type VersionRecord } from "../src/db.ts";
import { Upstream, type UpstreamPackage } from "../src/upstream.ts";

const T0 = Date.parse("2026-11-13T05:49:20Z");
const JOB: AnalysisJob = { name: "express-like", version: "1.0.0" };

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

function tarball(): Uint8Array {
  const parts = [
    ...tarFile("package/package.json", JSON.stringify({ name: JOB.name, version: JOB.version, license: "MIT", main: "index.js" })),
    ...tarFile("package/index.js", "module.exports = 2;\n"),
    new Uint8Array(1024),
  ];

  const tar = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;

  for (const p of parts) {
    tar.set(p, at);
    at += p.length;
  }

  return new Uint8Array(gzipSync(tar));
}

const BYTES = tarball();

function pkg(): UpstreamPackage {
  const v: VersionRecord = {
    package: JOB.name,
    version: JOB.version,
    manifest: { name: JOB.name, version: JOB.version, main: "index.js" },
    shasum: createHash("sha1").update(BYTES).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(BYTES).digest("base64")}`,
    size: BYTES.length,
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

  return { name: JOB.name, distTags: { latest: JOB.version }, description: "", readme: "", maintainers: [], versions: [v], tarballs: new Map() };
}

const upstream = Layer.succeed(
  Upstream,
  Upstream.of({
    baseUrl: "http://upstream.invalid/",
    scopeExists: () => Effect.succeed("unknown"),
    search: () => Effect.succeed({ kind: "unavailable" }),
    probe: () => Effect.succeed({ kind: "found", pkg: pkg() }),
    probeWithin: () => Effect.succeed({ kind: "found", pkg: pkg() }),
    devDependencies: () => Effect.succeed(null),
    probeMany: (names) => Effect.succeed(new Map(names.map((n) => [n, { kind: "found" as const, pkg: pkg() }]))),
    listing: () => Effect.succeed({ kind: "unknown" }),
    get: () => Effect.succeed(pkg()),
    tarball: () => Effect.succeed({ kind: "ok", bytes: BYTES, digest: { algo: "sha512", hex: createHash("sha512").update(BYTES).digest("hex") } }),
    advisories: () => Effect.succeed({ kind: "unavailable" }),
  }),
);

/** The platform ending the invocation: nothing the run would do after it happens, and nothing it can report. */
class PlatformStop extends Error {}

/** The real store, except that while `stop.armed` is set the result's write never happens: the run is ended there. */
function stoppingStore(stop: { armed: boolean }) {
  return Layer.effect(
    Store,
    Effect.gen(function* () {
      const real = yield* Store;

      return Store.of({ ...real, setUpstreamAnalysis: (input) => (stop.armed ? Effect.die(new PlatformStop()) : real.setUpstreamAnalysis(input)) });
    }),
  );
}

function layerFor(url: string, now: number, stop: { armed: boolean }) {
  const base = Layer.mergeAll(Layer.provideMerge(stoppingStore(stop), Store.postgres(url)), upstream, Clock.fixed({ now, wallNow: now }));

  return Layer.provideMerge(Analysis.layer(null), base);
}

const Signals = z.array(z.object({ analysis: z.object({ signals: z.array(z.object({ id: z.string(), evidence: z.array(z.string()) })) }) }));

async function withDb(fn: (url: string, sql: (q: string, p?: unknown[]) => Promise<unknown[]>) => Promise<void>): Promise<void> {
  const db = await freshDatabase();
  const client = new Client({ connectionString: db.url });

  await client.connect();

  try {
    await fn(db.url, async (q, p = []) => (await client.query(q, p)).rows);
  } finally {
    await client.end();
    await db.drop();
  }
}

/** One delivery at `now`; `stopped` ends it before it stores anything. */
function deliver(url: string, now: number, stopped: boolean) {
  return Effect.runPromiseExit(Effect.flatMap(Analysis, (a) => a.runJob(JOB)).pipe(Effect.provide(layerFor(url, now, { armed: stopped })), Effect.scoped));
}

/** A delivery the platform ends before it stores anything. */
async function stoppedAt(url: string, now: number): Promise<void> {
  expect(Exit.isFailure(await deliver(url, now, true))).toBe(true);
}

async function storedAt(url: string, now: number): Promise<string | null> {
  const exit = await deliver(url, now, false);

  return Exit.isSuccess(exit) ? exit.value : null;
}

const Row = z.array(z.object({ starts: z.number(), outcome: z.string().nullable(), detail: z.string().nullable() }));

const outcomeRow = async (sql: (q: string, p?: unknown[]) => Promise<unknown[]>) => Row.parse(await sql("SELECT starts, outcome, detail FROM analysis_outcomes WHERE package = $1", [JOB.name]))[0];

const STEP = RUN_WINDOW_MS + 1;

async function incompleteEvidence(sql: (q: string, p?: unknown[]) => Promise<unknown[]>): Promise<readonly string[] | null> {
  const [row] = Signals.parse(await sql("SELECT analysis FROM upstream_analysis WHERE package = $1 AND scorer = $2", [JOB.name, SCORER]));

  if (!row) throw new Error("nothing stored");

  return row.analysis.signals.find((s) => s.id === "incomplete")?.evidence ?? null;
}

describe("a run that began and stored nothing: full, full, reduced, then analysis-limit", () => {
  test("one stop (production's exceededMemory): the next delivery runs in full and stores a complete analysis", async () => {
    await withDb(async (url, sql) => {
      await stoppedAt(url, T0);

      expect(await storedAt(url, T0 + STEP)).toBe("stored");
      // on 3549541: "an earlier analysis of this version was stopped by the platform's CPU limit or failed before it
      // stored anything, so this one read at most 4 MB", incomplete -61
      expect(await incompleteEvidence(sql)).toBeNull();
    });
  }, 60_000);

  test(`after ${STOPS_BEFORE_RERUN} stops the next run reads less and says why first`, async () => {
    await withDb(async (url, sql) => {
      for (let i = 0; i < STOPS_BEFORE_RERUN; i++) await stoppedAt(url, T0 + i * STEP);

      expect(await storedAt(url, T0 + STOPS_BEFORE_RERUN * STEP)).toBe("stored");
      expect((await incompleteEvidence(sql))?.[0]).toBe(`${STOPS_BEFORE_RERUN} earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB`);
    });
  }, 60_000);

  test("if the smaller run is stopped too, the next records analysis-limit before it fetches anything", async () => {
    await withDb(async (url, sql) => {
      for (let i = 0; i <= STOPS_BEFORE_RERUN; i++) await stoppedAt(url, T0 + i * STEP);

      expect(await storedAt(url, T0 + (STOPS_BEFORE_RERUN + 1) * STEP)).toBe("unscorable");
      expect(await outcomeRow(sql)).toMatchObject({ starts: STOPS_BEFORE_RERUN + 2, outcome: "analysis-limit", detail: expect.stringContaining(`${STOPS_BEFORE_RERUN + 1} analyses of it were stopped by the platform before they finished`) });
    });
  }, 60_000);

  test("a run that failed with an error it reported is followed by a run in full", async () => {
    await withDb(async (url, sql) => {
      // what failAnalysis leaves after one failed run: its start, and the failure counted
      await sql("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at, failures) VALUES ($1, $2, $3, 1, $4, 1)", [JOB.name, JOB.version, SCORER, T0]);

      expect(await storedAt(url, T0 + STEP)).toBe("stored");
      expect(await incompleteEvidence(sql)).toBeNull();
    });
  }, 60_000);
});

describe("planFor", () => {
  const history = (h: Partial<RunHistory>): RunHistory => ({ starts: 1, fetchFailures: 0, fetchFailedSince: null, failures: 0, ...h });

  const kindOf = (h: Partial<RunHistory>): string => {
    const next = planFor(history(h));

    return next.kind === "give-up" ? "give-up" : next.plan.maxScannedBytes === undefined ? "full" : "reduced";
  };

  test("full, full, reduced, then give up, counting only runs that began and stored nothing", () => {
    expect([1, 2, 3, 4, 5].map((starts) => kindOf({ starts }))).toEqual(["full", "full", "reduced", "give-up", "give-up"]);
  });

  test("runs that ended (a fetch failure, a reported error) are not stops", () => {
    expect(kindOf({ starts: 4, fetchFailures: 3 })).toBe("full");
    // a run that failed with an error it reported: the next is in full; MAX_FAILED_RUNS decides what follows
    expect(kindOf({ starts: 2, failures: 1 })).toBe("full");
    expect(kindOf({ starts: MAX_FAILED_RUNS + 1, failures: MAX_FAILED_RUNS })).toBe("full");
    expect(kindOf({ starts: 3, fetchFailures: 1, failures: 1 })).toBe("full");
    expect(kindOf({ starts: 4, fetchFailures: 1 })).toBe("reduced");
  });
});
