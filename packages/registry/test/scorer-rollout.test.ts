// apm-score-v11 reads an apm-score-v10 analysis it would store the same as its own (review of e8616ca, finding 2). The
// test is written twice, as SQL (apm_v10_reusable, migration 0023) for the store's queries and as TypeScript
// (@apm/core's reusableAnalysis) for what they return: here both answer every fixture the same, and the store's reads,
// decisions and runs follow them. Against the real Postgres store.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { Client } from "pg";
import { analyze, finalize, parseAnalysis, PREVIOUS_SCORER, reusableAnalysis, SCORER, type Analysis } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { unscoredOf } from "../src/apm.ts";
import { Store, type UpstreamAnalyses, type VersionRecord } from "../src/db.ts";
import { admitted } from "../src/kept-package.ts";
import { scoredPackage, type CachedPackage, type UpstreamPackage } from "../src/upstream.ts";

const enc = new TextEncoder();
const manifest = { name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" };

/** A real analysis of a two-file package. */
function base(): Analysis {
  const text = "module.exports = 1;\n";
  const files = [{ path: "package.json", data: JSON.stringify(manifest) }, { path: "index.js", data: text }].map((f) => ({ path: f.path, size: f.data.length, mode: 0o644, data: enc.encode(f.data) }));

  return analyze({ name: "pkg", manifest, files, publisher: "a", previousPublishers: [] });
}

/** `a` as apm-score-v10 stored it: its name, and no coverage (v11 added it). */
function asV10(a: Analysis, change: (a: Analysis) => Analysis = (x) => x): Analysis {
  const { coverage: _coverage, ...rest } = a;

  return change({ ...rest, scorer: PREVIOUS_SCORER });
}

const incomplete = { id: "incomplete" as const, label: "Analysis incomplete", points: -61, evidence: ["not analyzed: big.js (34.0 MB, over the 32 MB limit)"], confidence: "confirmed" as const };

/** What the store's TypeScript makes of a stored row: parsed, then the current scorer's reading of it. */
const readAs = (stored: VersionRecord["score"]): Analysis | null => {
  const parsed = parseAnalysis(stored);

  return parsed === null ? null : reusableAnalysis(parsed);
};

/** Every kind of stored analysis the rule decides on, with whether v11 takes it as its own. */
const FIXTURES: { name: string; analysis: VersionRecord["score"]; reusable: boolean }[] = [
  { name: "v10, clean", analysis: asV10(base()), reusable: true },
  { name: "v10, a file skipped", analysis: asV10(base(), (a) => ({ ...a, skipped: [{ path: "big.js", size: 1, reason: "too-large" }] })), reusable: false },
  { name: "v10, incomplete", analysis: asV10(base(), (a) => ({ ...a, signals: [...a.signals, incomplete] })), reusable: false },
  // incomplete for any reason, not only a file's size: a flow cut or an analysis that stopped early is scored differently
  // by the scorer that ships with apm-score-v11, so it is never reused
  {
    name: "v10, incomplete for a cut flow",
    analysis: asV10(base(), (a) => ({ ...a, signals: [...a.signals, { ...incomplete, evidence: ["flows across files: stopped at the work budget (2000000 steps), so values one file gives another were not all followed"] }] })),
    reusable: false,
  },
  {
    name: "v10, stopped at the work limit",
    analysis: asV10(base(), (a) => ({ ...a, signals: [{ ...incomplete, evidence: ["analysis work limit: apm stopped reading this version while following where values go, at the 320,000,000 units one analysis may spend, so nothing it holds was cleared"] }] })),
    reusable: false,
  },
  { name: "v10, unanalyzed files", analysis: asV10(base(), (a) => ({ ...a, signals: [...a.signals, { ...incomplete, id: "unanalyzed-files", points: -20 }] })), reusable: false },
  { name: "v10, partial coverage", analysis: asV10(base(), (a) => ({ ...a, coverage: { kind: "partial", omittedFiles: 1, omittedBytes: 1, reasons: ["over-budget"], notes: [] } })), reusable: false },
  { name: "v10, complete coverage", analysis: asV10(base(), (a) => ({ ...a, coverage: { kind: "complete" } })), reusable: true },
  { name: "v9", analysis: { ...asV10(base()), scorer: "apm-score-v9" }, reusable: false },
  { name: "not an analysis", analysis: { scorer: PREVIOUS_SCORER, signals: "none" }, reusable: false },
];

async function withDatabase<A>(use: (input: { sql: (text: string, params?: unknown[]) => Promise<unknown[]>; url: string }) => Promise<A>): Promise<A> {
  const db = await freshDatabase();
  const c = new Client({ connectionString: db.url });
  await c.connect();

  try {
    return await use({ sql: async (text, params = []) => (await c.query(text, params)).rows, url: db.url });
  } finally {
    await c.end();
    await db.drop();
  }
}

const run = <A>(url: string, effect: Effect.Effect<A, unknown, Store>) => Effect.runPromise(effect.pipe(Effect.provide(Store.postgres(url)), Effect.scoped));

describe("which apm-score-v10 analyses apm-score-v11 takes as its own", () => {
  test("the SQL rule and the TypeScript rule answer every fixture the same", async () => {
    await withDatabase(async ({ sql }) => {
      for (const f of FIXTURES) {
        const [row] = await sql("SELECT apm_v10_reusable($1::jsonb) AS reusable", [JSON.stringify(f.analysis)]);

        expect({ name: f.name, sql: row }).toEqual({ name: f.name, sql: { reusable: f.reusable } });
        expect({ name: f.name, ts: readAs(f.analysis) !== null }).toEqual({ name: f.name, ts: f.reusable });
      }
    });
  });

  test("the store reads a reusable v10 analysis as complete, prefers v11's for the same bytes, and leaves the rest out", async () => {
    await withDatabase(async ({ sql, url }) => {
      const insert = (version: string, digest: string, scorer: string, analysis: VersionRecord["score"]) =>
        sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('pkg', $1, $2, $3, $4::jsonb, 1)", [version, digest, scorer, JSON.stringify(analysis)]);

      await insert("1.0.0", "d1", PREVIOUS_SCORER, FIXTURES[0]?.analysis);
      await insert("1.0.1", "d2", PREVIOUS_SCORER, FIXTURES[2]?.analysis);
      // the same bytes analysed by both: v11's is the one read
      await insert("1.0.2", "d3", PREVIOUS_SCORER, FIXTURES[0]?.analysis);
      await insert("1.0.2", "d3", SCORER, { ...base(), facts: { ...base().facts, fileCount: 99 } });
      const { scores } = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalyses("pkg")));

      // on e8616ca: none of the v10 rows was read
      expect(readAs(scores.get("1.0.0 d1"))).toMatchObject({ scorer: PREVIOUS_SCORER, coverage: { kind: "complete" } });
      expect(scores.has("1.0.1 d2")).toBe(false);
      expect(readAs(scores.get("1.0.2 d3"))).toMatchObject({ scorer: SCORER, facts: { fileCount: 99 } });
    });
  });

  test("evidence an apm reviewer dismissed against v10 still applies to the analysis v11 reuses", async () => {
    await withDatabase(async ({ sql, url }) => {
      // a dismissable signal as a stored v10 analysis carries one: -2 for data that looks encoded, cited at index.js:1
      const v10 = asV10(base(), (a) => ({ ...a, signals: [...a.signals, { id: "encoded-data", label: "Holds long encoded data", points: -2, evidence: ["index.js:1: AGFzbQEAAAAB… (text match)"], confidence: "confirmed" }] }));

      expect(finalize(v10, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null }).score).toBe(98);
      await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('pkg', '1.0.0', 'd1', $1, $2::jsonb, 1)", [PREVIOUS_SCORER, JSON.stringify(v10)]);
      await sql("INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at) VALUES ($1, 'pkg', '1.0.0', 'd1', 'encoded-data', 'index.js', 1, 'a font table', 'admin', 1)", [PREVIOUS_SCORER]);
      const { scores } = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalyses("pkg")));
      const read = readAs(scores.get("1.0.0 d1"));

      expect(read?.signals.find((s) => s.id === "encoded-data")).toBeUndefined();
      expect(finalize(read ?? v10, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null }).score).toBe(100);
    });
  });

  test("evidence dismissed against v10 does not carry onto v11's own analysis of the same bytes", async () => {
    await withDatabase(async ({ sql, url }) => {
      // a v11 analysis citing the same line a v10 reviewer dismissed: the dismissal names v10, so it stays
      const v11 = { ...base(), signals: [{ id: "encoded-data" as const, label: "Holds long encoded data", points: -2, evidence: ["index.js:1: AGFzbQEAAAAB… (text match)"], confidence: "confirmed" as const }] };

      await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('pkg', '1.0.0', 'd1', $1, $2::jsonb, 1)", [SCORER, JSON.stringify(v11)]);
      await sql("INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at) VALUES ($1, 'pkg', '1.0.0', 'd1', 'encoded-data', 'index.js', 1, 'a font table', 'admin', 1)", [PREVIOUS_SCORER]);
      const { scores } = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalyses("pkg")));

      expect(readAs(scores.get("1.0.0 d1"))?.signals.find((s) => s.id === "encoded-data")?.evidence).toEqual(["index.js:1: AGFzbQEAAAAB… (text match)"]);
    });
  });

  test("a reusable v10 result is decided: waits end on it, and no run starts for it", async () => {
    await withDatabase(async ({ sql, url }) => {
      await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('pkg', '1.0.0', 'd1', $1, $2::jsonb, 1), ('pkg', '1.0.1', 'd2', $1, $3::jsonb, 1)", [PREVIOUS_SCORER, JSON.stringify(FIXTURES[0]?.analysis), JSON.stringify(FIXTURES[2]?.analysis)]);
      await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ('pkg', '1.0.2', $1, 'unreadable', 'x', 1), ('pkg', '1.0.3', $1, 'too-large', 'x', 1)", [PREVIOUS_SCORER]);
      const versions = ["1.0.0", "1.0.1", "1.0.2", "1.0.3"].map((version) => ({ name: "pkg", version }));
      const decided = await run(url, Effect.flatMap(Store, (s) => s.decidedAnalyses(versions)));

      // a clean v10 analysis and a v10 decision v11 keeps; not one v11 scores differently, nor a v10 size refusal
      expect([...decided].sort()).toEqual(["pkg 1.0.0", "pkg 1.0.2"]);
      const starts = await run(url, Effect.flatMap(Store, (s) => Effect.forEach(versions, (v) => s.startAnalysis({ ...v, now: 1000, runMs: 10 }))));

      expect(starts.map((x) => x.kind)).toEqual(["decided", "started", "decided", "started"]);
    });
  });
});

describe("apm-score-v11's reuse rule and main's outcome digest (migration 0022) agree", () => {
  // next 16.4.6's bytes and those of a version v10 could not open, by the label migration 0022 records
  const TOO_LARGE_DIGEST = `sha512-${"aa".repeat(64)}`;
  const UNREADABLE_DIGEST = `sha512-${"bb".repeat(64)}`;
  const integrity = (label: string) => `sha512-${Buffer.from(label.slice("sha512-".length), "hex").toString("base64")}`;

  /** next as npm lists it: 16.4.6, which v10 refused as too large, and 16.4.5, which v10 could not open. */
  function next(): CachedPackage {
    const v = (version: string, seq: number, digest: string): Omit<VersionRecord, "score"> => ({
      package: "next",
      version,
      manifest: { name: "next", version },
      shasum: "",
      integrity: integrity(digest),
      size: 0,
      tarball_key: "",
      published_at: seq,
      seq,
      published_by: "a",
      deprecated: null,
      status: "active",
      status_reason: null,
      status_at: null,
      status_by: null,
    });

    return { name: "next", distTags: { latest: "16.4.6" }, description: "", readme: "", maintainers: [], versions: [v("16.4.5", 0, UNREADABLE_DIGEST), v("16.4.6", 1, TOO_LARGE_DIGEST)], tarballs: new Map(), serveCost: { versionDocs: 0, maxPieceChars: 0 }, etag: null, fetchedAt: 0, readAt: 0 };
  }

  const found = (analyses: UpstreamAnalyses): UpstreamPackage => {
    const p = scoredPackage(next(), analyses);

    if (p.kind !== "found") throw new Error("not found");

    return p.pkg;
  };

  test("a v10 too-large outcome with a digest is analysed again; a v10 unreadable one keeps its digest, so sameTarball holds", async () => {
    await withDatabase(async ({ sql, url }) => {
      await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES ('next', '16.4.6', $1, 'too-large', 'the tarball (43.7 MB) is larger than the 32 MiB apm downloads', $2, 1), ('next', '16.4.5', $1, 'unreadable', 'x', $3, 1)", [
        PREVIOUS_SCORER,
        TOO_LARGE_DIGEST,
        UNREADABLE_DIGEST,
      ]);
      const one = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalyses("next")));
      const many = (await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalysesOf(["next"])))).get("next");

      for (const a of [one, many]) {
        expect([...(a?.unscorable ?? new Map())]).toEqual([["16.4.5", { reason: "unreadable", detail: "x", digest: UNREADABLE_DIGEST }]]);
      }

      const pkg = found(one);
      const [older, latest] = pkg.versions;

      expect(older && unscoredOf({ kind: "upstream" }, older)).toMatchObject({ kind: "unscorable", sameTarball: true });
      // 16.4.6 waits for v11's streamed read instead of showing v10's refusal
      expect(latest && unscoredOf({ kind: "upstream" }, latest)).toEqual({ kind: "queued", text: "not scored yet: queued for analysis" });
      expect((await run(url, Effect.flatMap(Store, (s) => s.startAnalysis({ name: "next", version: "16.4.6", now: 1000, runMs: 10 })))).kind).toBe("started");
    });
  });

  test("next is kept without a score on its v10 unreadable outcome, and by its score once v11 scores 16.4.6", async () => {
    await withDatabase(async ({ sql, url }) => {
      await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES ('next', '16.4.6', $1, 'too-large', 'x', $2, 1)", [PREVIOUS_SCORER, TOO_LARGE_DIGEST]);
      const read = () => run(url, Effect.flatMap(Store, (s) => s.upstreamAnalyses("next")));

      // v10's size refusal alone no longer admits next: v11 does not read it as decided
      expect(admitted(found(await read()))).toBe(false);
      await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES ('next', '16.4.5', $1, 'unreadable', 'x', $2, 1)", [PREVIOUS_SCORER, UNREADABLE_DIGEST]);
      expect(admitted(found(await read()))).toBe(true);
      await sql("DELETE FROM analysis_outcomes WHERE package = 'next'");
      // v11's streamed read of 16.4.6, a partial reading, is a score like any other
      const v11 = { ...base(), coverage: { kind: "partial", omittedFiles: 3, omittedBytes: 120_000_000, reasons: ["too-large"], notes: [] } };

      await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('next', '16.4.6', $1, $2, $3::jsonb, 1)", [TOO_LARGE_DIGEST, SCORER, JSON.stringify(v11)]);
      const pkg = found(await read());

      expect(pkg.versions.map((v) => v.score !== null)).toEqual([false, true]);
      expect(admitted(pkg)).toBe(true);
    });
  });
});
