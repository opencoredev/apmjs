// upstreamAnalysesOf sends each stored analysis as a row of its own: every stored analysis of next as one jsonb_agg
// value was tens of MB, and production's connection dropped it, so resolve answered 503 for next (2026-11-25).
// upstreamAnalyses (one package) kept that one-row shape, so the ~safe and full packuments of next answered 503 too
// (2026-11-26). Against the real Postgres store: what upstreamAnalysesOf returns is what upstreamAnalyses returns, and no
// row the server sends either of them holds more than one analysis.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { analyze, parseAnalysis, PREVIOUS_SCORER, SCORER, type Analysis } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store } from "../src/db.ts";
import { measured } from "./pg-proxy.ts";

const enc = new TextEncoder();
const manifest = { name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" };

/** An analysis with one dismissable item: index.js:1 names credential files. */
function base(): Analysis {
  const files = [{ path: "package.json", data: JSON.stringify(manifest) }, { path: "index.js", data: "module.exports = { deny: ['.env', '.npmrc'] };\n" }].map((f) => ({ path: f.path, size: f.data.length, mode: 0o644, data: enc.encode(f.data) }));

  return analyze({ name: "pkg", manifest, files, publisher: "a", previousPublishers: [] });
}

/** `a` as apm-score-v10 stored it, which v11 reuses only with complete coverage. */
const asV10 = (a: Analysis, coverage: Analysis["coverage"]): Analysis => ({ ...a, coverage, scorer: PREVIOUS_SCORER });

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

const insert = (sql: (text: string, params?: unknown[]) => Promise<unknown[]>, row: { name: string; version: string; digest: string; scorer: string; analysis: unknown }) =>
  sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, $2, $3, $4, $5::jsonb, 1)", [row.name, row.version, row.digest, row.scorer, JSON.stringify(row.analysis)]);

describe("upstreamAnalysesOf reads one analysis a row", () => {
  test("it returns what upstreamAnalyses returns, across packages, scorers, dismissals and outcomes", async () => {
    await withDatabase(async ({ sql, url }) => {
      // one's analyses are 1 MiB each, two's small
      const big = { ...base(), padding: "x".repeat(1024 * 1024) };
      const count = 11;

      for (const name of ["one", "two"]) {
        const a = name === "one" ? big : base();

        for (let i = 0; i < count; i++) await insert(sql, { name, version: `1.0.${i}`, digest: `d${i}`, scorer: SCORER, analysis: a });
        // v10 rows: reused with complete coverage, left out with partial, and one replaced by v11's for the same bytes
        await insert(sql, { name, version: "2.0.0", digest: "e1", scorer: PREVIOUS_SCORER, analysis: asV10(a, { kind: "complete" }) });
        await insert(sql, { name, version: "2.0.1", digest: "e2", scorer: PREVIOUS_SCORER, analysis: asV10(a, { kind: "partial", omittedFiles: 1, omittedBytes: 1, reasons: ["over-budget"], notes: [] }) });
        await insert(sql, { name, version: "1.0.0", digest: "d0", scorer: PREVIOUS_SCORER, analysis: asV10(a, { kind: "complete" }) });
        await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES ($1, '3.0.0', $2, 'unreadable', 'x', 'f1', 1)", [name, SCORER]);
      }

      await sql("INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at) VALUES ($1, 'one', '1.0.1', 'd1', 'credential-mention', 'index.js', 1, 'a deny list', 'admin', 1)", [SCORER]);
      const many = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalysesOf(["one", "two", "none"])));

      expect([...many.keys()].sort()).toEqual(["one", "two"]);

      for (const name of ["one", "two"]) {
        const one = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalyses(name)));
        const got = many.get(name);

        expect(got?.scores.size).toBe(count + 1);
        expect([...(got?.scores ?? [])].sort()).toEqual([...one.scores].sort());
        expect([...(got?.unscorable ?? [])]).toEqual([...one.unscorable]);
      }

      // written out, since upstreamAnalyses is upstreamAnalysesOf for one name: every v11 row, v10's complete reading
      // reused and its partial one left out, and the outcome decided
      for (const name of ["one", "two"]) {
        const got = many.get(name);

        expect([...(got?.scores.keys() ?? [])].sort()).toEqual([...Array.from({ length: count }, (_, i) => `1.0.${i} d${i}`), "2.0.0 e1"].sort());
        expect([...(got?.unscorable ?? [])]).toEqual([["3.0.0", { reason: "unreadable", detail: "x", digest: "f1" }]]);
      }

      // the dismissal is for evidence the analysis has: it moves from the signal to dismissed, for those bytes only
      expect(base().signals.some((s) => s.id === "credential-mention")).toBe(true);
      const dismissed = parseAnalysis(many.get("one")?.scores.get("1.0.1 d1"));
      const other = parseAnalysis(many.get("one")?.scores.get("1.0.2 d2"));

      expect(dismissed?.dismissed?.map((d) => [d.signal, d.file, d.line, d.reason])).toEqual([["credential-mention", "index.js", 1, "a deny list"]]);
      expect(dismissed?.signals.some((s) => s.id === "credential-mention")).toBe(false);
      expect(other?.dismissed ?? []).toEqual([]);
      expect(other?.signals.some((s) => s.id === "credential-mention")).toBe(true);
    });
  });

  // the rows of each package as one value: next-like, 60 analyses of about 270 kB (16 MB), and 3000 small ones
  test.each([
    { name: "next-like", count: 60, padding: 270_000 },
    { name: "many-small", count: 3000, padding: 0 },
  ])("no row of the reply holds more than one analysis: $name", async ({ name, count, padding }) => {
    await withDatabase(async ({ sql, url }) => {
      await sql(
        "INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) SELECT $1, '1.0.' || i, 'd' || i, $2, $3::jsonb, 1 FROM generate_series(1, $4::int) i",
        [name, SCORER, JSON.stringify({ ...base(), padding: "x".repeat(padding) }), count],
      );
      const [sizes] = await sql("SELECT max(octet_length(analysis::text)) AS one, sum(octet_length(analysis::text)) AS every FROM upstream_analysis");
      const { one, every } = z.object({ one: z.coerce.number(), every: z.coerce.number() }).parse(sizes);
      expect(every).toBeGreaterThan(10 * one);

      for (const read of [(s: Store["Service"]) => Effect.map(s.upstreamAnalysesOf([name]), (m) => m.get(name)), (s: Store["Service"]) => s.upstreamAnalyses(name)]) {
        const proxy = await measured(url);

        try {
          const got = await run(proxy.url, Effect.flatMap(Store, read));

          expect(got?.scores.size).toBe(count);
          expect(proxy.largest()).toBeGreaterThan(one);
          // the analysis and its key, kind and place in the reply
          expect(proxy.largest()).toBeLessThan(one + 1024);
        } finally {
          proxy.close();
        }
      }
    });
  });
});
