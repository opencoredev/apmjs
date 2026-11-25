// upstreamAnalysesOf reads at most ANALYSES_BUDGET of analyses in a round trip: every stored analysis of next as one
// jsonb_agg value was tens of MB, and production's connection dropped it, so resolve answered 503 for next (2026-11-25).
// Against the real Postgres store: what it returns is what upstreamAnalyses (one package, one statement) returns, and no
// row the server sends holds more than the budget.
import { describe, expect, test } from "bun:test";
import { createServer, connect } from "node:net";
import { Effect } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { analyze, PREVIOUS_SCORER, SCORER, type Analysis } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { ANALYSES_BUDGET, Store } from "../src/db.ts";

const enc = new TextEncoder();
const manifest = { name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" };

function base(): Analysis {
  const files = [{ path: "package.json", data: JSON.stringify(manifest) }, { path: "index.js", data: "module.exports = 1;\n" }].map((f) => ({ path: f.path, size: f.data.length, mode: 0o644, data: enc.encode(f.data) }));

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

/**
 * A proxy in front of Postgres that records the largest DataRow message the server sends: each is one row of a result,
 * so the largest is the most one value of the reply held.
 */
async function measured(url: string): Promise<{ url: string; largest: () => number; close: () => void }> {
  const target = new URL(url);
  let largest = 0;

  const server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    // the server's messages are a type byte and a length that counts itself: skip each one's body as it passes
    let header = new Uint8Array(0);
    let skip = 0;

    upstream.on("data", (chunk: Uint8Array) => {
      let at = 0;

      while (at < chunk.length) {
        if (skip > 0) {
          const n = Math.min(skip, chunk.length - at);
          skip -= n;
          at += n;
          continue;
        }

        const need = 5 - header.length;
        header = new Uint8Array([...header, ...chunk.subarray(at, at + need)]);
        at += Math.min(need, chunk.length - at);

        if (header.length < 5) break;
        const length = new DataView(header.buffer).getUint32(1);

        if (header[0] === 0x44) largest = Math.max(largest, length);
        skip = length - 4;
        header = new Uint8Array(0);
      }
    });
    client.pipe(upstream);
    upstream.pipe(client);
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const proxied = new URL(url);
  proxied.hostname = "127.0.0.1";
  proxied.port = String(z.object({ port: z.number() }).parse(server.address()).port);

  return { url: proxied.toString(), largest: () => largest, close: () => server.close() };
}

describe("upstreamAnalysesOf reads analyses a budget at a time", () => {
  test("it returns what upstreamAnalyses returns, across pages, scorers, dismissals and outcomes", async () => {
    await withDatabase(async ({ sql, url }) => {
      // one's analyses of 1 MiB fill several budgets, so they come in pages; two's small ones all come with the keys
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

      await sql("INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at) VALUES ($1, 'one', '1.0.1', 'd1', 'encoded-data', 'index.js', 1, 'a font table', 'admin', 1)", [SCORER]);
      const many = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalysesOf(["one", "two", "none"])));

      expect([...many.keys()].sort()).toEqual(["one", "two"]);

      for (const name of ["one", "two"]) {
        const one = await run(url, Effect.flatMap(Store, (s) => s.upstreamAnalyses(name)));
        const got = many.get(name);

        expect(got?.scores.size).toBe(count + 1);
        expect([...(got?.scores ?? [])].sort()).toEqual([...one.scores].sort());
        expect([...(got?.unscorable ?? [])]).toEqual([...one.unscorable]);
      }
    });
  });

  test("no row of the reply holds more than the budget, however many analyses a package has", async () => {
    await withDatabase(async ({ sql, url }) => {
      // 30 analyses of about 600 kB each: 18 MB as the one value the read was before
      const analysis = { ...base(), padding: "x".repeat(600_000) };
      const size = JSON.stringify(analysis).length;

      for (let i = 0; i < 30; i++) await insert(sql, { name: "huge", version: `1.0.${i}`, digest: `d${i}`, scorer: SCORER, analysis });
      const proxy = await measured(url);

      try {
        const got = await run(proxy.url, Effect.flatMap(Store, (s) => s.upstreamAnalysesOf(["huge"])));

        expect(got.get("huge")?.scores.size).toBe(30);
        expect(proxy.largest()).toBeGreaterThan(size);
        expect(proxy.largest()).toBeLessThan(ANALYSES_BUDGET + 64 * 1024);
      } finally {
        proxy.close();
      }
    });
  });
});
