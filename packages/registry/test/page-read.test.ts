// Store.pageRead is the package page's first read in one round trip: it must answer exactly what the statements it
// replaced answer (getPackage, then listVersions and owners, or keptPackage and upstreamAnalyses), mark a kept row asked
// about as keptPackage does, and read no scores when told not to. touchKeptPackage, which a view now writes after its
// answer, marks only the summary npm confirmed, and only forward. Against a real Postgres, through the real Store.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { createHash } from "node:crypto";
import { Client } from "pg";
import { z } from "zod";
import { SCORER } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store, type PageRow } from "../src/db.ts";
import { digestLabel, digestOf } from "../src/digest.ts";

const HOUR = 60 * 60_000;

const integrityOf = (text: string) => `sha512-${createHash("sha512").update(text).digest("base64")}`;

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

const run = <A>(url: string, use: (store: Store["Service"]) => Effect.Effect<A, unknown>) => Effect.runPromise(Effect.flatMap(Store, use).pipe(Effect.provide(Store.postgres(url)), Effect.scoped));

const asLocal = (row: PageRow) => {
  if (row.kind !== "local") throw new Error(`expected a local row, got ${row.kind}`);

  return row;
};

const asUpstream = (row: PageRow) => {
  if (row.kind !== "upstream") throw new Error(`expected an upstream row, got ${row.kind}`);

  return row;
};

const AskedAt = z.array(z.object({ asked_at: z.coerce.number(), computed_at: z.coerce.number() }));

describe("pageRead", () => {
  test("a package published here: the row, its versions with their dismissals left out, and its owners, as the separate reads have them", async () => {
    await withDatabase(async ({ sql, url }) => {
      const name = "@here/pkg";
      await sql("INSERT INTO packages (name, created_at, modified_at, dist_tags, description, keywords, readme, readme_version) VALUES ($1, 1, 2, $2, 'desc', $3, '# readme', '1.0.1')", [
        name,
        JSON.stringify({ latest: "1.0.1" }),
        JSON.stringify(["k"]),
      ]);

      for (const [i, version] of ["1.0.0", "1.0.1"].entries()) {
        await sql(
          `INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, status, status_reason, status_at, score)
           VALUES ($1, $2, $3, $4, $5, 10, 'sha512/x', $6, 'alice', $7, $8, $9, $10)`,
          [
            name,
            version,
            JSON.stringify({ name, version, repository: { url: "git+https://github.com/o/r.git" } }),
            "a".repeat(40),
            integrityOf(version),
            1_000 + i,
            i === 0 ? "revoke-pending" : "active",
            i === 0 ? "a leaked key" : null,
            i === 0 ? 5_000 : null,
            JSON.stringify({ score: 80, grade: "B", signals: [] }),
          ],
        );
      }

      for (const user of ["bob", "alice"]) {
        await sql("INSERT INTO users (name, password_hash, email, created_at) VALUES ($1, '', '', 0)", [user]);
        await sql('INSERT INTO owners (package, "user") VALUES ($1, $2)', [name, user]);
      }

      const digest = digestOf({ integrity: integrityOf("1.0.1"), shasum: "a".repeat(40) });

      if (!digest) throw new Error("no digest");
      await sql(
        `INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at)
         VALUES ($1, $2, '1.0.1', $3, 'eval', 'index.js', 3, 'a fixture', 'admin', 7)`,
        [SCORER, name, digestLabel(digest)],
      );

      const [row, pkg, versions, owners] = await run(url, (s) => Effect.all([s.pageRead({ name, at: 10 * HOUR, scores: true }), s.getPackage(name), s.listVersions(name), s.owners(name)]));
      const local = asLocal(row);

      expect(pkg).not.toBeNull();
      expect<unknown>(local.pkg).toEqual(pkg);
      expect(local.versions).toEqual(versions);
      expect(local.versions.map((v) => v.version)).toEqual(["1.0.0", "1.0.1"]);
      expect(local.owners).toEqual(owners);
      expect(local.owners).toEqual(["alice", "bob"]);
    });
  });

  test("an upstream package: its kept row and its scores, as keptPackage and upstreamAnalyses have them, and the row marked asked about", async () => {
    await withDatabase(async ({ sql, url }) => {
      const name = "from-npm";
      const summary = { name, etag: '"e1"', versions: [] };
      await sql("INSERT INTO kept_packages (package, summary, computed_at, asked_at) VALUES ($1, $2, 100, 0)", [name, JSON.stringify(summary)]);
      await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, '1.0.0', 'sha512-d', $2, $3, 0)", [name, SCORER, JSON.stringify({ score: 70, grade: "C", signals: [] })]);
      await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail) VALUES ($1, '0.9.0', $2, 'too-large', 'over the cap')", [name, SCORER]);
      const at = 10 * HOUR;

      const row = asUpstream(await run(url, (s) => s.pageRead({ name, at, scores: true })));
      // asked about now: the mark is written once an hour, as keptPackage writes it
      expect(AskedAt.parse(await sql("SELECT asked_at, computed_at FROM kept_packages WHERE package = $1", [name]))).toEqual([{ asked_at: at, computed_at: 100 }]);
      const [kept, analyses] = await run(url, (s) => Effect.all([s.keptPackage({ name, at }), s.upstreamAnalyses(name)]));

      expect(row.kept).toEqual(kept);
      expect(row.kept?.summary).toEqual(summary);
      expect([...row.analyses.scores]).toEqual([...analyses.scores]);
      expect([...row.analyses.unscorable]).toEqual([...analyses.unscorable]);
      expect(row.analyses.scores.size).toBe(1);
      expect(row.analyses.unscorable.get("0.9.0")).toEqual({ reason: "too-large", detail: "over the cap" });

      // the review answer's read: the same row, no scores
      const listing = asUpstream(await run(url, (s) => s.pageRead({ name, at, scores: false })));
      expect(listing.kept).toEqual(kept);
      expect(listing.analyses.scores.size).toBe(0);
      expect(listing.analyses.unscorable.size).toBe(0);
    });
  });

  test("a name nobody kept or scored: an upstream row with nothing in it", async () => {
    await withDatabase(async ({ url }) => {
      const row = asUpstream(await run(url, (s) => s.pageRead({ name: "never-seen", at: 1, scores: true })));

      expect(row.kept).toBeNull();
      expect(row.analyses.scores.size).toBe(0);
      expect(row.analyses.unscorable.size).toBe(0);
    });
  });
});

describe("touchKeptPackage", () => {
  test("marks only the summary with the ETag npm confirmed, and only forward", async () => {
    await withDatabase(async ({ sql, url }) => {
      const name = "touched";
      await sql("INSERT INTO kept_packages (package, summary, computed_at, asked_at, failures, next_attempt_at) VALUES ($1, $2, 100, 0, 2, 999)", [name, JSON.stringify({ name, etag: '"now"' })]);
      const computed = async () => AskedAt.parse(await sql("SELECT asked_at, computed_at FROM kept_packages WHERE package = $1", [name]))[0]?.computed_at;

      // another summary's ETag: replaced since npm was asked, so left alone
      await run(url, (s) => s.touchKeptPackage({ name, at: 500, etag: '"before"' }));
      expect(await computed()).toBe(100);

      await run(url, (s) => s.touchKeptPackage({ name, at: 500, etag: '"now"' }));
      expect(await computed()).toBe(500);
      expect(await sql("SELECT failures, next_attempt_at FROM kept_packages WHERE package = $1", [name])).toEqual([{ failures: 0, next_attempt_at: null }]);

      // a touch that lands late, after a newer one: the summary's time does not go back
      await run(url, (s) => s.touchKeptPackage({ name, at: 300, etag: '"now"' }));
      expect(await computed()).toBe(500);
    });
  });
});
