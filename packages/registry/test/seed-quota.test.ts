// A page's seeding is admitted under one global quota (db.ts admitSeedJobs, review of 4ac264b P2): on 4ac264b one claim
// from 59 reached 67 and four at once reached 91, since each counted, then inserted all eight, in one statement whose
// snapshot did not see the others. Admissions now queue on an advisory lock and claim only the room left. A user's own
// ask (claimAnalysisJob) never takes that lock. Against the real Postgres store.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store } from "../src/db.ts";

const NOW = Date.parse("2026-11-18T12:00:00Z");
const WINDOW = 10 * 60_000;
const MAX = 60;

/** The lock a trigger holds every insert on, so the test can hold four admissions at once (as the reviewer did). */
const GATE = 941_810;

async function withDatabase<A>(use: (input: { sql: (text: string, params?: unknown[]) => Promise<unknown[]>; url: string; admin: Client }) => Promise<A>): Promise<A> {
  const db = await freshDatabase();
  const admin = new Client({ connectionString: db.url });
  await admin.connect();

  try {
    return await use({ sql: async (text, params = []) => (await admin.query(text, params)).rows, url: db.url, admin });
  } finally {
    await admin.end();
    await db.drop();
  }
}

const run = <A>(url: string, effect: Effect.Effect<A, unknown, Store>) => Effect.runPromise(effect.pipe(Effect.provide(Store.postgres(url)), Effect.scoped));

const seed = (url: string, name: string) =>
  run(url, Effect.flatMap(Store, (s) => s.admitSeedJobs({ name, versions: Array.from({ length: 8 }, (_, i) => `1.0.${i}`), now: NOW, staleMs: WINDOW, since: NOW - WINDOW, max: MAX })));

/** One count a query returns. */
const Count = z.array(z.object({ n: z.number() })).length(1);

const total = async (sql: (text: string) => Promise<unknown[]>): Promise<number> => Count.parse(await sql("SELECT count(*)::int AS n FROM analysis_jobs"))[0]?.n ?? -1;

/** 59 jobs claimed in the window by other callers: one place left. */
const fill = (sql: (text: string, params?: unknown[]) => Promise<unknown[]>) => sql("INSERT INTO analysis_jobs (package, version, queued_at, scorer) SELECT 'filler', g::text, $1, 'apm-score-v12' FROM generate_series(1, 59) g", [NOW - 1000]);

describe("a page's seeding under one global quota", () => {
  test("one admission from 59 takes the one place left, not eight", async () => {
    await withDatabase(async ({ sql, url }) => {
      await fill(sql);

      // on 4ac264b: 8 admitted, 67 in the window
      expect((await seed(url, "single")).length).toBe(1);
      expect(await total(sql)).toBe(MAX);
    });
  }, 60_000);

  test("four admissions at once from 59 take the one place left between them", async () => {
    await withDatabase(async ({ sql, url, admin }) => {
      await fill(sql);
      // every insert waits on GATE while the admin holds it, so all four are in flight before any commits
      await sql(`CREATE FUNCTION test_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock_shared(${GATE}); RETURN NEW; END $$`);
      await sql("CREATE TRIGGER test_gate BEFORE INSERT ON analysis_jobs FOR EACH ROW EXECUTE FUNCTION test_gate()");
      await admin.query(`SELECT pg_advisory_lock(${GATE})`);
      const pending = Array.from({ length: 4 }, (_, i) => seed(url, `parallel-${i}`));
      let waiting = 0;

      for (let i = 0; i < 200 && waiting < 4; i++) {
        waiting = Count.parse(await sql("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'advisory'"))[0]?.n ?? 0;
        await Bun.sleep(10);
      }

      // the four are in flight: one in the gate, three queued on the seeding lock
      expect(waiting).toBe(4);
      await admin.query(`SELECT pg_advisory_unlock(${GATE})`);
      const admitted = await Promise.all(pending);

      // on 4ac264b: [8, 8, 8, 8], 91 in the window
      expect(admitted.map((a) => a.length).reduce((n, k) => n + k, 0)).toBe(1);
      expect(await total(sql)).toBe(MAX);
    });
  }, 60_000);

  test("a user's own ask is admitted at a full quota, and never waits on the seeding lock", async () => {
    await withDatabase(async ({ sql, url, admin }) => {
      await sql("INSERT INTO analysis_jobs (package, version, queued_at, scorer) SELECT 'filler', g::text, $1, 'apm-score-v12' FROM generate_series(1, 70) g", [NOW - 1000]);
      // an admission holding the seeding lock for as long as the test likes
      await admin.query("BEGIN");
      await admin.query("SELECT pg_advisory_xact_lock(x'61706d5341'::bigint)");

      const asked = await Promise.race([
        run(url, Effect.flatMap(Store, (s) => s.claimAnalysisJob("user-request", "1.0.0", NOW, WINDOW))),
        Bun.sleep(5_000).then(() => "waited" as const),
      ]);

      await admin.query("COMMIT");
      expect(asked).toBe(true);
      // and a seed at the full quota takes nothing
      expect(await seed(url, "seed-after-full")).toEqual([]);
    });
  }, 60_000);
});
