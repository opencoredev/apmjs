// popular-scores keeps a scored package's answer (migration 0019). Anyone can name any package, so the table is capped,
// and two new rows at once must not both take the last free place (review of d7ac98c, reproduced against a real Postgres).
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store, type LatestScore } from "../src/db.ts";

const CAPACITY = 1_000;

const scored = (name: string): LatestScore => ({ name, version: "1.0.0", score: 90, grade: "A" });

const Count = z.array(z.object({ count: z.union([z.string(), z.number()]).transform(Number) }));

describe("keepLatestScore", () => {
  test("two new rows at once cannot both take the last free place", async () => {
    const db = await freshDatabase();
    const c = new Client({ connectionString: db.url });

    await c.connect();

    try {
      const run = <A>(effect: Effect.Effect<A, unknown, Store>) => Effect.runPromise(effect.pipe(Effect.provide(Store.postgres(db.url)), Effect.scoped));
      const keep = (name: string) => Effect.flatMap(Store, (s) => s.keepLatestScore({ score: scored(name), at: 1, capacity: CAPACITY }));

      await c.query("INSERT INTO latest_scores SELECT 'seed-' || i, '1.0.0', 90, 'A', 1, 1 FROM generate_series(1, $1::int) i", [CAPACITY - 1]);
      // the first new row is added inside a transaction held open, so it has counted 999 and not committed yet
      const { promise: added, resolve: onAdded } = Promise.withResolvers<void>();
      const { promise: commit, resolve: release } = Promise.withResolvers<void>();

      const first = run(
        Effect.flatMap(Store, (s) =>
          s.tx(
            Effect.gen(function* () {
              yield* keep("race-a");
              yield* Effect.sync(() => onAdded());
              yield* Effect.promise(() => commit);
            }),
          ),
        ),
      );

      await added;
      const second = run(keep("race-b"));
      // the second waits for the first's lock instead of counting the same 999
      const deadline = Date.now() + 5_000;

      for (;;) {
        const waiting = await c.query("SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%pg_advisory_xact_lock%'");

        if (waiting.rows.length > 0) break;

        if (Date.now() > deadline) throw new Error("the second new row did not wait for the first");
        await Bun.sleep(20);
      }

      release();
      await Promise.all([first, second]);
      expect(Count.parse((await c.query("SELECT count(*) FROM latest_scores")).rows)[0]?.count).toBe(CAPACITY);
      expect((await c.query("SELECT 1 FROM latest_scores WHERE package = 'race-b'")).rows).toEqual([]);
    } finally {
      await c.end();
      await db.drop();
    }
  });

  test("an unscored answer never adds a row, and replaces a kept one", async () => {
    const db = await freshDatabase();
    const c = new Client({ connectionString: db.url });

    await c.connect();

    try {
      const run = <A>(effect: Effect.Effect<A, unknown, Store>) => Effect.runPromise(effect.pipe(Effect.provide(Store.postgres(db.url)), Effect.scoped));
      const unscored = (name: string): LatestScore => ({ name, version: null, score: null, grade: null });

      await run(Effect.flatMap(Store, (s) => s.keepLatestScore({ score: unscored("never-scored"), at: 1, capacity: CAPACITY })));
      expect((await c.query("SELECT 1 FROM latest_scores WHERE package = 'never-scored'")).rows).toEqual([]);

      await run(Effect.flatMap(Store, (s) => s.keepLatestScore({ score: scored("kept"), at: 1, capacity: CAPACITY })));
      await run(Effect.flatMap(Store, (s) => s.keepLatestScore({ score: unscored("kept"), at: 2, capacity: CAPACITY })));
      expect((await c.query("SELECT version, score, grade FROM latest_scores WHERE package = 'kept'")).rows).toEqual([{ version: null, score: null, grade: null }]);
    } finally {
      await c.end();
      await db.drop();
    }
  });
});
