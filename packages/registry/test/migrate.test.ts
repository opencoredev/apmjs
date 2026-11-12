// Review item 10: two deploys (or a deploy and a test run) migrating one database at once must not race. One
// waits for the other and then finds nothing left to do.
import { expect, test } from "bun:test";
import { Client } from "pg";
import { emptyDatabase } from "../../../tests/acceptance/postgres.ts";
import { migrate, migrationFiles } from "../scripts/migrate.ts";

test("concurrent migration runs apply each migration once and both succeed", async () => {
  const db = await emptyDatabase();

  try {
    const runs = await Promise.allSettled([migrate(db.url), migrate(db.url), migrate(db.url)]);
    const failures = runs.flatMap((r) => (r.status === "rejected" ? [String(r.reason)] : []));

    expect(failures).toEqual([]);
    const applied = runs.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
    const ids = migrationFiles().map((m) => m.id);
    // every migration was applied by exactly one of the runs
    expect([...applied].sort()).toEqual([...ids].sort());

    const c = new Client({ connectionString: db.url });
    await c.connect();

    try {
      const recorded = await c.query<{ id: string }>("SELECT id FROM apm_migrations ORDER BY id");
      expect(recorded.rows.map((r) => r.id)).toEqual(ids);
    } finally {
      await c.end();
    }

    expect(await migrate(db.url)).toEqual([]);
  } finally {
    await db.drop();
  }
});
