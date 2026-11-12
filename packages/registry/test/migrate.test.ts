// Review item 10: two deploys (or a deploy and a test run) migrating one database at once must not race. One
// waits for the other and then finds nothing left to do.
import { expect, test } from "bun:test";
import { Client } from "pg";
import { emptyDatabase } from "../../../tests/acceptance/postgres.ts";
import { lockTimeoutFrom, migrate, migrationFiles, statementsOf } from "../scripts/migrate.ts";

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

const RECENT_INDEX = "0009_upstream_analysis_recent";

async function connect(url: string): Promise<Client> {
  const c = new Client({ connectionString: url });
  await c.connect();

  return c;
}

/** A database with every migration applied but 0009, as production was before it. */
async function before0009(): Promise<{ url: string; drop: () => Promise<void> }> {
  const db = await emptyDatabase();
  await migrate(db.url);
  const c = await connect(db.url);

  try {
    await c.query("DROP INDEX upstream_analysis_analyzed_at");
    await c.query("DELETE FROM apm_migrations WHERE id = $1", [RECENT_INDEX]);
  } finally {
    await c.end();
  }

  return db;
}

const insertAnalysis = (c: Client, pkg: string) =>
  c.query("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, '1.0.0', 'd', 's', '{}', 1)", [pkg]);

// Review item 8: a plain CREATE INDEX inside the migration's transaction takes a SHARE lock on upstream_analysis. While it
// waits behind a long write, every later write queues behind it, so a deploy stalls the registry's scoring.
test("migration 0009 builds its index without blocking writes to upstream_analysis", async () => {
  const db = await before0009();
  const holder = await connect(db.url);
  const writer = await connect(db.url);

  try {
    // a write in flight when the deploy starts
    await holder.query("BEGIN");
    await insertAnalysis(holder, "in-flight");
    const run = migrate(db.url);
    await Bun.sleep(300);
    // a new write while the index is being built: it must not wait for the build
    await writer.query("SET statement_timeout = '2s'");
    await insertAnalysis(writer, "during-build");
    await holder.query("COMMIT");
    expect(await run).toEqual([RECENT_INDEX]);
    const index = await writer.query<{ valid: boolean }>("SELECT i.indisvalid AS valid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'upstream_analysis_analyzed_at'");

    expect(index.rows).toEqual([{ valid: true }]);
  } finally {
    await holder.end();
    await writer.end();
    await db.drop();
  }
}, 30_000);

test("migration 0009 gives up after its lock_timeout instead of waiting on a long transaction, and a retry finishes it", async () => {
  const db = await before0009();
  const holder = await connect(db.url);

  try {
    await holder.query("BEGIN");
    await insertAnalysis(holder, "long-running");
    const started = Date.now();

    const failed = await migrate(db.url).then(
      () => null,
      (e: Error) => e.message,
    );

    expect(failed).toContain(`migration ${RECENT_INDEX} failed`);
    // bounded: the migration's lock_timeout, not however long the transaction stays open
    expect(Date.now() - started).toBeLessThan(15_000);
    await holder.query("COMMIT");
    // not recorded, and the half-built index it left behind does not stop the retry
    expect(await migrate(db.url)).toEqual([RECENT_INDEX]);
    const index = await holder.query<{ valid: boolean }>("SELECT i.indisvalid AS valid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'upstream_analysis_analyzed_at'");

    expect(index.rows).toEqual([{ valid: true }]);
    // the lock_timeout stayed with the migration: the runner's later statements are not bounded by it
    expect(migrationFiles().find((m) => m.id === RECENT_INDEX)?.transaction).toBe(false);
  } finally {
    await holder.end();
    await db.drop();
  }
}, 30_000);

test("a migration marked no-transaction runs one statement at a time; the others still run inside one transaction", () => {
  const m = migrationFiles();

  expect(m.filter((x) => !x.transaction).map((x) => x.id)).toEqual([RECENT_INDEX]);
  expect(statementsOf("-- apm:no-transaction\n-- a note; with a semicolon\nSET lock_timeout = '5s';\n\nCREATE INDEX CONCURRENTLY IF NOT EXISTS a ON t (x);\n")).toEqual([
    "SET lock_timeout = '5s'",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS a ON t (x)",
  ]);
});

// Re-review finding 6: a run waiting for the migration lock polled forever, so a run that died holding it (or a stuck
// session) hung every later deploy with no message.
test("a run waiting for the migration lock gives up at its deadline and names the session that holds it", async () => {
  const db = await emptyDatabase();
  const holder = await connect(db.url);

  try {
    const pid = (await holder.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]?.pid;
    await holder.query("SELECT pg_advisory_lock($1)", [String(0x61_706d_6d69_67)]);
    const started = Date.now();
    const run = migrate(db.url, { lockTimeoutMs: 500 });
    // the old code waited forever: a 10 s ceiling stands in for that
    const outcome = await Promise.race([run.then(() => "finished", String), Bun.sleep(10_000).then(() => "still waiting after 10 s")]);

    expect(outcome).toContain("gave up after 500 ms waiting for the migration lock (Postgres advisory lock 0x61706d6d6967");
    expect(outcome).toContain(`held by backend pid ${pid}`);
    expect(outcome).toContain(`SELECT pg_terminate_backend(${pid});`);
    expect(outcome).toContain("APM_MIGRATE_LOCK_TIMEOUT_MS");
    expect(Date.now() - started).toBeLessThan(5_000);
    // once the holder lets go, a run goes through
    await holder.query("SELECT pg_advisory_unlock($1)", [String(0x61_706d_6d69_67)]);
    expect((await migrate(db.url, { lockTimeoutMs: 5_000 })).length).toBe(migrationFiles().length);
  } finally {
    await holder.end();
    await db.drop();
  }
});

test("APM_MIGRATE_LOCK_TIMEOUT_MS sets the wait; unset is five minutes; anything but a whole number of ms is refused", () => {
  expect(lockTimeoutFrom({})).toBe(5 * 60_000);
  expect(lockTimeoutFrom({ APM_MIGRATE_LOCK_TIMEOUT_MS: "1500" })).toBe(1500);

  for (const bad of ["0", "-1", "1.5", "5m", "abc"]) expect(() => lockTimeoutFrom({ APM_MIGRATE_LOCK_TIMEOUT_MS: bad })).toThrow("APM_MIGRATE_LOCK_TIMEOUT_MS");
});
