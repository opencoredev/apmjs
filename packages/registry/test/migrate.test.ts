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

  expect(m.filter((x) => !x.transaction).map((x) => x.id)).toEqual([RECENT_INDEX, "0011_unfinished_analyses", "0014_analysis_indexes"]);

  // no migration in a transaction builds an index: a plain CREATE INDEX holds every write to its table behind it
  for (const x of m.filter((y) => y.transaction && y.id > RECENT_INDEX)) expect(x.sql).not.toMatch(/CREATE\s+(?:UNIQUE\s+)?INDEX/i);
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

/**
 * A database migrated, as the deploy would, through every migration before `through` (applied directly, without the
 * runner's lock), as one that last deployed before it was.
 */
async function migratedBefore(through: string): Promise<{ url: string; drop: () => Promise<void> }> {
  const db = await emptyDatabase();
  const c = await connect(db.url);

  try {
    await c.query("CREATE TABLE apm_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");

    for (const m of migrationFiles().filter((x) => x.id < through)) {
      if (m.transaction) {
        await c.query("BEGIN");
        await c.query(m.sql);
        await c.query("INSERT INTO apm_migrations (id) VALUES ($1)", [m.id]);
        await c.query("COMMIT");
      } else {
        for (const s of statementsOf(m.sql)) await c.query(s);
        await c.query("RESET ALL");
        await c.query("INSERT INTO apm_migrations (id) VALUES ($1)", [m.id]);
      }
    }
  } finally {
    await c.end();
  }

  return db;
}

const validIndexes = async (c: Client, names: readonly string[]): Promise<Record<string, boolean>> => {
  const rows = (await c.query<{ name: string; valid: boolean }>("SELECT c.relname AS name, i.indisvalid AS valid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = ANY($1)", [names])).rows;

  return Object.fromEntries(rows.map((r) => [r.name, r.valid]));
};

// Review of 5b5b492, finding 4: 0013 built analysis_jobs_queued with a plain CREATE INDEX inside its transaction. Behind
// one open write to analysis_jobs the build waited, and the queue's next write waited behind the build, for as long as
// that transaction stayed open. On 5b5b492 the writer below times out.
test("upgrading from 0012 with a write to analysis_jobs open does not hold later writes behind the index build", async () => {
  const db = await migratedBefore("0013");
  const holder = await connect(db.url);
  const writer = await connect(db.url);
  let run: Promise<string[]> | undefined;

  try {
    await holder.query("BEGIN");
    await holder.query("INSERT INTO analysis_jobs (package, version, queued_at) VALUES ('in-flight', '1.0.0', 1)");
    run = migrate(db.url);
    await Bun.sleep(300);
    // the queue's next write, while the build waits for the one in flight
    await writer.query("SET statement_timeout = '1s'");
    await writer.query("INSERT INTO analysis_jobs (package, version, queued_at) VALUES ('later', '1.0.0', 2)");
    await holder.query("COMMIT");
    expect(await run).toEqual(["0013_analysis_attempts", "0014_analysis_indexes", "0015_rescore_runtime_failures", "0016_release_rescore_reservations"]);
    expect(await validIndexes(writer, ["analysis_jobs_queued", "analysis_outcomes_unswept", "analysis_outcomes_unfinished"])).toEqual({ analysis_jobs_queued: true, analysis_outcomes_unswept: true });
    const cols = (await writer.query<{ name: string }>("SELECT column_name AS name FROM information_schema.columns WHERE table_name = 'analysis_outcomes' AND column_name LIKE 'fetch_%' ORDER BY 1")).rows;

    expect(cols.map((r) => r.name)).toEqual(["fetch_failed_since", "fetch_failures"]);
  } finally {
    await holder.query("ROLLBACK").catch(() => {});
    await run?.catch(() => {});
    await holder.end();
    await writer.end();
    await db.drop();
  }
}, 30_000);

// The same check for 0011, whose index on analysis_outcomes was a plain CREATE INDEX too.
test("upgrading from 0010 with a write to analysis_outcomes open does not hold later writes behind the index build", async () => {
  const db = await migratedBefore("0011");
  const holder = await connect(db.url);
  const writer = await connect(db.url);
  let run: Promise<string[]> | undefined;

  try {
    await holder.query("BEGIN");
    await holder.query("INSERT INTO analysis_outcomes (package, version, scorer) VALUES ('in-flight', '1.0.0', 's')");
    run = migrate(db.url);
    await Bun.sleep(300);
    await writer.query("SET statement_timeout = '1s'");
    await writer.query("INSERT INTO analysis_outcomes (package, version, scorer) VALUES ('later', '1.0.0', 's')");
    await holder.query("COMMIT");
    expect(await run).toEqual(["0011_unfinished_analyses", "0012_analysis_failures", "0013_analysis_attempts", "0014_analysis_indexes", "0015_rescore_runtime_failures", "0016_release_rescore_reservations"]);
  } finally {
    await holder.query("ROLLBACK").catch(() => {});
    await run?.catch(() => {});
    await holder.end();
    await writer.end();
    await db.drop();
  }
}, 30_000);

test("0014 gives up at its lock_timeout behind a long write, drops the invalid index a failed build left, and a retry finishes it", async () => {
  const db = await migratedBefore("0014");
  const holder = await connect(db.url);

  try {
    await holder.query("BEGIN");
    await holder.query("INSERT INTO analysis_jobs (package, version, queued_at) VALUES ('long-running', '1.0.0', 1)");
    const started = Date.now();

    const failed = await migrate(db.url).then(
      () => null,
      (e: Error) => e.message,
    );

    expect(failed).toContain("migration 0014_analysis_indexes failed");
    expect(Date.now() - started).toBeLessThan(15_000);
    // the failed concurrent build left an invalid index behind
    expect(await validIndexes(holder, ["analysis_jobs_queued"])).toEqual({ analysis_jobs_queued: false });
    await holder.query("COMMIT");
    expect(await migrate(db.url)).toEqual(["0014_analysis_indexes", "0015_rescore_runtime_failures", "0016_release_rescore_reservations"]);
    expect(await validIndexes(holder, ["analysis_jobs_queued", "analysis_outcomes_unswept"])).toEqual({ analysis_jobs_queued: true, analysis_outcomes_unswept: true });
    expect(await migrate(db.url)).toEqual([]);
  } finally {
    await holder.end();
    await db.drop();
  }
}, 30_000);

// Staging's queue recorded 54 versions unreadable because workerd refused an inflate held to the trailer's exact size
// (core/src/tarball.ts, GUNZIP_SLACK_BYTES), and stored the smaller re-run's incomplete score for versions the 30 s CPU
// limit or a store error stopped (three 0.187.0, vite 8.3.8). 0015 drops those so they are scored again, and only those.
test("0015 and 0016 drop the outcomes the runtime caused and their reservations, and keep every other outcome", async () => {
  const db = await migratedBefore("0015");
  const c = await connect(db.url);
  const rerun = { signals: [{ id: "incomplete", evidence: ["an earlier analysis of this version was stopped by the platform's CPU limit or failed before it stored anything, so this one read at most 4 MB"] }] };
  const full = { signals: [{ id: "incomplete", evidence: ["src/huge.js: too large to analyze"] }] };

  try {
    await c.query(
      `INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, starts, started_at, failures) VALUES
         ('react', '19.3.1', 's', 'unreadable', 'the tarball is not one apm can read (not valid gzip: it inflates to more than the 200192 bytes its trailer says)', 1, 1, 0),
         ('broken', '1.0.0', 's', 'unreadable', 'the tarball is not one apm can read (not valid gzip: incorrect header check)', 1, 1, 0),
         ('next', '16.4.6', 's', 'too-large', 'the tarball inflates to more than 48 MB', 1, 1, 0),
         ('limited', '1.0.0', 's', 'analysis-limit', 'two analyses of it were stopped', 3, 1, 0),
         ('vite', '8.3.8', 's', NULL, NULL, 2, 1, 0),
         ('three', '0.186.0', 's', NULL, NULL, 1, 1, 0),
         ('throws', '1.0.0', 's', NULL, NULL, 1, 1, 1),
         ('hono', '4.13.18', 's', NULL, NULL, 1, 1, 0)`,
    );
    await c.query(
      `INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES
         ('vite', '8.3.8', 'd1', 's', $1::jsonb, 1), ('hono', '4.13.18', 'd2', 's', $2::jsonb, 1)`,
      [JSON.stringify(rerun), JSON.stringify(full)],
    );
    // reservations: vite's (its re-run is dropped), hono's (stored), next's (an outcome), and one never started
    await c.query(`INSERT INTO analysis_jobs (package, version, queued_at) VALUES ('vite', '8.3.8', 1), ('hono', '4.13.18', 1), ('next', '16.4.6', 1), ('three', '0.187.0', 1)`);
    expect(await migrate(db.url)).toEqual(["0015_rescore_runtime_failures", "0016_release_rescore_reservations"]);
    const outcomes = (await c.query<{ package: string }>("SELECT package FROM analysis_outcomes ORDER BY package")).rows.map((r) => r.package);
    const analyses = (await c.query<{ package: string }>("SELECT package FROM upstream_analysis ORDER BY package")).rows.map((r) => r.package);

    expect(outcomes).toEqual(["broken", "hono", "next", "throws"]);
    expect(analyses).toEqual(["hono"]);
    // 0016: the versions with nothing stored can be queued again at once
    const reserved = (await c.query<{ package: string }>("SELECT package FROM analysis_jobs ORDER BY package")).rows.map((r) => r.package);

    expect(reserved).toEqual(["hono", "next"]);
  } finally {
    await c.end();
    await db.drop();
  }
}, 30_000);
