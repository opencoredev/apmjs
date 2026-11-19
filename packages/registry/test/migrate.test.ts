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

/** Every migration from `first` on, in order: what an upgrade from just before it applies. */
const idsFrom = (first: string): string[] => migrationFiles().map((m) => m.id).filter((id) => id >= first);

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
    expect(await run).toEqual(idsFrom("0013"));
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
    expect(await run).toEqual(idsFrom("0011"));
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
    expect(await migrate(db.url)).toEqual(idsFrom("0014"));
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
    expect(await migrate(db.url)).toEqual(idsFrom("0015"));
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

// Production, 13 Nov: seven queue runs sharing one isolate were ended by its memory limit, and the next delivery of
// five versions was the smaller re-run, which stored an incomplete 39. 0018 drops those results so they are scored
// again in full, and nothing else. Review of 2326d2c, finding 9: it matched the old message anywhere in an analysis's
// text, so a correct analysis that quotes it in a source evidence line was deleted too; it now matches only the five
// versions' apm-score-v10 analyses whose `incomplete` signal has a line that begins with the message.
test("0018 drops the five smaller re-runs stored after the 13 Nov memory stops, and no analysis that only quotes their reason", async () => {
  const db = await migratedBefore("0018");
  const c = await connect(db.url);
  const reason = "an earlier analysis of this version was stopped by the platform's CPU limit or failed before it stored anything, so this one read at most 4 MB";
  const skippedLines = Array.from({ length: 6 }, (_, i) => `not analyzed: lib/parser-${i}.js (nested past the parser's depth)`);
  // as 3549541 stored them: the reason after the skipped-file lines, so past the five shown, in `more`
  const rerunInMore = { score: 39, signals: [{ id: "incomplete", label: "incomplete", points: -61, evidence: skippedLines.slice(0, 5), more: [...skippedLines.slice(5), reason] }] };
  const rerunShown = { score: 39, signals: [{ id: "incomplete", label: "incomplete", points: -61, evidence: [reason, "not analyzed: lib/big.js (0.8 MB, past the analysis budget)"] }] };
  const clean = { score: 95, signals: [] };
  // the reviewer's false positive: a correct analysis whose source evidence quotes the old message
  const quoting = { score: 88, signals: [{ id: "network", label: "network", points: -12, evidence: [`lib/report.js:41: const note = "${reason}";`] }] };
  // the message inside an incomplete line that does not begin with it
  const quotedInIncomplete = { score: 70, signals: [{ id: "incomplete", label: "incomplete", points: -10, evidence: [`not analyzed: docs/${reason}.md (binary)`] }] };
  // a re-run under the new rule names its own reason
  const ownReason = { score: 30, signals: [{ id: "incomplete", label: "incomplete", points: -61, evidence: ["2 earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB"] }] };

  const incident = [
    ["express", "5.3.0", rerunInMore],
    ["axios", "1.21.1", rerunShown],
    ["eslint", "10.14.0", rerunInMore],
    ["prettier", "3.10.1", rerunShown],
    ["tailwindcss", "4.3.5", rerunInMore],
  ] as const;

  /** A stored analysis as these fixtures write it: a score and its signals. */
  type Stored = { score: number; signals: readonly { id: string; label: string; points: number; evidence: readonly string[]; more?: readonly string[] }[] };

  const analysis = (pkg: string, version: string, digest: string, scorer: string, value: Stored) =>
    c.query("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, $2, $3, $4, $5::jsonb, 1)", [pkg, version, digest, scorer, JSON.stringify(value)]);

  try {
    for (const [pkg, version, value] of incident) {
      await analysis(pkg, version, "d", "apm-score-v10", value);
      // the run the memory limit ended and the re-run: two starts, no outcome
      await c.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ($1, $2, 'apm-score-v10', 2, 1)", [pkg, version]);
      await c.query("INSERT INTO analysis_jobs (package, version, queued_at) VALUES ($1, $2, 1)", [pkg, version]);
    }

    // must survive, each with its outcome row and reservation where it has one:
    // - the reviewer's fixture: another package's analysis that quotes the message in a source line
    await analysis("hono", "4.13.18", "d", "apm-score-v10", quoting);
    // - one of the five versions, re-published (another digest) and scored in full, quoting the message too
    await analysis("express", "5.3.0", "d2", "apm-score-v10", quoting);
    // - one of the five whose incomplete line only contains the message
    await analysis("axios", "1.21.1", "d2", "apm-score-v10", quotedInIncomplete);
    // - one of the five under an older scorer, with the real line: not apm-score-v10's
    await analysis("eslint", "10.14.0", "d", "apm-score-v9", rerunShown);
    // - the same real line on a version not in the incident
    await analysis("express", "5.2.1", "d", "apm-score-v10", rerunShown);
    // - a clean analysis and a re-run under the new rule
    await analysis("vite", "8.3.8", "d", "apm-score-v10", clean);
    await analysis("three", "0.187.0", "d", "apm-score-v10", ownReason);
    await c.query(
      `INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at, outcome, detail) VALUES
         ('hono', '4.13.18', 'apm-score-v10', 1, 1, NULL, NULL), ('express', '5.2.1', 'apm-score-v10', 2, 1, NULL, NULL),
         ('three', '0.187.0', 'apm-score-v10', 3, 1, NULL, NULL), ('huge', '1.0.0', 'apm-score-v10', 1, 1, 'too-large', 'the tarball inflates to more than 48 MB')`,
    );
    await c.query(`INSERT INTO analysis_jobs (package, version, queued_at) VALUES ('hono', '4.13.18', 1), ('express', '5.2.1', 1), ('huge', '1.0.0', 1)`);

    expect(await migrate(db.url)).toEqual(idsFrom("0018"));
    const rows = async (table: string, extra = "") => (await c.query<{ k: string }>(`SELECT package || '@' || version${extra} AS k FROM ${table} ORDER BY 1`)).rows.map((r) => r.k);

    // on 2326d2c the reviewer's fixture (hono), express's full re-score and axios's quoted line were deleted too
    expect(await rows("upstream_analysis", " || ' ' || digest || ' ' || scorer")).toEqual([
      "axios@1.21.1 d2 apm-score-v10",
      "eslint@10.14.0 d apm-score-v9",
      "express@5.2.1 d apm-score-v10",
      "express@5.3.0 d2 apm-score-v10",
      "hono@4.13.18 d apm-score-v10",
      "three@0.187.0 d apm-score-v10",
      "vite@8.3.8 d apm-score-v10",
    ]);
    expect(await rows("analysis_outcomes")).toEqual(["express@5.2.1", "hono@4.13.18", "huge@1.0.0", "three@0.187.0"]);
    expect(await rows("analysis_jobs")).toEqual(["express@5.2.1", "hono@4.13.18", "huge@1.0.0"]);
    expect(await migrate(db.url)).toEqual([]);
  } finally {
    await c.end();
    await db.drop();
  }
}, 30_000);

// Production, 16 to 18 Nov: four macOS typescript builds stored apm-score-v11's smaller re-run (29/100, F) after two
// platform stops on their Mach-O lib/tsc. 0025 drops exactly those four results, their outcome rows and reservations, at
// the digest each was stored for, so the deploy that reads them in full scores them again. Rows shaped as production's.
/** A stored analysis as the 0025 fixtures write it: its scorer and signals, and whatever else the stored row holds. */
type Stored0025 = {
  readonly scorer: string;
  readonly signals: readonly { id: string; points: number; evidence: readonly string[]; more?: readonly string[] }[];
  readonly skipped?: readonly { path: string; size: number; reason: string }[];
  readonly coverage?: { kind: string; notes?: readonly string[]; reasons?: readonly string[]; omittedBytes?: number; omittedFiles?: number };
  readonly facts?: readonly string[];
  readonly capabilities?: readonly string[];
};

test("0025 drops the four typescript darwin re-runs and nothing else, and a second run of it drops nothing", async () => {
  const db = await migratedBefore("0025");
  const c = await connect(db.url);
  const reason = "2 earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB";
  const ARM = "@typescript/typescript-darwin-arm64";
  const X64 = "@typescript/typescript-darwin-x64";

  const D = {
    arm702: "sha512-828c336abf4cc12fda456a7a7f76b8294ab34630198ceb2618d08ce8b713817ba6f9d05f82c05530df8082f38209b82e5f289c93a2c986906ccf131e6c9f2cc8",
    armDev: "sha512-193fee4506d937c47b581f2bcd06f2715d080b20f5bf90be32fafcdcc0c95fd28904378b157affa5ce14760c2e1fa7eb1a8918fec52b00eb64b79ae431206498",
    x64702: "sha512-499f716489ea02936534673db345b5552b24b5848e7bd705a8d388aa63751acf129a48ca65816dd35ec6e15c0fc404889ce0ee01d6d35bbb1788551ff3ddd180",
    x64Dev: "sha512-4c2658941144e5feccb14c92dda360f33c3fbd39b3413eee70a6f55758076446f3a372f29b45667faa5f440912801e2b50a6f2c0c9b752329e4e55596ba8a610",
  };

  const skipped = (size: number) => [{ path: "lib/tsc", size, reason: "over-budget" }];
  const coverage = (size: number) => ({ kind: "partial", notes: [], reasons: ["over-budget"], omittedBytes: size, omittedFiles: 1 });
  // as production stored them: the re-run's line first in `incomplete`, new-publisher on the 7.0.2 builds

  const rerun = (size: number, publisher: boolean) => ({
    scorer: "apm-score-v11",
    signals: [
      { id: "incomplete", points: -61, evidence: [reason] },
      ...(publisher ? [{ id: "new-publisher", points: -10, evidence: ["microsoft1es has not published this package before (previous: typescript-deploys)"] }] : []),
    ],
    skipped: skipped(size),
    coverage: coverage(size),
    facts: [],
    capabilities: [],
  });
  // the same line past the evidence shown, in `more`

  const rerunInMore = (size: number) => ({ ...rerun(size, false), signals: [{ id: "incomplete", points: -61, evidence: ["not analyzed: lib/tsc (over-budget)"], more: [reason] }] });
  const complete = { scorer: "apm-score-v11", signals: [], skipped: [], coverage: { kind: "complete" }, facts: [], capabilities: ["native"] };
  const v10 = { scorer: "apm-score-v10", signals: [{ id: "incomplete", points: -61, evidence: ["an earlier analysis of this version was stopped"] }, { id: "unanalyzed-files", points: 0, evidence: ["lib/tsc"] }] };


  const analysis = (pkg: string, version: string, digest: string, scorer: string, value: Stored0025) =>
    c.query("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, $2, $3, $4, $5::jsonb, 1)", [pkg, version, digest, scorer, JSON.stringify(value)]);

  const outcome = (pkg: string, version: string, scorer: string, starts: number, result: string | null = null) =>
    c.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at, outcome, detail, decided_at) VALUES ($1, $2, $3, $4, 1, $5, $6, $7)", [pkg, version, scorer, starts, result, result === null ? null : "x", result === null ? null : 1]);

  const job = (pkg: string, version: string, scorer: string | null) => c.query("INSERT INTO analysis_jobs (package, version, queued_at, scorer) VALUES ($1, $2, 1, $3)", [pkg, version, scorer]);

  try {
    // the four: the analysis, three starts and no outcome, the v11 reservation
    for (const [pkg, version, digest, value] of [
      [ARM, "7.0.2", D.arm702, rerun(23_653_616, true)],
      [ARM, "7.1.0-dev.20261118.1", D.armDev, rerun(25_883_698, false)],
      [X64, "7.0.2", D.x64702, rerun(24_971_184, true)],
      [X64, "7.1.0-dev.20261118.1", D.x64Dev, rerunInMore(27_330_912)],
    ] as const) {
      await analysis(pkg, version, digest, "apm-score-v11", value);
      await outcome(pkg, version, "apm-score-v11", 3);
      await job(pkg, version, "apm-score-v11");
    }

    // must survive:
    // - apm-score-v10's rows for the same versions (its analysis, its outcome row)
    await analysis(ARM, "7.0.2", D.arm702, "apm-score-v10", v10);
    await outcome(ARM, "7.0.2", "apm-score-v10", 3);
    // - one of the four re-published at another digest, with the same line
    await analysis(X64, "7.0.2", "sha512-republished", "apm-score-v11", rerun(24_971_184, true));
    // - a correct v11 analysis of another darwin build, its outcome row and reservation
    await analysis(X64, "7.1.0-dev.20261116.1", "sha512-x64-20261116", "apm-score-v11", complete);
    await outcome(X64, "7.1.0-dev.20261116.1", "apm-score-v11", 1);
    await job(X64, "7.1.0-dev.20261116.1", "apm-score-v11");
    // - the same line on versions left out on purpose: 7.0.1-rc (analysis-limit) and a large-JavaScript package
    await analysis(ARM, "7.0.1-rc", "sha512-rc", "apm-score-v11", rerun(25_421_488, false));
    await outcome(ARM, "7.0.1-rc", "apm-score-v11", 4, "analysis-limit");
    await job(ARM, "7.0.1-rc", "apm-score-v11");
    await analysis("hyperframes", "0.9.58", "sha512-hf", "apm-score-v11", rerun(1_301_737, false));
    await outcome("hyperframes", "0.9.58", "apm-score-v11", 3);
    await job("hyperframes", "0.9.58", "apm-score-v11");
    // - typescript@7.0.2's own rows: v10's clean analysis, its outcome row, its reservation from before scorers were recorded
    await analysis("typescript", "7.0.2", "sha512-ts702", "apm-score-v10", { scorer: "apm-score-v10", signals: [{ id: "new-publisher", points: -10, evidence: ["x"] }] });
    await outcome("typescript", "7.0.2", "apm-score-v10", 1);
    await job("typescript", "7.0.2", null);
    // - the AI reviews of the four, and a review job

    for (const [pkg, version, digest] of [[ARM, "7.0.2", D.arm702], [X64, "7.0.2", D.x64702]] as const) {
      await c.query("INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, $2, $3, 'benign', '{}'::jsonb, 1, 'none')", [pkg, version, digest]);
    }

    await c.query(
      "INSERT INTO review_jobs (id, package, version, digest, source, reasons, priority, state, enqueued_at, updated_at) VALUES ('rj1', $1, '7.1.0-dev.20261118.1', $2, 'upstream', '[]'::jsonb, 1, 'done', 1, 1)",
      [ARM, D.armDev],
    );

    const rows = async (table: string, extra = "") => (await c.query<{ k: string }>(`SELECT package || '@' || version${extra} AS k FROM ${table} ORDER BY 1`)).rows.map((r) => r.k);
    // sorted here, not by the database's collation
    const sorted = (xs: readonly string[]): string[] => [...xs].sort();

    const snapshot = async () => ({
      analyses: sorted(await rows("upstream_analysis", " || ' ' || digest || ' ' || scorer")),
      outcomes: sorted(await rows("analysis_outcomes", " || ' ' || scorer")),
      jobs: sorted(await rows("analysis_jobs", " || ' ' || COALESCE(scorer, '-')")),
      reviews: sorted(await rows("reviews", " || ' ' || digest")),
      reviewJobs: sorted(await rows("review_jobs", " || ' ' || digest")),
    });

    const listed = {
      analyses: [
        `${ARM}@7.0.1-rc sha512-rc apm-score-v11`,
        `${ARM}@7.0.2 ${D.arm702} apm-score-v10`,
        `${X64}@7.0.2 sha512-republished apm-score-v11`,
        `${X64}@7.1.0-dev.20261116.1 sha512-x64-20261116 apm-score-v11`,
        "hyperframes@0.9.58 sha512-hf apm-score-v11",
        "typescript@7.0.2 sha512-ts702 apm-score-v10",
      ],
      outcomes: [`${ARM}@7.0.1-rc apm-score-v11`, `${ARM}@7.0.2 apm-score-v10`, `${X64}@7.1.0-dev.20261116.1 apm-score-v11`, "hyperframes@0.9.58 apm-score-v11", "typescript@7.0.2 apm-score-v10"],
      jobs: [`${ARM}@7.0.1-rc apm-score-v11`, `${X64}@7.1.0-dev.20261116.1 apm-score-v11`, "hyperframes@0.9.58 apm-score-v11", "typescript@7.0.2 -"],
      reviews: [`${ARM}@7.0.2 ${D.arm702}`, `${X64}@7.0.2 ${D.x64702}`],
      reviewJobs: [`${ARM}@7.1.0-dev.20261118.1 ${D.armDev}`],
    };

    const after = { analyses: sorted(listed.analyses), outcomes: sorted(listed.outcomes), jobs: sorted(listed.jobs), reviews: sorted(listed.reviews), reviewJobs: sorted(listed.reviewJobs) };

    expect(await migrate(db.url)).toEqual(idsFrom("0025"));
    expect(await snapshot()).toEqual(after);
    // the runner applies it once; its statements run again, as a second apply would, delete nothing more
    const sql = migrationFiles().find((m) => m.id === "0025_rescore_ts_darwin")?.sql ?? "";

    expect(sql).toContain("apm:rollback-safe");
    await c.query("BEGIN");
    await c.query(sql);
    await c.query("COMMIT");
    expect(await snapshot()).toEqual(after);
    expect(await migrate(db.url)).toEqual([]);
  } finally {
    await c.end();
    await db.drop();
  }
}, 30_000);

// If one of the four was scored again in full before 0025 runs (same version, digest and scorer, no re-run line), its
// result, outcome row and reservation stay: the line is what marks a row as the re-run.
test("0025 keeps one of the four when its v11 analysis no longer carries the re-run's line", async () => {
  const db = await migratedBefore("0025");
  const c = await connect(db.url);
  const ARM = "@typescript/typescript-darwin-arm64";
  const digest = "sha512-828c336abf4cc12fda456a7a7f76b8294ab34630198ceb2618d08ce8b713817ba6f9d05f82c05530df8082f38209b82e5f289c93a2c986906ccf131e6c9f2cc8";
  const fullRead = { scorer: "apm-score-v11", signals: [{ id: "new-publisher", points: -10, evidence: ["microsoft1es has not published this package before (previous: typescript-deploys)"] }], skipped: [], coverage: { kind: "complete" } };
  // a later read, incomplete for another reason, whose line only quotes the re-run's: still not the re-run
  const quoting = { ...fullRead, signals: [...fullRead.signals, { id: "incomplete", points: -20, evidence: ["not analyzed: docs/2 earlier analyses of this version were stopped by the platform.md (binary)"] }] };

  try {
    await c.query("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, '7.0.2', $2, 'apm-score-v11', $3::jsonb, 1)", [ARM, digest, JSON.stringify(quoting)]);
    await c.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ($1, '7.0.2', 'apm-score-v11', 1, 1)", [ARM]);
    await c.query("INSERT INTO analysis_jobs (package, version, queued_at, scorer) VALUES ($1, '7.0.2', 1, 'apm-score-v11')", [ARM]);

    expect(await migrate(db.url)).toEqual(idsFrom("0025"));
    const count = async (table: string) => (await c.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table} WHERE package = $1`, [ARM])).rows[0]?.n;

    expect([await count("upstream_analysis"), await count("analysis_outcomes"), await count("analysis_jobs")]).toEqual([1, 1, 1]);
  } finally {
    await c.end();
    await db.drop();
  }
}, 30_000);

// Round 5 review of f328874, P2: the migration chose its rows in one statement and deleted them in later ones, so a
// complete analysis another connection wrote over a chosen row in between was deleted, with its bookkeeping. Now one
// statement deletes under the whole guard: here another connection holds one of the four rows, rewritten as complete,
// while the migration waits on it; once that commits, the migration reads the row as it now stands and keeps it.
test("0025 keeps one of the four that another connection replaces with a complete analysis while the migration waits on it", async () => {
  const db = await migratedBefore("0025");
  const c = await connect(db.url);
  const writer = await connect(db.url);
  const ARM = "@typescript/typescript-darwin-arm64";
  const X64 = "@typescript/typescript-darwin-x64";
  const rerun = JSON.stringify({ scorer: "apm-score-v11", signals: [{ id: "incomplete", points: -61, evidence: ["2 earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB"] }] });
  const complete = JSON.stringify({ scorer: "apm-score-v11", signals: [], coverage: { kind: "complete" } });

  const four = [
    [ARM, "7.0.2", "sha512-828c336abf4cc12fda456a7a7f76b8294ab34630198ceb2618d08ce8b713817ba6f9d05f82c05530df8082f38209b82e5f289c93a2c986906ccf131e6c9f2cc8"],
    [ARM, "7.1.0-dev.20261118.1", "sha512-193fee4506d937c47b581f2bcd06f2715d080b20f5bf90be32fafcdcc0c95fd28904378b157affa5ce14760c2e1fa7eb1a8918fec52b00eb64b79ae431206498"],
    [X64, "7.0.2", "sha512-499f716489ea02936534673db345b5552b24b5848e7bd705a8d388aa63751acf129a48ca65816dd35ec6e15c0fc404889ce0ee01d6d35bbb1788551ff3ddd180"],
    [X64, "7.1.0-dev.20261118.1", "sha512-4c2658941144e5feccb14c92dda360f33c3fbd39b3413eee70a6f55758076446f3a372f29b45667faa5f440912801e2b50a6f2c0c9b752329e4e55596ba8a610"],
  ] as const;

  try {
    for (const [pkg, version, digest] of four) {
      await c.query("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, $2, $3, 'apm-score-v11', $4::jsonb, 1)", [pkg, version, digest, rerun]);
      await c.query("INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at) VALUES ($1, $2, 'apm-score-v11', 3, 1)", [pkg, version]);
      await c.query("INSERT INTO analysis_jobs (package, version, queued_at, scorer) VALUES ($1, $2, 1, 'apm-score-v11')", [pkg, version]);
    }

    // a run stores its complete analysis over the first of the four, and resets its outcome row, and has not committed
    await writer.query("BEGIN");
    await writer.query("UPDATE upstream_analysis SET analysis = $3::jsonb, analyzed_at = 2 WHERE package = $1 AND version = $2 AND scorer = 'apm-score-v11'", [ARM, "7.0.2", complete]);
    const migrating = migrate(db.url);
    let waiting = 0;

    for (let i = 0; i < 300 && waiting === 0; i++) {
      waiting = (await c.query<{ n: number }>("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'")).rows[0]?.n ?? 0;

      if (waiting === 0) await Bun.sleep(5);
    }

    // the migration is in its statement, waiting on that row
    expect(waiting).toBe(1);
    await writer.query("COMMIT");
    expect(await migrating).toEqual(idsFrom("0025"));

    const rows = async (table: string) => (await c.query<{ k: string }>(`SELECT package || '@' || version AS k FROM ${table} ORDER BY 1`)).rows.map((r) => r.k);

    // on f328874 (its statements split as the reviewer split them): the complete analysis deleted, with its outcome row
    // and reservation
    expect(await rows("upstream_analysis")).toEqual([`${ARM}@7.0.2`]);
    expect((await c.query("SELECT analysis FROM upstream_analysis")).rows).toEqual([{ analysis: JSON.parse(complete) }]);
    expect(await rows("analysis_outcomes")).toEqual([`${ARM}@7.0.2`]);
    expect(await rows("analysis_jobs")).toEqual([`${ARM}@7.0.2`]);
  } finally {
    await writer.end();
    await c.end();
    await db.drop();
  }
}, 30_000);
