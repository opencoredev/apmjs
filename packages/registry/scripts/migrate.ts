// Applies packages/registry/migrations/*.sql in order, each once, inside a transaction. Used by the deploy
// (against Neon) and by the acceptance suite (against a local Postgres). A run holds a session advisory lock
// from creating the ledger to its last migration, so concurrent runs take turns: the second finds nothing to do.
// This connects to Postgres directly (never through Hyperdrive), so a session-level lock is safe here.
//
// A migration whose first line is `-- apm:no-transaction` runs outside a transaction, one statement at a time, for
// work Postgres refuses inside one (CREATE INDEX CONCURRENTLY, which builds an index without blocking writes). Its
// statements are split at a `;` that ends a line, so it must not hold a function body or a DO block. It is recorded
// only once every statement succeeded, so it must be safe to run again after a failure part way (IF NOT EXISTS,
// IF EXISTS). Session settings it makes (SET lock_timeout) are reset after it, pass or fail.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "pg";

const DIR = join(import.meta.dir, "..", "migrations");

/** The advisory lock every migration run holds: "apm-migrate" in ASCII. */
const MIGRATION_LOCK = 0x61_706d_6d69_67;

/** The marker on a migration's first line that runs it outside a transaction. */
export const NO_TRANSACTION = "-- apm:no-transaction";

export type Migration = { id: string; sql: string; transaction: boolean };

export function migrationFiles(): Migration[] {
  return readdirSync(DIR)
    .filter((f) => /^\d{4}_.+\.sql$/.test(f))
    .sort()
    .map((f) => {
      const sql = readFileSync(join(DIR, f), "utf8");

      return { id: f.replace(/\.sql$/, ""), sql, transaction: sql.split("\n", 1)[0]?.trim() !== NO_TRANSACTION };
    });
}

/** A no-transaction migration's statements: whole-line comments dropped, split at each `;` that ends a line. */
export function statementsOf(sql: string): string[] {
  return sql
    .split("\n")
    .filter((line) => !line.trim().startsWith("--"))
    .join("\n")
    .split(/;[ \t]*(?:\n|$)/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** One migration and its ledger row: in one transaction, or statement by statement with the row written last. */
async function apply(client: Client, m: Migration): Promise<void> {
  if (!m.transaction) {
    try {
      for (const statement of statementsOf(m.sql)) await client.query(statement);
      await client.query("INSERT INTO apm_migrations (id) VALUES ($1)", [m.id]);
    } finally {
      await client.query("RESET ALL").catch(() => {});
    }

    return;
  }

  await client.query("BEGIN");

  try {
    await client.query(m.sql);
    await client.query("INSERT INTO apm_migrations (id) VALUES ($1)", [m.id]);
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  }
}

/** The migrations not yet applied to the database at `url`. Reads only: creates nothing, not even the ledger. */
export async function pendingMigrations(url: string): Promise<string[]> {
  const client = new Client({ connectionString: url });
  await client.connect();

  try {
    const ledger = await client.query<{ present: boolean }>("SELECT to_regclass('apm_migrations') IS NOT NULL AS present");
    const done = ledger.rows[0]?.present === true ? new Set((await client.query<{ id: string }>("SELECT id FROM apm_migrations")).rows.map((r) => r.id)) : new Set<string>();

    return migrationFiles()
      .map((m) => m.id)
      .filter((id) => !done.has(id));
  } finally {
    await client.end();
  }
}

/** How often a run waiting for another run's lock asks again. */
const LOCK_POLL_MS = 100;

/** How long a run waits for another run's lock before it gives up, unless APM_MIGRATE_LOCK_TIMEOUT_MS says otherwise. */
export const DEFAULT_LOCK_TIMEOUT_MS = 5 * 60_000;

/** The wait for the lock, from APM_MIGRATE_LOCK_TIMEOUT_MS (whole milliseconds, at least 1); unset means the default. */
export function lockTimeoutFrom(env: Record<string, string | undefined>): number {
  const raw = env.APM_MIGRATE_LOCK_TIMEOUT_MS;

  if (raw === undefined || raw.trim() === "") return DEFAULT_LOCK_TIMEOUT_MS;

  if (!/^\d{1,10}$/.test(raw.trim()) || Number(raw) < 1) throw new Error(`APM_MIGRATE_LOCK_TIMEOUT_MS must be a whole number of milliseconds, 1 or more (got "${raw}")`);

  return Number(raw);
}

const lockHex = `0x${MIGRATION_LOCK.toString(16)}`;

/** Who holds the migration lock, as one line for the error: the backend's pid and what it said about itself. */
async function lockHolder(client: Client): Promise<{ pid: number; line: string } | null> {
  // a bigint advisory lock is stored as classid (high 32 bits) and objid (low 32 bits), with objsubid 1
  const r = await client.query<{ pid: number; application_name: string | null; client_addr: string | null; backend_start: Date | null; state: string | null }>(
    `SELECT l.pid, a.application_name, a.client_addr::text AS client_addr, a.backend_start, a.state
       FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid
      WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1
        AND ((l.classid::bigint << 32) | l.objid::bigint) = $1::bigint
      LIMIT 1`,
    [String(MIGRATION_LOCK)],
  );

  const row = r.rows[0];

  if (!row) return null;
  const about = [row.application_name ? `application "${row.application_name}"` : null, row.client_addr ? `from ${row.client_addr}` : null, row.backend_start ? `connected ${row.backend_start.toISOString()}` : null, row.state ? `state ${row.state}` : null].filter(Boolean);

  return { pid: row.pid, line: `backend pid ${row.pid}${about.length > 0 ? ` (${about.join(", ")})` : ""}` };
}

/**
 * Takes the migration lock, waiting for a run that holds it. A waiter asks with pg_try_advisory_lock between short
 * sleeps rather than blocking in pg_advisory_lock: a blocked statement holds a snapshot, and CREATE INDEX CONCURRENTLY
 * in the run holding the lock waits for every older snapshot, so the two would deadlock.
 */
async function lockMigrations(client: Client, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const r = await client.query<{ locked: boolean }>("SELECT pg_try_advisory_lock($1) AS locked", [MIGRATION_LOCK]);

    if (r.rows[0]?.locked === true) return;

    if (Date.now() >= deadline) {
      const holder = await lockHolder(client).catch(() => null);
      const who = holder ? `It is held by ${holder.line}.` : "No session holds it now; it was released as this run gave up, so run again.";
      const clear = holder ? ` If that run is still working, let it finish. If it is gone or stuck, end its session with SELECT pg_terminate_backend(${holder.pid}); and run again.` : "";

      throw new Error(
        `migrations: gave up after ${timeoutMs % 1000 === 0 ? `${timeoutMs / 1000}s` : `${timeoutMs} ms`} waiting for the migration lock (Postgres advisory lock ${lockHex}, "apm-migrate"). ${who}${clear} Set APM_MIGRATE_LOCK_TIMEOUT_MS to wait longer.`,
      );
    }

    await Bun.sleep(Math.min(LOCK_POLL_MS, Math.max(1, deadline - Date.now())));
  }
}

/**
 * Applies pending migrations; returns the ids it applied. Waits up to `lockTimeoutMs` (APM_MIGRATE_LOCK_TIMEOUT_MS, else
 * 5 minutes) for another run's lock, then fails naming the session that holds it.
 */
export async function migrate(url: string, opts: { lockTimeoutMs?: number } = {}): Promise<string[]> {
  const lockTimeoutMs = opts.lockTimeoutMs ?? lockTimeoutFrom(process.env);
  const client = new Client({ connectionString: url });
  await client.connect();
  let locked = false;

  try {
    await lockMigrations(client, lockTimeoutMs);
    locked = true;
    await client.query("CREATE TABLE IF NOT EXISTS apm_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
    const done = new Set((await client.query<{ id: string }>("SELECT id FROM apm_migrations")).rows.map((r) => r.id));
    const applied: string[] = [];

    for (const m of migrationFiles()) {
      if (done.has(m.id)) continue;

      try {
        await apply(client, m);
      } catch (e) {
        throw new Error(`migration ${m.id} failed: ${e instanceof Error ? e.message : String(e)}`);
      }

      applied.push(m.id);
    }

    return applied;
  } finally {
    // ending the session releases the lock too; unlocking first frees it even if end() is slow
    if (locked) await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK]).catch(() => {});
    await client.end();
  }
}

if (import.meta.main) {
  const url = process.env.DATABASE_URL;

  if (!url) throw new Error("Set DATABASE_URL to the Postgres to migrate.");
  const applied = await migrate(url);
  process.stdout.write(applied.length === 0 ? "migrations: up to date\n" : `migrations: applied ${applied.join(", ")}\n`);
}
