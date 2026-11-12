// Applies packages/registry/migrations/*.sql in order, each once, inside a transaction. Used by the deploy
// (against Neon) and by the acceptance suite (against a local Postgres). A run holds a session advisory lock
// from creating the ledger to its last migration, so concurrent runs take turns: the second finds nothing to do.
// This connects to Postgres directly (never through Hyperdrive), so a session-level lock is safe here.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "pg";

const DIR = join(import.meta.dir, "..", "migrations");

/** The advisory lock every migration run holds: "apm-migrate" in ASCII. */
const MIGRATION_LOCK = 0x61_706d_6d69_67;

export function migrationFiles(): { id: string; sql: string }[] {
  return readdirSync(DIR)
    .filter((f) => /^\d{4}_.+\.sql$/.test(f))
    .sort()
    .map((f) => ({ id: f.replace(/\.sql$/, ""), sql: readFileSync(join(DIR, f), "utf8") }));
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

/** Applies pending migrations; returns the ids it applied. */
export async function migrate(url: string): Promise<string[]> {
  const client = new Client({ connectionString: url });
  await client.connect();

  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK]);
    await client.query("CREATE TABLE IF NOT EXISTS apm_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
    const done = new Set((await client.query<{ id: string }>("SELECT id FROM apm_migrations")).rows.map((r) => r.id));
    const applied: string[] = [];

    for (const m of migrationFiles()) {
      if (done.has(m.id)) continue;
      await client.query("BEGIN");

      try {
        await client.query(m.sql);
        await client.query("INSERT INTO apm_migrations (id) VALUES ($1)", [m.id]);
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        throw new Error(`migration ${m.id} failed: ${e instanceof Error ? e.message : String(e)}`);
      }

      applied.push(m.id);
    }

    return applied;
  } finally {
    // ending the session releases the lock too; unlocking first frees it even if end() is slow
    await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK]).catch(() => {});
    await client.end();
  }
}

if (import.meta.main) {
  const url = process.env.DATABASE_URL;

  if (!url) throw new Error("Set DATABASE_URL to the Postgres to migrate.");
  const applied = await migrate(url);
  process.stdout.write(applied.length === 0 ? "migrations: up to date\n" : `migrations: applied ${applied.join(", ")}\n`);
}
