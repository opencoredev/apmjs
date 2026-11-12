// Applies packages/registry/migrations/*.sql in order, each once, inside a transaction. Used by the deploy
// (against Neon) and by the acceptance suite (against a local Postgres).
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "pg";

const DIR = join(import.meta.dir, "..", "migrations");

export function migrationFiles(): { id: string; sql: string }[] {
  return readdirSync(DIR)
    .filter((f) => /^\d{4}_.+\.sql$/.test(f))
    .sort()
    .map((f) => ({ id: f.replace(/\.sql$/, ""), sql: readFileSync(join(DIR, f), "utf8") }));
}

/** Applies pending migrations; returns the ids it applied. */
export async function migrate(url: string): Promise<string[]> {
  const client = new Client({ connectionString: url });
  await client.connect();

  try {
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
    await client.end();
  }
}

if (import.meta.main) {
  const url = process.env.DATABASE_URL;

  if (!url) throw new Error("Set DATABASE_URL to the Postgres to migrate.");
  const applied = await migrate(url);
  process.stdout.write(applied.length === 0 ? "migrations: up to date\n" : `migrations: applied ${applied.join(", ")}\n`);
}
