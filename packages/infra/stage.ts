// The stage's database and auth secret, as deploy.ts prepares them before running the Alchemy stack.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Client } from "pg";
import { migrate, migrationFiles, pendingMigrations } from "../registry/scripts/migrate.ts";

export type DeployAction = "plan" | "deploy";

/** What the database step found or did. `pending` lists migrations a deploy would apply (plan) or applied (deploy). */
export type DatabaseReport = { kind: "missing"; pending: readonly string[] } | { kind: "planned"; pending: readonly string[] } | { kind: "migrated"; applied: readonly string[]; created: boolean };

async function withClient<T>(url: string, run: (c: Client) => Promise<T>): Promise<T> {
  const c = new Client({ connectionString: url });
  await c.connect();

  try {
    return await run(c);
  } finally {
    await c.end();
  }
}

/** Whether `database` exists on the server `adminUrl` points at. */
function databaseExists(adminUrl: string, database: string): Promise<boolean> {
  return withClient(adminUrl, async (c) => ((await c.query("SELECT 1 FROM pg_database WHERE datname = $1", [database])).rowCount ?? 0) > 0);
}

/**
 * The stage's database. `deploy` creates it when it is missing and applies pending migrations; `plan` only
 * reports what deploy would do and writes nothing. `adminUrl` is a database on the same server to create it
 * from; `databaseUrl` is the stage's own.
 */
export async function prepareDatabase(input: { action: DeployAction; adminUrl: string; databaseUrl: string; database: string }): Promise<DatabaseReport> {
  const exists = await databaseExists(input.adminUrl, input.database);

  switch (input.action) {
    case "plan":
      return exists ? { kind: "planned", pending: await pendingMigrations(input.databaseUrl) } : { kind: "missing", pending: migrationFiles().map((m) => m.id) };
    case "deploy":
      if (!exists) await withClient(input.adminUrl, (c) => c.query(`CREATE DATABASE "${input.database.replace(/"/g, "")}"`));

      return { kind: "migrated", applied: await migrate(input.databaseUrl), created: !exists };
    default: {
      const _exhaustive: never = input.action;

      return _exhaustive;
    }
  }
}

export type AuthSecret = { kind: "existing"; value: string } | { kind: "created"; value: string } | { kind: "missing" };

/** The auth secret signs sessions and encrypts TOTP secrets, so it is made once per stage, on its first deploy, and kept. A plan never makes it. */
export function authSecret(input: { action: DeployAction; dir: string; stage: string }): AuthSecret {
  const path = join(input.dir, `auth-secret-${input.stage}`);

  if (existsSync(path)) return { kind: "existing", value: readFileSync(path, "utf8").trim() };

  if (input.action === "plan") return { kind: "missing" };
  mkdirSync(input.dir, { recursive: true, mode: 0o700 });
  const value = randomBytes(48).toString("base64url");
  writeFileSync(path, `${value}\n`, { mode: 0o600 });

  return { kind: "created", value };
}
