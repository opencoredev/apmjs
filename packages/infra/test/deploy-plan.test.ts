// Review item 9: `deploy.ts plan` changes nothing. It reports a missing database and pending migrations, and
// a missing auth secret, but creates and applies none of them; `deploy` does.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "pg";
import { emptyDatabase } from "../../../tests/acceptance/postgres.ts";
import { migrationFiles } from "../../registry/scripts/migrate.ts";
import { authSecret, prepareDatabase } from "../stage.ts";

let server: { url: string; drop: () => Promise<void> };
let secrets: string;

beforeAll(async () => {
  server = await emptyDatabase();
  secrets = mkdtempSync(join(tmpdir(), "apm-plan-secrets-"));
});

afterAll(async () => {
  await server?.drop();
  rmSync(secrets, { recursive: true, force: true });
});

/** The URL of `database` on the test server. */
function urlOf(database: string): string {
  const u = new URL(server.url);
  u.pathname = `/${database}`;

  return u.toString();
}

async function query<T>(url: string, text: string, params: readonly unknown[] = []): Promise<T[]> {
  const c = new Client({ connectionString: url });
  await c.connect();

  try {
    return (await c.query(text, [...params])).rows;
  } finally {
    await c.end();
  }
}

const ids = migrationFiles().map((m) => m.id);

describe("deploy.ts plan is read-only", () => {
  test("a missing database is reported, not created", async () => {
    const database = `apm_plan_missing_${process.pid}`;
    const report = await prepareDatabase({ action: "plan", adminUrl: server.url, databaseUrl: urlOf(database), database });

    expect(report).toEqual({ kind: "missing", pending: ids });
    expect(await query(server.url, "SELECT 1 FROM pg_database WHERE datname = $1", [database])).toEqual([]);
  });

  test("pending migrations are listed, not applied", async () => {
    const report = await prepareDatabase({ action: "plan", adminUrl: server.url, databaseUrl: server.url, database: new URL(server.url).pathname.slice(1) });

    expect(report).toEqual({ kind: "planned", pending: ids });
    // not even the migration ledger was created
    expect(await query(server.url, "SELECT to_regclass('apm_migrations') AS t")).toEqual([{ t: null }]);
  });

  test("a missing auth secret is reported, not written", () => {
    expect(authSecret({ action: "plan", dir: secrets, stage: "staging" })).toEqual({ kind: "missing" });
    expect(readdirSync(secrets)).toEqual([]);
  });
});

describe("deploy.ts deploy prepares the stage", () => {
  test("it creates the database, migrates it and makes the auth secret once", async () => {
    const database = `apm_deploy_new_${process.pid}`;

    try {
      const report = await prepareDatabase({ action: "deploy", adminUrl: server.url, databaseUrl: urlOf(database), database });
      expect(report).toEqual({ kind: "migrated", applied: ids, created: true });
      expect(await prepareDatabase({ action: "plan", adminUrl: server.url, databaseUrl: urlOf(database), database })).toEqual({ kind: "planned", pending: [] });
    } finally {
      await query(server.url, `DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    }

    const made = authSecret({ action: "deploy", dir: secrets, stage: "staging" });
    expect(made.kind).toBe("created");
    expect(existsSync(join(secrets, "auth-secret-staging"))).toBe(true);
    const again = authSecret({ action: "plan", dir: secrets, stage: "staging" });
    expect(again).toEqual(made.kind === "created" ? { kind: "existing", value: made.value } : { kind: "missing" });
  });
});
