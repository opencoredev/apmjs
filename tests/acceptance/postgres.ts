// A real Postgres for the tests: APM_TEST_DATABASE_URL (a server the suite may create databases on), or a
// throwaway local cluster made with initdb. Every database the tests use is a copy of one migrated template.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { Client } from "pg";
import { migrate } from "../../packages/registry/scripts/migrate.ts";

type Postgres = { adminUrl: (db: string) => string; stop: () => void };

let postgres: Promise<Postgres> | null = null;
let template: Promise<string> | null = null;
let counter = 0;

function findInitdb(): string | null {
  const onPath = spawnSync("sh", ["-c", "command -v initdb"], { encoding: "utf8" }).stdout.trim();

  if (onPath) return onPath;
  const base = "/usr/lib/postgresql";

  if (!existsSync(base)) return null;

  const versions = readdirSync(base)
    .filter((v) => existsSync(join(base, v, "bin", "initdb")))
    .sort((a, b) => Number(b) - Number(a));

  return versions[0] ? join(base, versions[0], "bin", "initdb") : null;
}

/** APM_TEST_DATABASE_URL (a server the suite may create databases on), or a throwaway local cluster. */
async function startPostgres(): Promise<Postgres> {
  const given = process.env.APM_TEST_DATABASE_URL;

  if (given) {
    return {
      adminUrl: (db) => {
        const u = new URL(given);
        u.pathname = `/${db}`;

        return u.toString();
      },
      stop: () => {},
    };
  }

  const initdb = findInitdb();

  if (!initdb) throw new Error("The acceptance suite needs Postgres: install it (initdb on PATH or under /usr/lib/postgresql), or set APM_TEST_DATABASE_URL.");
  const bin = join(initdb, "..");
  const dir = mkdtempSync(join(tmpdir(), "apm-pg-"));
  const data = join(dir, "data");
  const init = spawnSync(initdb, ["-D", data, "-U", "postgres", "--auth=trust", "-E", "UTF8", "--no-sync"], { encoding: "utf8" });

  if (init.status !== 0) throw new Error(`initdb failed: ${init.stderr}`);
  const port = 20000 + Math.floor(Math.random() * 20000);
  const opts = `-p ${port} -k ${dir} -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=400`;
  const start = spawnSync(join(bin, "pg_ctl"), ["-D", data, "-o", opts, "-l", join(dir, "log"), "-w", "start"], { encoding: "utf8" });

  if (start.status !== 0) throw new Error(`pg_ctl start failed: ${start.stderr}${start.stdout}`);
  // The server is stopped by PID: the test harness may delete this directory (it lives under the run's TMPDIR)
  // before anything here gets to run pg_ctl against it.
  const pid = Number(readFileSync(join(data, "postmaster.pid"), "utf8").split("\n")[0]);

  const stop = (): void => {
    try {
      process.kill(pid, "SIGQUIT");
    } catch {
      // already gone
    }

    rmSync(dir, { recursive: true, force: true });
  };

  process.on("exit", stop);
  // `exit` handlers don't run on every way a test process ends, so a watchdog outlives it: once this process is
  // gone it stops the server (SIGQUIT is Postgres's immediate shutdown) and removes the cluster's own directory.
  const cleanup = `while kill -0 ${process.pid} 2>/dev/null; do sleep 1; done; kill -QUIT ${pid} 2>/dev/null; sleep 1; rm -rf -- "\${1:?}"`;
  spawn("sh", ["-c", cleanup, "watchdog", dir], { detached: true, stdio: "ignore" }).unref();

  return { adminUrl: (db) => `postgres://postgres:postgres@127.0.0.1:${port}/${db}`, stop };
}

async function admin<T>(pg: Postgres, run: (c: Client) => Promise<T>): Promise<T> {
  const c = new Client({ connectionString: pg.adminUrl("postgres") });
  await c.connect();

  try {
    return await run(c);
  } finally {
    await c.end();
  }
}

/** A migrated database every registry copies, so each one starts from the real schema in milliseconds. */
async function makeTemplate(pg: Postgres): Promise<string> {
  const name = `apm_template_${process.pid}`;
  await admin(pg, async (c) => {
    await c.query(`DROP DATABASE IF EXISTS ${name}`);
    await c.query(`CREATE DATABASE ${name}`);
  });
  await migrate(pg.adminUrl(name));

  return name;
}


/** A fresh database with the registry's schema, and a way to drop it. */
export async function freshDatabase(): Promise<{ url: string; drop: () => Promise<void> }> {
  postgres ??= startPostgres();
  const server = await postgres;
  template ??= makeTemplate(server);
  const tpl = await template;
  const db = `apm_${process.pid}_${++counter}`;
  await admin(server, (c) => c.query(`CREATE DATABASE ${db} TEMPLATE ${tpl}`));

  return {
    url: server.adminUrl(db),
    drop: async () => {
      await admin(server, (c) => c.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`)).catch(() => {});
    },
  };
}
