// The health check (health.ts) against a real Postgres, a stand-in npm and a bucket the test controls: the block list
// counts as ready only when the degraded routes could use it (its body parsed, synced once), and no install is reported
// working while R2 does not answer, whatever the database says.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { BLOCKLIST_KEY } from "../src/blocklist.ts";
import { checkHealth, type HealthEnv } from "../src/health.ts";
import { emptyDatabase } from "../../../tests/acceptance/postgres.ts";

let db: { url: string; drop: () => Promise<void> };
let npm: ReturnType<typeof Bun.serve>;

beforeAll(async () => {
  db = await emptyDatabase();
  npm = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => Response.json({}) });
});

afterAll(async () => {
  await npm.stop(true);
  await db?.drop();
});

/** A bucket holding `objects` by key; `fails` makes every read throw, as an R2 outage does. */
function bucket(objects: Record<string, string>, fails = false): HealthEnv["bucket"] {
  return {
    get: async (key) => {
      if (fails) throw new Error("R2 is unavailable");
      const text = objects[key];

      return text === undefined ? null : { body: new Blob([text]).stream(), etag: "e1" };
    },
  };
}

const SYNCED = JSON.stringify({ format: 1, syncedAt: Date.now() - 60_000, local: [], confirmed: [] });

function env(over: Partial<HealthEnv>): HealthEnv {
  return { databaseUrl: db.url, bucket: bucket({ [BLOCKLIST_KEY]: SYNCED }), queueBound: false, upstreamUrl: `http://127.0.0.1:${npm.port}/`, ...over };
}

/** A database nothing listens on: the check fails fast with a refused connection. */
const NO_DATABASE = "postgres://postgres:postgres@127.0.0.1:1/none";

describe("the block list check", () => {
  test("a synced list whose body parses is ready, and lets npm's packages install without the database", async () => {
    const h = await checkHealth(env({ databaseUrl: NO_DATABASE }));

    expect(h.checks.blocklist.status).toBe("up");
    expect(h.installs).toBe("npm-only");
  });

  test("a corrupt body is not ready, whatever its metadata says, so installs without the database are down", async () => {
    const h = await checkHealth(env({ databaseUrl: NO_DATABASE, bucket: bucket({ [BLOCKLIST_KEY]: "{ not json" }) }));

    expect(h.checks.blocklist.status).toBe("down");
    expect(h.checks.blocklist.detail).toContain("unreadable");
    expect(h.installs).toBe("down");
  });

  test("a list never synced from the database is not ready", async () => {
    const h = await checkHealth(env({ databaseUrl: NO_DATABASE, bucket: bucket({ [BLOCKLIST_KEY]: JSON.stringify({ format: 1, syncedAt: null, local: [], confirmed: [] }) }) }));

    expect(h.checks.blocklist.status).toBe("down");
    expect(h.installs).toBe("down");
  });
});

describe("R2", () => {
  test("with the database up and R2 down, installs are down: tarballs are read through R2", async () => {
    const h = await checkHealth(env({ bucket: bucket({}, true) }));

    expect(h.checks.database.status).toBe("up");
    expect(h.checks.r2.status).toBe("down");
    expect(h.installs).toBe("down");
    expect(h.status).toBe("down");
  });

  test("with everything up, installs work", async () => {
    const h = await checkHealth(env({}));

    expect(h).toMatchObject({ status: "ok", installs: "working" });
  });
});
