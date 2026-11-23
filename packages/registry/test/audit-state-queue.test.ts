// A queue probe record that is not JSON must read as "unknown" (unreadable), like one that fails the schema, not "down".
import { expect, test } from "bun:test";
import { BLOCKLIST_KEY } from "../src/blocklist.ts";
import { checkHealth, QUEUE_PROBE_KEY, type HealthEnv } from "../src/health.ts";

const SYNCED = JSON.stringify({ format: 1, syncedAt: Date.now() - 60_000, local: [], confirmed: [] });

function env(probe: string): HealthEnv {
  const objects: Record<string, string> = { [BLOCKLIST_KEY]: SYNCED, [QUEUE_PROBE_KEY]: probe };

  return {
    databaseUrl: "postgres://postgres:x@127.0.0.1:1/none",
    bucket: { get: async (key) => (objects[key] === undefined ? null : { body: new Blob([objects[key]]).stream(), etag: "e" }) },
    queueBound: true,
    upstreamUrl: null,
  };
}

test("a probe record that is not JSON is unknown, as one of the wrong shape is", async () => {
  const wrongShape = await checkHealth(env(JSON.stringify({ nope: 1 })));
  const garbage = await checkHealth(env("{ not json"));

  expect(wrongShape.checks.queue.status).toBe("unknown");
  expect(garbage.checks.queue.status).toBe("unknown");
});
