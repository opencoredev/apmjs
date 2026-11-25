// A queue probe record that is not JSON reads as unknown (unreadable), as one of the wrong form does: it read as
// "down", which took the health answer from ok to degraded.
import { expect, test } from "bun:test";
import { BLOCKLIST_KEY } from "../src/blocklist.ts";
import { checkHealth, QUEUE_PROBE_KEY, type HealthEnv } from "../src/health.ts";

const SYNCED = JSON.stringify({ format: 1, syncedAt: Date.now() - 60_000, local: [], confirmed: [] });

function env(probe: string): HealthEnv {
  const objects = new Map([
    [BLOCKLIST_KEY, SYNCED],
    [QUEUE_PROBE_KEY, probe],
  ]);

  return {
    databaseUrl: "postgres://postgres:unused@127.0.0.1:1/none",
    bucket: {
      get: async (key) => {
        const text = objects.get(key);

        return text === undefined ? null : { body: new Blob([text]).stream(), etag: "e" };
      },
    },
    queueBound: true,
    upstreamUrl: null,
  };
}

test("a probe record that is not JSON is unknown, as one of the wrong form is", async () => {
  const mismatched = await checkHealth(env(JSON.stringify({ nope: 1 })));
  const garbage = await checkHealth(env("{ not json"));

  expect(mismatched.checks.queue.status).toBe("unknown");
  expect(garbage.checks.queue.status).toBe("unknown");
});
