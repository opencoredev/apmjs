// The suite's throwaway Postgres (postgres.ts). Sweep of 2026-11-16: it started on a random port between 20000 and
// 40000 with no retry, and half that range is the kernel's ephemeral range (32768-60999), so a port another process
// held made pg_ctl fail and the score gate's first run fail with it. The port now comes from the kernel (port 0), and
// a start whose port was taken in the meantime is tried again on a new one.
import { afterAll, expect, test } from "bun:test";
import { Client } from "pg";
import { freePort, startLocalCluster } from "./postgres.ts";

const held: { stop: (force?: boolean) => Promise<void> }[] = [];

afterAll(async () => {
  for (const s of held) await s.stop(true);
});

/** A port this process listens on for the whole test, as another program would. */
function holdPort(): number {
  const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response(null, { status: 204 }) });

  held.push(server);

  return Number(server.url.port);
}

test("freePort gives a port nothing listens on", async () => {
  const port = await freePort();

  // on a7d36f6 there was no such function: the port was 20000 + random(20000), taken or not
  const server = Bun.serve({ port, hostname: "127.0.0.1", fetch: () => new Response(null, { status: 204 }) });

  expect(Number(server.url.port)).toBe(port);
  await server.stop(true);
});

test("a cluster whose first port is taken starts on another one", async () => {
  const taken = holdPort();
  const tried: number[] = [];
  const ports = [taken];

  const cluster = await startLocalCluster({
    pickPort: async () => {
      const port = ports.shift() ?? (await freePort());

      tried.push(port);

      return port;
    },
  });

  try {
    // the first start failed on the held port and was retried, not thrown
    expect(tried[0]).toBe(taken);
    expect(tried.length).toBeGreaterThan(1);
    const c = new Client({ connectionString: cluster.adminUrl("postgres") });

    await c.connect();
    const r = await c.query<{ one: number }>("SELECT 1 AS one");

    await c.end();
    expect(r.rows[0]?.one).toBe(1);
  } finally {
    cluster.stop();
  }
}, 60_000);
