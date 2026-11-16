// A TCP link between the registry Worker and its Postgres that a test can cut, to run the registry through a database
// outage. "refuse" closes every connection at once (a database that is down); "hang" accepts connections and never
// answers (a database, or Hyperdrive's way to it, that stopped responding), which only a timeout ends; both drop the
// connections open when the link is cut. "stall" keeps every open connection and stops carrying bytes on it, and hangs
// new ones: a network that went silent under a session, mid-transaction included.
import { connect, createServer, type Socket } from "node:net";
import { z } from "zod";

export type LinkMode = "up" | "refuse" | "hang" | "stall";

export type DatabaseLink = {
  /** The database URL through the link. */
  readonly url: string;
  readonly set: (mode: LinkMode) => void;
  readonly stop: () => Promise<void>;
};

export async function startDatabaseLink(databaseUrl: string): Promise<DatabaseLink> {
  const target = new URL(databaseUrl);
  const open = new Set<Socket>();
  const pairs = new Set<{ client: Socket; upstream: Socket }>();
  let mode: LinkMode = "up";

  const server = createServer((client) => {
    open.add(client);
    client.on("close", () => open.delete(client));
    client.on("error", () => client.destroy());

    if (mode === "refuse") {
      client.destroy();

      return;
    }

    // accepted and never answered, nor read
    if (mode === "hang" || mode === "stall") return;
    const upstream = connect(Number(target.port || 5432), target.hostname);
    open.add(upstream);
    upstream.on("close", () => {
      open.delete(upstream);
      client.destroy();
    });
    upstream.on("error", () => upstream.destroy());
    client.on("close", () => upstream.destroy());
    client.pipe(upstream);
    upstream.pipe(client);
    const pair = { client, upstream };
    pairs.add(pair);
    client.on("close", () => pairs.delete(pair));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = z.object({ port: z.number() }).parse(server.address());
  const url = new URL(databaseUrl);
  url.hostname = "127.0.0.1";
  url.port = String(port);

  return {
    url: url.toString(),
    set: (next) => {
      mode = next;

      if (next === "stall") {
        // nothing more crosses, either way, and nothing is closed
        for (const p of pairs) {
          p.client.unpipe(p.upstream);
          p.upstream.unpipe(p.client);
          p.client.pause();
          p.upstream.pause();
        }

        return;
      }

      if (next !== "up") for (const s of open) s.destroy();
    },
    stop: async () => {
      for (const s of open) s.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
