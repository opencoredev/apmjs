// Test helper: a TCP proxy in front of the test Postgres that measures what the server sends.
import { createServer, connect } from "node:net";
import { z } from "zod";

/**
 * A proxy in front of Postgres that records the DataRow messages the server sends: each is one row of a result, so the
 * largest is the most one value of a reply held, and their total is what the client was sent of every result.
 */
export async function measured(url: string): Promise<{ url: string; largest: () => number; total: () => number; close: () => void }> {
  const target = new URL(url);
  let largest = 0;
  let total = 0;

  const server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    // the server's messages are a type byte and a length that counts itself: skip each one's body as it passes
    let header = new Uint8Array(0);
    let skip = 0;

    upstream.on("data", (chunk: Uint8Array) => {
      let at = 0;

      while (at < chunk.length) {
        if (skip > 0) {
          const n = Math.min(skip, chunk.length - at);
          skip -= n;
          at += n;
          continue;
        }

        const need = 5 - header.length;
        header = new Uint8Array([...header, ...chunk.subarray(at, at + need)]);
        at += Math.min(need, chunk.length - at);

        if (header.length < 5) break;
        const length = new DataView(header.buffer).getUint32(1);

        if (header[0] === 0x44) {
          largest = Math.max(largest, length);
          total += length;
        }

        skip = length - 4;
        header = new Uint8Array(0);
      }
    });
    client.pipe(upstream);
    upstream.pipe(client);
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const proxied = new URL(url);
  proxied.hostname = "127.0.0.1";
  proxied.port = String(z.object({ port: z.number() }).parse(server.address()).port);

  return { url: proxied.toString(), largest: () => largest, total: () => total, close: () => server.close() };
}
