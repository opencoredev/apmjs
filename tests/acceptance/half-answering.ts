// A server that accepts a Postgres connection and then answers half of the first query: for the tests that check that
// nothing the registry or its tools run waits on such a server past its own deadline.
import { createServer, type Socket } from "node:net";
import { z } from "zod";

/**
 * A server that speaks just enough Postgres to accept a connection (authentication ok, ready for query), then answers
 * the first query with one byte and nothing more: the reply a stalled server leaves half sent.
 */
export async function halfAnswering(): Promise<{ url: string; open: () => number; stop: () => Promise<void> }> {
  const sockets = new Set<Socket>();

  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    let started = false;

    socket.on("data", () => {
      if (!started) {
        started = true;
        // AuthenticationOk, then ReadyForQuery (idle)
        socket.write(Buffer.from([0x52, 0, 0, 0, 8, 0, 0, 0, 0, 0x5a, 0, 0, 0, 5, 0x49]));

        return;
      }

      // the first byte of an answer, and then silence
      socket.write(Buffer.from([0x31]));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = z.object({ port: z.number() }).parse(server.address());

  return {
    url: `postgres://postgres:postgres@127.0.0.1:${port}/postgres`,
    open: () => sockets.size,
    stop: async () => {
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
