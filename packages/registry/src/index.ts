// @apm/registry: npm-compatible registry server.
import { Store } from "./db.ts";
import { createHandler } from "./server.ts";

export type StartOptions = { dataDir: string; port: number; hostname?: string; now?: () => number; publicUrl?: string };

export async function startRegistry(opts: StartOptions): Promise<{ url: string; stop: () => Promise<void> }> {
  const store = new Store(opts.dataDir);
  let base = opts.publicUrl ?? "";
  const handler = createHandler({ store, now: opts.now ?? Date.now, baseUrl: () => base });
  const server = Bun.serve({
    port: opts.port,
    hostname: opts.hostname ?? "127.0.0.1",
    maxRequestBodySize: 64 * 1024 * 1024,
    fetch: handler,
  });
  if (!base) base = server.url.toString();
  if (!base.endsWith("/")) base += "/";
  return {
    url: base,
    stop: async () => {
      await server.stop(true);
      store.close();
    },
  };
}

export { Store } from "./db.ts";
