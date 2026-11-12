// @apm/registry: npm-compatible registry server.
import { Store } from "./db.ts";
import { createHandler, type Ctx } from "./server.ts";
import { apmExtensions } from "./apm.ts";

export type StartOptions = { dataDir: string; port: number; hostname?: string; now?: () => number; publicUrl?: string };

export async function startRegistry(opts: StartOptions): Promise<{ url: string; stop: () => Promise<void> }> {
  const store = new Store(opts.dataDir);
  let base = opts.publicUrl ?? "";
  const ctx: Ctx = { store, now: opts.now ?? Date.now, baseUrl: () => base };
  const handler = createHandler(ctx, apmExtensions(ctx));
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
