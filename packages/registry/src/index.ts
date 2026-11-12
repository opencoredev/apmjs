// @apm/registry: npm-compatible registry server.
import { Store } from "./db.ts";
import { createHandler, type Ctx } from "./server.ts";
import { apmExtensions } from "./apm.ts";
import { Upstream } from "./upstream.ts";

export type StartOptions = {
  dataDir: string;
  port: number;
  hostname?: string;
  now?: () => number;
  publicUrl?: string;
  /** Public registry to proxy, e.g. https://registry.npmjs.org/ */
  upstream?: string;
};

export async function startRegistry(opts: StartOptions): Promise<{ url: string; stop: () => Promise<void> }> {
  const store = new Store(opts.dataDir);
  let base = opts.publicUrl ?? "";
  const ctx: Ctx = { store, now: opts.now ?? Date.now, baseUrl: () => base };
  const upstream = opts.upstream ? new Upstream(opts.upstream.endsWith("/") ? opts.upstream : `${opts.upstream}/`) : null;
  const handler = createHandler(ctx, apmExtensions(ctx, upstream));
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
