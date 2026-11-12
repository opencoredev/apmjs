// @apm/registry: npm-compatible registry server.
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Store } from "./db.ts";
import { createHandler, issueToken, type Ctx, type Extensions, type NamePolicy, type TokenScope } from "./server.ts";
import { apmExtensions } from "./apm.ts";
import { Upstream } from "./upstream.ts";
import { createAuth, type AuthOptions } from "./auth.ts";
import { buildAccess } from "./access.ts";
import { accountRoutes, sweepStaged } from "./account.ts";

export type StartOptions = {
  dataDir: string;
  port: number;
  hostname?: string;
  now?: () => number;
  /** Base URL in tarball links. Defaults to the server's own URL. */
  publicUrl?: string;
  /** The website: sign-in, approval links and the device page. Defaults to the registry URL (one origin). */
  webUrl?: string;
  /** Public registry to proxy, e.g. https://registry.npmjs.org/ */
  upstream?: string;
  /** How long an upstream packument is trusted before it is fetched again. Default 60s. */
  upstreamTtlMs?: number;
  /** npm's password adduser and password re-auth. Default off: accounts come from GitHub or Vercel sign-in. */
  legacyAuth?: boolean;
  /** "scoped" (default): new packages live under the publisher's GitHub login. "open": bare names allowed (tests, legacy). */
  namePolicy?: NamePolicy;
  /** OAuth apps and the signing secret. Without a secret, one is generated once and kept in the data dir. */
  auth?: Partial<AuthOptions>;
  /** The clock authenticator codes are checked against. Wall-clock time unless a test passes its own. */
  totpNow?: () => number;
};

export type StartedRegistry = {
  url: string;
  stop: () => Promise<void>;
  /** For tests and operators: a token for `user` with no login flow. "publish" goes live at once; "stage" needs approval. */
  mintToken: (input: { user: string; scope: TokenScope }) => string;
};

function withSlash(u: string): string {
  return u.endsWith("/") ? u : `${u}/`;
}

/** The auth secret signs sessions and encrypts TOTP secrets, so it must survive restarts. */
function persistentSecret(dataDir: string): string {
  const path = join(dataDir, "auth-secret");
  if (existsSync(path)) return readFileSync(path, "utf8").trim();
  const secret = randomBytes(32).toString("base64url");
  writeFileSync(path, `${secret}\n`, { mode: 0o600 });
  return secret;
}

export async function startRegistry(opts: StartOptions): Promise<StartedRegistry> {
  const store = new Store(opts.dataDir);
  const now = opts.now ?? Date.now;
  let handle: (req: Request) => Promise<Response> = async () => new Response("starting", { status: 503 });
  const server = Bun.serve({
    port: opts.port,
    hostname: opts.hostname ?? "127.0.0.1",
    maxRequestBodySize: 64 * 1024 * 1024,
    fetch: (req) => handle(req),
  });
  const base = withSlash(opts.publicUrl ?? server.url.toString());
  const web = withSlash(opts.webUrl ?? base);

  const auth = await createAuth({
    store,
    now,
    totpNow: opts.totpNow ?? Date.now,
    baseURL: web,
    options: {
      secret: opts.auth?.secret ?? persistentSecret(opts.dataDir),
      ...(opts.auth?.github ? { github: opts.auth.github } : {}),
      ...(opts.auth?.vercel ? { vercel: opts.auth.vercel } : {}),
    },
  });
  const upstream = opts.upstream ? new Upstream(withSlash(opts.upstream), opts.upstreamTtlMs) : null;
  const access = buildAccess({
    store,
    auth,
    upstream,
    legacyAuth: opts.legacyAuth ?? false,
    namePolicy: opts.namePolicy ?? "scoped",
    webUrl: () => web,
    now,
  });
  const ctx: Ctx = { store, now, baseUrl: () => base, access };
  const apm = apmExtensions(ctx, upstream);
  const account = accountRoutes({ ctx, auth });
  const ext: Extensions = {
    ...apm,
    routes: async (req, url, c, a) => {
      sweepStaged(c);
      return (await account(req, url)) ?? (apm.routes ? apm.routes(req, url, c, a) : null);
    },
  };
  const handler = createHandler(ctx, ext);
  handle = async (req) => {
    if (new URL(req.url).pathname.startsWith("/api/auth/")) {
      try {
        return await auth.handler(req);
      } catch (e) {
        process.stderr.write(`apm auth error: ${req.method} ${req.url}: ${e instanceof Error ? e.message : String(e)}\n`);
        return new Response(JSON.stringify({ error: "Internal error" }), { status: 500, headers: { "content-type": "application/json" } });
      }
    }
    return handler(req);
  };

  return {
    url: base,
    stop: async () => {
      await server.stop(true);
      store.close();
    },
    mintToken: ({ user, scope }) => {
      if (!store.getUser(user)) store.createUser({ name: user, password_hash: "", email: "", created_at: now() });
      return issueToken(ctx, { user, label: scope === "publish" ? "direct publish (minted)" : "staging (minted)", scope });
    },
  };
}

export { Store } from "./db.ts";
