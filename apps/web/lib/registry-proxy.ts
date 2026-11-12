// Forwards /api/auth/* and /-/apm/v1/* to the registry, so sign-in and the account routes keep their
// session cookie on this origin. This replaces next.config.ts rewrites, which can't set response headers
// on a proxied response: these answers belong to one signed-in user and must say so to every cache.
import { registryFetch } from "./registry-transport";
import { PRIVATE_HEADERS, securityHeaders } from "./security-headers";

export const REGISTRY_PREFIXES = ["/api/auth/", "/-/apm/v1/"] as const;

export function isRegistryPath(pathname: string): boolean {
  return REGISTRY_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

// What the old rewrite allowed: long enough for a slow OAuth exchange, short enough to free the socket.
const FORWARD_TIMEOUT_MS = 30_000;

// Per-hop headers, and ones fetch() has already applied (the body arrives decoded and re-framed).
const HOP_BY_HOP = ["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "content-encoding", "content-length"];

export type ForwardOptions = {
  registry: string;
  /** Request headers with client-supplied forwarding headers already removed (proxy.ts). */
  headers: Headers;
  dev: boolean;
};

/** Sends the request on to the registry and returns its answer with this site's headers on it. */
export async function forwardToRegistry(request: Request, opts: ForwardOptions): Promise<Response> {
  const url = new URL(request.url);
  const target = new URL(`${url.pathname.slice(1)}${url.search}`, opts.registry);
  const base = new URL(opts.registry);

  // URL parsing resolves "%2e%2e" segments, so check where the path landed: only the two prefixes.
  if (target.origin !== base.origin || !REGISTRY_PREFIXES.some((prefix) => target.pathname.startsWith(`${base.pathname}${prefix.slice(1)}`))) {
    return withSiteHeaders(Response.json({ error: "Not found" }, { status: 404 }), opts.dev);
  }

  const headers = new Headers(opts.headers);

  for (const name of HOP_BY_HOP) headers.delete(name);
  // As the old rewrite did: the browser's Host goes on as X-Forwarded-Host, and X-Forwarded-Proto and
  // -Port stay as Next.js set them. The registry's configured public URL still decides its own links.
  headers.set("x-forwarded-host", opts.headers.get("host") ?? url.host);
  headers.delete("host");
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  let upstream: Response;

  // Node's fetch needs duplex "half" to stream a request body; the DOM typings don't list it yet.
  const init: RequestInit & { duplex: "half" } = {
    method: request.method,
    headers,
    body: hasBody ? request.body : null,
    redirect: "manual",
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(FORWARD_TIMEOUT_MS)]),
    duplex: "half",
  };

  try {
    upstream = await registryFetch(target, init);
  } catch {
    return withSiteHeaders(Response.json({ error: "The registry did not answer." }, { status: 502 }), opts.dev);
  }

  const out = new Headers(upstream.headers);

  for (const name of HOP_BY_HOP) out.delete(name);

  return withSiteHeaders(new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out }), opts.dev);
}

function withSiteHeaders(res: Response, dev: boolean): Response {
  for (const h of securityHeaders(dev)) res.headers.set(h.key, h.value);

  for (const h of PRIVATE_HEADERS) {
    if (h.key === "Vary") res.headers.append("Vary", h.value);
    else res.headers.set(h.key, h.value);
  }

  return res;
}
