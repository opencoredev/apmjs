// Which address a request came from, without trusting what the client says about itself.
//
// proxy.ts deletes every client-supplied forwarding header. For app routes Next.js then fills
// X-Forwarded-For from the TCP peer (base-server.js: `x-forwarded-for ??= socket.remoteAddress`).
// Behind a CDN or load balancer that peer is the proxy, so set APM_CLIENT_IP_HEADER to the header the
// edge overwrites on every request (cf-connecting-ip on Cloudflare, x-real-ip from nginx) and only
// that header is read. Never point it at a header clients can set past the edge. The Cloudflare deploy
// (packages/infra/alchemy.run.ts) sets it to cf-connecting-ip; the agent routes' limits read only that.

/** Headers a client can send to claim a different address. Removed in proxy.ts before anything reads them. */
export const CLIENT_FORWARDING_HEADERS = ["forwarded", "x-forwarded-for", "x-real-ip", "x-client-ip", "true-client-ip", "cf-connecting-ip", "fastly-client-ip", "x-cluster-client-ip"] as const;

/** The header the deployment's edge sets with the real client address, when there is one. */
export function trustedIpHeader(env: Partial<Record<string, string>> = process.env): string | null {
  const name = env.APM_CLIENT_IP_HEADER?.trim().toLowerCase();

  return name ? name : null;
}

/** First address in a header value, or null. */
function firstAddress(value: string | null): string | null {
  const first = value?.split(",")[0]?.trim();

  return first ? first : null;
}

/** The address of the edge-reported client, read in proxy.ts before the forwarding headers are removed. */
export function edgeClientIp(headers: Headers, env: Partial<Record<string, string>> = process.env): string | null {
  const name = trustedIpHeader(env);

  return name ? firstAddress(headers.get(name)) : null;
}

/** The client address in a route handler, after proxy.ts has run. "unknown" when nothing reports one. */
export function clientIp(headers: Headers): string {
  return firstAddress(headers.get("x-forwarded-for")) ?? "unknown";
}

/**
 * The request headers proxy.ts passes on: every client-supplied forwarding header removed, then the edge-reported
 * address set as X-Forwarded-For and, under its own name, the trusted header (cf-connecting-ip on Cloudflare), so a
 * route can read the edge's header itself whether or not the runtime applies the removal.
 */
export function forwardingHeaders(headers: Headers, env: Partial<Record<string, string>> = process.env): Headers {
  const out = new Headers(headers);
  const edge = edgeClientIp(headers, env);
  const name = trustedIpHeader(env);

  for (const h of CLIENT_FORWARDING_HEADERS) out.delete(h);

  // With no X-Forwarded-For, Next.js fills it from the TCP peer for app routes. Requests forwarded to
  // the registry don't get that, so they only carry an address when the edge reported one.
  if (edge) out.set("x-forwarded-for", edge);

  if (edge && name) out.set(name, edge);

  return out;
}

/** The header Cloudflare sets on every request with the visitor's address. A client cannot set it past Cloudflare. */
export const CLOUDFLARE_IP_HEADER = "cf-connecting-ip";

/**
 * Who a rate limit counts an agent request against: Cloudflare's CF-Connecting-IP and nothing else, never
 * X-Forwarded-For, which a client can write. Without it (next dev, next start) every request shares one key.
 */
export function agentClientKey(headers: Headers): string {
  return firstAddress(headers.get(CLOUDFLARE_IP_HEADER)) ?? "unknown";
}
