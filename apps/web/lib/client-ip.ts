// Which address a request came from, without trusting what the client says about itself.
//
// proxy.ts deletes every client-supplied forwarding header. For app routes Next.js then fills
// X-Forwarded-For from the TCP peer (base-server.js: `x-forwarded-for ??= socket.remoteAddress`).
// Behind a CDN or load balancer that peer is the proxy, so set APM_CLIENT_IP_HEADER to the header the
// edge overwrites on every request (cf-connecting-ip on Cloudflare, x-real-ip from nginx) and only
// that header is read. Never point it at a header clients can set past the edge.

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
