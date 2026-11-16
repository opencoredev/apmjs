// The sign-in options (GET /-/apm/v1/auth/config): which providers this registry has set up. The answer is the same
// for everyone and read without the visitor's cookie, so proxy.ts serves it from the edge cache and the sign-in panel
// does not wake the registry each time. Kept apart from registry-proxy.ts, which the acceptance tests import outside a
// Worker's types.
import { z } from "zod";
import { POLICIES } from "./edge-cache";
import { fetchCachedJson } from "./registry-fetch";
import { withSiteHeaders } from "./registry-proxy";

export const AUTH_CONFIG_PATH = "/-/apm/v1/auth/config";

/** The cached answer, with the site's headers; null for any other request, or when the registry gave none to keep. */
export async function cachedAuthConfig(request: Request, opts: { registry: string; dev: boolean }): Promise<Response | null> {
  const url = new URL(request.url);

  if (request.method !== "GET" || url.pathname !== AUTH_CONFIG_PATH || url.search !== "") return null;
  const r = await fetchCachedJson({ url: new URL(AUTH_CONFIG_PATH.slice(1), opts.registry).toString(), schema: z.unknown(), signal: request.signal, cache: POLICIES.authConfig });

  return r.kind === "ok" ? withSiteHeaders(Response.json(r.value), opts.dev) : null;
}
