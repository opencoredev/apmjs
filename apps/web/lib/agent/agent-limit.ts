// The rate limit on the agent routes (POST /mcp, GET /api/explain), per client address as Cloudflare reports it
// (CF-Connecting-IP; see lib/client-ip.ts). Two layers:
//  1. A token bucket in this isolate's memory: a burst, then a steady rate. It answers first and costs nothing.
//  2. The Workers rate limiting binding (AGENT_RATE_LIMIT), shared by every isolate in a Cloudflare location: at most
//     AGENT_SHARED_LIMIT requests per AGENT_SHARED_PERIOD_S seconds per address. Cloudflare counts per location and
//     eventually, so a burst can pass slightly over before it applies. Outside a Worker there is no binding.
// No "server-only": the unit tests import it.
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { z } from "zod";
import type { Take, TokenBucket } from "../rate-limit";

/** What packages/infra/alchemy.run.ts gives the binding: 60 a minute is the bucket's one a second, shared. */
export const AGENT_SHARED_LIMIT = 60;
export const AGENT_SHARED_PERIOD_S = 60;

export type SharedLimit = { limit: (options: { key: string }) => Promise<{ success: boolean }> };

const Binding = z.object({ limit: z.instanceof(Function) });

/** AGENT_RATE_LIMIT when this runs inside the website Worker, else null. */
export function sharedLimitBinding(): SharedLimit | null {
  let env: CloudflareEnv;

  try {
    env = getCloudflareContext().env;
  } catch {
    // not on Cloudflare: no request context to read bindings from
    return null;
  }

  const limiter = env.AGENT_RATE_LIMIT;

  return limiter !== undefined && Binding.safeParse(limiter).success ? limiter : null;
}

/** One request's admission: the isolate's bucket first, then the shared limit. A binding that fails lets the bucket decide. */
export async function takeAgentRequest(input: { key: string; local: TokenBucket; shared: SharedLimit | null }): Promise<Take> {
  const local = input.local.take(input.key);

  if (!local.ok || input.shared === null) return local;

  try {
    const { success } = await input.shared.limit({ key: input.key });

    return success ? { ok: true } : { ok: false, retryAfterSeconds: AGENT_SHARED_PERIOD_S };
  } catch {
    return local;
  }
}
