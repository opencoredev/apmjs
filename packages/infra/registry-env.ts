// What the registry Worker is given besides its storage: the rate limiting binding behind the per-address limit on
// GET /-/apm/v1/resolve (packages/registry/src/resolve-limit.ts, which reads RESOLVE_RATE_LIMIT and says the same number).
import * as Cloudflare from "@alchemy.run/cloudflare";

/** Resolves per client address per minute, across every isolate in a Cloudflare location. */
export const RESOLVE_RATE = { limit: 60, period: 60 } as const;

/**
 * A rate limit namespace counts per account, and a binding shares counters with any other on the same id: each stage
 * gets its own, apart from the website's agent limit (web-env.ts, 4801 and 4802).
 */
const NAMESPACE = { production: 4803, staging: 4804 } as const;

export function registryLimitEnv(stage: string) {
  return {
    RESOLVE_RATE_LIMIT: Cloudflare.RateLimit("RESOLVE_RATE_LIMIT", { namespaceId: stage === "production" ? NAMESPACE.production : NAMESPACE.staging, simple: RESOLVE_RATE }),
  };
}
