// What the website Worker is given besides the registry: the header Cloudflare puts the visitor's address in, and the
// rate limit binding its agent routes (/mcp, /api/explain) share across isolates. apps/web/lib/client-ip.ts and
// apps/web/lib/agent/agent-limit.ts read them; the numbers here are the ones those files document.
import * as Cloudflare from "@alchemy.run/cloudflare";

/** Requests per client address per period on the agent routes, across every isolate in a Cloudflare location. */
export const AGENT_RATE = { limit: 60, period: 60 } as const;

/** A rate limit namespace counts per account: each stage gets its own, so staging traffic never spends production's. */
const NAMESPACE = { production: 4801, staging: 4802 } as const;

export function websiteAgentEnv(stage: string) {
  return {
    // Cloudflare sets CF-Connecting-IP on every request and overwrites one a client sends; X-Forwarded-For it does not
    APM_CLIENT_IP_HEADER: "cf-connecting-ip",
    AGENT_RATE_LIMIT: Cloudflare.RateLimit("AGENT_RATE_LIMIT", { namespaceId: stage === "production" ? NAMESPACE.production : NAMESPACE.staging, simple: AGENT_RATE }),
  };
}
