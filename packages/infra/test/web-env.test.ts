// Review findings 6 and 7: the website Worker had no APM_CLIENT_IP_HEADER, so its rate limits read X-Forwarded-For,
// and no shared rate limit. The website must trust CF-Connecting-IP and carry the agent routes' shared binding.
import { describe, expect, test } from "bun:test";
import { AGENT_RATE, websiteAgentEnv } from "../web-env.ts";

describe("the website Worker's agent settings", () => {
  test("it trusts CF-Connecting-IP and binds the shared agent rate limit", () => {
    const env = websiteAgentEnv("production");

    expect(env.APM_CLIENT_IP_HEADER).toBe("cf-connecting-ip");
    expect(env.AGENT_RATE_LIMIT).toMatchObject({ kind: "Cloudflare.RateLimit", name: "AGENT_RATE_LIMIT", simple: { limit: 60, period: 60 } });
  });

  // apps/web/lib/agent/agent-limit.ts (AGENT_SHARED_LIMIT, AGENT_SHARED_PERIOD_S) and docs/AGENTS.md say the same
  test("the limit is the one the website documents, and each stage counts on its own", () => {
    expect(AGENT_RATE).toEqual({ limit: 60, period: 60 });
    expect(websiteAgentEnv("production").AGENT_RATE_LIMIT.namespaceId).not.toBe(websiteAgentEnv("staging").AGENT_RATE_LIMIT.namespaceId);
  });
});
