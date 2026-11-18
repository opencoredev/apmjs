// The registry's resolve limit as the stack binds it: the number the registry says in its 429, and a namespace per
// stage that no other binding of apm's shares.
import { describe, expect, test } from "bun:test";
import { RESOLVE_LIMIT_PER_MINUTE } from "../../registry/src/resolve-limit.ts";
import { registryLimitEnv, RESOLVE_RATE } from "../registry-env.ts";
import { websiteAgentEnv } from "../web-env.ts";

describe("registryLimitEnv", () => {
  test("binds RESOLVE_RATE_LIMIT at the limit the registry's answer names", () => {
    expect(RESOLVE_RATE).toEqual({ limit: RESOLVE_LIMIT_PER_MINUTE, period: 60 });
    expect(registryLimitEnv("production").RESOLVE_RATE_LIMIT).toMatchObject({ kind: "Cloudflare.RateLimit", name: "RESOLVE_RATE_LIMIT", simple: { limit: 60, period: 60 } });
  });

  test("each stage counts apart, and apart from the website's agent limit", () => {
    const ids = ["production", "staging"].flatMap((stage) => [registryLimitEnv(stage).RESOLVE_RATE_LIMIT.namespaceId, websiteAgentEnv(stage).AGENT_RATE_LIMIT.namespaceId]);

    expect(new Set(ids).size).toBe(4);
  });
});
