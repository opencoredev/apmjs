// Review findings 6 and 7: the MCP limit was keyed on X-Forwarded-For, which a client writes, and counted per isolate,
// so rotating that header or landing on a fresh isolate reset it. Now it counts CF-Connecting-IP only, and every
// isolate shares the Workers rate limiting binding.
import { describe, expect, mock, test } from "bun:test";
import { NextRequest } from "next/server";
import { createTokenBucket } from "../rate-limit";
import { agentClientKey, forwardingHeaders } from "../client-ip";
import { AGENT_SHARED_LIMIT, takeAgentRequest, type SharedLimit } from "./agent-limit";

// the route imports the registry port, which is server code; this test only sends ping, which reads nothing
mock.module("server-only", () => ({}));

const { POST } = await import("../../app/mcp/route");

const ping = (headers: Record<string, string>) =>
  new NextRequest("https://apmjs.dev/mcp", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });

/** A stand-in for the Workers binding: one counter per key, shared by everyone who holds it. */
function sharedCounter(limit: number): SharedLimit & { counts: Map<string, number> } {
  const counts = new Map<string, number>();

  return {
    counts,
    async limit({ key }) {
      const n = (counts.get(key) ?? 0) + 1;

      counts.set(key, n);

      return { success: n <= limit };
    },
  };
}

describe("the MCP route's limit", () => {
  test("a client that rotates X-Forwarded-For is still limited by its CF-Connecting-IP", async () => {
    const statuses: number[] = [];

    for (let i = 0; i < 31; i++) statuses.push((await POST(ping({ "cf-connecting-ip": "198.51.100.7", "x-forwarded-for": `10.0.${i}.1` }))).status);

    expect(statuses.slice(0, 30).every((s) => s === 200)).toBe(true);
    expect(statuses[30]).toBe(429);
    // another address has its own allowance
    expect((await POST(ping({ "cf-connecting-ip": "198.51.100.8" }))).status).toBe(200);
  });
});

describe("agentClientKey and forwardingHeaders", () => {
  test("the key is CF-Connecting-IP and nothing a client can write", () => {
    expect(agentClientKey(new Headers({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "5.6.7.8" }))).toBe("unknown");
    expect(agentClientKey(new Headers({ "cf-connecting-ip": "198.51.100.4", "x-forwarded-for": "1.2.3.4" }))).toBe("198.51.100.4");
  });

  test("proxy.ts keeps Cloudflare's address under its own name when the deploy trusts it, and drops every client header", () => {
    const sent = new Headers({ "cf-connecting-ip": "198.51.100.4", "x-forwarded-for": "1.2.3.4", "x-real-ip": "5.6.7.8" });
    const trusted = forwardingHeaders(sent, { APM_CLIENT_IP_HEADER: "cf-connecting-ip" });

    expect(trusted.get("cf-connecting-ip")).toBe("198.51.100.4");
    expect(trusted.get("x-forwarded-for")).toBe("198.51.100.4");
    expect(trusted.get("x-real-ip")).toBeNull();
    // off Cloudflare nothing is trusted: the client's own CF-Connecting-IP does not survive
    const untrusted = forwardingHeaders(sent, {});

    expect(untrusted.get("cf-connecting-ip")).toBeNull();
    expect(untrusted.get("x-forwarded-for")).toBeNull();
  });
});

describe("takeAgentRequest", () => {
  test("isolates share one count: two fresh buckets cannot together pass the shared limit", async () => {
    const shared = sharedCounter(AGENT_SHARED_LIMIT);
    const isolates = [createTokenBucket({ capacity: 1_000, refillPerSecond: 1, maxKeys: 10 }), createTokenBucket({ capacity: 1_000, refillPerSecond: 1, maxKeys: 10 })];
    let passed = 0;

    for (let i = 0; i < 100; i++) if ((await takeAgentRequest({ key: "198.51.100.9", local: isolates[i % 2] ?? isolates[0], shared })).ok) passed++;

    expect(passed).toBe(AGENT_SHARED_LIMIT);
  });

  test("the isolate's bucket answers first and spares the binding; a failing binding leaves the bucket to decide", async () => {
    const shared = sharedCounter(1_000);
    const local = createTokenBucket({ capacity: 1, refillPerSecond: 0.001, maxKeys: 10 });

    expect((await takeAgentRequest({ key: "a", local, shared })).ok).toBe(true);
    expect((await takeAgentRequest({ key: "a", local, shared })).ok).toBe(false);
    expect(shared.counts.get("a")).toBe(1);
    const broken: SharedLimit = { limit: () => Promise.reject(new Error("binding down")) };

    expect((await takeAgentRequest({ key: "b", local, shared: broken })).ok).toBe(true);
  });
});
