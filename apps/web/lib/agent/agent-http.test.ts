// Review finding 1: GET /api/explain was cached for 60 seconds and the Markdown view for 5 minutes, so a version
// confirmed malicious or yanked kept its old answer. Decisions are never stored; views for seconds at most.
import { describe, expect, test } from "bun:test";
import { AGENT_CACHE, explainResponse, markdownResponse } from "./agent-http";
import type { ReviewAnswer } from "../review-schema";
import type { Message } from "./mcp";
import { mcpPost } from "./mcp-http";
import type { ResolveOutcome } from "./source";
import { fakeSource, pkg, REVIEW_CLEAN } from "./testing";

const allow = () => ({ ok: true }) as const;

const clean: ResolveOutcome = {
  kind: "ok",
  version: "1.3.0",
  source: "upstream",
  report: { score: 92, grade: "A", signals: [], notChecked: [] },
  skipped: [],
  deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] } },
};

/** The longest a response may be stored, in seconds; 0 for no-store or no-cache. */
function maxAge(res: Response): number {
  const cc = res.headers.get("cache-control") ?? "";

  if (/no-store|no-cache/.test(cc)) return 0;
  const ages = [...cc.matchAll(/(?:s-maxage|max-age)=(\d+)/g)].map((m) => Number(m[1]));

  if (ages.length === 0) throw new Error(`no cache policy: "${cc}"`);

  return Math.max(...ages);
}

describe("GET /api/explain is never stored", () => {
  test("a verdict, a bad request and a rate-limited request all say no-store", async () => {
    const source = fakeSource({ resolve: () => clean, reviews: { "left-pad@1.3.0": REVIEW_CLEAN } });
    const ok = await explainResponse(new URL("https://apmjs.dev/api/explain?package=left-pad"), { source, take: allow });

    expect(ok.status).toBe(200);
    expect(ok.headers.get("cache-control")).toBe("no-store");
    expect((await ok.json()).verdict).toBe("install");
    expect((await explainResponse(new URL("https://apmjs.dev/api/explain"), { source, take: allow })).headers.get("cache-control")).toBe("no-store");
    const limited = await explainResponse(new URL("https://apmjs.dev/api/explain?package=left-pad"), { source, take: () => ({ ok: false, retryAfterSeconds: 2 }) });

    expect(limited.status).toBe(429);
    expect(limited.headers.get("cache-control")).toBe("no-store");
  });
});

// Review finding P1: resolve picked an active version, a revoke started before the review read, and the review
// answer said so (redacted, revoke-pending); the web dropped the flag and its clean review gave "install".
describe("a revoke that starts between the resolve and the review read", () => {
  const revoking: ReviewAnswer = { ...REVIEW_CLEAN, versionStatus: "revoke-pending", redacted: true };

  test("GET /api/explain answers do-not-install with no commands", async () => {
    const source = fakeSource({ resolve: () => clean, reviews: { "left-pad@1.3.0": revoking } });
    const body = await (await explainResponse(new URL("https://apmjs.dev/api/explain?package=left-pad"), { source, take: allow })).json();

    expect(body).toMatchObject({ verdict: "do-not-install", version: "1.3.0", score: null, commands: null, coverage: { aiReview: "not-read", dependencies: "not-read" } });
  });

  test("the explain_install MCP tool answers do-not-install with no commands", async () => {
    const source = fakeSource({ resolve: () => clean, reviews: { "left-pad@1.3.0": revoking } });
    const req = new Request("https://apmjs.dev/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "explain_install", arguments: { name: "left-pad" } } }) });
    const body = await (await mcpPost(req, { source, take: allow })).json();

    expect(body.result.structuredContent).toMatchObject({ verdict: "do-not-install", commands: null });
    expect(body.result.content[0].text).toStartWith("Verdict: do-not-install\nDo not install left-pad@1.3.0: it is being revoked.");
    expect(body.result.content[0].text).not.toContain("Run: ");
  });
});

describe("the MCP endpoint is never stored", () => {
  test("a tool answer and a notification's 202 say no-store", async () => {
    const post = (body: Message) => new Request("https://apmjs.dev/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const source = fakeSource({ resolve: () => clean, reviews: { "left-pad@1.3.0": REVIEW_CLEAN } });
    const call = await mcpPost(post({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "explain_install", arguments: { name: "left-pad" } } }), { source, take: allow });

    expect(call.headers.get("cache-control")).toBe("no-store");
    const note = await mcpPost(post({ jsonrpc: "2.0", method: "notifications/initialized" }), { source, take: allow });

    expect(note.status).toBe(202);
    expect(note.headers.get("cache-control")).toBe("no-store");
  });
});

// Re-review finding 3: the Markdown view quotes evidence lines and the AI review's excerpts, and was public for 5
// seconds, so a version revoked a moment ago could still be shown from a cache. It is now never stored.
describe("the Markdown view is never stored", () => {
  test("found, missing and unavailable answers are private, no-store", async () => {
    const source = fakeSource({ packages: { "left-pad": pkg() }, reviews: { "left-pad@1.3.0": REVIEW_CLEAN } });
    const ok = await markdownResponse({ name: "left-pad", version: null, registry: "https://registry.apmjs.dev/", source });

    expect(ok.status).toBe(200);
    expect(ok.headers.get("cache-control")).toBe("private, no-store");
    expect((await markdownResponse({ name: "left-pad", version: "9.9.9", registry: "https://registry.apmjs.dev/", source })).headers.get("cache-control")).toBe("private, no-store");
    expect((await markdownResponse({ name: "left-pad", version: null, registry: "https://registry.apmjs.dev/", source: fakeSource({ down: true }) })).headers.get("cache-control")).toBe("private, no-store");
  });

  test("the decision and source policies are never stored; only the OG image keeps a few seconds", () => {
    expect(AGENT_CACHE.decision).toBe("no-store");
    expect(AGENT_CACHE.source).toBe("private, no-store");
    expect(maxAge(new Response(null, { headers: { "cache-control": AGENT_CACHE.image } }))).toBeLessThanOrEqual(5);
  });
});
