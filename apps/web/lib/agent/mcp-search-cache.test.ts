// Review finding (P1, MCP search cache): search_packages read search through the site's edge cache whatever the answer
// held, so a local package's description from a version revoked a moment ago was still quoted to agents. search_packages
// now follows the website's rule (lib/registry.ts): only an answer made entirely of npm's packages may be cached, and one
// with a local package is asked of the registry every time. The registry is a stub behind fetch.
import { afterAll, beforeAll, describe, expect, mock, spyOn, test } from "bun:test";
import { REGISTRY } from "../registry-url";

// registry-source.ts is server code; outside Next.js the "server-only" guard would refuse the import
void mock.module("server-only", () => ({}));

const { registrySource } = await import("./registry-source");
const { handleMessage } = await import("./mcp");

/** Per query: the description the stub answers with, the source of its one hit, and how often it was asked. */
const descriptions = new Map<string, string>();
const sources = new Map<string, "local" | "npm">();
const reads = new Map<string, number>();
const realFetch = globalThis.fetch;

beforeAll(() => {
  const stub = (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : input.toString());

    if (!url.href.startsWith(REGISTRY) || url.pathname !== "/-/v1/search") return realFetch(input, init);
    const q = url.searchParams.get("text") ?? "";
    reads.set(q, (reads.get(q) ?? 0) + 1);
    const object = { source: sources.get(q) ?? "local", package: { name: q, version: "1.0.0", description: descriptions.get(q) ?? "", date: null } };

    return Promise.resolve(Response.json({ objects: [object], total: 1, upstreamFailed: false }));
  };

  spyOn(globalThis, "fetch").mockImplementation(Object.assign(stub, { preconnect: realFetch.preconnect }));
});

afterAll(() => {
  mock.restore();
});

async function searchPackages(query: string): Promise<{ text: string; structured: string }> {
  const answer = await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_packages", arguments: { query } } }, registrySource);
  const result = answer?.result && "content" in answer.result ? answer.result : null;

  return { text: result?.content[0]?.text ?? "", structured: JSON.stringify(result?.structuredContent ?? null) };
}

describe("search_packages and the search cache", () => {
  test("warmed, then a local version is revoked: the next search quotes the registry's answer now, not the cached one", async () => {
    const q = "mcp-local-widget";

    descriptions.set(q, "LEAKMARK-withdrawn-description");
    const warm = await searchPackages(q);

    expect(warm.text).toContain("LEAKMARK-withdrawn-description");

    // the version that wrote the description is revoked: the registry answers with the shown version's text
    descriptions.set(q, "the shown version's description");
    const after = await searchPackages(q);

    expect(after.text).toContain("the shown version's description");
    expect(after.text).not.toContain("LEAKMARK");
    expect(after.structured).not.toContain("LEAKMARK");
    expect(reads.get(q)).toBe(2);
  });

  test("an answer of npm's packages only is still served from the cache", async () => {
    const q = "mcp-npm-widget";

    sources.set(q, "npm");
    descriptions.set(q, "from npm");
    expect((await searchPackages(q)).text).toContain("from npm");
    expect((await searchPackages(q)).text).toContain("from npm");
    expect(reads.get(q)).toBe(1);
  });
});
