// Search through the site's own route, against a registry stub whose answers this file controls. A local package's
// description changes the moment one of its versions is revoked (the registry withholds that publish's text), so an
// answer with a local package is asked of the registry every time and sent no-store. npm-only answers stay cached.
import { afterAll, beforeAll, describe, expect, mock, spyOn, test } from "bun:test";
import { NextRequest } from "next/server";
import { REGISTRY } from "./registry-url";
import { SearchAnswer } from "./search-schema";

// lib/registry.ts is the server entry point; outside Next its marker import would throw
void mock.module("server-only", () => ({}));

const { GET: searchRoute } = await import("../app/api/search/route");
const { search } = await import("./registry");

/** The description the stub answers with per query, and how often each query reached it. */
const descriptions = new Map<string, string>();
const reads = new Map<string, number>();
const sources = new Map<string, "local" | "npm">();
const realFetch = globalThis.fetch;

function answer(q: string): Response {
  const object = { source: sources.get(q) ?? "local", package: { name: q, version: "1.0.0", description: descriptions.get(q) ?? "", date: null } };

  return Response.json({ objects: [object], total: 1, upstreamFailed: false });
}

beforeAll(() => {
  const stub = (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : input.toString());

    if (!url.href.startsWith(REGISTRY) || url.pathname !== "/-/v1/search") return realFetch(input, init);
    const q = url.searchParams.get("text") ?? "";
    reads.set(q, (reads.get(q) ?? 0) + 1);

    return Promise.resolve(answer(q));
  };

  spyOn(globalThis, "fetch").mockImplementation(Object.assign(stub, { preconnect: realFetch.preconnect }));
});

afterAll(() => {
  mock.restore();
});

async function viaRoute(q: string): Promise<{ description: string; cacheControl: string | null }> {
  const res = await searchRoute(new NextRequest(`https://apm.example/api/search?q=${q}`));
  const body = SearchAnswer.parse(await res.json());

  return { description: body.hits[0]?.description ?? "", cacheControl: res.headers.get("cache-control") };
}

describe("search caching", () => {
  test("a local package's description is the registry's answer at the time of each search, never a cached one", async () => {
    descriptions.set("local-widget", "before the revoke");
    expect(await viaRoute("local-widget")).toEqual({ description: "before the revoke", cacheControl: "no-store" });

    // the version that wrote it is revoked: the registry now answers with the shown version's text
    descriptions.set("local-widget", "after the revoke");
    expect(await viaRoute("local-widget")).toEqual({ description: "after the revoke", cacheControl: "no-store" });
    expect(reads.get("local-widget")).toBe(2);
  });

  test("lib/registry.ts's search reads a local answer from the registry every time", async () => {
    descriptions.set("local-gadget", "first");
    expect((await search("local-gadget"))?.hits[0]?.description).toBe("first");
    descriptions.set("local-gadget", "second");
    expect((await search("local-gadget"))?.hits[0]?.description).toBe("second");
    expect(reads.get("local-gadget")).toBe(2);
  });

  test("an answer of npm's packages only is still cached", async () => {
    sources.set("npm-widget", "npm");
    descriptions.set("npm-widget", "from npm");
    expect(await viaRoute("npm-widget")).toEqual({ description: "from npm", cacheControl: "private, max-age=30" });
    expect(await viaRoute("npm-widget")).toEqual({ description: "from npm", cacheControl: "private, max-age=30" });
    expect(reads.get("npm-widget")).toBe(1);
  });
});
