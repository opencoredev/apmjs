// The MCP server over real Request objects: the handshake, the tool list, each tool, and the HTTP rules.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { mcpGet, mcpOptions, mcpPost } from "./mcp-http";
import type { Json } from "./json";
import { PROTOCOL_VERSIONS, TOOLS } from "./mcp";
import { fakeSource, NETWORK, pkg, REVIEW_CLEAN, type Fake } from "./testing";

const allow = () => ({ ok: true }) as const;

function postText(body: string, headers: Record<string, string> = {}): Request {
  return new Request("https://apmjs.dev/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body });
}

const post = (body: Json, headers: Record<string, string> = {}): Request => postText(JSON.stringify(body), headers);

const ToolResult = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.number(),
  result: z.object({ content: z.array(z.object({ type: z.literal("text"), text: z.string() })), structuredContent: z.record(z.string(), z.unknown()).optional(), isError: z.boolean().optional() }),
});

async function call(name: string, args: { [key: string]: Json }, fake: Fake = {}) {
  const source = fakeSource(fake);
  const res = await mcpPost(post({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name, arguments: args } }), { source, take: allow });

  expect(res.status).toBe(200);
  const body = ToolResult.parse(await res.json());

  return { text: body.result.content.map((c) => c.text).join("\n"), structured: body.result.structuredContent ?? {}, isError: body.result.isError === true, calls: source.calls };
}

describe("handshake", () => {
  test("initialize echoes a supported protocol version and offers tools", async () => {
    const res = await mcpPost(post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } }), { source: fakeSource(), take: allow });
    const body = await res.json();

    expect(res.headers.get("content-type")).toBe("application/json");
    expect(body).toMatchObject({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "apm" } } });
  });

  test("an unknown protocol version gets the newest one", async () => {
    const res = await mcpPost(post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "1999-01-01" } }), { source: fakeSource(), take: allow });

    expect((await res.json()).result.protocolVersion).toBe(PROTOCOL_VERSIONS[0]);
  });

  test("a notification is accepted with 202 and no body", async () => {
    const res = await mcpPost(post({ jsonrpc: "2.0", method: "notifications/initialized" }), { source: fakeSource(), take: allow });

    expect(res.status).toBe(202);
    expect(await res.text()).toBe("");
  });

  test("ping answers, an unknown method is -32601, bad JSON -32700, a batch is refused", async () => {
    const deps = { source: fakeSource(), take: allow };

    expect(await (await mcpPost(post({ jsonrpc: "2.0", id: 2, method: "ping" }), deps)).json()).toEqual({ jsonrpc: "2.0", id: 2, result: {} });
    expect((await (await mcpPost(post({ jsonrpc: "2.0", id: 3, method: "sampling/createMessage" }), deps)).json()).error.code).toBe(-32601);
    const bad = await mcpPost(postText("{not json"), deps);

    expect(bad.status).toBe(400);
    expect((await bad.json()).error.code).toBe(-32700);
    expect((await mcpPost(post([{ jsonrpc: "2.0", id: 1, method: "ping" }]), deps)).status).toBe(400);
  });

  test("tools/list has the five read-only tools, each with an object input schema", async () => {
    const res = await mcpPost(post({ jsonrpc: "2.0", id: 4, method: "tools/list" }), { source: fakeSource(), take: allow });
    const { tools } = (await res.json()).result;

    expect(tools.map((t: { name: string }) => t.name)).toEqual(["search_packages", "check_package", "check_name", "explain_install", "get_file_excerpt"]);

    for (const t of tools) {
      expect(t.inputSchema.type).toBe("object");
      expect(t.annotations.readOnlyHint).toBe(true);
    }

    expect(tools.find((t: { name: string }) => t.name === "check_package").inputSchema.required).toEqual(["name"]);
  });
});

describe("tools", () => {
  test("search_packages lists hits with their scores", async () => {
    const r = await call("search_packages", { query: "pad", limit: 1 }, {
      search: { query: "pad", total: 2, upstreamFailed: false, hits: [{ name: "left-pad", version: "1.3.0", description: "String left pad", date: null, source: "npm", score: { score: 75, grade: "B" }, weeklyDownloads: 1000 }, { name: "right-pad", version: "1.0.0", description: "", date: null, source: "npm", score: null, weeklyDownloads: null }] },
    });

    expect(r.isError).toBe(false);
    expect(r.text).toContain('1 of 2 for "pad":');
    expect(r.text).toContain("- left-pad@1.3.0 score 75/100 (B), 1000 downloads/week: `String left pad`");
    expect(r.text).not.toContain("right-pad");
    expect(r.calls).toEqual(["search pad"]);
  });

  test("check_package returns the Markdown view and the score, signals and capabilities as data", async () => {
    const r = await call("check_package", { name: "Left-Pad" }, { packages: { "left-pad": pkg() }, reviews: { "left-pad@1.3.0": REVIEW_CLEAN } });

    expect(r.text).toContain("# left-pad");
    expect(r.text).toContain("## Risk signals");
    expect(r.structured).toMatchObject({ name: "left-pad", version: "1.3.0", score: { score: 75, grade: "B" }, aiReview: { status: "reviewed", state: "found-nothing" } });
    expect(r.structured.signals).toEqual([NETWORK]);
    expect(r.structured.capabilities).toContainEqual({ id: "network", label: "Network access", state: "seen" });
  });

  test("check_package on an unknown package is a tool error the model can read", async () => {
    const r = await call("check_package", { name: "nope" });

    expect(r.isError).toBe(true);
    expect(r.text).toBe("No package named nope on apm or npm.");
  });

  test("check_name checks alternatives under the scope given, without its @", async () => {
    const r = await call("check_name", { name: "left-pad", scope: "@leo" }, {
      names: {
        query: "left-pad",
        valid: true,
        taken: true,
        source: "npm",
        unknown: false,
        available: false,
        owners: ["stevemao"],
        latest: { version: "1.3.0", score: 75, grade: "B" },
        description: null,
        conflicts: [],
        lookalikes: [],
        similar: [],
        scope: "leo",
        suggestions: [{ name: "@leo/left-pad", available: true, taken: false, unknown: false, checked: true }],
      },
    });

    expect(r.calls).toEqual(["names left-pad leo"]);
    expect(r.text).toContain("left-pad is taken by `stevemao`; latest `1.3.0`, score 75/100.");
    expect(r.text).toContain("Free under @leo: @leo/left-pad");
  });

  test("explain_install resolves the range, reads the review of the picked version, and gives a verdict", async () => {
    const r = await call("explain_install", { name: "left-pad", version: "^1" }, {
      resolve: () => ({
        kind: "ok",
        version: "1.3.0",
        source: "upstream",
        report: { score: 92, grade: "A", signals: [], notChecked: [] },
        skipped: [],
        deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] }, warnings: [] },
      }),
      reviews: { "left-pad@1.3.0": REVIEW_CLEAN },
    });

    expect(r.calls).toEqual(["resolve left-pad@^1", "review left-pad@1.3.0"]);
    expect(r.structured).toMatchObject({ verdict: "install", version: "1.3.0", commands: { apm: "apm add left-pad@1.3.0" } });
    expect(r.text).toStartWith("Verdict: install\nleft-pad@1.3.0 passes apm's checks");
  });

  test("get_file_excerpt shows numbered lines inside a fence the file can't close", async () => {
    const r = await call("get_file_excerpt", { name: "left-pad", version: "1.3.0", path: "index.js", line: 2, context: 1 }, {
      excerpt: { kind: "ok", value: { kind: "excerpt", name: "left-pad", version: "1.3.0", path: "index.js", size: 30, line: 2, totalLines: 3, from: 1, to: 3, lines: [{ n: 1, text: "a", truncated: null }, { n: 2, text: "```", truncated: null }, { n: 3, text: "c", truncated: null }] } },
    });

    expect(r.calls).toEqual(["excerpt left-pad@1.3.0 index.js:2±1"]);
    expect(r.text).toContain("`index.js` in left-pad@`1.3.0`, lines 1-3 of 3:");
    expect(r.text).toContain("````\n1  a\n2  ```\n3  c\n````");
  });

  test("bad arguments come back as a tool error naming the field", async () => {
    const r = await call("get_file_excerpt", { name: "left-pad", path: "x" });

    expect(r.isError).toBe(true);
    expect(r.text).toContain("version:");
  });

  test("an unknown tool is a protocol error", async () => {
    const res = await mcpPost(post({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "publish" } }), { source: fakeSource(), take: allow });

    expect((await res.json()).error.code).toBe(-32602);
  });

  test("every tool is listed with a description", () => {
    for (const t of TOOLS) expect(t.description.length).toBeGreaterThan(40);
  });
});

describe("HTTP", () => {
  test("over the limit: 429 with Retry-After, and the registry is not asked", async () => {
    const source = fakeSource();
    const res = await mcpPost(post({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_packages", arguments: { query: "x" } } }), { source, take: () => ({ ok: false, retryAfterSeconds: 3 }) });

    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("3");
    expect(source.calls).toEqual([]);
  });

  test("an unknown MCP-Protocol-Version header is a 400", async () => {
    expect((await mcpPost(post({ jsonrpc: "2.0", id: 1, method: "ping" }, { "mcp-protocol-version": "2020-01-01" }), { source: fakeSource(), take: allow })).status).toBe(400);
  });

  test("GET is 405 (no stream); OPTIONS allows any origin", async () => {
    expect(mcpGet().status).toBe(405);
    const pre = mcpOptions();

    expect(pre.status).toBe(204);
    expect(pre.headers.get("access-control-allow-origin")).toBe("*");
    expect(pre.headers.get("access-control-allow-headers")).toContain("mcp-protocol-version");
  });
});
