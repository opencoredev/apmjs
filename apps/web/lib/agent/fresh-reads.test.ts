// Review finding 1: the install verdict and the MCP tools read the AI review through the website's edge cache, so a
// version confirmed malicious a moment ago still got "install". Here the registry is a stub behind fetch whose answers
// change between two reads; the second read must see the change.
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import { REVIEW_CLEAN } from "./testing";

// registry-source.ts is server code; outside Next.js the "server-only" guard would refuse the import
mock.module("server-only", () => ({}));

const { registrySource } = await import("./registry-source");
const { explainFor } = await import("./explain");
const { handleMessage } = await import("./mcp");

type Answer = { status: number; body: unknown };

const answers = new Map<string, Answer>();
const asked: string[] = [];
const realFetch = globalThis.fetch;

function stubFetch(input: string | URL | Request): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  const key = url.pathname.replace(/^\/+/, "");

  asked.push(key);
  const a = answers.get(key);

  return Promise.resolve(a ? Response.json(a.body, { status: a.status }) : Response.json({ error: "Not found" }, { status: 404 }));
}

beforeAll(() => {
  globalThis.fetch = Object.assign(stubFetch, { preconnect: realFetch.preconnect });
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

const cleanReview = REVIEW_CLEAN.review;

if (!cleanReview) throw new Error("REVIEW_CLEAN has a review");

const reviewed = (state: "found-nothing" | "confirmed"): Answer => ({ status: 200, body: { ...REVIEW_CLEAN, name: "fresh-pkg", version: "1.0.0", job: "done", review: { ...cleanReview, state } } });

const resolveOk: Answer = {
  status: 200,
  body: { name: "fresh-pkg", version: "1.0.0", report: { score: 95, grade: "A", signals: [] }, skipped: [], tree: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] } } },
};

describe("the agent views read version state and the AI review without a cache", () => {
  test("a review confirmed between two reads is seen by the second", async () => {
    answers.set("-/apm/v1/review/fresh-pkg/1.0.0", reviewed("found-nothing"));
    const first = await registrySource.review({ name: "fresh-pkg", version: "1.0.0" });

    expect(first.kind === "ok" && first.value.review?.state).toBe("found-nothing");
    answers.set("-/apm/v1/review/fresh-pkg/1.0.0", reviewed("confirmed"));
    const second = await registrySource.review({ name: "fresh-pkg", version: "1.0.0" });

    expect(second.kind === "ok" && second.value.review?.state).toBe("confirmed");
  });

  test("explain_install turns from install to do-not-install the moment the review is confirmed", async () => {
    answers.set("-/apm/v1/resolve", resolveOk);
    answers.set("-/apm/v1/review/fresh-pkg/1.0.0", reviewed("found-nothing"));
    expect((await explainFor({ name: "fresh-pkg", range: null, source: registrySource })).verdict).toBe("install");
    answers.set("-/apm/v1/review/fresh-pkg/1.0.0", reviewed("confirmed"));
    expect((await explainFor({ name: "fresh-pkg", range: null, source: registrySource })).verdict).toBe("do-not-install");
  });

  test("a version yanked between two reads shows as yanked", async () => {
    const version = (status: string): Answer => ({ status: 200, body: { name: "fresh-pkg", version: "1.0.0", status, statusReason: status === "yanked" ? "broken" : null, deprecated: null, facts: null, score: null } });

    answers.set("-/apm/v1/packages/fresh-pkg/versions/1.0.0", version("active"));
    const a = await registrySource.version({ name: "fresh-pkg", version: "1.0.0" });

    expect(a.kind === "ok" && a.value.status).toBe("active");
    answers.set("-/apm/v1/packages/fresh-pkg/versions/1.0.0", version("yanked"));
    const b = await registrySource.version({ name: "fresh-pkg", version: "1.0.0" });

    expect(b.kind === "ok" && b.value.status).toBe("yanked");
  });

  test("a registry that fails mid-way is unreadable, not an empty answer", async () => {
    answers.set("-/apm/v1/review/fresh-pkg/1.0.0", { status: 502, body: { error: "upstream" } });
    expect((await registrySource.review({ name: "fresh-pkg", version: "1.0.0" })).kind).toBe("unavailable");
    expect((await explainFor({ name: "fresh-pkg", range: null, source: registrySource })).verdict).toBe("unknown");
  });
});

// Re-review finding 3: get_file_excerpt read through the cached getExcerpt, so after the registry started answering 410
// for a revoked version, a second call still returned the source from the cache without asking the registry.
describe("get_file_excerpt asks the registry on every call", () => {
  const EXCERPT = "-/apm/v1/file/fresh-pkg/1.0.0";
  const SECRET = "const token = process.env.NPM_TOKEN; // FRESH-SOURCE-LINE";

  const lines: Answer = {
    status: 200,
    body: { kind: "excerpt", name: "fresh-pkg", version: "1.0.0", path: "lib/a.js", size: 60, line: 1, totalLines: 1, from: 1, to: 1, lines: [{ n: 1, text: SECRET, truncated: null }] },
  };

  const call = async (): Promise<{ text: string; structured: unknown }> => {
    const answer = await handleMessage({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "get_file_excerpt", arguments: { name: "fresh-pkg", version: "1.0.0", path: "lib/a.js", line: 1 } } }, registrySource);
    const result = answer?.result && "content" in answer.result ? answer.result : null;

    return { text: result?.content[0]?.text ?? "", structured: result?.structuredContent ?? null };
  };

  test("a version revoked between two calls: the second asks the registry, shows no source and gives the revoke's reason", async () => {
    answers.set(EXCERPT, lines);
    const first = await call();

    expect(first.text).toContain(SECRET);
    answers.set(EXCERPT, { status: 410, body: { error: "fresh-pkg@1.0.0 was revoked" } });
    answers.set("-/apm/v1/packages/fresh-pkg/versions/1.0.0", { status: 200, body: { name: "fresh-pkg", version: "1.0.0", status: "revoked", statusReason: "credential stealer", deprecated: null, facts: null, score: null } });
    asked.length = 0;
    const second = await call();

    expect(asked).toContain(EXCERPT);
    expect(second.text).not.toContain(SECRET);
    expect(JSON.stringify(second.structured)).not.toContain(SECRET);
    expect(second.text).toBe("fresh-pkg@`1.0.0` is revoked: apm shows none of its files. Reason: `credential stealer`.");
  });
});
