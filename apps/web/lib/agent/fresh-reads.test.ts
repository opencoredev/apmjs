// Review finding 1: the install verdict and the MCP tools read the AI review through the website's edge cache, so a
// version confirmed malicious a moment ago still got "install". Here the registry is a stub behind fetch whose answers
// change between two reads; the second read must see the change.
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import { REVIEW_CLEAN } from "./testing";

// registry-source.ts is server code; outside Next.js the "server-only" guard would refuse the import
mock.module("server-only", () => ({}));

const { registrySource } = await import("./registry-source");
const { explainFor } = await import("./explain");

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
