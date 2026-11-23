// The Workers' error reports to Databuddy (src/error-report.ts): every field is a fixed code, a static label or a value
// apm set, the limit is one per isolate, the report is built and sent only once waitUntil holds the task, and it never
// follows a redirect.
import { describe, expect, test } from "bun:test";
import { DATABUDDY_ERRORS_URL, ERROR_CODES, errorPayload, errorReporter, rateLimiter, REPORT_LIMIT, type ServerError } from "../src/error-report.ts";

const E: ServerError = { worker: "registry", code: "db_error", route: "GET staged detail", status: 500, build: "b1", colo: "SJC" };

type Sent = { url: string; init: RequestInit };

/** A collector stand-in: what was sent, and the fetch that records it. */
type Collector = { sent: Sent[]; fetch: (url: string, init: RequestInit) => Promise<Response> };

function collector(): Collector {
  const sent: Sent[] = [];

  return {
    sent,
    fetch: async (url, init) => {
      sent.push({ url, init });

      return new Response("ok", { status: 200 });
    },
  };
}

describe("errorPayload", () => {
  test("is the code, the label, the status, the build and the colo, in the collector's fields", () => {
    expect(errorPayload(E, 7)).toEqual({
      timestamp: 7,
      path: "https://registry.apmjs.dev/_server/GET_staged_detail",
      message: "db_error",
      errorType: "db_error",
      filename: "registry@b1",
      stack: "worker=registry code=db_error status=500 route=GET_staged_detail colo=SJC build=b1",
    });
    expect(errorPayload({ ...E, worker: "web", route: "GET render package" }, 7).path).toBe("https://apmjs.dev/_server/GET_render_package");
  });

  test("anything outside a field's closed form is sent as unknown or -, never as passed", () => {
    // a caller's mistake the types would refuse (Object.assign keeps E's type): none of this may leave
    const bad = Object.assign({ ...E }, { code: "device?code=ABCD-1234", route: "/approve/stg_AbCdEf123456", status: 200, build: "b1 someone@example.com", colo: "SJC?x=1" });
    const p = errorPayload(bad, 7);

    expect(p).toEqual({
      timestamp: 7,
      path: "https://registry.apmjs.dev/_server/unknown",
      message: "unknown",
      errorType: "unknown",
      filename: "registry@-",
      stack: "worker=registry code=unknown status=500 route=unknown colo=- build=-",
    });

    for (const route of ["GET packument extra words that go on", "GET Packument", "get packument", "GET pack/ument", "GET ", "GET stg_AbCdEf123456"]) {
      expect(errorPayload({ ...E, route }, 7).path, route).toBe("https://registry.apmjs.dev/_server/unknown");
    }
  });

  test("every code is lowercase words, so a message is never more than a code", () => {
    for (const c of ERROR_CODES) expect(c).toMatch(/^[a-z_]+$/);
  });
});

describe("rateLimiter", () => {
  test("allows max per window and starts again in the next", () => {
    let t = 0;
    const take = rateLimiter({ max: 2, windowMs: 100 }, () => t);

    expect([take(), take(), take()]).toEqual([true, true, false]);
    t = 100;
    expect(take()).toBe(true);
  });
});

describe("errorReporter", () => {
  test("is off without a client id, or with one that is not an id", async () => {
    const c = collector();
    const r = errorReporter({ fetch: c.fetch });
    const waited: Promise<unknown>[] = [];

    for (const clientId of ["", " ", "a b", "x?y=1", "x".repeat(65)]) expect(r.report({ clientId, waitUntil: (w) => waited.push(w), error: () => E })).toBe(false);
    await Promise.all(waited);
    expect(c.sent).toHaveLength(0);
  });

  test("posts one item to the collector, with the canonical origin and no redirects", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];

    expect(errorReporter({ fetch: c.fetch, now: () => 5 }).report({ clientId: "client-1", waitUntil: (w) => waited.push(w), error: () => E })).toBe(true);
    await Promise.all(waited);
    expect(c.sent).toHaveLength(1);
    const [s] = c.sent;

    expect(s?.url).toBe(`${DATABUDDY_ERRORS_URL}?client_id=client-1`);
    expect(s?.init.method).toBe("POST");
    expect(s?.init.redirect).toBe("manual");
    // Databuddy's edge blocks a report with no User-Agent (missing_user_agent), and a Worker's fetch() sends none
    expect(Object.fromEntries(new Headers(s?.init.headers))).toEqual({ "content-type": "application/json", origin: "https://registry.apmjs.dev", "user-agent": "apmjs/1.0" });
    expect(JSON.parse(String(s?.init.body))).toEqual([errorPayload(E, 5)]);
  });

  test("allows REPORT_LIMIT per window for the reporter, across client ids", async () => {
    const c = collector();
    const r = errorReporter({ fetch: c.fetch, now: () => 0 });
    const waited: Promise<unknown>[] = [];
    const results = Array.from({ length: REPORT_LIMIT.max + 5 }, (_, i) => r.report({ clientId: `client-${i % 2}`, waitUntil: (w) => waited.push(w), error: () => E }));

    await Promise.all(waited);
    expect(results.filter(Boolean)).toHaveLength(REPORT_LIMIT.max);
    expect(c.sent).toHaveLength(REPORT_LIMIT.max);
  });

  test("builds the report in the waitUntil task, after report() returns", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];
    const r = errorReporter({ fetch: c.fetch });
    let built = false;

    expect(
      r.report({
        clientId: "client-1",
        waitUntil: (w) => waited.push(w),
        error: () => {
          built = true;

          return E;
        },
      }),
    ).toBe(true);
    expect(built).toBe(false);
    await Promise.all(waited);
    expect(built).toBe(true);
    expect(c.sent).toHaveLength(1);
  });

  test("a throwing builder sends nothing, throws nothing and leaves a task that settles", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];
    const r = errorReporter({ fetch: c.fetch });

    expect(
      r.report({
        clientId: "client-1",
        waitUntil: (w) => waited.push(w),
        error: () => {
          throw new Error("getter");
        },
      }),
    ).toBe(true);
    expect(await Promise.all(waited)).toEqual([undefined]);
    expect(c.sent).toHaveLength(0);
  });

  test("starts the send only after waitUntil took it, and not at all when waitUntil throws", async () => {
    const c = collector();
    const r = errorReporter({ fetch: c.fetch });
    let sentWhenHeld = -1;
    const waited: Promise<unknown>[] = [];

    r.report({
      clientId: "client-1",
      waitUntil: (w) => {
        sentWhenHeld = c.sent.length;
        waited.push(w);
      },
      error: () => E,
    });
    await Promise.all(waited);
    expect(sentWhenHeld).toBe(0);
    expect(c.sent).toHaveLength(1);

    expect(
      r.report({
        clientId: "client-1",
        waitUntil: () => {
          throw new Error("no context");
        },
        error: () => E,
      }),
    ).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(c.sent).toHaveLength(1);
  });

  test("a real fetch with the reporter's options does not follow the collector's redirect", async () => {
    const hits: string[] = [];

    using server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        const path = new URL(req.url).pathname;

        hits.push(path);

        return path === "/errors" ? new Response(null, { status: 307, headers: { location: "/elsewhere" } }) : new Response("followed");
      },
    });

    const waited: Promise<unknown>[] = [];
    const r = errorReporter({ fetch: (_url, init) => fetch(new URL("/errors", server.url), init) });

    expect(r.report({ clientId: "c", waitUntil: (w) => waited.push(w), error: () => E })).toBe(true);
    await Promise.all(waited);
    expect(hits).toEqual(["/errors"]);
  });

  test("a failed or redirected send settles quietly", async () => {
    const waited: Promise<unknown>[] = [];
    const failing = errorReporter({ fetch: () => Promise.reject(new Error("no network")) });
    const redirected = errorReporter({ fetch: async () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } }) });

    expect(failing.report({ clientId: "c", waitUntil: (w) => waited.push(w), error: () => E })).toBe(true);
    expect(redirected.report({ clientId: "c", waitUntil: (w) => waited.push(w), error: () => E })).toBe(true);
    expect(await Promise.all(waited)).toEqual([undefined, undefined]);
  });
});
