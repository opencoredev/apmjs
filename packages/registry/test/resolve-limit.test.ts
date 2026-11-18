// The resolve limit's decisions (resolve-limit.ts) with a stand-in for Cloudflare's rate limiting binding: which
// requests it counts, by which key, and that a binding that fails lets the request through. The limit on the Worker,
// with Miniflare's binding, is tests/acceptance/resolve-limit.test.ts. Production's Workers Logs (2026-11-18) show the
// website's service-binding reads carry no CF-Connecting-IP and requests from the internet always do.
import { describe, expect, test } from "bun:test";
import { Effect, Layer } from "effect";
import { Clock } from "../src/clock.ts";
import { admitResolve, countsLate, type RateLimiter, type ResolveCaller } from "../src/resolve-limit.ts";
import { handle, type RawEnv } from "../src/worker.ts";

/** A limiter that allows `allowed` asks per key and records the keys it was asked about. */
function counting(allowed: number): RateLimiter & { keys: string[] } {
  const seen = new Map<string, number>();
  const keys: string[] = [];

  return {
    keys,
    limit: async ({ key }) => {
      keys.push(key);
      const n = (seen.get(key) ?? 0) + 1;
      seen.set(key, n);

      return { success: n <= allowed };
    },
  };
}

const RESOLVE = "https://registry.apmjs.dev/-/apm/v1/resolve?name=zod&range=latest";

const req = (url: string, headers: Record<string, string> = {}, method = "GET"): Request => new Request(url, { method, headers });

describe("admitResolve", () => {
  test("counts a resolve by its CF-Connecting-IP and refuses past the limit", async () => {
    const limiter = counting(1);

    expect(await admitResolve({ req: req(RESOLVE, { "cf-connecting-ip": "203.0.113.1" }), limiter })).toBeNull();
    const refused = await admitResolve({ req: req(RESOLVE, { "cf-connecting-ip": "203.0.113.1" }), limiter });

    expect(refused?.status).toBe(429);
    expect(refused?.headers.get("retry-after")).toBe("60");
    expect(await admitResolve({ req: req(RESOLVE, { "cf-connecting-ip": "203.0.113.2" }), limiter })).toBeNull();
    expect(limiter.keys).toEqual(["203.0.113.1", "203.0.113.1", "203.0.113.2"]);
  });

  test("a request with no address (the website's service binding) is not counted", async () => {
    const limiter = counting(0);

    expect(await admitResolve({ req: req(RESOLVE), limiter })).toBeNull();
    expect(await admitResolve({ req: req(RESOLVE, { "x-forwarded-for": "203.0.113.1" }), limiter })).toBeNull();
    expect(limiter.keys).toEqual([]);
  });

  test("other routes and methods are not counted", async () => {
    const limiter = counting(0);
    const ip = { "cf-connecting-ip": "203.0.113.1" };

    for (const url of ["https://registry.apmjs.dev/zod", "https://registry.apmjs.dev/-/apm/v1/packages/zod", "https://registry.apmjs.dev/-/apm/v1/names?q=zod", "https://registry.apmjs.dev/zod/-/zod-3.0.0.tgz"]) {
      expect(await admitResolve({ req: req(url, ip), limiter })).toBeNull();
    }

    expect(await admitResolve({ req: req(RESOLVE, ip, "POST"), limiter })).toBeNull();
    expect(limiter.keys).toEqual([]);
    expect((await admitResolve({ req: req(RESOLVE, ip, "HEAD"), limiter }))?.status).toBe(429);
  });

  test("no binding, or a binding that fails, lets the request through", async () => {
    const ip = { "cf-connecting-ip": "203.0.113.1" };
    const failing: RateLimiter = { limit: () => Promise.reject(new Error("rate limiter unavailable")) };

    expect(await admitResolve({ req: req(RESOLVE, ip), limiter: null })).toBeNull();
    expect(await admitResolve({ req: req(RESOLVE, ip), limiter: failing })).toBeNull();
  });
});

// review of 0126b2b, findings 2 and 3: what a credentialed resolve the resolve handler did not count comes to
describe("countsLate", () => {
  const resolve = (headers: Record<string, string>): Request => new Request(RESOLVE, { headers: { "cf-connecting-ip": "203.0.113.1", ...headers } });
  const token = { authorization: "Bearer t" };

  const cases: readonly { caller: ResolveCaller; status: number; counts: boolean }[] = [
    // checked and named someone: never
    { caller: "verified", status: 405, counts: false },
    { caller: "verified", status: 503, counts: false },
    // checked and named nobody: unless apm failed (5xx)
    { caller: "unverified", status: 405, counts: true },
    { caller: "unverified", status: 404, counts: true },
    { caller: "unverified", status: 500, counts: false },
    { caller: "unverified", status: 503, counts: false },
    // never checked (an outage, a defect): whatever the answer
    { caller: "unknown", status: 503, counts: true },
    { caller: "unknown", status: 500, counts: true },
    { caller: "unknown", status: 405, counts: true },
  ];

  for (const c of cases) {
    test(`${c.caller} credentials answered ${c.status}: ${c.counts ? "counted" : "not counted"}`, () => {
      expect(countsLate({ req: resolve(token), request: { caller: c.caller, counted: false }, status: c.status })).toBe(c.counts);
    });
  }

  test("a request counted already, or with no credentials (counted before the router), is not counted again", () => {
    expect(countsLate({ req: resolve(token), request: { caller: "unknown", counted: true }, status: 405 })).toBe(false);
    expect(countsLate({ req: resolve({}), request: { caller: "unknown", counted: false }, status: 405 })).toBe(false);
  });
});

// review of 0126b2b, finding 3: the late 429 was returned before the defect was logged and reported
describe("a defect on a credentialed resolve", () => {
  test("is logged before the answer is chosen, and its credentials, never checked, still count", async () => {
    let over = false;
    const errors: string[] = [];
    const error = console.error;
    const stub = { get: async () => null, put: async () => null, head: async () => null, delete: async () => {}, list: async () => ({ objects: [], truncated: false }) };

    const env: RawEnv = {
      HYPERDRIVE: { connectionString: "postgres://postgres:postgres@127.0.0.1:1/unused" },
      // SAFETY: the Worker checks a binding only for the methods apm calls (worker.ts `binding`), which `stub` has, and
      // the defect below ends every request before any of them is called
      // oxlint-disable-next-line anti-slop/no-chained-type-assertions -- a test stand-in for R2, which only Miniflare can build whole; see SAFETY above
      BLOBS: stub as unknown as R2Bucket,
      APM_AUTH_SECRET: "test-only-secret-that-is-long-enough-for-better-auth",
      APM_UPSTREAM: "off",
      RESOLVE_RATE_LIMIT: { limit: async () => ({ success: !over }) },
    };

    // the services cannot be built: the router never runs, so the credentials are never checked
    const broken = Layer.effect(Clock, Effect.die(new Error("test-service-build-defect")));
    const ask = (): Request => new Request("http://registry.test/-/apm/v1/resolve?name=missing", { headers: { authorization: "junk", "cf-connecting-ip": "192.0.2.90" } });

    console.error = (...args: unknown[]) => errors.push(args.map(String).join(" "));

    try {
      const first = await handle(ask(), env, broken);
      await first.body?.cancel();

      expect(first.status).toBe(500);
      expect(errors.some((e) => e.includes('"event":"defect"'))).toBe(true);
      errors.length = 0;
      over = true;
      const second = await handle(ask(), env, broken);
      await second.body?.cancel();

      expect(second.status).toBe(429);
      expect(errors.some((e) => e.includes('"event":"defect"'))).toBe(true);
    } finally {
      console.error = error;
    }
  });
});
