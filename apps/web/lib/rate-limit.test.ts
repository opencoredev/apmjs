import { describe, expect, test } from "bun:test";
import { createSharedCache, createTokenBucket } from "./rate-limit";
import { clientIp, edgeClientIp } from "./client-ip";

describe("createTokenBucket", () => {
  test("allows the burst, then refuses until tokens refill", () => {
    const bucket = createTokenBucket({ capacity: 3, refillPerSecond: 1, maxKeys: 10 });

    expect([bucket.take("a", 0), bucket.take("a", 0), bucket.take("a", 0)].every((t) => t.ok)).toBe(true);
    expect(bucket.take("a", 0)).toEqual({ ok: false, retryAfterSeconds: 1 });
    expect(bucket.take("a", 1_000).ok).toBe(true);
  });

  test("keys are independent", () => {
    const bucket = createTokenBucket({ capacity: 1, refillPerSecond: 1, maxKeys: 10 });

    expect(bucket.take("a", 0).ok).toBe(true);
    expect(bucket.take("a", 0).ok).toBe(false);
    expect(bucket.take("b", 0).ok).toBe(true);
  });

  test("keeps at most maxKeys buckets", () => {
    const bucket = createTokenBucket({ capacity: 1, refillPerSecond: 0.001, maxKeys: 2 });

    bucket.take("a", 0);
    bucket.take("b", 0);
    bucket.take("c", 0);
    // "a" was dropped to make room, so it starts full again.
    expect(bucket.take("a", 0).ok).toBe(true);
  });
});

describe("createSharedCache", () => {
  test("reuses an answer within the TTL and coalesces concurrent loads", async () => {
    const cache = createSharedCache<number>({ ttlMs: 1_000, maxEntries: 10 });
    let loads = 0;

    const load = async (): Promise<number> => {
      loads++;
      await Bun.sleep(10);

      return 42;
    };

    const both = await Promise.all([cache.get("q", load, 0), cache.get("q", load, 0)]);

    expect(both).toEqual([42, 42]);
    expect(await cache.get("q", load, 500)).toBe(42);
    expect(loads).toBe(1);
    expect(await cache.get("q", load, 2_000)).toBe(42);
    expect(loads).toBe(2);
  });

  test("does not keep failures", async () => {
    const cache = createSharedCache<number>({ ttlMs: 1_000, maxEntries: 10 });
    let loads = 0;

    await cache.get("q", async () => (loads++, null), 0);
    await cache.get("q", async () => (loads++, null), 0);
    expect(loads).toBe(2);
  });
});

describe("client address", () => {
  test("route handlers read the first X-Forwarded-For address", () => {
    expect(clientIp(new Headers({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" }))).toBe("203.0.113.7");
    expect(clientIp(new Headers())).toBe("unknown");
  });

  test("the edge header is read only when configured", () => {
    const h = new Headers({ "cf-connecting-ip": "198.51.100.4", "x-forwarded-for": "9.9.9.9" });

    expect(edgeClientIp(h, {})).toBeNull();
    expect(edgeClientIp(h, { APM_CLIENT_IP_HEADER: "CF-Connecting-IP" })).toBe("198.51.100.4");
  });
});
