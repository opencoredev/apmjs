// The isolate's packument cache counts what it holds by bytes kept, not only by entries: a few big packuments held at
// once (next, typescript, @types/node, aws-sdk) are more than an isolate's 128 MB. Its entries are blocks of the
// isolate's memory pool (memory.ts): the cache holds them beside whoever else does, and the pool counts each once.
import { expect, test } from "bun:test";
import { MemoryPool } from "../src/memory.ts";
import { IsolateCache } from "../src/upstream.ts";

/** Keeps `value` under `key` with a block of `weight` that, once kept, only the cache holds. */
function keep(cache: IsolateCache<string>, pool: MemoryPool, key: string, value: string, now: number, weight: number): void {
  const maker = pool.request(Number.POSITIVE_INFINITY);
  expect(maker.take(weight)).toBe(true);
  cache.set(key, value, now, maker.seal(weight));
  maker.release();
}

test("past its byte budget the oldest entries leave, and one heavier than the whole budget is not kept", () => {
  const pool = new MemoryPool(1_000);
  const cache = new IsolateCache<string>(60_000, pool.cache(100));

  keep(cache, pool, "a", "a", 0, 40);
  keep(cache, pool, "b", "b", 0, 40);
  expect([cache.get("a", 1), cache.get("b", 1)]).toEqual(["a", "b"]);

  // 120 > 100: a, the oldest, leaves
  keep(cache, pool, "c", "c", 0, 40);
  expect([cache.get("a", 1), cache.get("b", 1), cache.get("c", 1)]).toEqual([undefined, "b", "c"]);

  keep(cache, pool, "huge", "huge", 0, 101);
  expect(cache.get("huge", 1)).toBeUndefined();
  expect([cache.get("b", 1), cache.get("c", 1)]).toEqual(["b", "c"]);

  // replacing an entry counts its new weight only, and an expired one gives its weight back
  keep(cache, pool, "b", "b2", 0, 10);
  keep(cache, pool, "d", "d", 0, 50);
  expect([cache.get("b", 1), cache.get("c", 1), cache.get("d", 1)]).toEqual(["b2", "c", "d"]);
  expect(cache.get("c", 60_000)).toBeUndefined();
  keep(cache, pool, "e", "e", 60_000, 40);
  expect([cache.get("b", 60_001), cache.get("d", 60_001), cache.get("e", 60_001)]).toEqual([undefined, undefined, "e"]);
  // what is left in the pool is what the cache holds
  expect(pool.charged).toBe(cache.weight);
  expect(pool.charged).toBe(40);
});

test("an entry a request still holds stays charged to the pool after the cache lets it go", () => {
  const pool = new MemoryPool(1_000);
  const cache = new IsolateCache<string>(60_000, pool.cache(100));
  const request = pool.request();
  expect(request.take(80)).toBe(true);
  const block = request.seal(80);

  cache.set("a", "a", 0, block);
  // one block, two holders: counted once
  expect(pool.charged).toBe(80);
  expect([request.taken, cache.weight]).toEqual([80, 80]);

  // a heavier entry pushes it out of the cache, but the request still refers to it
  keep(cache, pool, "b", "b", 0, 60);
  expect(cache.get("a", 1)).toBeUndefined();
  expect(pool.charged).toBe(140);

  request.release();
  expect(pool.charged).toBe(60);
});

test("when the pool needs room it takes back entries only the cache holds, oldest first", () => {
  const pool = new MemoryPool(100);
  const cache = new IsolateCache<string>(60_000, pool.cache(100));
  const request = pool.request();
  expect(request.take(30)).toBe(true);
  const shared = request.seal(30);

  cache.set("shared", "shared", 0, shared);
  keep(cache, pool, "old", "old", 0, 30);
  keep(cache, pool, "new", "new", 0, 30);
  expect(pool.charged).toBe(90);

  // 30 more: "old" goes (only the cache holds it); "shared" stays, evicting it would free nothing
  const reader = pool.request();
  expect(reader.take(30)).toBe(true);
  expect([cache.get("shared", 1), cache.get("old", 1), cache.get("new", 1)]).toEqual(["shared", undefined, "new"]);
  expect(pool.charged).toBe(90);

  // nothing more the cache alone holds than "new": 50 cannot fit, and the take is refused, not over-committed
  expect(reader.take(50)).toBe(false);
  expect(pool.charged).toBeLessThanOrEqual(pool.limit);
  reader.release();
  request.release();
});
