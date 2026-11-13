// The isolate's packument cache counts what it holds by bytes kept, not only by entries: a few big packuments held at
// once (next, typescript, @types/node, aws-sdk) are more than an isolate's 128 MB.
import { expect, test } from "bun:test";
import { IsolateCache } from "../src/upstream.ts";

test("past its byte budget the oldest entries leave, and one heavier than the whole budget is not kept", () => {
  const cache = new IsolateCache<string>(60_000, 100);

  cache.set("a", "a", 0, 40);
  cache.set("b", "b", 0, 40);
  expect([cache.get("a", 1), cache.get("b", 1)]).toEqual(["a", "b"]);

  // 120 > 100: a, the oldest, leaves
  cache.set("c", "c", 0, 40);
  expect([cache.get("a", 1), cache.get("b", 1), cache.get("c", 1)]).toEqual([undefined, "b", "c"]);

  cache.set("huge", "huge", 0, 101);
  expect(cache.get("huge", 1)).toBeUndefined();
  expect([cache.get("b", 1), cache.get("c", 1)]).toEqual(["b", "c"]);

  // replacing an entry counts its new weight only, and an expired one gives its weight back
  cache.set("b", "b2", 0, 10);
  cache.set("d", "d", 0, 50);
  expect([cache.get("b", 1), cache.get("c", 1), cache.get("d", 1)]).toEqual(["b2", "c", "d"]);
  expect(cache.get("c", 60_000)).toBeUndefined();
  cache.set("e", "e", 60_000, 40);
  expect([cache.get("b", 60_001), cache.get("d", 60_001), cache.get("e", 60_001)]).toEqual([undefined, undefined, "e"]);
});
