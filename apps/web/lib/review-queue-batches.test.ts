// The independent review of 17be3f6, finding 4: "Select all" could send more flags than the bulk route takes (100), and
// the route answered 400 for the lot. Selections go in batches of at most BULK_LIMIT, in order, and stop at a failure.
import { describe, expect, test } from "bun:test";
import { BULK_LIMIT, dismissInBatches } from "./review-queue";

const keys = (n: number) => Array.from({ length: n }, (_, i) => ({ name: `p${i}`, version: "1.0.0", digest: `sha512-${i}` }));

describe("dismissing a large selection", () => {
  test("250 flags go in three requests of at most 100, and every one is sent once", async () => {
    const sent: number[][] = [];

    const r = await dismissInBatches({
      items: keys(250),
      send: async (batch) => {
        sent.push(batch.map((k) => Number(k.name.slice(1))));

        return { kind: "ok", dismissed: batch.length };
      },
    });

    expect(BULK_LIMIT).toBe(100);
    expect(sent.map((b) => b.length)).toEqual([100, 100, 50]);
    expect(sent.flat()).toEqual(Array.from({ length: 250 }, (_, i) => i));
    expect(r).toEqual({ kind: "ok", dismissed: 250 });
  });

  test("a failed batch stops the rest and says how many went through", async () => {
    let calls = 0;

    const r = await dismissInBatches({
      items: keys(230),
      send: async (batch) => {
        calls++;

        return calls === 2 ? { kind: "error", message: "Unlock decisions first." } : { kind: "ok", dismissed: batch.length };
      },
    });

    expect(calls).toBe(2);
    expect(r).toEqual({ kind: "error", message: "Unlock decisions first.", dismissed: 100 });
  });
});
