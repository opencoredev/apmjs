// The fast tarball path's read of the install block list (blocklist.ts, recentFrom and Blocklist.recent): one read per
// isolate per BLOCKLIST_RECENT_MS, shared while in flight, never kept when it failed, dropped by this isolate's own
// writes; and the readers that must see R2 as it is now (Blocklist.read) never use it.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { BLOCKLIST_KEY, BLOCKLIST_RECENT_MS, Blocklist, recentFrom, type BlocklistBody, type BlocklistBucket } from "../src/blocklist.ts";

const list = (names: readonly string[]): BlocklistBody => ({ format: 1, syncedAt: 1, local: names.map((name) => ({ name, addedAt: 1 })), confirmed: [] });

/** An R2 bucket holding only the list, counting reads; `failNext` makes the next read throw. */
function bucket(initial: BlocklistBody) {
  let text = JSON.stringify(initial);
  let etag = 1;
  const state = { reads: 0, failNext: false };

  const api: BlocklistBucket = {
    get: (key) => {
      state.reads++;

      if (state.failNext) {
        state.failNext = false;

        return Promise.reject(new Error("R2 is down"));
      }

      const body = text;

      return Promise.resolve(key === BLOCKLIST_KEY ? { text: () => Promise.resolve(body), etag: String(etag) } : null);
    },
    put: (_key, value) => {
      text = value;
      etag++;

      return Promise.resolve({});
    },
  };

  return { api, state, set: (b: BlocklistBody) => (text = JSON.stringify(b)) };
}

const names = async (read: Promise<{ kind: string; list?: BlocklistBody }>): Promise<string[]> => ((await read).list?.local ?? []).map((e) => e.name);

describe("the block list's recent read", () => {
  test("is read once per isolate within BLOCKLIST_RECENT_MS, shared while in flight, and read again after", async () => {
    const b = bucket(list(["a"]));

    const [one, two] = await Promise.all([names(recentFrom(b.api, 1_000)), names(recentFrom(b.api, 1_000))]);

    expect([one, two]).toEqual([["a"], ["a"]]);
    expect(b.state.reads).toBe(1);

    b.set(list(["a", "b"]));
    // within the window: the read already made
    expect(await names(recentFrom(b.api, 1_000 + BLOCKLIST_RECENT_MS - 1))).toEqual(["a"]);
    // past it: R2 again, and the new entry shows
    expect(await names(recentFrom(b.api, 1_000 + BLOCKLIST_RECENT_MS))).toEqual(["a", "b"]);
    expect(b.state.reads).toBe(2);
    // a clock that went back does not make an old read young
    expect(await names(recentFrom(b.api, 0))).toEqual(["a", "b"]);
    expect(b.state.reads).toBe(3);
  });

  test("a read that failed is not kept: the next request reads R2", async () => {
    const b = bucket(list(["a"]));

    b.state.failNext = true;
    await expect(recentFrom(b.api, 5_000)).rejects.toThrow("R2 is down");
    expect(await names(recentFrom(b.api, 5_000))).toEqual(["a"]);
    expect(b.state.reads).toBe(2);
  });

  test("a block written by this isolate is seen by its next recent read at once, and the plain read never uses the recent one", async () => {
    const b = bucket(list(["a"]));
    let now = 10_000;

    const blocklist = Effect.runSync(
      Effect.gen(function* () {
        return yield* Blocklist;
      }).pipe(Effect.provide(Blocklist.r2(b.api, () => now))),
    );

    expect(await names(Effect.runPromise(blocklist.recent))).toEqual(["a"]);
    await Effect.runPromise(blocklist.block({ local: ["b"] }));
    expect((await names(Effect.runPromise(blocklist.recent))).sort()).toEqual(["a", "b"]);

    b.set(list(["c"]));
    now += 1;
    expect(await names(Effect.runPromise(blocklist.read))).toEqual(["c"]);
  });
});
