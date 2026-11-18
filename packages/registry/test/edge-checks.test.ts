// The edge views (edge-checks.ts) on a simulated clock: how long a view decides, when the next read starts, what a
// failed, never-synced or stale read decides, the data center's copy, one read per isolate at a time, the read's
// deadline, the downloads queue, and the promises the design makes: a clearance decides an answer only while its view
// is under EDGE_VIEW_MAX_AGE_MS old at the moment of the answer (so an R2 read begun before a publish's put and landing
// after its commit never clears the name), a version confirmed through the list is refused by every view within
// EDGE_VIEW_MAX_AGE_MS of the list's write, and a name a first publish puts on the list is in every view deciding an
// answer once FIRST_PUBLISH_HOLD_MS has passed, which is when that publish opens its transaction.
import { beforeEach, describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { BLOCKLIST_KEY, type BlocklistBody, type BlocklistReader } from "../src/blocklist.ts";
import {
  EDGE_READ_DEADLINE_MS,
  EDGE_REFRESH_AFTER_MS,
  EDGE_VIEW_MAX_AGE_MS,
  EdgeChecks,
  FIRST_PUBLISH_HOLD_MS,
  LIST_STALE_MS,
  PublishFence,
  QUEUED_MAX,
  READ_ABANDON_MS,
  verdictOf,
  WAITING_MAX,
  ASK_WAIT_MS,
  type AskOutcome,
  type Clearance,
  type ColoCache,
  type EdgeOptions,
  type EdgeReport,
  type EdgeVerdict,
} from "../src/edge-checks.ts";

let clock = 0;
let later: Promise<void>[] = [];

beforeEach(() => {
  clock = 1_000_000;
  later = [];
});

/** When the lists below were synced, unless a test says: later than any clock the tests use, so none is stale. */
const SYNCED = 10_000_000;

const list = (input: { local?: readonly string[]; confirmed?: readonly string[]; syncedAt?: number | null }): BlocklistBody => ({
  format: 1,
  syncedAt: input.syncedAt === undefined ? SYNCED : input.syncedAt,
  local: (input.local ?? []).map((name) => ({ name, addedAt: 1 })),
  confirmed: (input.confirmed ?? []).map((name) => ({ name, version: "1.0.0", digest: "sha512-00", addedAt: 1 })),
});

/** A promise and the function that settles it. */
type Gate = { readonly wait: Promise<void>; readonly open: () => void };

function gate(): Gate {
  let open = (): void => undefined;

  const wait = new Promise<void>((resolve) => {
    open = resolve;
  });

  return { wait, open };
}

/**
 * An R2 bucket holding only the list, counting reads; `fail` makes reads throw; `text` replaces the object's body.
 * With `held` set, a read takes the object as it is when the read is made and hands it over once the gate opens, as
 * a slow R2 read does.
 */
/** What a test bucket does: reads so far, whether reads fail, the object's text, and the gate a read waits on. */
type BucketState = { reads: number; fail: boolean; text: string | null; held: Promise<void> | null };

function bucket(initial: BlocklistBody | null) {
  const state: BucketState = { reads: 0, fail: false, text: initial === null ? null : JSON.stringify(initial), held: null };

  const api: BlocklistReader = {
    get: async (key) => {
      state.reads++;

      if (state.fail) throw new Error("R2 is down");
      const body = state.text;

      if (state.held !== null) await state.held;

      return key === BLOCKLIST_KEY && body !== null ? { text: () => Promise.resolve(body), etag: String(state.reads) } : null;
    },
  };

  return { api, state, set: (b: BlocklistBody) => void (state.text = JSON.stringify(b)) };
}

/** A data center cache in memory: one entry per key, kept as sent. */
function colo() {
  const entries = new Map<string, { text: string; headers: Headers }>();

  const cache: ColoCache = {
    match: (key) => {
      const e = entries.get(key);

      return Promise.resolve(e === undefined ? undefined : new Response(e.text, { headers: e.headers }));
    },
    put: async (key, res) => void entries.set(key, { text: await res.text(), headers: new Headers(res.headers) }),
  };

  return { cache, entries };
}

const options = (b: BlocklistReader, extra: Partial<EdgeOptions> = {}): EdgeOptions => ({
  bucket: b,
  cache: null,
  cacheKey: "http://registry.test/-/apm/internal/edge-view",
  now: () => clock,
  background: (work) => void later.push(work),
  report: null,
  ...extra,
});

const settle = async (): Promise<void> => {
  while (later.length > 0) {
    const now = later;

    later = [];
    await Promise.all(now);
  }
};

const edgeOf = (o: EdgeOptions, ask: (input: { name: string; version: string }) => Promise<AskOutcome> = () => Promise.resolve("asked")) =>
  Effect.runSync(
    Effect.gen(function* () {
      return yield* EdgeChecks;
    }).pipe(Effect.provide(EdgeChecks.layer(o, ask))),
  );

const verdict = (o: EdgeOptions, name: string): Promise<EdgeVerdict> => Effect.runPromise(edgeOf(o).verdict(name));

/** A clearance, without its date. */
const CLEAR = { kind: "clear" } satisfies Pick<Clearance, "kind">;

/** What a verdict decides, without the clearance's date. */
const decided = async (o: EdgeOptions, name: string): Promise<typeof CLEAR | Exclude<EdgeVerdict, Clearance>> => {
  const v = await verdict(o, name);

  return v.kind === "clear" ? CLEAR : v;
};

describe("verdictOf", () => {
  test("clears only a name the synced list neither lists as published here nor as having a confirmed version, dated from the read", () => {
    const view = { readAt: 7, seen: { kind: "list" as const, local: new Set(["mine"]), flagged: new Set(["bad"]) } };

    expect(verdictOf(view, "react")).toEqual({ kind: "clear", readAt: 7 });
    expect(verdictOf(view, "mine")).toEqual({ kind: "database", reason: "published-here" });
    expect(verdictOf(view, "bad")).toEqual({ kind: "database", reason: "confirmed" });
    expect(verdictOf({ readAt: 0, seen: { kind: "none", why: "failed" } }, "react")).toEqual({ kind: "database", reason: "no-view" });
  });
});

describe("an isolate's edge view", () => {
  test("decides for EDGE_VIEW_MAX_AGE_MS from when its read began: read again after the response from half that, before the answer past it", async () => {
    const b = bucket(list({}));
    const o = options(b.api);

    expect(await decided(o, "react")).toEqual(CLEAR);
    await settle();
    expect(b.state.reads).toBe(1);
    b.set(list({ confirmed: ["react"] }));

    // young: the same view, no read
    clock += EDGE_REFRESH_AFTER_MS - 1;
    expect(await decided(o, "react")).toEqual(CLEAR);
    expect(later).toHaveLength(0);
    expect(b.state.reads).toBe(1);

    // half its age: still answers, and the next read starts after the response (once, however many ask)
    clock += 1;
    expect(await decided(o, "react")).toEqual(CLEAR);
    await decided(o, "react");
    expect(later).toHaveLength(1);
    await settle();
    expect(b.state.reads).toBe(2);
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "confirmed" });
  });

  test("a view past its age is never used: the request reads first", async () => {
    const b = bucket(list({}));
    const o = options(b.api, { background: null });

    expect(await decided(o, "react")).toEqual(CLEAR);
    b.set(list({ confirmed: ["react"] }));
    clock += EDGE_VIEW_MAX_AGE_MS - 1;
    // no background here: the old view still answers within its age
    expect(await decided(o, "react")).toEqual(CLEAR);
    clock += 1;
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "confirmed" });
    expect(b.state.reads).toBe(2);
  });

  test("a clearance decides only while its view is young at the moment it is used: one that aged during npm's answer is refused", async () => {
    const b = bucket(list({}));
    const o = options(b.api);
    const edge = edgeOf(o);
    const clearance = await Effect.runPromise(edge.verdict("react"));

    if (clearance.kind !== "clear") throw new Error("not cleared");
    expect(clearance.readAt).toBe(clock);
    clock += EDGE_VIEW_MAX_AGE_MS - 1;
    expect(await Effect.runPromise(edge.stillClear(clearance))).toBe(true);
    // the wait for npm ran past the window: the route takes the database path
    clock += 1;
    expect(await Effect.runPromise(edge.stillClear(clearance))).toBe(false);
    // and a clock that went back past the skew allowance does not make it young again
    clock -= 10_000;
    expect(await Effect.runPromise(edge.stillClear(clearance))).toBe(false);
  });

  test("an R2 read begun before a publish's put that lands after the publish commits never clears the name", async () => {
    // the review's scenario: the read takes the list as it was, the publish puts the name and waits its fence, the
    // read lands 6,002 ms after it began
    const begin = async (o: EdgeOptions, b: ReturnType<typeof bucket>) => {
      const slow = gate();

      b.state.held = slow.wait;
      const asked = verdict(o, "taken");

      await Bun.sleep(5);
      expect(b.state.reads).toBe(1);
      // the publish: on the list a millisecond later, its transaction opened after the fence
      clock += 1;
      b.set(list({ local: ["taken"] }));
      clock += 6_001;

      return { asked, slow };
    };

    // past the read's deadline the request takes the database path while the read is still out
    const b = bucket(list({}));
    const o = options(b.api);
    const deadline = await begin(o, b);

    expect(await deadline.asked).toEqual({ kind: "database", reason: "slow-read" });
    deadline.slow.open();
    await settle();
    // what landed is 6 s old: the next request reads again, and finds the name
    b.state.held = null;
    expect(await decided(o, "taken")).toEqual({ kind: "database", reason: "published-here" });

    // with no deadline to cut it short, the old list lands, is too old by then, and decides nothing
    const late = bucket(list({}));
    const patient = options(late.api, { readDeadlineMs: 60_000 });
    const landed = await begin(patient, late);

    landed.slow.open();
    expect(await landed.asked).toEqual({ kind: "database", reason: "expired" });
    late.state.held = null;
    expect(await decided(patient, "taken")).toEqual({ kind: "database", reason: "published-here" });
    expect(late.state.reads).toBe(2);
  });

  test("a read that misses its deadline sends the request to the database path, and lands for the next one", async () => {
    const b = bucket(list({}));
    const o = options(b.api);
    const slow = gate();

    b.state.held = slow.wait;
    const start = performance.now();

    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "slow-read" });
    expect(performance.now() - start).toBeGreaterThanOrEqual(EDGE_READ_DEADLINE_MS - 5);
    expect(performance.now() - start).toBeLessThan(EDGE_READ_DEADLINE_MS + 200);
    // a request after the deadline does not wait on the read still out
    clock += EDGE_READ_DEADLINE_MS;
    const after = performance.now();

    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "slow-read" });
    expect(performance.now() - after).toBeLessThan(50);
    expect(b.state.reads).toBe(1);
    slow.open();
    await settle();
    b.state.held = null;
    expect(await decided(o, "react")).toEqual(CLEAR);
    expect(b.state.reads).toBe(1);
  });

  test("a stalled read stays the isolate's one read until it settles: requests past its deadline take the database path at once and start no second read", async () => {
    const b = bucket(list({}));
    const o = options(b.api);
    const stalled = gate();

    b.state.held = stalled.wait;
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "slow-read" });
    expect(b.state.reads).toBe(1);

    // past the view's age, and long past the read's deadline: still the one read, and no request waits on it
    for (const step of [EDGE_VIEW_MAX_AGE_MS, EDGE_VIEW_MAX_AGE_MS, 10_000]) {
      clock += step;
      const start = performance.now();

      expect(await decided(o, "react")).toEqual({ kind: "database", reason: "slow-read" });
      expect(performance.now() - start).toBeLessThan(50);
      expect(b.state.reads).toBe(1);
    }

    // a read out for READ_ABANDON_MS was lost with its request: one more read starts
    clock += READ_ABANDON_MS;
    b.state.held = null;
    expect(await decided(o, "react")).toEqual(CLEAR);
    expect(b.state.reads).toBe(2);

    // the lost read landing late changes nothing: the view read after it is kept
    b.set(list({ confirmed: ["react"] }));
    stalled.open();
    await settle();
    expect(await decided(o, "react")).toEqual(CLEAR);
  });

  test("a read that settles frees the isolate for the next one, however late it settled", async () => {
    const b = bucket(list({}));
    const o = options(b.api);
    const slow = gate();

    b.state.held = slow.wait;
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "slow-read" });
    clock += 2 * EDGE_VIEW_MAX_AGE_MS;
    slow.open();
    await settle();
    // what it read is too old to decide by now: the next request reads again
    b.state.held = null;
    expect(await decided(o, "react")).toEqual(CLEAR);
    expect(b.state.reads).toBe(2);
  });

  test("concurrent requests with no view share one read, and a miss during a refresh waits for it instead of reading again", async () => {
    const b = bucket(list({}));
    const o = options(b.api);
    const slow = gate();

    b.state.held = slow.wait;
    const asked = Array.from({ length: 20 }, () => decided(o, "react"));

    await Bun.sleep(20);
    slow.open();
    expect(await Promise.all(asked)).toEqual(Array.from({ length: 20 }, () => CLEAR));
    expect(b.state.reads).toBe(1);
    await settle();

    // half its age: a refresh starts after the response; a request that finds the view too old while it runs waits on it
    const refresh = gate();

    b.state.held = refresh.wait;
    b.set(list({ confirmed: ["react"] }));
    clock += EDGE_REFRESH_AFTER_MS;
    expect(await decided(o, "react")).toEqual(CLEAR);
    await Bun.sleep(5);
    expect(b.state.reads).toBe(2);
    // a request just after it began waits for it rather than reading again
    clock += 10;
    b.state.held = null;
    const waiting = decided(o, "react");

    await Bun.sleep(20);
    expect(b.state.reads).toBe(2);
    // (the view is still young here, so it answers at once; the refresh is what a miss would have waited on)
    expect(await waiting).toEqual(CLEAR);
    // the view ages out while the refresh, out 2 s and past its deadline, has not landed: no wait and no second read
    clock += EDGE_VIEW_MAX_AGE_MS - EDGE_REFRESH_AFTER_MS - 10;
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "slow-read" });
    expect(b.state.reads).toBe(2);
    refresh.open();
    await settle();
    // what the refresh read began 2 s ago: young, so it decides (and, at half its age, starts the next refresh)
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "confirmed" });
    await settle();
    expect(b.state.reads).toBe(3);
  });

  test("a request that finds the view too old just after another request's read began waits for that read", async () => {
    const b = bucket(list({}));
    const o = options(b.api);

    expect(await decided(o, "react")).toEqual(CLEAR);
    await settle();
    b.set(list({ confirmed: ["react"] }));
    clock += EDGE_VIEW_MAX_AGE_MS;
    const slow = gate();

    b.state.held = slow.wait;
    const first = decided(o, "react");

    await Bun.sleep(5);
    clock += 50;
    const second = decided(o, "react");

    await Bun.sleep(30);
    slow.open();
    expect(await Promise.all([first, second])).toEqual([
      { kind: "database", reason: "confirmed" },
      { kind: "database", reason: "confirmed" },
    ]);
    expect(b.state.reads).toBe(2);
  });

  test("a clock that went back past the skew allowance does not make a view young", async () => {
    const b = bucket(list({}));
    const o = options(b.api);

    await verdict(o, "react");
    await settle();
    clock -= 1_000;
    await verdict(o, "react");
    expect(b.state.reads).toBe(2);
  });

  test("a list that is missing, unreadable, never synced, not synced for LIST_STALE_MS or unreachable decides nothing, and that is kept for the view's age too", async () => {
    const unreadable = bucket(list({}));

    unreadable.state.text = "{not json";

    for (const b of [bucket(null), bucket(list({ syncedAt: null })), bucket(list({ syncedAt: clock - LIST_STALE_MS - 1 })), unreadable]) {
      const o = options(b.api);

      expect(await decided(o, "react")).toEqual({ kind: "database", reason: "no-view" });
      // kept: an outage costs one read a window, not one a request
      expect(await decided(o, "react")).toEqual({ kind: "database", reason: "no-view" });
      expect(b.state.reads).toBe(1);
    }

    // a sync just inside the bound still decides
    expect(await decided(options(bucket(list({ syncedAt: clock - LIST_STALE_MS + 1_000 })).api), "react")).toEqual(CLEAR);

    const b = bucket(list({}));
    const o = options(b.api);

    b.state.fail = true;
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "no-view" });
    b.state.fail = false;
    expect(await decided(o, "react")).toEqual({ kind: "database", reason: "no-view" });
    clock += EDGE_VIEW_MAX_AGE_MS;
    b.set(list({}));
    expect(await decided(o, "react")).toEqual(CLEAR);
  });

  test("the data center's copy serves another isolate while under half the age, dated from the first read; older or future copies are not used", async () => {
    const b = bucket(list({}));
    const { cache, entries } = colo();
    const first = options(b.api, { cache });

    await verdict(first, "react");
    await settle();
    expect(entries.size).toBe(1);

    // another isolate (another bucket object, same cache): uses the copy without reading R2
    const other = bucket(list({ confirmed: ["react"] }));
    const second = options(other.api, { cache });

    clock += EDGE_REFRESH_AFTER_MS - 1;
    const copied = await verdict(second, "react");

    expect(copied).toEqual({ kind: "clear", readAt: clock - EDGE_REFRESH_AFTER_MS + 1 });
    expect(other.state.reads).toBe(0);
    // and its view is as old as the copy: past the age limit from the first read, it reads again
    clock += EDGE_VIEW_MAX_AGE_MS - EDGE_REFRESH_AFTER_MS + 1;
    expect(await decided(options(other.api, { cache, background: null }), "react")).toEqual({ kind: "database", reason: "confirmed" });
    expect(other.state.reads).toBe(1);

    // a copy dated in the future is not used
    const third = bucket(list({ confirmed: ["react"] }));
    const future = entries.get(first.cacheKey);

    if (future === undefined) throw new Error("no copy");
    future.headers.set("x-apm-edge-read-at", String(clock + 60_000));
    expect(await decided(options(third.api, { cache }), "react")).toEqual({ kind: "database", reason: "confirmed" });
    expect(third.state.reads).toBe(1);
  });

  test("a confirmation put on the list at t is refused by every view, however it was read, from t + EDGE_VIEW_MAX_AGE_MS", async () => {
    // views read at every point of the window before the write, on their own isolates, used at every later point
    for (let readBefore = 0; readBefore <= EDGE_VIEW_MAX_AGE_MS; readBefore += 250) {
      const b = bucket(list({}));
      const o = options(b.api, { background: null });
      const t = 2_000_000;

      clock = t - readBefore;
      await verdict(o, "evil");
      b.set(list({ confirmed: ["evil"] }));

      for (clock = t + EDGE_VIEW_MAX_AGE_MS; clock < t + 2 * EDGE_VIEW_MAX_AGE_MS; clock += 100) {
        expect(await decided(o, "evil")).toEqual({ kind: "database", reason: "confirmed" });
      }
    }
  });

  test("a first publish's name is in every view deciding an answer once its hold has passed, a clearance from before included", async () => {
    expect(FIRST_PUBLISH_HOLD_MS).toBeGreaterThanOrEqual(EDGE_VIEW_MAX_AGE_MS + 3_000);

    for (let readBefore = 0; readBefore <= EDGE_VIEW_MAX_AGE_MS; readBefore += 250) {
      const b = bucket(list({}));
      const { cache } = colo();
      const isolate = options(b.api, { cache });
      const put = 3_000_000;

      // an isolate's view, and the data center's copy, from before the publish put the name on the list, and a
      // clearance from it still held by a request waiting on npm
      clock = put - readBefore;
      const edge = edgeOf(isolate);
      const held = await Effect.runPromise(edge.verdict("taken"));

      if (held.kind !== "clear") throw new Error("not cleared");
      await settle();
      b.set(list({ local: ["taken"] }));

      // the transaction, and every request after it, in this isolate and in a new one that finds the copy
      for (clock = put + FIRST_PUBLISH_HOLD_MS; clock < put + FIRST_PUBLISH_HOLD_MS + 3 * EDGE_VIEW_MAX_AGE_MS; clock += 100) {
        expect(await Effect.runPromise(edge.stillClear(held))).toBe(false);
        expect(await decided(isolate, "taken")).toEqual({ kind: "database", reason: "published-here" });
        expect(await decided(options(bucket(list({ local: ["taken"] })).api, { cache }), "taken")).toEqual({ kind: "database", reason: "published-here" });
        await settle();
      }
    }
  });

  test("an isolate reports what its views decided once a minute: R2 reads, copies, and each reason a request fell back", async () => {
    const reports: EdgeReport[] = [];
    const b = bucket(list({ local: ["mine"] }));
    const o = options(b.api, { report: (r) => void reports.push(r) });
    const edge = edgeOf(o);

    /** One request: its verdict, and for a clearance the route's check just before it answers. */
    const answer = async (name: string): Promise<void> => {
      const v = await Effect.runPromise(edge.verdict(name));

      if (v.kind === "clear") await Effect.runPromise(edge.stillClear(v));
    };

    await answer("react");
    await answer("mine");
    clock += EDGE_VIEW_MAX_AGE_MS;
    await settle();
    expect(reports).toEqual([]);
    clock += 60_000;
    await answer("react");
    expect(reports).toHaveLength(1);
    expect(reports[0]).toMatchObject({ clear: 2, "published-here": 1, r2Reads: 2, coloHits: 0, "slow-read": 0, expired: 0 });
  });

  test("each request is counted once, as it was answered: a clearance that expires before the answer counts only as expired, one npm's document does not let the route use as unservable", async () => {
    const reports: EdgeReport[] = [];
    const o = options(bucket(list({})).api, { report: (r) => void reports.push(r) });
    const edge = edgeOf(o);

    const cleared = async (): Promise<Clearance> => {
      const v = await Effect.runPromise(edge.verdict("react"));

      if (v.kind !== "clear") throw new Error(`expected a clearance, got ${v.reason}`);

      return v;
    };

    // a verdict alone counts nothing: the route has not answered yet
    const used = await cleared();
    const aging = await cleared();

    // a third request is cleared too, but npm's document does not link the tarball the route would redirect to
    await cleared();
    expect(await Effect.runPromise(edge.stillClear(used))).toBe(true);
    await Effect.runPromise(edge.declined);
    clock += EDGE_VIEW_MAX_AGE_MS;
    expect(await Effect.runPromise(edge.stillClear(aging))).toBe(false);
    await settle();
    clock += 60_000;
    // the line goes out on the next decision: a fallback for a missing view (the clock moved past every view)
    expect(await decided(o, "react")).toEqual(CLEAR);
    expect(reports).toHaveLength(0);
    const last = await cleared();

    expect(await Effect.runPromise(edge.stillClear(last))).toBe(true);
    expect(reports).toHaveLength(1);
    expect(reports[0]).toMatchObject({ clear: 2, expired: 1, unservable: 1, "slow-read": 0, "no-view": 0 });
  });
});

describe("the publish fence", () => {
  test("waits the time it is given; a Worker gives FIRST_PUBLISH_HOLD_MS, twice the view's age", async () => {
    expect(FIRST_PUBLISH_HOLD_MS).toBe(2 * EDGE_VIEW_MAX_AGE_MS);

    const fence = Effect.runSync(
      Effect.gen(function* () {
        return yield* PublishFence;
      }).pipe(Effect.provide(PublishFence.layer(300))),
    );

    const start = performance.now();

    await Effect.runPromise(fence.hold);
    expect(performance.now() - start).toBeGreaterThanOrEqual(290);
  });
});

describe("downloads answered from a view", () => {
  test("are asked about once a minute per isolate, after the answer", async () => {
    const asked: string[] = [];

    const edge = edgeOf(options(bucket(list({})).api), (input) => {
      asked.push(`${input.name}@${input.version}`);

      return Promise.resolve("asked");
    });

    await Effect.runPromise(edge.downloaded({ name: "dl", version: "1.0.0" }));
    await Effect.runPromise(edge.downloaded({ name: "dl", version: "1.0.0" }));
    await Effect.runPromise(edge.downloaded({ name: "dl", version: "1.0.1" }));
    await settle();
    clock += 60_000;
    await Effect.runPromise(edge.downloaded({ name: "dl", version: "1.0.0" }));
    await settle();
    expect(asked).toEqual(["dl@1.0.0", "dl@1.0.1", "dl@1.0.0"]);
  });

  test("a failed ask is tried again after a few seconds, not a minute", async () => {
    let tries = 0;

    const edge = edgeOf(options(bucket(list({})).api), () => {
      tries++;

      return tries === 1 ? Promise.resolve("failed") : Promise.reject(new Error("queue down"));
    });

    const ask = async () => {
      await Effect.runPromise(edge.downloaded({ name: "dl", version: "1.0.0" }));
      await settle();
    };

    await ask();
    await ask();
    expect(tries).toBe(1);
    clock += 5_000;
    await ask();
    expect(tries).toBe(2);
    // a rejection counts as a failure too
    clock += 5_000;
    await ask();
    expect(tries).toBe(3);
  });

  test("at most QUEUED_MAX asks run at once per isolate; more wait their turn in their own request's background, and past WAITING_MAX one is skipped and asked about on a later download", async () => {
    let release = gate();
    const asked: string[] = [];
    let running = 0;
    let most = 0;

    const edge = edgeOf(options(bucket(list({})).api), async (input) => {
      asked.push(input.version);
      running++;
      most = Math.max(most, running);
      await release.wait;
      running--;

      return "asked";
    });

    const total = QUEUED_MAX + WAITING_MAX + 3;

    for (let i = 0; i < total; i++) await Effect.runPromise(edge.downloaded({ name: "dl", version: `1.0.${i}` }));
    // every accepted download is held by the background of the request that accepted it, and no other
    expect(later).toHaveLength(QUEUED_MAX + WAITING_MAX);
    await Bun.sleep(50);
    expect(asked).toHaveLength(QUEUED_MAX);
    release.open();
    await settle();
    // every waiting one was asked about, first come first, never more than QUEUED_MAX at once; the last three skipped
    expect(asked).toEqual(Array.from({ length: QUEUED_MAX + WAITING_MAX }, (_, i) => `1.0.${i}`));
    expect(most).toBe(QUEUED_MAX);
    release = gate();
    release.open();
    // the skipped ones were not remembered: the next download of one is asked about; an asked one is not
    await Effect.runPromise(edge.downloaded({ name: "dl", version: `1.0.${total - 1}` }));
    await Effect.runPromise(edge.downloaded({ name: "dl", version: "1.0.0" }));
    await settle();
    expect(asked).toHaveLength(QUEUED_MAX + WAITING_MAX + 1);
  });

  test("a download that waits ASK_WAIT_MS without its turn is dropped, counted and forgotten: its request's background ends, and a later download asks again", async () => {
    const reports: EdgeReport[] = [];
    const release = gate();
    const asked: string[] = [];
    const o = options(bucket(list({})).api, { askWaitMs: 200, report: (r) => void reports.push(r) });

    const edge = edgeOf(o, async (input) => {
      asked.push(input.version);
      await release.wait;

      return "asked";
    });

    for (let i = 0; i < QUEUED_MAX + 2; i++) await Effect.runPromise(edge.downloaded({ name: "dl", version: `2.0.${i}` }));
    const waiting = later.slice(QUEUED_MAX);
    const start = performance.now();

    // the two that found every ask busy give up on their own: nothing they wait on belongs to another request
    await Promise.all(waiting);
    expect(performance.now() - start).toBeLessThan(600);
    expect(asked).toHaveLength(QUEUED_MAX);
    release.open();
    await settle();
    expect(asked).toHaveLength(QUEUED_MAX);
    // forgotten: the next download of one asks
    await Effect.runPromise(edge.downloaded({ name: "dl", version: `2.0.${QUEUED_MAX}` }));
    await settle();
    expect(asked).toEqual([...Array.from({ length: QUEUED_MAX }, (_, i) => `2.0.${i}`), `2.0.${QUEUED_MAX}`]);
    clock += 60_000;
    // the line goes out with the next decision counted
    await Effect.runPromise(edge.declined);
    expect(reports.at(-1)).toMatchObject({ queueLate: 2, queueSkipped: 0 });
  });

  test("the waiting line is no longer than what QUEUED_MAX asks get through in ASK_WAIT_MS at a third of a second each", () => {
    expect(WAITING_MAX).toBeLessThanOrEqual((QUEUED_MAX * ASK_WAIT_MS) / 333);
    // and the wait leaves an ask of two statements at their 8 s limit inside the 30 s after a response
    expect(ASK_WAIT_MS + 2 * 9_000).toBeLessThan(30_000);
  });
});
