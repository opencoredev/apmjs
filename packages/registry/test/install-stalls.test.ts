// Install stalls (fix/install-stalls): every wait an install read makes on a call that takes no AbortSignal has a local
// deadline and a fallback (deadline.ts). Production saw npm installs hang for 120 s and 315 s, and a review found the
// install document waiting on the data center's copy (Cache API match) with no deadline: a match that never settled held
// the request until the client gave up. Each test injects a call that never settles, or a body that never sends, and
// checks the request still answers within its bound:
// - the install document's copy lookup, the copy's body, and its background put;
// - the packument copy's lookup (the full packument route and every other npm read);
// - R2's get, a whole object's bytes, a streamed body and a cache put of an upstream tarball;
// - npm's packument body;
// and the slow-response line the Worker writes for Workers Logs names the route, never the path.
// npm is a local stand-in on 127.0.0.1; no real host is contacted.
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Fiber, Layer, Option } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { upstreamRoute } from "../src/apm.ts";
import { Blobs, type BlobBucket } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { BLOCKLIST_KEY, readFrom } from "../src/blocklist.ts";
import { BodyStalled, DeadlinePassed, firstChunkWithin, idleGuarded, matchWithin, readAllWithin, within } from "../src/deadline.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { PendingPuts } from "../src/pending-puts.ts";
import { Timing } from "../src/timing.ts";
import { Upstream, type UpstreamApi } from "../src/upstream.ts";
import { slowWatch, type SlowResponseLine } from "../src/worker.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-12T00:00:00Z");
const INSTALL_ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

/** A promise that never settles: a platform call that hangs. */
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

/** A body that sends nothing and never ends; `cancelled` says whether its reader let it go. */
function silentBody() {
  const state = { cancelled: false };

  const body = new ReadableStream<Uint8Array>({
    cancel() {
      state.cancelled = true;
    },
  });

  return { body, state };
}

/** What settles a deferred promise, set once the promise is made. */
type Settler<T> = { settle: (value: T) => void };

/** A promise and what settles it, for a call that answers when the test says. */
function deferred<T>() {
  const control: Settler<T> = { settle: () => undefined };

  const promise = new Promise<T>((resolve) => {
    control.settle = resolve;
  });

  return { promise, settle: (value: T) => control.settle(value) };
}

/** The error `work` failed with, or null when it did not fail. */
async function failureOf<T>(work: Promise<T>): Promise<Error | null> {
  try {
    await work;

    return null;
  } catch (e) {
    return e instanceof Error ? e : null;
  }
}

/** A test's hold on a stream source: what sends a chunk, and whether the source was cancelled. */
type SourceControl = { push: (chunk: Uint8Array) => void; cancelled: boolean };

/** Milliseconds `work` took. */
async function timedRun<T>(work: () => Promise<T>): Promise<{ value: T; ms: number }> {
  const start = performance.now();
  const value = await work();

  return { value, ms: performance.now() - start };
}

describe("deadline.ts", () => {
  test("within: a promise that never settles is late at its bound, and a late value goes to onLate", async () => {
    const { value, ms } = await timedRun(() => within(never<number>(), 50));

    expect(value.kind).toBe("late");
    expect(ms).toBeLessThan(1_000);
    const lateValues: number[] = [];
    const slow = deferred<number>();

    expect((await within(slow.promise, 20, (v) => lateValues.push(v))).kind).toBe("late");
    slow.settle(7);
    await slow.promise;
    await Promise.resolve();
    expect(lateValues).toEqual([7]);
  });

  test("matchWithin: a match that never settles is late, a late hit's body is cancelled, a throwing match is a miss", async () => {
    const hung = await timedRun(() => matchWithin({ cache: { match: () => never() }, key: "k", ms: 50, operation: "test" }));

    expect(hung.value.kind).toBe("late");
    expect(hung.ms).toBeLessThan(1_000);
    const { body, state } = silentBody();
    const late = deferred<Response>();

    expect((await matchWithin({ cache: { match: () => late.promise }, key: "k", ms: 20, operation: "test" })).kind).toBe("late");
    late.settle(new Response(body));
    await late.promise;
    await Bun.sleep(10);
    expect(state.cancelled).toBe(true);
    expect((await matchWithin({ cache: { match: () => Promise.reject(new Error("no")) }, key: "k", ms: 50, operation: "test" })).kind).toBe("miss");
  });

  test("idleGuarded: a source that stops sending ends the body in BodyStalled and is cancelled; a slow reader does not", async () => {
    const control: SourceControl = { push: () => undefined, cancelled: false };

    const source = new ReadableStream<Uint8Array>({
      start(c) {
        control.push = (chunk) => c.enqueue(chunk);
      },
      cancel() {
        control.cancelled = true;
      },
    });

    const guarded = idleGuarded({ source, idleMs: 60, operation: "test" });
    const reader = guarded.getReader();

    control.push(new Uint8Array([1]));
    // the reader waits longer than the bound before it asks again: only the source is timed
    await Bun.sleep(150);
    control.push(new Uint8Array([2]));
    expect((await reader.read()).value).toEqual(new Uint8Array([1]));
    expect((await reader.read()).value).toEqual(new Uint8Array([2]));
    const stalled = await timedRun(() => failureOf(reader.read()));

    expect(stalled.value).toBeInstanceOf(BodyStalled);
    expect(stalled.ms).toBeLessThan(1_000);
    await Bun.sleep(10);
    expect(control.cancelled).toBe(true);
  });

  test("firstChunkWithin: a body with no first bytes in time is no body, and is cancelled", async () => {
    const { body, state } = silentBody();
    const got = await timedRun(() => firstChunkWithin({ source: body, firstMs: 50, idleMs: 50, operation: "test" }));

    expect(got.value).toBeNull();
    expect(got.ms).toBeLessThan(1_000);
    await Bun.sleep(10);
    expect(state.cancelled).toBe(true);
    const ok = await firstChunkWithin({ source: new Blob(["hello"]).stream(), firstMs: 50, idleMs: 50, operation: "test" });

    expect(await new Response(ok).text()).toBe("hello");
  });

  test("readAllWithin: a body still coming at the deadline is cancelled, and the read fails with DeadlinePassed", async () => {
    const { body, state } = silentBody();
    const got = await timedRun(() => failureOf(readAllWithin({ source: body, ms: 50, operation: "test" })));

    expect(got.value).toBeInstanceOf(DeadlinePassed);
    expect(got.ms).toBeLessThan(1_000);
    await Bun.sleep(10);
    // on 11cbf13 a whole read raced arrayBuffer()/text() with a timer: the source was left reading
    expect(state.cancelled).toBe(true);
    expect(new TextDecoder().decode(await readAllWithin({ source: new Blob(["hello"]).stream(), ms: 1_000, operation: "test" }))).toBe("hello");
  });

  test("readAllWithin: a caller that is interrupted (its signal aborts) cancels the source at once", async () => {
    const { body, state } = silentBody();
    const stop = new AbortController();
    const reading = failureOf(readAllWithin({ source: body, ms: 60_000, operation: "test", signal: stop.signal }));

    await Bun.sleep(20);
    stop.abort(new Error("the request ended"));
    const got = await timedRun(() => reading);

    expect(got.value?.message).toBe("the request ended");
    expect(got.ms).toBeLessThan(1_000);
    await Bun.sleep(10);
    expect(state.cancelled).toBe(true);
  });

  test("readFrom (the block list): a body that never ends is cancelled at the read's bound, and when the caller stops", async () => {
    const late = silentBody();
    const lateBucket = { get: async (key: string) => (key === BLOCKLIST_KEY ? { body: late.body, etag: "e" } : null) };
    const read = await timedRun(() => failureOf(readFrom(lateBucket, { ms: 50, operation: "test" })));

    expect(read.value).toBeInstanceOf(DeadlinePassed);
    expect(read.ms).toBeLessThan(1_000);
    await Bun.sleep(10);
    expect(late.state.cancelled).toBe(true);
    const stopped = silentBody();
    const stop = new AbortController();
    const reading = failureOf(readFrom({ get: async () => ({ body: stopped.body, etag: "e" }) }, { ms: 60_000, operation: "test", signal: stop.signal }));

    await Bun.sleep(20);
    stop.abort(new Error("interrupted"));
    expect((await reading)?.message).toBe("interrupted");
    await Bun.sleep(10);
    expect(stopped.state.cancelled).toBe(true);
  });
});

describe("the slow-response line (worker.ts)", () => {
  test("a request with no answer past the threshold writes one 'waiting' line, and one 'answered' line when it comes", async () => {
    const lines: SlowResponseLine[] = [];
    const timing = Timing.make();
    const req = new Request("http://registry.test/@secret-scope%2fprivate-name", { headers: { accept: INSTALL_ACCEPT } });
    const watch = slowWatch({ req, timing, start: performance.now(), thresholdMs: 30, write: (l) => lines.push(l) });

    timing.add("install-copy", 12.4);
    await Bun.sleep(80);
    watch.stop();
    watch.answered(200);
    expect(lines.map((l) => l.stage)).toEqual(["waiting", "answered"]);
    expect(lines[0]?.route).toBe("GET packument");
    expect(lines[0]?.install).toBe(true);
    expect(lines[1]?.status).toBe(200);
    expect(lines[1]?.phases["install-copy"]).toBe(12);
    // the route's label and the phases only: nothing the request named
    expect(JSON.stringify(lines)).not.toContain("secret");
  });

  test("a fast request writes nothing", async () => {
    const lines: SlowResponseLine[] = [];
    const watch = slowWatch({ req: new Request("http://registry.test/react"), timing: Timing.make(), start: performance.now(), thresholdMs: 200, write: (l) => lines.push(l) });

    watch.stop();
    watch.answered(200);
    await Bun.sleep(250);
    expect(lines).toEqual([]);
  });
});

// ---------- npm, standing in ----------

const TARBALL = new Uint8Array(createHash("sha512").update("tarball bytes").digest());

/** A package's tarball: one of its own for a `distinct-` name, else the shared TARBALL (one digest for every package). */
function tarballOf(name: string): Uint8Array {
  return name.startsWith("distinct-") ? new Uint8Array(createHash("sha512").update(name).digest()) : TARBALL;
}

function fakeNpm() {
  // the first read of a `slow-` package is held SLOW_LEAD_MS before npm answers, or until a test's gate opens
  // (holdLead); later reads answer at once, or when a test's gate for the package opens (holdLater)
  const held = new Set<string>();
  const leadGates = new Map<string, Promise<void>>();
  const gates = new Map<string, Promise<void>>();
  // packument reads per package name
  const reads = new Map<string, number>();

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const path = new URL(req.url).pathname;
      const origin = new URL(req.url).origin;
      const tarball = /^\/-\/t\/([a-z0-9-]+)-1\.0\.0\.tgz$/.exec(path);

      if (tarball?.[1] !== undefined) return new Response(tarballOf(tarball[1]), { headers: { "content-type": "application/octet-stream" } });

      if (path === "/stalled-body") return new Response(silentBody().body, { headers: { "content-type": "application/json" } });
      const name = path.slice(1);

      if (!/^[a-z0-9-]+$/.test(name)) return Response.json({ error: "Not found" }, { status: 404 });
      reads.set(name, (reads.get(name) ?? 0) + 1);

      if (name.startsWith("slow-") && !held.has(name)) {
        held.add(name);
        await (leadGates.get(name) ?? Bun.sleep(SLOW_LEAD_MS));
      } else {
        await gates.get(name);
      }

      const bytes = tarballOf(name);
      const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;

      const packument = {
        _id: name,
        name,
        "dist-tags": { latest: "1.0.0" },
        versions: { "1.0.0": { name, version: "1.0.0", dist: { tarball: `${origin}/-/t/${name}-1.0.0.tgz`, integrity, shasum: "1".repeat(40) } } },
        time: { "1.0.0": "2026-10-01T00:00:00Z" },
      };

      return Response.json(packument, { headers: { etag: `"${name}-1"` } });
    },
  });

  /** A gate in `on` for `name`, and the function that opens it. */
  const gate = (on: Map<string, Promise<void>>, name: string): (() => void) => {
    let open = (): void => undefined;

    on.set(
      name,
      new Promise<void>((resolve) => {
        open = resolve;
      }),
    );

    return () => open();
  };

  return {
    url: server.url.href,
    reads,
    /** Holds the first read of `name` (a `slow-` package) until the returned function opens it, not SLOW_LEAD_MS. */
    holdLead: (name: string) => gate(leadGates, name),
    /** Holds every later read of `name` until the returned function opens it. */
    holdLater: (name: string) => gate(gates, name),
    stop: () => server.stop(true),
  };
}

const SLOW_LEAD_MS = 6_000;

let db: Awaited<ReturnType<typeof freshDatabase>>;
let npm: ReturnType<typeof fakeNpm>;

beforeAll(async () => {
  db = await freshDatabase();
  npm = fakeNpm();
});

afterAll(async () => {
  npm.stop();
  await db.drop();
});

afterEach(() => {
  Reflect.deleteProperty(globalThis, "caches");
});

type Kept = { headers: Headers; text: string };

/** The data center's cache, standing in: `match` and `put` as each test makes them. */
function useCache(cache: { match: (key: Request) => Promise<Response | undefined>; put: (key: Request, res: Response) => Promise<void> }): void {
  Object.defineProperty(globalThis, "caches", { value: { default: cache }, configurable: true });
}

const noBlobs = Layer.succeed(Blobs, Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }));

/** One request through upstreamRoute with a background (so copies are shared), and the work it left for after its answer. */
async function get(path: string, accept: string, blobs: Layer.Layer<Blobs> = noBlobs): Promise<{ status: number; text: string; retryAfter: string | null; ms: number; works: Promise<void>[] }> {
  const works: Promise<void>[] = [];
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url, legacyAuth: false, namePolicy: "open", admins: [], tarballRedirects: "npm" } as const;
  const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, blobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  const layers = Layer.provideMerge(Upstream.layer(npm.url, 60_000, (w) => works.push(w)), base);
  const req = new Request(`http://registry.test${path}`, { headers: { accept } });
  const start = performance.now();

  const program = Effect.flatMap(upstreamRoute(req, new URL(req.url), false), (res) =>
    Effect.promise(async () => (res ? { status: res.status, text: await res.text(), retryAfter: res.headers.get("retry-after") } : { status: 404, text: "", retryAfter: null })),
  );

  const got = await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));

  return { ...got, ms: performance.now() - start, works };
}

describe("the install document never waits on the data center's cache past its bounds", () => {
  test("a copy lookup (cache.match) that never settles: the document is made from npm within the lookup's bound", async () => {
    useCache({ match: () => never(), put: async (_k, res) => void (await res.arrayBuffer()) });
    // on 8ea60e1 this request waited on the match until the client gave up
    const r = await get("/hung-match", INSTALL_ACCEPT);

    expect(r.status).toBe(200);
    expect(JSON.parse(r.text).name).toBe("hung-match");
    // CACHE_MATCH_MS (1 s) for the install copy, and 1 s more for the packument copy npm's read looks up
    expect(r.ms).toBeLessThan(4_000);
  }, 20_000);

  test("a copy whose body never starts: the document is made from npm within the first byte's bound", async () => {
    const kept = new Map<string, Kept>();

    useCache({
      match: async (key) => {
        const copy = kept.get(key.url);

        if (copy === undefined) return undefined;

        // the copy's headers as they were written, and a body that never sends a byte
        return new Response(silentBody().body, { headers: copy.headers });
      },
      put: async (key, res) => {
        kept.set(key.url, { headers: new Headers(res.headers), text: await res.text() });
      },
    });

    const first = await get("/stuck-copy", INSTALL_ACCEPT);

    await Promise.all(first.works);
    expect(first.status).toBe(200);
    // the first answer left the install copy (and a packument copy) in the stand-in cache
    expect([...kept.keys()].some((k) => k.includes("stuck-copy"))).toBe(true);
    const second = await get("/stuck-copy", INSTALL_ACCEPT);

    expect(second.status).toBe(200);
    expect(JSON.parse(second.text)).toEqual(JSON.parse(first.text));
    // CACHE_FIRST_BYTE_MS (2 s) for each copy that will not start, the install copy's and the packument's
    expect(second.ms).toBeLessThan(6_000);
  }, 30_000);

  test("a put that never settles: the answer does not wait for it", async () => {
    let puts = 0;

    useCache({
      match: async () => undefined,
      put: () => {
        puts++;

        return never();
      },
    });
    const r = await get("/hung-put", INSTALL_ACCEPT);

    expect(r.status).toBe(200);
    expect(r.ms).toBeLessThan(2_000);
    // the copies' puts went to the background, which settles on its own bound (SHARE_WAIT_MS) whatever the put does
    expect(puts).toBeGreaterThan(0);
    expect(r.works.length).toBeGreaterThan(0);
  }, 20_000);

  test("the full packument with a packument-copy lookup that never settles is answered from npm", async () => {
    useCache({ match: () => never(), put: async (_k, res) => void (await res.arrayBuffer()) });
    const r = await get("/hung-full", "application/json");

    expect(r.status).toBe(200);
    expect(JSON.parse(r.text).name).toBe("hung-full");
    expect(r.ms).toBeLessThan(4_000);
  }, 20_000);
});

describe("a wait for another request's read of the same packument (single flight)", () => {
  test("ends at its bound: the waiter reads npm itself instead of waiting on a slow leader", async () => {
    useCache({ match: async () => undefined, put: async (_k, res) => void (await res.arrayBuffer()) });
    const layers = Layer.provide(Upstream.layer(npm.url, 60_000, () => undefined), Layer.mergeAll(Store.postgres(db.url), noBlobs));

    // the install document's read with no copy: a whole read of npm's packument, which takes the single flight
    const read = (pool: MemoryPool) =>
      Effect.runPromise(
        Effect.flatMap(Upstream, (up) => up.installCopy({ name: "slow-lead", served: "http://registry.test/", lease: pool.request(), read: Effect.succeed("stamp"), stampOf: (stamp) => stamp })).pipe(
          Effect.map(({ copy }) => (copy?.kind === "read" ? copy.listing : null)),
          Effect.provide(layers),
          Effect.scoped,
        ),
      );

    const lead = timedRun(() => read(new MemoryPool()));

    await Bun.sleep(200);
    const waiter = await timedRun(() => read(new MemoryPool()));

    expect(waiter.value?.kind).toBe("found");
    // on 8ea60e1 it waited up to 10 s for the leader; now SINGLE_FLIGHT_WAIT_MS (3 s), then its own read
    expect(waiter.ms).toBeLessThan(SLOW_LEAD_MS - 1_000);
    expect(waiter.ms).toBeGreaterThan(2_500);
    expect((await lead).value?.kind).toBe("found");
  }, 30_000);

  test("ends at its bound on the wall clock when the isolate is busy, not after its polls' slip adds up", async () => {
    useCache({ match: async () => undefined, put: async (_k, res) => void (await res.arrayBuffer()) });
    const layers = Layer.provide(Upstream.layer(npm.url, 60_000, () => undefined), Layer.mergeAll(Store.postgres(db.url), noBlobs));

    const read = (pool: MemoryPool) =>
      Effect.runPromise(
        Effect.flatMap(Upstream, (up) => up.installCopy({ name: "slow-busy", served: "http://registry.test/", lease: pool.request(), read: Effect.succeed("stamp"), stampOf: (stamp) => stamp })).pipe(
          Effect.map(({ copy }) => (copy?.kind === "read" ? copy.listing : null)),
          Effect.provide(layers),
          Effect.scoped,
        ),
      );

    const openLead = npm.holdLead("slow-busy");
    const lead = timedRun(() => read(new MemoryPool()));

    await Bun.sleep(200);

    // the isolate is busy 40 ms in every 50: each 25 ms poll takes about twice that or more, so 120 polls counted as
    // 3 s were 7 s and more of waiting (counted in polls, as on main, this test's waiter took 9.7 s)
    const busy = setInterval(() => {
      const until = performance.now() + 40;

      while (performance.now() < until) {
        // keep the event loop busy
      }
    }, 10);

    try {
      const waiter = await timedRun(() => read(new MemoryPool()));

      expect(waiter.value?.kind).toBe("found");
      expect(waiter.ms).toBeGreaterThan(2_900);
      expect(waiter.ms).toBeLessThan(4_500);
    } finally {
      clearInterval(busy);
      openLead();
    }

    expect((await lead).value?.kind).toBe("found");
  }, 30_000);

  test("waiters behind a stuck leader make one more npm read between them; the rest are told to retry (503, Retry-After)", async () => {
    useCache({ match: async () => undefined, put: async (_k, res) => void (await res.arrayBuffer()) });
    // npm's reads are held on gates the test opens, not on timers. The extra read answered at once used to reach the
    // isolate's cache while a waiter whose own wait had not run out was still looking, and that waiter was served from
    // it (a 200, which is right), so the three answers depended on how far the waiters' timers drifted under load. It
    // is held until the other two have answered, and so is the leader's, so those two answered without either read.
    const openLead = npm.holdLead("slow-many");
    const openExtra = npm.holdLater("slow-many");
    const lead = get("/slow-many", INSTALL_ACCEPT);

    await Bun.sleep(200);
    // three requests that come while the leader's read is held: each waits SINGLE_FLIGHT_WAIT_MS, then one reads npm
    let answered = 0;

    const waiter = () =>
      get("/slow-many", INSTALL_ACCEPT).then((w) => {
        // two answered while the leader's read was still held, so neither waited on it; the third makes its own read
        // (two reads in all). Both reads go on now, well inside npm's 10 s deadline for the leader's.
        if (++answered === 2) {
          openExtra();
          openLead();
        }

        return w;
      });

    const waiters = await Promise.all([waiter(), waiter(), waiter()]);

    // on 11cbf13 every waiter read npm itself: four requests, four reads
    expect(npm.reads.get("slow-many")).toBe(2);
    expect(waiters.map((w) => w.status).sort()).toEqual([200, 503, 503]);

    for (const w of waiters) if (w.status === 503) expect(Number(w.retryAfter)).toBeGreaterThan(0);

    expect((await lead).status).toBe(200);
    expect(npm.reads.get("slow-many")).toBe(2);
  }, 30_000);
});

describe("an npm packument body that never ends", () => {
  test("is a 503 the client retries, at npm's 10 s read deadline", async () => {
    useCache({ match: async () => undefined, put: async (_k, res) => void (await res.arrayBuffer()) });
    const r = await get("/stalled-body", INSTALL_ACCEPT);

    expect(r.status).toBe(503);
    expect(r.ms).toBeLessThan(13_000);
  }, 30_000);
});

// ---------- R2 ----------

/** An R2 bucket standing in, each call as the test makes it. */
function bucket(over: Partial<BlobBucket>): BlobBucket {
  return {
    get: async () => null,
    put: async () => null,
    head: async () => null,
    delete: async () => undefined,
    ...over,
  };
}

const LIMITS = { getMs: 100, readMs: 100, idleMs: 100 };

describe("R2 waits are bounded (blobs.ts)", () => {
  test("a get that never settles fails with DeadlinePassed at its bound", async () => {
    const r2 = Blobs.r2(bucket({ get: () => never() }), LIMITS);
    const got = await timedRun(() => Effect.runPromise(Effect.flatMap(Blobs, (b) => Effect.flip(b.stream("k"))).pipe(Effect.provide(r2))));

    expect(got.value.cause).toBeInstanceOf(DeadlinePassed);
    expect(got.ms).toBeLessThan(1_000);
  });

  test("an object whose body never sends: a streamed body ends in BodyStalled, a whole read fails at its bound", async () => {
    const { body, state } = silentBody();
    const r2 = Blobs.r2(bucket({ get: async () => ({ body, size: 10 }) }), LIMITS);
    const streamed = await Effect.runPromise(Effect.flatMap(Blobs, (b) => b.stream("k")).pipe(Effect.provide(r2)));

    if (Option.isNone(streamed)) throw new Error("the stand-in has the object");
    const read = await timedRun(() => failureOf(new Response(streamed.value.body).arrayBuffer()));

    expect(read.value).toBeInstanceOf(BodyStalled);
    expect(read.ms).toBeLessThan(1_000);
    await Bun.sleep(10);
    expect(state.cancelled).toBe(true);

    const silent = silentBody();
    const silentR2 = Blobs.r2(bucket({ get: async () => ({ body: silent.body, size: 10 }) }), LIMITS);
    const whole = await timedRun(() => Effect.runPromise(Effect.flatMap(Blobs, (b) => Effect.flip(b.bytes("k"))).pipe(Effect.provide(silentR2))));

    expect(whole.value.cause).toBeInstanceOf(DeadlinePassed);
    expect(whole.ms).toBeLessThan(1_000);
    await Bun.sleep(10);
    // the whole read's body is cancelled at its bound, not left reading (on 11cbf13 arrayBuffer() ran on)
    expect(silent.state.cancelled).toBe(true);
  });

  test("a whole read whose request is interrupted cancels the object's body", async () => {
    const silent = silentBody();
    const r2 = Blobs.r2(bucket({ get: async () => ({ body: silent.body, size: 10 }) }), { getMs: 1_000, readMs: 60_000, idleMs: 60_000 });
    const fiber = Effect.runFork(Effect.flatMap(Blobs, (b) => b.bytes("k")).pipe(Effect.provide(r2)));

    await Bun.sleep(50);
    await Effect.runPromise(Fiber.interrupt(fiber));
    await Bun.sleep(10);
    expect(silent.state.cancelled).toBe(true);
  });

  /** `use` against the real Upstream layer, over an R2 stand-in, with a request background and a cache that has nothing. */
  const withUpstream = <A>(r2: BlobBucket, use: (up: UpstreamApi) => Effect.Effect<A, unknown>, works: Promise<void>[], puts: PendingPuts = new PendingPuts({ maxPuts: 8, maxBytes: 1 << 20 })): Promise<A> => {
    useCache({ match: async () => undefined, put: async (_k, res) => void (await res.arrayBuffer()) });

    return Effect.runPromise(
      Effect.flatMap(Upstream, use).pipe(Effect.provide(Layer.provide(Upstream.layer(npm.url, 60_000, (w) => works.push(w), puts), Layer.mergeAll(Store.postgres(db.url), Blobs.r2(r2, LIMITS)))), Effect.scoped),
    );
  };

  /** The tarball of `name`@1.0.0 served through the Upstream layer. */
  const served = (name: string) => (up: UpstreamApi) => Effect.flatMap(up.get(name, POOL.request()), (pkg) => (pkg === null ? Effect.die(new Error("not found")) : up.serve(pkg, "1.0.0")));

  test("background tarball puts are one per digest and capped per isolate; a put that never settles keeps its share", async () => {
    const works: Promise<void>[] = [];
    const asked: string[] = [];
    const ledger = new PendingPuts({ maxPuts: 2, maxBytes: 1 << 20 });

    const r2 = bucket({
      put: (key) => {
        asked.push(key);

        return never();
      },
    });

    // two packages with the same bytes (one digest), then two more with bytes of their own, all while R2 never answers
    for (const name of ["shared-a", "shared-b", "distinct-one", "distinct-two"]) expect((await withUpstream(r2, served(name), works, ledger)).kind).toBe("ok");

    // on 11cbf13 every answer started a put of its own: four puts, each holding its tarball until R2 answered
    expect(asked.length).toBe(2);
    expect(new Set(asked).size).toBe(2);
    expect(ledger.load.puts).toBe(2);
  }, 20_000);

  test("an upstream tarball with an R2 get that never settles is served from npm", async () => {
    const works: Promise<void>[] = [];

    const got = await timedRun(() =>
      withUpstream(
        bucket({ get: () => never() }),
        (up) => Effect.flatMap(up.get("r2-hung", POOL.request()), (pkg) => (pkg === null ? Effect.die(new Error("not found")) : up.serve(pkg, "1.0.0"))),
        works,
      ),
    );

    expect(got.value.kind).toBe("ok");
    expect(got.ms).toBeLessThan(2_000);
  }, 20_000);

  // R2 answering with an error of its own (10001, "We encountered an internal error") is a miss like a late get: before
  // this, serve and openTarball failed with BlobError and every download of an npm package was a 500 (2026-11-22)
  const failingR2 = () =>
    bucket({
      get: () => Promise.reject(new Error("get: We encountered an internal error. Please try again. (10001)")),
    });

  test("an upstream tarball whose R2 get fails is served from npm", async () => {
    const works: Promise<void>[] = [];
    const got = await withUpstream(failingR2(), served("r2-failing"), works);

    expect(got.kind).toBe("ok");
  }, 20_000);

  test("an upstream tarball whose R2 get fails is opened from npm (openTarball)", async () => {
    const works: Promise<void>[] = [];

    const got = await withUpstream(
      failingR2(),
      (up) => Effect.flatMap(up.get("r2-failing-open", POOL.request()), (pkg) => (pkg === null ? Effect.die(new Error("not found")) : up.openTarball(pkg, "1.0.0"))),
      works,
    );

    expect(got.kind).toBe("stream");

    if (got.kind === "stream") await new Response(got.body).arrayBuffer();
  }, 20_000);

  test("a cache put to R2 that never settles: the tarball is answered without waiting for it", async () => {
    const works: Promise<void>[] = [];
    let puts = 0;

    const got = await timedRun(() =>
      withUpstream(
        bucket({
          put: () => {
            puts++;

            return never();
          },
        }),
        (up) => Effect.flatMap(up.get("r2-put-hung", POOL.request()), (pkg) => (pkg === null ? Effect.die(new Error("not found")) : up.serve(pkg, "1.0.0"))),
        works,
      ),
    );

    expect(got.value.kind).toBe("ok");
    expect(got.ms).toBeLessThan(2_000);
    expect(puts).toBe(1);
    // the put went to the request's background, bounded there by R2_PUT_MS
    expect(works.length).toBeGreaterThan(0);
  }, 20_000);
});

describe("the isolate's ledger of upstream tarball puts (pending-puts.ts)", () => {
  test("one put per key, at most maxPuts and maxBytes out; a share is given back only when the put itself settles", async () => {
    const ledger = new PendingPuts({ maxPuts: 2, maxBytes: 100 });
    const first = deferred<void>();
    let calls = 0;

    const put = (p: Promise<void>) => () => {
      calls++;

      return p;
    };

    const a = ledger.start({ key: "a", bytes: 60, put: put(first.promise) });

    expect(a.kind).toBe("started");
    expect(ledger.start({ key: "a", bytes: 60, put: put(never()) }).kind).toBe("duplicate");
    // 60 + 50 bytes would pass maxBytes: skipped, and its put never called
    expect(ledger.start({ key: "b", bytes: 50, put: put(never()) }).kind).toBe("full");
    expect(ledger.start({ key: "c", bytes: 40, put: put(never()) }).kind).toBe("started");
    // two out: a third is skipped whatever its size
    expect(ledger.start({ key: "d", bytes: 0, put: put(never()) }).kind).toBe("full");
    expect(calls).toBe(2);
    expect(ledger.load).toEqual({ puts: 2, bytes: 100 });
    // a caller that stopped waiting (R2_PUT_MS) gives nothing back: the put still holds its bytes
    await Bun.sleep(20);
    expect(ledger.load).toEqual({ puts: 2, bytes: 100 });
    first.settle();

    if (a.kind === "started") await a.settled;
    expect(ledger.load).toEqual({ puts: 1, bytes: 40 });
    expect(ledger.start({ key: "a", bytes: 60, put: put(Promise.reject(new Error("R2 refused"))) }).kind).toBe("started");
    await Bun.sleep(0);
    // a put that failed gives its share back too
    expect(ledger.load).toEqual({ puts: 1, bytes: 40 });
  });
});
