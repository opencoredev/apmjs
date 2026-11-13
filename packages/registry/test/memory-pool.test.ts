// The isolate's memory pool (src/memory.ts): one pool of weight that every request, the isolate cache and the
// background work after a response lease from, so together they never hold more than POOL_WEIGHT. npm is a local
// stand-in on 127.0.0.1, and the data center's cache a stand-in whose writes stall until the test lets them finish.
//
// Review of 6862fc7:
// - finding 3: a shared-cache write kept the packument it was serializing after the read's charge was given back, and
//   one was started even when converting the read was then refused;
// - finding 5: two requests' 64 MiB and the cache's 32 MiB were independent, 160 MiB in all on a 128 MiB isolate.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Effect, Layer, Option } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Blobs } from "../src/blobs.ts";
import { Store } from "../src/db.ts";
import { STREAM_OVERHEAD_WEIGHT } from "../src/http.ts";
import { BACKGROUND_DEADLINE_MS, CACHE_WEIGHT, MemoryPool, POOL_WEIGHT, REQUEST_WEIGHT, type Lease } from "../src/memory.ts";
import { READ_OVERHEAD_WEIGHT, readPackument } from "../src/packument-read.ts";
import { packageMoment, packageWeight, Upstream, type UpstreamApi } from "../src/upstream.ts";

const MiB = 1024 * 1024;

describe("leases of one pool", () => {
  test("two requests and the cache never hold more than the pool, each within its own limit", () => {
    const pool = new MemoryPool();
    const a = pool.request();
    const b = pool.request();
    const cache = pool.cache();

    expect(a.take(REQUEST_WEIGHT)).toBe(true);
    // on 6862fc7 each request had its own 64 MiB: b's would fit as well, and the cache's 32 MiB beside them
    expect(b.take(REQUEST_WEIGHT)).toBe(false);
    expect(b.take(POOL_WEIGHT - REQUEST_WEIGHT)).toBe(true);
    expect(cache.take(1)).toBe(false);
    expect(pool.charged).toBe(POOL_WEIGHT);
    expect(a.take(1)).toBe(false);

    a.release();
    expect(cache.take(CACHE_WEIGHT)).toBe(true);
    expect(cache.take(1)).toBe(false);
    expect(pool.charged).toBe(POOL_WEIGHT - REQUEST_WEIGHT + CACHE_WEIGHT);
    expect(pool.peakCharged).toBe(POOL_WEIGHT);
  });

  test("a block is counted once in the pool and against every holder's limit, until its last holder drops it", () => {
    const pool = new MemoryPool(100);
    const reader = pool.request(60);
    const other = pool.request(60);
    const background = pool.backgroundLease();

    expect(reader.take(50)).toBe(true);
    const block = reader.seal(50);

    expect([other.hold(block), background.hold(block)]).toEqual([true, true]);
    expect(pool.charged).toBe(50);
    expect([reader.taken, other.taken, background.taken]).toEqual([50, 50, 50]);
    // a holder's own limit counts the block: 50 held, 11 more is past 60
    expect(other.take(11)).toBe(false);

    reader.release();
    other.release();
    expect(pool.charged).toBe(50);
    background.release();
    expect(pool.charged).toBe(0);
    // a block nobody holds has left the pool and is never held again
    expect(pool.request().hold(block)).toBe(false);
  });

  test("a child counts against its parent, and closing the parent closes it", () => {
    const pool = new MemoryPool(1_000);
    const request = pool.request(100);
    const walk = request.child(40);

    expect(walk.take(40)).toBe(true);
    expect(walk.take(1)).toBe(false);
    expect(request.take(61)).toBe(false);
    expect(request.take(60)).toBe(true);
    expect(walk.root).toBe(request);
    walk.release();
    expect(request.taken).toBe(60);

    const scan = request.child();
    expect(scan.take(30)).toBe(true);
    request.release();
    expect([scan.open, pool.charged]).toEqual([false, 0]);
  });

  test("a retained lease stays open until its last holder lets go", () => {
    const pool = new MemoryPool(1_000);
    const request = pool.request();
    expect(request.take(10)).toBe(true);
    const stream = request.retain();

    request.release();
    expect([request.open, pool.charged]).toEqual([true, 10]);
    stream();
    stream();
    expect([request.open, pool.charged]).toEqual([false, 0]);
    expect(() => request.take(1)).toThrow("used after it was released");
  });

  test("background work past its deadline is told to stop, and keeps its charge until it has", () => {
    let now = 0;
    const pool = new MemoryPool(100, () => now);
    const work = pool.backgroundLease();
    expect(work.take(80)).toBe(true);

    expect(pool.request().take(30)).toBe(false);
    expect(work.signal.aborted).toBe(false);
    now = BACKGROUND_DEADLINE_MS;
    // on 747a032 the pool closed the lease here and gave the room away while the work still referred to it
    expect(pool.request().take(30)).toBe(false);
    expect([work.signal.aborted, work.open, pool.charged]).toEqual([true, true, 80]);
    // the work has stopped and lets go: only now is the room free
    work.release();
    expect(pool.request().take(30)).toBe(true);
  });

  test("stopping background work aborts its signal and gives nothing back", () => {
    const work = new MemoryPool().backgroundLease();
    expect(work.signal.aborted).toBe(false);
    work.stop();
    expect(work.signal.aborted).toBe(true);
    expect(work.open).toBe(true);
    work.release();
    expect(work.open).toBe(false);
  });
});

describe("the reader takes no read without a lease", () => {
  test("a call with none does not compile, and a closed lease is refused at run time", async () => {
    const body = () => new Blob(['{"name":"p"}']).stream();
    // @ts-expect-error -- the reader's options require a lease: code with none cannot read
    const unleased = readPackument(body(), {});

    await expect(unleased).rejects.toThrow();
    const closed = new MemoryPool().request();
    closed.release();
    await expect(readPackument(body(), { lease: closed })).rejects.toThrow("used after it was released");
  });

  test("every method of the upstream reader that reads a packument requires a lease", () => {
    // each of these must take a Lease as its last parameter (a type error here when one stops requiring it)
    type Leased = { [K in "probe" | "probeWithin" | "listing" | "probeMany" | "devDependencies" | "get"]: Parameters<UpstreamApi[K]> extends [...unknown[], Lease] ? true : false };

    const leased: Leased = { probe: true, probeWithin: true, listing: true, probeMany: true, devDependencies: true, get: true };

    expect(Object.values(leased).every(Boolean)).toBe(true);
  });
});

// A packument of 5,000 small versions, each with 500 bytes of notes: 3 to 4 MiB of weight kept.
const VERSIONS = 5_000;

function packumentText(name: string): string {
  const versions = Array.from({ length: VERSIONS }, (_, i) => `"1.0.${i}":${JSON.stringify({ name, version: `1.0.${i}`, dist: { tarball: `https://npm.invalid/${name}/-/${name}-1.0.${i}.tgz` }, notes: "z".repeat(500) })}`);

  return `{"name":${JSON.stringify(name)},"dist-tags":{"latest":"1.0.0"},"versions":{${versions.join(",")}}}`;
}

/** The data center's cache, standing in: no hits, and each put held until `finish` lets it settle. */
function stallingCache() {
  const puts: { key: string; body: ReadableStream<Uint8Array> | null }[] = [];
  const waiting: (() => void)[] = [];

  const cache = {
    match: async () => undefined,
    put: async (key: Request, res: Response) => {
      puts.push({ key: key.url, body: res.body });
      await new Promise<void>((resolve) => waiting.push(resolve));
    },
  };

  return { cache, puts, finish: () => waiting.splice(0).forEach((f) => f()) };
}

describe("a shared-cache write holds a lease of its own (review of 6862fc7, finding 3)", () => {
  let db: Awaited<ReturnType<typeof freshDatabase>>;
  let npm: ReturnType<typeof Bun.serve>;
  const text = packumentText("p");
  const stall = stallingCache();
  const works: Promise<void>[] = [];

  beforeAll(async () => {
    db = await freshDatabase();
    npm = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response(text, { headers: { "content-type": "application/json" } }) });
    Object.defineProperty(globalThis, "caches", { value: { default: stall.cache }, configurable: true });
  });

  afterAll(async () => {
    Reflect.deleteProperty(globalThis, "caches");
    await npm.stop(true);
    await db.drop();
  });

  const noBlobs = Layer.succeed(
    Blobs,
    Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
  );

  /** `use` against the real Upstream layer, sharing copies through the stand-in cache. */
  const withUpstream = <A>(use: (up: UpstreamApi) => Effect.Effect<A, unknown>): Promise<A> =>
    Effect.runPromise(
      Effect.flatMap(Upstream, use).pipe(
        Effect.provide(Layer.provide(Upstream.layer(npm.url.href, 60_000, (work) => works.push(work)), Layer.mergeAll(Store.postgres(db.url), noBlobs))),
        Effect.scoped,
      ),
    );

  test("a write that stalls keeps the package and its buffers charged after the request is done, until it settles", async () => {
    const pool = new MemoryPool();
    const request = pool.request();
    const before = stall.puts.length;
    const got = await withUpstream((up) => up.listing("stalled", request));

    expect(got.kind).toBe("found");
    expect(stall.puts.length).toBe(before + 1);
    const cache = pool.cache();
    request.release();
    // the cache holds the package; the write holds it too, and what serializing it takes, on top
    expect(cache.taken).toBeGreaterThan(VERSIONS * 500);
    expect(pool.charged - cache.taken).toBeGreaterThanOrEqual(STREAM_OVERHEAD_WEIGHT);

    // the client that read the copy goes away: the write still holds its lease until the put settles
    await stall.puts.at(-1)?.body?.cancel();
    expect(pool.charged - cache.taken).toBeGreaterThanOrEqual(STREAM_OVERHEAD_WEIGHT);
    stall.finish();
    await Promise.all(works);
    expect(pool.charged).toBe(cache.taken);
  });

  test("a read whose conversion does not fit starts no write and holds nothing", async () => {
    const probe = await readPackument(new Blob([text]).stream(), { lease: new MemoryPool(Number.POSITIVE_INFINITY).request(Number.POSITIVE_INFINITY) });

    if (probe.kind !== "ok") throw new Error("the fixture is not read");
    // room for the read itself, not for converting it into a package (packageWeight and packageMoment beside it)
    expect(packageWeight(probe) - probe.weight + packageMoment(probe)).toBeGreaterThan(1 * MiB);
    const pool = new MemoryPool();
    const request = pool.request(probe.weight + READ_OVERHEAD_WEIGHT + 256 * 1024);
    const before = stall.puts.length;
    const got = await withUpstream((up) => up.probeWithin("refused", request));

    expect(got.kind).toBe("over-budget");
    // on 6862fc7 the write was started before the conversion was refused, and kept the packument
    expect(stall.puts.length).toBe(before);
    expect(pool.charged).toBe(0);
  });
});

describe("requests that read at once share the pool (review of 6862fc7, finding 5)", () => {
  // four packages of about 10 MiB kept each, read one after another: 40 MiB a request, and 30 MiB more while one is
  // parsed, within its own 64 MiB; 80 MiB for two, and their reads in flight beside it
  const pad = 10 * MiB;
  let npm: ReturnType<typeof Bun.serve>;
  let db: Awaited<ReturnType<typeof freshDatabase>>;

  beforeAll(async () => {
    db = await freshDatabase();
    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        const name = new URL(req.url).pathname.slice(1);

        return new Response(`{"name":${JSON.stringify(name)},"description":"${"d".repeat(pad)}","versions":{}}`, { headers: { "content-type": "application/json" } });
      },
    });
  });

  afterAll(async () => {
    await npm.stop(true);
    await db.drop();
  });

  test("two requests of 40 MiB each are not both held: the pool's 80 MiB bounds them together", async () => {
    const pool = new MemoryPool();
    const [a, b] = [pool.request(), pool.request()];
    const noBlobs = Layer.succeed(Blobs, Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }));
    const layers = Layer.provide(Upstream.layer(npm.url.href, 60_000, null), Layer.mergeAll(Store.postgres(db.url), noBlobs));
    const names = (p: string) => [0, 1, 2, 3].map((i) => `${p}${i}`);
    const reads = (up: UpstreamApi, prefix: string, lease: Lease) => Effect.forEach(names(prefix), (n) => up.probeWithin(n, lease));

    const [ra, rb] = await Effect.runPromise(Effect.flatMap(Upstream, (up) => Effect.all([reads(up, "a", a), reads(up, "b", b)], { concurrency: 2 })).pipe(Effect.provide(layers), Effect.scoped));
    const kinds = [...ra, ...rb].map((p) => p.kind);

    process.stdout.write(`[pool] two requests of four 10 MiB packuments: ${kinds.join(", ")}; peak ${(pool.peakCharged / MiB).toFixed(1)} MiB charged\n`);
    // on 6862fc7 every one was read and held: 80 MiB of packuments beside the reads in flight
    expect(kinds.filter((k) => k === "found").length).toBeLessThan(8);
    expect(kinds.filter((k) => k === "over-budget").length).toBeGreaterThan(0);
    expect(pool.peakCharged).toBeLessThanOrEqual(POOL_WEIGHT);
    expect(a.taken).toBeLessThanOrEqual(REQUEST_WEIGHT);
    expect(b.taken).toBeLessThanOrEqual(REQUEST_WEIGHT);
    a.release();
    b.release();
    expect(pool.charged).toBe(pool.cache().taken);
  }, 60_000);
});

// The real packuments the reader is checked against, saved from registry.npmjs.org (not in the repository: 118 MB).
const REAL = process.env.APM_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments");

describe.skipIf(!existsSync(REAL))("real packuments under one request's lease", () => {
  test("next, react and typescript fit in one walk beside a 4 MiB root, with their shared-cache copies written beside it", async () => {
    const db = await freshDatabase();
    const npm = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: (req) => new Response(Bun.file(join(REAL, `${new URL(req.url).pathname.slice(1)}.json`))) });
    const written: string[] = [];

    const cache = {
      match: async () => undefined,
      put: async (key: Request, res: Response) => {
        await res.arrayBuffer();
        written.push(key.url);
      },
    };

    Object.defineProperty(globalThis, "caches", { value: { default: cache }, configurable: true });
    const works: Promise<void>[] = [];

    try {
      const pool = new MemoryPool();
      const walk = pool.request();
      // the resolve's root, held under the same request lease (review of 747a032, finding 5: at 64 MiB a 1 MiB root left next unchecked)
      expect(walk.take(4 * MiB)).toBe(true);
      const noBlobs = Layer.succeed(Blobs, Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }));
      const layers = Layer.provide(Upstream.layer(npm.url.href, 60_000, (w) => works.push(w)), Layer.mergeAll(Store.postgres(db.url), noBlobs));
      const got = await Effect.runPromise(Effect.flatMap(Upstream, (up) => up.probeMany(["next", "react", "typescript"], walk)).pipe(Effect.provide(layers), Effect.scoped));
      const peak = pool.peakCharged;
      await Promise.all(works);

      process.stdout.write(`[pool] next, react and typescript in one walk: ${[...got.values()].map((p) => p.kind).join(", ")}; the walk holds ${(walk.taken / MiB).toFixed(1)} MiB (at most ${(walk.peakTaken / MiB).toFixed(1)}), the pool ${(peak / MiB).toFixed(1)} MiB at most\n`);
      expect([...got.values()].map((p) => p.kind)).toEqual(["found", "found", "found"]);
      expect(written).toHaveLength(3);
      expect(peak).toBeLessThanOrEqual(POOL_WEIGHT);
      walk.release();
      expect(pool.charged).toBe(pool.cache().taken);
    } finally {
      Reflect.deleteProperty(globalThis, "caches");
      await npm.stop(true);
      await db.drop();
    }
  }, 120_000);
});
