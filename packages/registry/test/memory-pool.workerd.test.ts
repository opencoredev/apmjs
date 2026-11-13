// The isolate's memory pool (src/memory.ts), measured where it runs: inside workerd, after a full GC, the JS heap and
// ArrayBuffer bytes together (workerd-heap.ts). What the pool's leases are charged must be at least what the isolate
// holds of npm's package metadata, whatever mix of requests, background writes and cache evictions is running.
//
// Review of 6862fc7:
// - finding 1: a top-level key the reader discards, 8,000,000 characters long, held 7.8 MiB while the read was charged 0;
// - finding 2: 5,000,000 bytes of 0x80, which decode to U+FFFD, were charged 4.77 MiB and held 9.61 MiB;
// - finding 3: a stalled shared-cache write kept 3.6 MiB after the read's charge was given back.
// And the round's claim (docs/ARCHITECTURE.md): random concurrent mixes of reads, walks, scans, streamed packuments,
// cache writes and evictions hold no more above the isolate's base than the pool's peak charge and a small overhead.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { POOL_WEIGHT } from "../src/memory.ts";
import { ENTRY } from "./memory-pool-entry.ts";
import { startWorkerdHeap, type WorkerdHeap } from "./workerd-heap.ts";

const MB = 1024 * 1024;

/** What two measurements of the same heap differ by: the request's own objects, code the run compiled. */
const NOISE = 256 * 1024;

/**
 * What a mix holds beyond what its leases are charged, at most: per read in flight, the reader's two 64 KiB slabs, its
 * stacks and up to FLUSH_WEIGHT of weight not yet taken, and the network chunk it is reading; the Effect fibers and
 * streams of each operation; the fixture generators. Measured: see the [pool-mix] lines.
 */
const MIX_OVERHEAD = 4 * MB;


let heap: WorkerdHeap;

beforeAll(async () => {
  heap = await startWorkerdHeap(ENTRY);
}, 60_000);

afterAll(async () => {
  await heap.dispose();
});

const mb = (n: number): string => `${(n / MB).toFixed(2)} MiB`;

describe("what the reader holds is charged while it holds it", () => {
  for (const at of ["root", "version"] as const) {
    test(`finding 1: a discarded key of 8,000,000 characters (${at === "root" ? "at the root" : "in a version document"}) is never built, and what is held is charged`, async () => {
      const got = z.object({ read: z.string(), weight: z.number(), held: z.number(), taken: z.number() }).parse(await (await heap.dispatch(`/ignored-key?n=8000000&at=${at}`)).json());

      process.stdout.write(`[pool] discarded key (${at}), 8,000,000 characters: held ${mb(got.held)} while skipping it, charged ${mb(got.taken)}\n`);
      expect(got.read).toBe("ok");
      // on 6862fc7: 7.8 MiB held, 0 charged
      expect(got.held).toBeLessThan(MB);
      expect(got.taken).toBeGreaterThanOrEqual(got.held - NOISE);
    }, 120_000);
  }

  test("finding 1: a version key the reader keeps, of 4,000,000 characters, is charged from when it is read", async () => {
    const got = z.object({ read: z.string(), weight: z.number(), held: z.number(), taken: z.number(), after: z.number() }).parse(await (await heap.dispatch("/kept-key?n=4000000")).json());

    process.stdout.write(`[pool] kept version key, 4,000,000 characters: held ${mb(got.held)} while reading its document, charged ${mb(got.taken)}; ${mb(got.after)} held once read, weight ${mb(got.weight)}\n`);
    expect(got.read).toBe("ok");
    expect(got.held).toBeGreaterThan(3 * MB);
    expect(got.taken).toBeGreaterThanOrEqual(got.held - NOISE);
    expect(got.weight).toBeGreaterThanOrEqual(got.after - NOISE);
  }, 120_000);

  test("finding 2: 5,000,000 bytes that are not UTF-8 are charged as the two-byte string they decode to", async () => {
    const got = z.object({ read: z.string(), weight: z.number(), taken: z.number(), held: z.number(), length: z.number() }).parse(await (await heap.dispatch("/bad-utf8?n=5000000")).json());

    process.stdout.write(`[pool] 5,000,000 bytes of 0x80: weight ${mb(got.weight)}, held ${mb(got.held)}\n`);
    expect(got.read).toBe("ok");
    expect(got.length).toBe(5_000_000);
    // on 6862fc7: 4.77 MiB charged, 9.61 MiB held
    expect(got.weight).toBeGreaterThanOrEqual(got.held - NOISE);
    expect(got.taken).toBe(got.weight);
  }, 120_000);
});

describe("background writes hold their own lease", () => {
  test("finding 3: a refused conversion starts no write, and a stalled write stays charged for what it holds", async () => {
    const got = z
      .object({ refused: z.string(), writesAfterRefusal: z.number(), afterRefusal: z.number(), kind: z.string(), stalled: z.number(), chargedStalled: z.number(), done: z.number(), chargedDone: z.number() })
      .parse(await (await heap.dispatch("/background")).json());

    process.stdout.write(`[pool] stalled write: held ${mb(got.stalled)} after the request, charged ${mb(got.chargedStalled)}; after it settles held ${mb(got.done)}, charged ${mb(got.chargedDone)}; refused: ${got.refused}, ${got.writesAfterRefusal} writes, held ${mb(got.afterRefusal)}\n`);
    expect(got.refused).toBe("over-budget");
    // on 6862fc7 the write was started before conversion was refused, and kept 3.6 MiB nothing was charged for
    expect(got.writesAfterRefusal).toBe(0);
    expect(got.afterRefusal).toBeLessThan(NOISE);
    expect(got.kind).toBe("found");
    expect(got.stalled).toBeGreaterThan(MB);
    expect(got.chargedStalled).toBeGreaterThanOrEqual(got.stalled - NOISE);
    expect(got.chargedDone).toBe(0);
    // the code the write ran, compiled once: nothing of the package
    expect(got.done).toBeLessThan(2 * NOISE);
  }, 120_000);
});

describe("the pool's charge bounds the isolate's memory under any mix", () => {
  test("what a read in flight holds beyond its charge is fixed, whatever the packument", async () => {
    const got = z.object({ n: z.number(), held: z.number(), charged: z.number(), perRead: z.number() }).parse(await (await heap.dispatch("/in-flight?n=24")).json());

    process.stdout.write(`[pool] 24 reads in flight, each part way into a kept string: held ${mb(got.held)}, charged ${mb(got.charged)}, ${(got.perRead / 1024).toFixed(1)} KiB a read beyond its charge\n`);
    // the reader's slabs and stacks, its stream, the Effect fiber: charged as READ_OVERHEAD_WEIGHT while it runs
    expect(got.held).toBeLessThanOrEqual(got.charged + NOISE);
  }, 120_000);

  const Mix = z.object({
    failed: z.string().nullable(),
    counts: z.record(z.string(), z.number()),
    samples: z.number(),
    maxRunning: z.number(),
    peakCharged: z.number(),
    peakHeld: z.number(),
    worstOver: z.number(),
    worst: z.object({ held: z.number(), charged: z.number(), running: z.number() }),
    end: z.number(),
    endCharged: z.number(),
    cacheHeld: z.number(),
  });

  for (const seed of [1, 7, 42, 2026, 31337]) {
    test(`seed ${seed}: reads, walks, scans, streams, cache writes and evictions at once`, async () => {
      const got = Mix.parse(await (await heap.dispatch(`/mix?seed=${seed}&ops=150`)).json());

      process.stdout.write(
        `[pool-mix] seed ${seed}: ${JSON.stringify(got.counts)}; ${got.samples} samples, up to ${got.maxRunning} running; peak charged ${mb(got.peakCharged)}, peak held ${mb(got.peakHeld)}; held past charged at most ${mb(got.worstOver)} (${got.worst.running} running); at the end held ${mb(got.end)}, charged ${mb(got.endCharged)} (cache ${mb(got.cacheHeld)})\n`,
      );
      expect(got.failed).toBeNull();
      expect(got.samples).toBeGreaterThan(10);
      expect(got.peakCharged).toBeLessThanOrEqual(POOL_WEIGHT);
      // at every sample, and so at the peak
      expect(got.worstOver).toBeLessThanOrEqual(MIX_OVERHEAD);
      expect(got.peakHeld).toBeLessThanOrEqual(got.peakCharged + MIX_OVERHEAD);
      // once everything is done, only the isolate cache's entries are left
      expect(got.endCharged).toBe(got.cacheHeld);
      expect(got.end).toBeLessThanOrEqual(got.endCharged + MIX_OVERHEAD);
    }, 300_000);
  }
});
