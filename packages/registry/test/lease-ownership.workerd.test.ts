// Who owns memory until it is unreachable, measured where it runs: inside workerd, after a full GC, the JS heap and
// ArrayBuffer bytes together (workerd-heap.ts), beside what the isolate's memory pool (src/memory.ts) is charged.
//
// Review of 747a032, each a moment where the isolate held package metadata the pool no longer counted:
// - finding 1: a read interrupted by a failing sibling kept 8.18 MiB, with nothing charged, and its stream was never
//   cancelled;
// - finding 2: a malformed read whose cancel was pending kept 10.08 MiB with 192 KiB charged;
// - finding 3: a stalled look at a fetched package kept 8.01 MiB after the pool expired its lease at the deadline;
// - finding 4: the package page's answer, 8.4 MB, stayed readable with nothing charged.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { ENTRY } from "./lease-ownership-entry.ts";
import { startWorkerdHeap, type WorkerdHeap } from "./workerd-heap.ts";

const MiB = 1024 * 1024;

/** What two measurements of the same heap differ by: the request's own objects, code the run compiled. */
const NOISE = 256 * 1024;

const mb = (n: number): string => `${(n / MiB).toFixed(2)} MiB`;

let heap: WorkerdHeap;

beforeAll(async () => {
  heap = await startWorkerdHeap(ENTRY);
}, 60_000);

afterAll(async () => {
  await heap.dispose();
});

const Moment = z.object({ held: z.number(), charged: z.number() });

describe("memory stays charged until nothing refers to it", () => {
  test("finding 1: an interrupted read cancels its stream and lets go of what it read before its lease is released", async () => {
    const got = z
      .object({ exit: z.string(), during: Moment, after: Moment.extend({ open: z.boolean(), cancelled: z.boolean() }) })
      .parse(await (await heap.dispatch("/interrupt")).json());

    process.stdout.write(`[lease] interrupted 8 MiB read: held ${mb(got.during.held)} charged ${mb(got.during.charged)} as the sibling fails; once interrupted held ${mb(got.after.held)} charged ${mb(got.after.charged)}, stream cancelled: ${got.after.cancelled}\n`);
    expect(got.exit).toBe("Failure");
    expect(got.during.held).toBeLessThanOrEqual(got.during.charged + NOISE);
    // on 747a032: held 8.18 MiB, charged 0, the stream never cancelled
    expect(got.after.cancelled).toBe(true);
    expect(got.after.open).toBe(false);
    expect(got.after.held).toBeLessThanOrEqual(got.after.charged + NOISE);
  }, 120_000);

  test("finding 2: a malformed read keeps its charge while its cancel is pending, and holds nothing of what it read", async () => {
    const got = z.object({ read: z.string(), during: Moment, after: Moment }).parse(await (await heap.dispatch("/malformed")).json());

    process.stdout.write(`[lease] malformed 10 MiB read, cancel pending: held ${mb(got.during.held)} charged ${mb(got.during.charged)}; settled: held ${mb(got.after.held)} charged ${mb(got.after.charged)}\n`);
    expect(got.read).toBe("invalid");
    // on 747a032: held 10.08 MiB, charged 192 KiB
    expect(got.during.held).toBeLessThanOrEqual(got.during.charged + NOISE);
    // every reference to the scanner is dropped before the cancel is awaited
    expect(got.during.held).toBeLessThan(NOISE);
    expect(got.during.charged).toBeGreaterThan(10 * MiB);
    expect(got.after.charged).toBe(0);
  }, 120_000);

  const Deadline = z.object({
    kind: z.string(),
    before: Moment.extend({ open: z.boolean() }),
    fits: z.boolean(),
    after: Moment.extend({ open: z.boolean(), stopped: z.boolean() }),
    settled: Moment.extend({ open: z.boolean() }),
  });

  test("finding 3: background work that ignores its deadline keeps its charge, and the pool refuses the room", async () => {
    const got = Deadline.parse(await (await heap.dispatch("/deadline?mode=stalled")).json());

    process.stdout.write(`[lease] stalled look past its deadline: before it held ${mb(got.before.held)} charged ${mb(got.before.charged)}; after held ${mb(got.after.held)} charged ${mb(got.after.charged)}, lease open: ${got.after.open}, told to stop: ${got.after.stopped}, 80 MiB request fit: ${got.fits}\n`);
    expect(got.kind).toBe("found");
    expect(got.before.held).toBeGreaterThan(7 * MiB);
    // on 747a032: the lease was closed at the deadline and the pool's charge fell to 0 while 8.01 MiB stayed reachable
    expect(got.after.stopped).toBe(true);
    expect(got.after.open).toBe(true);
    expect(got.fits).toBe(false);
    expect(got.after.held).toBeLessThanOrEqual(got.after.charged + NOISE);
    expect(got.settled.open).toBe(false);
  }, 120_000);

  test("finding 3: background work that honours its deadline stops, lets go, and only then releases its lease", async () => {
    const got = Deadline.parse(await (await heap.dispatch("/deadline?mode=stops")).json());

    process.stdout.write(`[lease] look that stops at its deadline: held ${mb(got.after.held)} charged ${mb(got.after.charged)} after it stopped, lease open: ${got.after.open}\n`);
    expect(got.after.stopped).toBe(true);
    expect(got.after.open).toBe(false);
    expect(got.after.held).toBeLessThanOrEqual(got.after.charged + NOISE);
    expect(got.settled.held).toBeLessThanOrEqual(got.settled.charged + NOISE);
  }, 120_000);

  test("finding 4: the package page's answer is charged before it is serialized and until its last byte is sent or cancelled", async () => {
    const got = z
      .object({
        status: z.number(),
        fits: z.boolean(),
        unread: Moment.extend({ open: z.boolean() }),
        bytes: z.number(),
        chunks: z.number(),
        sent: Moment.extend({ open: z.boolean() }),
        beforeCancel: z.object({ charged: z.number(), open: z.boolean() }),
        afterCancel: z.object({ charged: z.number(), open: z.boolean(), cache: z.number() }),
        cache: z.number(),
      })
      .parse(await (await heap.dispatch("/package-answer")).json());

    process.stdout.write(
      `[lease] package answer, 8 MiB readme: unread ${mb(got.bytes)} with heap ${mb(got.unread.held)} and charge ${mb(got.unread.charged)}; sent in ${got.chunks} chunks, then charged ${mb(got.sent.charged)} (cache ${mb(got.cache)}); cancelled: ${mb(got.beforeCancel.charged)} before, ${mb(got.afterCancel.charged)} after\n`,
    );
    expect(got.status).toBe(200);
    expect(got.bytes).toBeGreaterThan(8 * MiB);
    // on 747a032: an 8.4 MB body stayed readable after the request's lease was released and the cache evicted, charged 0.
    // Workerd's inspector does not see a buffered body's bytes, so what is still to be sent counts as held too
    expect(got.unread.open).toBe(true);
    expect(got.fits).toBe(false);
    expect(Math.max(got.unread.held, got.bytes)).toBeLessThanOrEqual(got.unread.charged + NOISE);
    // streamed: never one buffer of the whole answer
    expect(got.chunks).toBeGreaterThan(64);
    expect(got.sent.open).toBe(false);
    expect(got.sent.charged).toBe(got.cache);
    expect(got.sent.held).toBeLessThanOrEqual(got.sent.charged + NOISE);
    expect(got.beforeCancel.open).toBe(true);
    expect(got.afterCancel.open).toBe(false);
    expect(got.afterCancel.charged).toBe(got.afterCancel.cache);
  }, 120_000);
});
