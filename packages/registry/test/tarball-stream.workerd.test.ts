// An upstream tarball over the 32 MiB analysis cap, served (Upstream.serve, verified-stream.ts), measured where it runs:
// inside workerd, after a full GC, the JS heap and ArrayBuffer bytes together (workerd-heap.ts). On 1627c5e there was no
// way to serve one (the route answered 502); a stream that gathered the tarball, or held what it had checked, would hold
// all 40 MB by its end. Here the isolate holds the same, give or take a few chunks, from the first byte to the last.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { MAX_UPSTREAM_TARBALL_BYTES } from "../src/upstream.ts";
import { ENTRY, TARBALL_BYTES } from "./tarball-stream-entry.ts";
import { startWorkerdHeap, type WorkerdHeap } from "./workerd-heap.ts";

const MB = 1024 * 1024;

/**
 * What the isolate may hold above its base while a tarball streams: the network's chunks queued in the pipe (each
 * TransformStream and the FixedLengthStream hold one or two of 64 KiB), the chunk held back for the checksum, the hash,
 * and what the measuring request itself allocates. A stream that kept what it sent would pass it within 4 MB of 40.
 */
const STREAM_OVERHEAD = 4 * MB;

let heap: WorkerdHeap;

beforeAll(async () => {
  heap = await startWorkerdHeap(ENTRY);
}, 60_000);

afterAll(async () => {
  await heap.dispose();
});

const mb = (n: number): string => `${(n / MB).toFixed(2)} MiB`;

async function measure(): Promise<number> {
  return Number(await (await heap.dispatch("/measure")).text());
}

describe("a tarball over the analysis cap is streamed", () => {
  test("40 MB pass through with their length and checksum while the isolate's memory stays flat", async () => {
    expect(TARBALL_BYTES).toBeGreaterThan(MAX_UPSTREAM_TARBALL_BYTES);
    const expected = await (await heap.dispatch("/expected")).text();

    // warm: the code a first request compiles is not counted against the stream
    await measure();
    const base = await measure();
    const res = await heap.dispatch("/serve");

    // on 1627c5e there is no Upstream.serve: the tarball route answered 502 "larger than the 32 MiB apm downloads"
    expect(res.status, res.status === 200 ? "" : await res.text()).toBe(200);
    // what workerd itself sends: the FixedLengthStream gives the response its Content-Length, not chunked encoding
    expect(res.headers.get("content-length")).toBe(String(TARBALL_BYTES));
    expect(res.headers.get("transfer-encoding")).toBeNull();
    // never kept in the blob store, and not charged to the memory pool beyond the packument
    expect(res.headers.get("x-blob-puts")).toBe("0");
    expect(Number(res.headers.get("x-pool-charged"))).toBeLessThan(MB);

    const body = res.body;

    if (!body) throw new Error("the tarball answer has no body");
    const reader = body.getReader();
    const hash = createHash("sha512");
    const samples: number[] = [];
    let received = 0;
    let nextSample = 4 * MB;

    for (;;) {
      const { done, value } = await reader.read();

      if (done) break;
      hash.update(value);
      received += value.byteLength;

      if (received >= nextSample) {
        samples.push((await measure()) - base);
        nextSample += 4 * MB;
      }
    }

    const after = (await measure()) - base;
    const peak = Math.max(...samples);

    process.stdout.write(`[stream] ${(TARBALL_BYTES / 1e6).toFixed(1)} MB streamed: ${samples.length} samples over a base of ${mb(base)}, peak +${mb(peak)}, after +${mb(after)}; samples ${samples.map((s) => mb(s)).join(", ")}\n`);
    expect(received).toBe(TARBALL_BYTES);
    expect(hash.digest("hex")).toBe(expected);
    expect(samples.length).toBeGreaterThanOrEqual(9);
    expect(peak).toBeLessThan(STREAM_OVERHEAD);
    expect(after).toBeLessThan(STREAM_OVERHEAD);
  }, 180_000);
});
