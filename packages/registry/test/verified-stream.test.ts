// The held-back last chunk is what keeps a client from receiving a whole tarball that fails its checksum
// (verified-stream.ts). Review of 23453ab: an empty final chunk released every byte before the check, a length
// overrun was forwarded, and a streamed transfer had no time bound.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { verifiedStream } from "../src/verified-stream.ts";

const bytes = (n: number, fill: number): Uint8Array => new Uint8Array(n).fill(fill);

const digestOf = (chunks: readonly Uint8Array[]) => {
  const h = createHash("sha512");

  for (const c of chunks) h.update(c);

  return { algo: "sha512" as const, hex: h.digest("hex") };
};

function sourceOf(chunks: readonly Uint8Array[], gapMs = 0): ReadableStream<Uint8Array> {
  let i = 0;

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (gapMs > 0) await new Promise((r) => setTimeout(r, gapMs));
      const next = chunks[i++];

      if (next === undefined) controller.close();
      else controller.enqueue(next);
    },
  });
}

/** Every byte the client reads before the stream ends or errors, and whether it errored. */
async function drain(stream: ReadableStream<Uint8Array>): Promise<{ received: number; errored: boolean }> {
  const reader = stream.getReader();
  let received = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();

      if (done) return { received, errored: false };
      received += value.byteLength;
    }
  } catch {
    return { received, errored: true };
  }
}

const body = [bytes(1000, 1), bytes(1000, 2), bytes(1000, 3)];

describe("verifiedStream", () => {
  test("a matching tarball is passed on whole", async () => {
    expect(await drain(verifiedStream({ source: sourceOf(body), digest: digestOf(body), length: 3000, url: "u" }))).toEqual({ received: 3000, errored: false });
  });

  test("an empty final chunk does not release the held bytes of a tarball that fails its checksum", async () => {
    const wrong = digestOf([bytes(3000, 9)]);
    const got = await drain(verifiedStream({ source: sourceOf([...body, new Uint8Array(0)]), digest: wrong, length: 3000, url: "u" }));

    // on 23453ab all 3,000 bytes were read and the stream ended cleanly
    expect(got.errored).toBe(true);
    expect(got.received).toBeLessThan(3000);
  });

  test("empty chunks anywhere are ignored, and a matching tarball still arrives whole", async () => {
    const source = sourceOf([new Uint8Array(0), body[0]!, new Uint8Array(0), body[1]!, body[2]!, new Uint8Array(0)]);

    expect(await drain(verifiedStream({ source, digest: digestOf(body), length: 3000, url: "u" }))).toEqual({ received: 3000, errored: false });
  });

  test("a chunk past the declared length is refused before the declared length's worth of bytes goes out", async () => {
    const long = [...body, bytes(10, 4)];
    const got = await drain(verifiedStream({ source: sourceOf(long), digest: digestOf(long), length: 3000, url: "u" }));

    expect(got.errored).toBe(true);
    expect(got.received).toBeLessThan(3000);
  });

  test("a stalled transfer errors after the idle limit, and the source is cancelled", async () => {
    let cancelled = false;

    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(body[0]!);
      },
      cancel() {
        cancelled = true;
      },
    });

    const got = await drain(verifiedStream({ source, digest: digestOf(body), length: 3000, url: "u", limits: { totalMs: 10_000, idleMs: 50 } }));

    // on 23453ab nothing bounded the transfer: this read would never end
    expect(got.errored).toBe(true);
    expect(cancelled).toBe(true);
  });

  test("a transfer past the total limit errors even while chunks keep arriving", async () => {
    const many = Array.from({ length: 40 }, (_, i) => bytes(10, i));
    const got = await drain(verifiedStream({ source: sourceOf(many, 20), digest: digestOf(many), length: 400, url: "u", limits: { totalMs: 150, idleMs: 10_000 } }));

    expect(got.errored).toBe(true);
    expect(got.received).toBeLessThan(400);
  });
});
