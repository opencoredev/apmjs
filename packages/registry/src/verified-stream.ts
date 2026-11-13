// An upstream tarball too large to hold (MAX_UPSTREAM_TARBALL_BYTES) is passed to the client as it arrives, never
// gathered. The registry cannot check its checksum before the first byte goes out, so it checks it on the way: the
// last chunk is held back until the whole tarball has been hashed, and sent only when it matches. A tarball that does
// not match ends with an error instead, so the client never receives its declared length of bytes, and npm, bun, pnpm
// and apm also check the bytes against the packument's integrity themselves.
import { createHash } from "node:crypto";
import type { Digest } from "./digest.ts";

/** Why a streamed tarball was cut off before its last chunk. */
export class StreamedTarballError extends Error {
  override readonly name = "StreamedTarballError";
}

/** How long a streamed tarball may take in all, and how long it may go without a chunk passing through. */
export const STREAM_LIMITS = { totalMs: 10 * 60_000, idleMs: 60_000 } as const;

/**
 * `source`'s bytes, unchanged and unbuffered: each nonempty chunk is hashed and passed on when the next nonempty one
 * arrives, so the last one with bytes is always held back. At the end it is sent only when every byte matches `digest`
 * and their count matches `length` when it is known; otherwise the stream errors. An empty chunk is ignored (passing
 * the held chunk on for it would let every byte out before the check: review of 23453ab, finding 1). A chunk that
 * would take the count past `length` is refused before the held one goes out. The whole transfer has `limits.totalMs`,
 * and `limits.idleMs` between chunks, whether the upstream or a slow client is the one stalling; past either the
 * stream errors and the upstream is cancelled. Holds one chunk of the network's at a time, whatever the size.
 */
export function verifiedStream({
  source,
  digest,
  length,
  url,
  limits = STREAM_LIMITS,
}: {
  source: ReadableStream<Uint8Array>;
  digest: Digest;
  length: number | null;
  url: string;
  limits?: { totalMs: number; idleMs: number };
}): ReadableStream<Uint8Array> {
  const hash = createHash(digest.algo);
  let held: Uint8Array | null = null;
  let seen = 0;
  let done = false;
  let total: ReturnType<typeof setTimeout> | null = null;
  let idle: ReturnType<typeof setTimeout> | null = null;

  const stopTimers = (): void => {
    if (total !== null) clearTimeout(total);

    if (idle !== null) clearTimeout(idle);

    total = null;
    idle = null;
  };

  const refuse = (controller: TransformStreamDefaultController<Uint8Array>, error: string): void => {
    if (done) return;
    done = true;
    stopTimers();
    held = null;
    console.error(JSON.stringify({ level: "error", event: "upstream-tarball-stream", error, url, bytes: seen, declared: length }));
    controller.error(new StreamedTarballError(error));
  };

  const armIdle = (controller: TransformStreamDefaultController<Uint8Array>): void => {
    if (idle !== null) clearTimeout(idle);
    idle = setTimeout(() => refuse(controller, "stalled"), limits.idleMs);
  };

  const checker = new TransformStream<Uint8Array, Uint8Array>({
    start(controller) {
      total = setTimeout(() => refuse(controller, "too-slow"), limits.totalMs);
      armIdle(controller);
    },
    transform(chunk, controller) {
      if (done) return;
      armIdle(controller);

      if (chunk.byteLength === 0) return;

      if (length !== null && seen + chunk.byteLength > length) {
        refuse(controller, "length-overrun");

        return;
      }

      if (held !== null) controller.enqueue(held);
      hash.update(chunk);
      seen += chunk.byteLength;
      held = chunk;
    },
    flush(controller) {
      if (done) return;
      stopTimers();

      if (length !== null && seen !== length) {
        refuse(controller, "length-mismatch");

        return;
      }

      if (hash.digest("hex") !== digest.hex) {
        refuse(controller, "integrity-mismatch");

        return;
      }

      done = true;

      if (held !== null) controller.enqueue(held);
      held = null;
    },
  });

  const checked = source.pipeThrough(checker);

  // in a Worker, a FixedLengthStream makes the response carry Content-Length instead of being chunked
  if (length === null || !("FixedLengthStream" in globalThis)) return checked;

  return checked.pipeThrough(new FixedLengthStream(length));
}
