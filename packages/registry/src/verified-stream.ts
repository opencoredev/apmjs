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

/**
 * `source`'s bytes, unchanged and unbuffered: each chunk is hashed and passed on when the next one arrives. At the end
 * the held chunk is sent only when every byte matches `digest`, and their count matches `length` when it is known;
 * otherwise the stream errors. Holds one chunk of the network's at a time, whatever the tarball's size.
 */
export function verifiedStream({ source, digest, length, url }: { source: ReadableStream<Uint8Array>; digest: Digest; length: number | null; url: string }): ReadableStream<Uint8Array> {
  const hash = createHash(digest.algo);
  let held: Uint8Array | null = null;
  let seen = 0;

  const refuse = (controller: TransformStreamDefaultController<Uint8Array>, error: string): void => {
    console.error(JSON.stringify({ level: "error", event: "upstream-tarball-stream", error, url, bytes: seen, declared: length }));
    controller.error(new StreamedTarballError(error));
  };

  const checker = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      if (held !== null) controller.enqueue(held);
      hash.update(chunk);
      seen += chunk.byteLength;
      held = chunk;
    },
    flush(controller) {
      if (length !== null && seen !== length) {
        refuse(controller, "length-mismatch");

        return;
      }

      if (hash.digest("hex") !== digest.hex) {
        refuse(controller, "integrity-mismatch");

        return;
      }

      if (held !== null) controller.enqueue(held);
    },
  });

  const checked = source.pipeThrough(checker);

  // in a Worker, a FixedLengthStream makes the response carry Content-Length instead of being chunked
  if (length === null || !("FixedLengthStream" in globalThis)) return checked;

  return checked.pipeThrough(new FixedLengthStream(length));
}
