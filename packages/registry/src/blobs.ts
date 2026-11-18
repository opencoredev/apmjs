// Tarball bytes in R2. Keys are content-addressed (sha512/<hex>), so a staged tarball that gets approved,
// or two versions with identical bytes, share one object.
//
// Every read is bounded (deadline.ts): a get that does not answer within R2_GET_MS fails with a DeadlinePassed cause,
// a whole object read into memory has R2_READ_MS, and a streamed body ends in an error when R2 sends nothing for
// R2_IDLE_MS; a whole read goes through a reader this owns, cancelled at its deadline or when the request ends, so no
// read runs on after its caller gave up. A put is not bounded here: a publish's upload runs inside its transaction,
// which has its own deadline (db-health.ts), and a cache's put bounds itself (upstream.ts).
//
// A delete is bounded only when its caller says the object is a disposable cache (`"cache"`: an upstream tarball that
// failed its checksum, which npm can always send again). A held delete (`"held"`: dropBlobIfUnused, under the blob's
// exclusive lock) is never given up on: a delete still in flight after its caller stopped waiting would release the
// lock, and a replacement upload of the same bytes could then write and commit before the late delete erased them.
import { Context, Effect, Layer, Option } from "effect";
import { idleGuarded, orDeadline, R2_GET_MS, R2_IDLE_MS, R2_READ_MS, readAllWithin } from "./deadline.ts";
import { BlobError } from "./errors.ts";

export type BlobBody = { readonly body: ReadableStream<Uint8Array>; readonly size: number };

/**
 * Whose object a delete removes: "held", one the registry's rows decide (a published or staged tarball), deleted under
 * the blob's lock and always waited for; "cache", a disposable copy of npm's, whose delete may be given up on.
 */
export type BlobDelete = "held" | "cache";

/** What the blob store uses of an R2 bucket: an R2Bucket in the Worker, a stand-in in tests. */
export type BlobBucket = {
  get(key: string): Promise<{ readonly body: ReadableStream<Uint8Array>; readonly size: number } | null>;
  put(key: string, value: Uint8Array, options: { httpMetadata: { contentType: string } }): Promise<object | null>;
  head(key: string): Promise<object | null>;
  delete(key: string): Promise<void>;
};

export class Blobs extends Context.Service<
  Blobs,
  {
    readonly put: (key: string, bytes: Uint8Array) => Effect.Effect<void, BlobError>;
    /** Streams the object; for responses. */
    readonly stream: (key: string) => Effect.Effect<Option.Option<BlobBody>, BlobError>;
    /** Reads the whole object; for analysis and approval. */
    readonly bytes: (key: string) => Effect.Effect<Option.Option<Uint8Array>, BlobError>;
    readonly exists: (key: string) => Effect.Effect<boolean, BlobError>;
    /** Deletes the object; a "held" delete is waited for however long R2 takes (see the head of this file). */
    readonly remove: (key: string, kind: BlobDelete) => Effect.Effect<void, BlobError>;
  }
>()("@apm/registry/Blobs") {
  static r2(bucket: BlobBucket, limits: { getMs: number; readMs: number; idleMs: number } = { getMs: R2_GET_MS, readMs: R2_READ_MS, idleMs: R2_IDLE_MS }): Layer.Layer<Blobs> {
    const attempt = <A>(operation: string, key: string, run: (signal: AbortSignal) => Promise<A>): Effect.Effect<A, BlobError> =>
      Effect.tryPromise({ try: (signal) => run(signal), catch: (cause) => new BlobError({ operation, key, cause }) });

    /** The object, or null, within getMs; an object that answers after that has its body cancelled. */
    const get = (key: string) =>
      orDeadline({ work: bucket.get(key), ms: limits.getMs, operation: "r2-get", onLate: (obj) => void obj?.body.cancel().catch(() => undefined) });

    return Layer.succeed(
      Blobs,
      Blobs.of({
        put: (key, bytes) =>
          attempt("put", key, async () => {
            await bucket.put(key, bytes, { httpMetadata: { contentType: "application/octet-stream" } });
          }),
        stream: (key) =>
          attempt("get", key, async () => {
            const obj = await get(key);

            if (obj === null) return Option.none();
            const body = idleGuarded({ source: obj.body, idleMs: limits.idleMs, operation: "r2-body" });

            // a FixedLengthStream keeps the answer's Content-Length in a Worker, as R2's own body did
            return Option.some({ body: "FixedLengthStream" in globalThis ? body.pipeThrough(new FixedLengthStream(obj.size)) : body, size: obj.size });
          }),
        bytes: (key) =>
          attempt("get", key, async (signal) => {
            const obj = await get(key);

            if (obj === null) return Option.none();

            // the body through a reader this owns: cancelled at readMs, or when the request that asked is interrupted
            return Option.some(await readAllWithin({ source: obj.body, ms: limits.readMs, operation: "r2-read", signal }));
          }),
        exists: (key) => attempt("head", key, async () => (await orDeadline({ work: bucket.head(key), ms: limits.getMs, operation: "r2-head" })) !== null),
        remove: (key, kind) => attempt("delete", key, () => (kind === "cache" ? orDeadline({ work: bucket.delete(key), ms: limits.getMs, operation: "r2-delete" }) : bucket.delete(key))),
      }),
    );
  }
}
