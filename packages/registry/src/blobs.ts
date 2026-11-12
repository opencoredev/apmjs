// Tarball bytes in R2. Keys are content-addressed (sha512/<hex>), so a staged tarball that gets approved,
// or two versions with identical bytes, share one object.
import { Context, Effect, Layer, Option } from "effect";
import { BlobError } from "./errors.ts";

export type BlobBody = { readonly body: ReadableStream<Uint8Array>; readonly size: number };

export class Blobs extends Context.Service<
  Blobs,
  {
    readonly put: (key: string, bytes: Uint8Array) => Effect.Effect<void, BlobError>;
    /** Streams the object; for responses. */
    readonly stream: (key: string) => Effect.Effect<Option.Option<BlobBody>, BlobError>;
    /** Reads the whole object; for analysis and approval. */
    readonly bytes: (key: string) => Effect.Effect<Option.Option<Uint8Array>, BlobError>;
    readonly exists: (key: string) => Effect.Effect<boolean, BlobError>;
    readonly remove: (key: string) => Effect.Effect<void, BlobError>;
  }
>()("@apm/registry/Blobs") {
  static r2(bucket: R2Bucket): Layer.Layer<Blobs> {
    const attempt = <A>(operation: string, key: string, run: () => Promise<A>): Effect.Effect<A, BlobError> =>
      Effect.tryPromise({ try: run, catch: (cause) => new BlobError({ operation, key, cause }) });

    return Layer.succeed(
      Blobs,
      Blobs.of({
        put: (key, bytes) =>
          attempt("put", key, async () => {
            await bucket.put(key, bytes, { httpMetadata: { contentType: "application/octet-stream" } });
          }),
        stream: (key) =>
          attempt("get", key, async () => {
            const obj = await bucket.get(key);

            return obj === null ? Option.none() : Option.some({ body: obj.body, size: obj.size });
          }),
        bytes: (key) =>
          attempt("get", key, async () => {
            const obj = await bucket.get(key);

            return obj === null ? Option.none() : Option.some(new Uint8Array(await obj.arrayBuffer()));
          }),
        exists: (key) => attempt("head", key, async () => (await bucket.head(key)) !== null),
        remove: (key) => attempt("delete", key, () => bucket.delete(key)),
      }),
    );
  }
}
