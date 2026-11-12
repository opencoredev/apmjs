// Typed failures. Infrastructure errors (storage, blobs, auth) carry the operation and the cause and become a
// 500 at the HTTP edge; HttpFailure is a refusal meant for the client, with its status and message.
import { Data } from "effect";

export class StoreError extends Data.TaggedError("StoreError")<{ readonly operation: string; readonly cause: unknown }> {}

export class BlobError extends Data.TaggedError("BlobError")<{ readonly operation: string; readonly key: string; readonly cause: unknown }> {}

export class AuthError extends Data.TaggedError("AuthError")<{ readonly operation: string; readonly cause: unknown }> {}

export class QueueError extends Data.TaggedError("QueueError")<{ readonly operation: string; readonly cause: unknown }> {}

/** Extra fields of an error body, beside `error`. Serialized as JSON. */
// oxlint-disable-next-line anti-slop/no-unsafe-dictionary-type -- an error body's extra fields are whatever the route reports (a finding list, a flag); they only reach JSON.stringify
export type ErrorExtra = Readonly<Record<string, unknown>>;

export class HttpFailure extends Data.TaggedError("HttpFailure")<{
  readonly status: number;
  readonly error: string;
  readonly extra?: ErrorExtra;
}> {}

export type InfraError = StoreError | BlobError | AuthError | QueueError;

export function refuse(status: number, error: string, extra?: ErrorExtra): HttpFailure {
  return new HttpFailure(extra === undefined ? { status, error } : { status, error, extra });
}
