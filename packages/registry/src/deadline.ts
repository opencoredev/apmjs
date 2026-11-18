// Local deadlines for the waits a request makes on platform calls that take no AbortSignal: the Workers Cache API
// (match, put), R2 (get, put, a body's bytes) and a body the Worker passes on. Without one, a call that never settles
// holds its request until the client gives up: an install document waited on the data center's copy before its
// answer (upstream.ts, installCopy), and a cached tarball on R2.
//
// A bound here never stops the call itself: nothing can. It stops waiting for it, and whatever the call hands over
// late (a Response, an R2 object) is let go, its body cancelled, so no connection or stream is left open. What the
// waiter does next is its caller's fallback: a cache lookup past its deadline is a miss, a body that stalls ends in an
// error (a client retries a cut-off answer), an R2 read past its deadline is a read that failed.
//
// A stalled wait is logged once, as one JSON line naming only the operation and the bound (`stall`): never a key, a
// URL or a package, so Workers Logs can count them without carrying anything a request named.

/** A Cache API lookup: the data center's copy is local, a few ms (Server-Timing install-copy 2/5 ms median/p90). */
export const CACHE_MATCH_MS = 1_000;

/** A Cache API copy's first bytes, once its lookup answered: past it the copy is not used. */
export const CACHE_FIRST_BYTE_MS = 2_000;

/** Between two chunks of a Cache API copy's body: past it the body ends in an error. */
export const CACHE_IDLE_MS = 5_000;

/** An R2 get, up to its object's metadata (bench R2_RTT 20-50 ms; production p99 well under a second). */
export const R2_GET_MS = 5_000;

/** Between two chunks of an R2 object's body passed on to a client. */
export const R2_IDLE_MS = 10_000;

/** A whole R2 object read into memory (an upstream tarball under MAX_UPSTREAM_TARBALL_BYTES, 32 MiB at most). */
export const R2_READ_MS = 15_000;

/** An R2 put of an upstream tarball kept as a cache: past it the copy is given up, the answer never waits on it. */
export const R2_PUT_MS = 15_000;

/** What a bounded wait came to: its value, its failure, or "late" once the deadline came first. */
export type Bounded<T> = { readonly kind: "done"; readonly value: T } | { readonly kind: "failed"; readonly cause: unknown } | { readonly kind: "late" };

/** One line per stalled wait, for Workers Logs: the operation and the bound, nothing a request named. */
export function logStall(operation: string, ms: number): void {
  console.warn(JSON.stringify({ level: "warn", event: "stall", operation, boundMs: ms }));
}

/**
 * `work`'s outcome, or "late" once `ms` passed first. `work` runs on: when it settles after the deadline, a value is
 * handed to `onLate` (to cancel a body, say) and a failure is dropped. Never rejects.
 */
export async function within<T>(work: Promise<T>, ms: number, onLate: (value: T) => void = () => undefined): Promise<Bounded<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let late = false;

  const settled = work.then(
    (value): Bounded<T> => {
      if (late) onLate(value);

      return { kind: "done", value };
    },
    (cause: unknown): Bounded<T> => ({ kind: "failed", cause }),
  );

  const deadline = new Promise<Bounded<T>>((resolve) => {
    timer = setTimeout(() => {
      late = true;
      resolve({ kind: "late" });
    }, ms);
  });

  try {
    return await Promise.race([settled, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** A Response that came too late to be used: its body is cancelled so nothing holds its stream. */
const dropResponse = (res: Response | undefined): void => void res?.body?.cancel().catch(() => undefined);

/** What a bounded Cache API lookup found: a hit, a miss (a failure is one), or nothing in time. */
export type CacheLookup = { readonly kind: "hit"; readonly res: Response } | { readonly kind: "miss" } | { readonly kind: "late" };

/** The subset of the Cache API a lookup uses. */
export type CacheReader = { match(key: Request | string): Promise<Response | undefined> };

/**
 * `cache.match(key)` within `ms`. Late is logged as a stall under `operation`; a hit that comes after the deadline has
 * its body cancelled. The caller takes "late" as a miss.
 */
export async function matchWithin(input: { cache: CacheReader; key: Request | string; ms?: number; operation: string }): Promise<CacheLookup> {
  const ms = input.ms ?? CACHE_MATCH_MS;
  let lookup: Promise<Response | undefined>;

  try {
    lookup = input.cache.match(input.key);
  } catch {
    return { kind: "miss" };
  }

  const got = await within(lookup, ms, dropResponse);

  switch (got.kind) {
    case "done":
      return got.value === undefined ? { kind: "miss" } : { kind: "hit", res: got.value };
    case "failed":
      return { kind: "miss" };
    case "late":
      logStall(input.operation, ms);

      return { kind: "late" };
    default: {
      const _exhaustive: never = got;

      return _exhaustive;
    }
  }
}

/** A call that did not settle within its bound: the cause of the failure a bounded R2 call fails with. */
export class DeadlinePassed extends Error {
  override readonly name = "DeadlinePassed";

  constructor(readonly operation: string, readonly ms: number) {
    super(`${operation}: no answer within ${ms / 1000} s`);
  }
}

/** `work`'s value within `ms`; past it, a DeadlinePassed rejection (logged as a stall). Late values go to `onLate`. */
export async function orDeadline<T>(input: { work: Promise<T>; ms: number; operation: string; onLate?: (value: T) => void }): Promise<T> {
  const got = await within(input.work, input.ms, input.onLate);

  switch (got.kind) {
    case "done":
      return got.value;
    case "failed":
      throw got.cause;
    case "late":
      logStall(input.operation, input.ms);

      throw new DeadlinePassed(input.operation, input.ms);
    default: {
      const _exhaustive: never = got;

      return _exhaustive;
    }
  }
}

/** Why readAllWithin stopped before the end: the deadline came first, or `signal` aborted (the request ended). */
type ReadStop = { readonly kind: "late" } | { readonly kind: "aborted"; readonly reason: unknown };

/**
 * Every byte of `source`, read through a reader this owns, within `ms` from now. At the deadline, or once `signal`
 * aborts, the source is cancelled (so nothing reads on after the caller gave up) and the read fails: DeadlinePassed
 * (logged as a stall under `operation`), or the signal's reason. A body that never sends is let go, not left running.
 */
export async function readAllWithin(input: { source: ReadableStream<Uint8Array>; ms: number; operation: string; signal?: AbortSignal }): Promise<Uint8Array> {
  const { source, ms, operation, signal } = input;
  const reader = source.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;

  const stop = new Promise<ReadStop>((resolve) => {
    timer = setTimeout(() => resolve({ kind: "late" }), Math.max(0, ms));
    onAbort = () => resolve({ kind: "aborted", reason: signal?.reason });

    if (signal?.aborted) onAbort();
    else signal?.addEventListener("abort", onAbort, { once: true });
  });

  const chunks: Uint8Array[] = [];
  let size = 0;

  try {
    for (;;) {
      const next = await Promise.race([reader.read().then((r) => ({ kind: "read", r }) as const), stop]);

      switch (next.kind) {
        case "read":
          if (next.r.done) {
            const all = new Uint8Array(size);
            let at = 0;

            for (const c of chunks) {
              all.set(c, at);
              at += c.length;
            }

            return all;
          }

          chunks.push(next.r.value);
          size += next.r.value.length;
          continue;
        case "late": {
          logStall(operation, ms);
          const late = new DeadlinePassed(operation, ms);

          void reader.cancel(late).catch(() => undefined);

          throw late;
        }

        case "aborted":
          void reader.cancel(next.reason).catch(() => undefined);

          throw next.reason;
        default: {
          const _exhaustive: never = next;

          return _exhaustive;
        }
      }
    }
  } finally {
    clearTimeout(timer);

    if (onAbort !== undefined) signal?.removeEventListener("abort", onAbort);
  }
}

/** Why a guarded body ended before its source did: its source sent nothing for `ms`. */
export class BodyStalled extends Error {
  override readonly name = "BodyStalled";

  constructor(readonly operation: string, readonly ms: number) {
    super(`${operation}: no bytes for ${ms / 1000} s`);
  }
}

/**
 * `source`'s bytes, unchanged, ending in a BodyStalled error when the source sends nothing for `idleMs` while the
 * reader waits for it. Only the source is timed: a chunk is asked of it when the reader wants one (the stream holds
 * none ahead), so a slow client never trips it. On a stall the source is cancelled. `first`, when given, is sent
 * before anything else is read (a chunk the caller already took).
 */
export function idleGuarded(input: { source: ReadableStream<Uint8Array>; idleMs: number; operation: string; first?: Uint8Array }): ReadableStream<Uint8Array> {
  const { idleMs, operation } = input;
  const reader = input.source.getReader();
  let cancelled = false;

  return new ReadableStream<Uint8Array>(
    {
      start(controller) {
        if (input.first !== undefined) controller.enqueue(input.first);
      },
      async pull(controller) {
        const got = await within(reader.read(), idleMs);

        // the reader may have cancelled while this waited: the stream is closed then, and takes nothing more
        if (cancelled) return;

        switch (got.kind) {
          case "done":
            if (got.value.done) controller.close();
            else controller.enqueue(got.value.value);

            return;
          case "failed":
            controller.error(got.cause);

            return;
          case "late": {
            logStall(operation, idleMs);
            const stalled = new BodyStalled(operation, idleMs);

            controller.error(stalled);
            void reader.cancel(stalled).catch(() => undefined);

            return;
          }

          default: {
            const _exhaustive: never = got;

            return _exhaustive;
          }
        }
      },
      cancel(reason) {
        cancelled = true;

        return reader.cancel(reason).catch(() => undefined);
      },
    },
    { highWaterMark: 0 },
  );
}

/**
 * `source` once its first chunk came within `firstMs`, guarded as idleGuarded is after that; null when it sent none
 * in time, failed first or was empty, with the source cancelled. For a copy that is only worth using if it answers:
 * the caller falls back to making the answer itself.
 */
export async function firstChunkWithin(input: { source: ReadableStream<Uint8Array>; firstMs: number; idleMs: number; operation: string }): Promise<ReadableStream<Uint8Array> | null> {
  const reader = input.source.getReader();
  const got = await within(reader.read(), input.firstMs);

  if (got.kind === "done" && !got.value.done) {
    reader.releaseLock();

    return idleGuarded({ source: input.source, idleMs: input.idleMs, operation: input.operation, first: got.value.value });
  }

  if (got.kind === "late") logStall(`${input.operation}-first-byte`, input.firstMs);
  void reader.cancel().catch(() => undefined);

  return null;
}
