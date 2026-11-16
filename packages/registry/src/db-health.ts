// How long the registry waits on Postgres, and what it remembers when Postgres does not answer.
//
// - Connecting is bounded (CONNECT_TIMEOUT), and so is every statement the Store and the AI review send
//   (STATEMENT_TIMEOUT_MS). A statement still running after PROBE_AFTER_MS starts a probe: a fresh connection and a
//   `SELECT 1` within PROBE_TIMEOUT_MS. When the probe fails too, the database is unreachable, and the statement fails
//   at once; when it answers, the database is up and only this statement is slow, so it may run to its timeout and
//   fails as a plain store error. A slow statement never marks the database down on its own.
// - A failure that says the database cannot be reached (a connection or authentication failure, a server shutting
//   down or out of connections, a failed probe) marks it down for this isolate for DOWN_WINDOW_MS: until then every
//   statement fails at once instead of waiting again.
// - The connection itself gives up on a database that went silent (watchedSocket): a write that gets no byte back
//   within STALL_MS destroys the socket. That is what bounds a transaction's BEGIN, COMMIT and ROLLBACK, which no
//   statement timeout covers. `transaction` bounds the whole transaction too, as a backstop: past it, the transaction
//   is ended by closing its connection and fails as a TransactionTimeout, without taking the database as down.
// - A statement or transaction is run on a fiber of its own, and a caller that gives up on it does not wait for it to
//   stop: interrupting a statement on a silent connection waits for a cancel request, up to 5 s more.
//
// The install routes then answer without the database (degraded.ts); every other route answers 503 with the reason
// (worker.ts).
import * as Net from "node:net";
import { PgClient } from "@effect/sql-pg";
import { Context, Data, Duration, Effect, Exit, Fiber, Option, Predicate, Redacted } from "effect";
import * as SqlClient from "effect/sql/SqlClient";
import type { SqlError } from "effect/sql/SqlError";
import { z } from "zod";
import { StoreError } from "./errors.ts";

/** Opening a connection, through Hyperdrive, including the startup and authentication exchange. */
export const CONNECT_TIMEOUT = Duration.millis(3_000);

/** One statement, from sending it to its last row. The registry's statements are small; the slowest take well under a second. */
export const STATEMENT_TIMEOUT_MS = 8_000;

/** How long a database found unreachable is taken as down by this isolate before a statement tries it again (APM_DB_DOWN_WINDOW_MS overrides it). */
export const DOWN_WINDOW_MS = 15_000;

/** How long a statement runs before the guard checks, on a connection of its own, that the database answers at all. */
export const PROBE_AFTER_MS = 2_000;

/** The probe's whole budget: connecting and `SELECT 1`. */
export const PROBE_TIMEOUT_MS = 2_000;

/** A connection that sent something and got no byte back for this long is destroyed: longer than any statement may run. */
export const STALL_MS = STATEMENT_TIMEOUT_MS + 1_000;

/** A whole transaction, BEGIN to COMMIT, the backstop under STALL_MS. A publish's runs an R2 upload of up to 32 MiB. */
export const TRANSACTION_TIMEOUT_MS = 60_000;

/** Why a statement did not reach the database. It is the `cause` of the StoreError the statement fails with. */
export class DatabaseUnavailable extends Data.TaggedError("DatabaseUnavailable")<{ readonly reason: string; readonly cause: unknown }> {}

/** Whether a store failure means the database could not be reached, rather than a statement that failed on it. */
export function isDatabaseUnavailable(e: StoreError): boolean {
  return e.cause instanceof DatabaseUnavailable;
}

/** SQLSTATEs Postgres (or Hyperdrive in front of it) sends when it cannot serve the connection at all. */
const UNAVAILABLE_STATES: ReadonlySet<string> = new Set(["57P01", "57P02", "57P03", "53300", "53400"]);

const WithState = z.object({ code: z.string() });

/** The SQLSTATE a driver error carries, when it has one. */
function sqlState(cause: unknown): string | null {
  const parsed = WithState.safeParse(cause);

  return parsed.success ? parsed.data.code : null;
}

/** Whether a failed statement says the database cannot be reached: a connection or authentication failure, or a server that is shutting down or out of connections. */
export function meansUnreachable(error: SqlError): boolean {
  const reason = error.reason;

  if (Predicate.isTagged(reason, "ConnectionError") || Predicate.isTagged(reason, "AuthenticationError")) return true;
  const state = sqlState(reason.cause);

  return state !== null && UNAVAILABLE_STATES.has(state);
}

type Down = { readonly until: number; readonly reason: string };

/**
 * What this isolate knows about each database URL. Isolate state like the packument cache, not request state: it holds
 * only when a database last failed to answer, never anything a request sent or read.
 */
const downs = new Map<string, Down>();

/** The reason a database is taken as down right now, or null when statements may try it. */
export function downReason(url: string, at: number = Date.now()): string | null {
  const d = downs.get(url);

  if (d === undefined) return null;

  if (d.until <= at) {
    downs.delete(url);

    return null;
  }

  return d.reason;
}

function markDown(url: string, reason: string, windowMs: number): void {
  downs.set(url, { until: Date.now() + windowMs, reason });
}

/** Forgets every database marked down. For tests that bring a database back. */
export function forgetDowns(): void {
  downs.clear();
}

/** The connection gave up on a database that went silent (watchedSocket). */
export class StalledConnection extends Error {}

/**
 * A TCP connection to the database that destroys itself when a write gets no byte back within `stallMs`. Only a write
 * arms it and any byte read clears it, so an idle connection (a transaction waiting on an R2 upload) is never cut.
 * sql-pg uses it as its stream (PgConnection's `stream`) with the same options it would connect with itself.
 */
export function watchedSocket(host: string, port: number, stallMs: number = STALL_MS, open: Set<Net.Socket> | null = null): Net.Socket {
  const socket = Net.connect({ host, port, noDelay: true });

  open?.add(socket);
  socket.on("close", () => open?.delete(socket));
  let timer: ReturnType<typeof setTimeout> | null = null;

  const disarm = (): void => {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  };

  const write = socket.write.bind(socket);

  // SAFETY: the replacement takes whatever arguments write takes and hands them to it unchanged; it only arms the timer.
  socket.write = ((...args: Parameters<typeof write>) => {
    timer ??= setTimeout(() => socket.destroy(new StalledConnection(`the database sent nothing for ${stallMs / 1000} s after a write`)), stallMs);

    return write(...args);
  }) as typeof socket.write;
  socket.on("data", disarm);
  socket.on("close", disarm);
  // the driver listens for errors while it uses the socket; this keeps one destroyed after it stopped listening (a
  // stall, a guard closing it) from becoming an uncaught error
  socket.on("error", () => undefined);

  return socket;
}

/**
 * The connection options for `url`: the connect timeout and the watched socket, recorded in `open` so its guard can
 * close it. With TLS the driver wraps that same socket (as it wraps the one it would open itself), so destroying it ends
 * the TLS connection too; the stall timer only sees the bytes before TLS takes the socket over, so a TLS connection is
 * bounded by the probes and timeouts, and closed by the guard.
 */
export function connectionOptions(url: string, open: Set<Net.Socket> | null = null, stallMs: number = STALL_MS) {
  const parsed = new URL(url);
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  const port = Number(parsed.port || "5432");

  return { url: Redacted.make(url), connectTimeout: CONNECT_TIMEOUT, stream: () => watchedSocket(host, port, stallMs, open) };
}

/**
 * One query on a connection of its own, all of it (connecting, the query and closing) within `deadlineMs`: its rows,
 * or null when it failed or ran out of time. At the deadline its connection is destroyed and its fiber interrupted, and
 * nothing waits for either, so a server that answers one byte and stops costs nothing past the deadline.
 */
export async function queryOnce(url: string, text: string, deadlineMs: number, stallMs: number = STALL_MS): Promise<ReadonlyArray<unknown> | null> {
  const sockets = new Set<Net.Socket>();
  const abort = new AbortController();

  const program = Effect.flatMap(SqlClient.SqlClient, (sql) => sql.unsafe(text)).pipe(
    Effect.provide(PgClient.layer({ ...connectionOptions(url, sockets, stallMs), maxConnections: 1, connectTimeout: Duration.millis(deadlineMs) })),
    Effect.scoped,
  );

  const run = Effect.runPromiseExit(program, { signal: abort.signal }).then((exit) => (Exit.isSuccess(exit) ? exit.value : null));
  let timer: ReturnType<typeof setTimeout> | undefined;

  const deadline = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), deadlineMs);
  });

  const rows = await Promise.race([run, deadline]);

  clearTimeout(timer);

  if (rows === null) {
    for (const socket of sockets) socket.destroy();
    abort.abort();
  }

  return rows;
}

/** Whether the database at `url` answers `SELECT 1` on a fresh connection within PROBE_TIMEOUT_MS. Never waits longer. */
export async function probe(url: string, timeoutMs: number = PROBE_TIMEOUT_MS, stallMs: number = STALL_MS): Promise<boolean> {
  return (await queryOnce(url, "SELECT 1", timeoutMs, stallMs)) !== null;
}

/**
 * Runs `effect` on a fiber of its own and waits for it. A caller that stops waiting (a timeout, a failed probe) is not
 * held up while the fiber stops: it is interrupted in the background.
 */
const detached = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
  Effect.flatMap(Effect.forkDetach(effect), (fiber) => Fiber.join(fiber).pipe(Effect.onInterrupt(() => Effect.asVoid(Effect.forkDetach(Fiber.interrupt(fiber))))));

/** The guard every statement to one database goes through. */
export type DatabaseGuard = {
  /** Runs one statement within STATEMENT_TIMEOUT_MS, or fails at once while the database is taken as down or a probe finds it unreachable. */
  readonly statement: <A>(operation: string, effect: Effect.Effect<A, SqlError>) => Effect.Effect<A, StoreError>;
  /** Runs a transaction within TRANSACTION_TIMEOUT_MS (past it, its connection is closed and it fails as a TransactionTimeout), classifying its own BEGIN, COMMIT and ROLLBACK failures. */
  readonly transaction: <A, E, R>(operation: string, effect: Effect.Effect<A, E | SqlError, R>) => Effect.Effect<A, E | StoreError, R>;
  /** The StoreError for a failure from a transaction's own BEGIN or COMMIT; it marks the database down when it was unreachable. */
  readonly failure: (operation: string, error: SqlError) => StoreError;
  /** Fails at once while the database is taken as down; for work that opens a transaction. */
  readonly ready: (operation: string) => Effect.Effect<void, StoreError>;
};

/** The guard of the request's database, beside its SqlClient: for modules that send their own statements (review.ts). */
export class Guard extends Context.Service<Guard, DatabaseGuard>()("@apm/registry/DatabaseGuard") {}

/** A statement that ran past its timeout on a database that answers: a store error, not an outage. */
export class StatementTimeout extends Data.TaggedError("StatementTimeout")<{ readonly ms: number }> {}

/**
 * A transaction that ran past its deadline on a database that answers (its probe did, or it never needed one): a store
 * error, not an outage. Its connection was closed to end it.
 */
export class TransactionTimeout extends Data.TaggedError("TransactionTimeout")<{ readonly ms: number }> {}

export type GuardTimings = { readonly windowMs?: number; readonly statementMs?: number; readonly probeAfterMs?: number; readonly transactionMs?: number; readonly stallMs?: number };

/**
 * The guard for `url`. `open` holds the sockets of the connections it guards (connectionOptions): once it takes the
 * database as unreachable it destroys them, so statements it gave up on end now and the request's connections close
 * without waiting for them.
 */
export function guardFor(url: string, timings: GuardTimings = {}, open: Set<Net.Socket> = new Set()): DatabaseGuard {
  const windowMs = timings.windowMs ?? DOWN_WINDOW_MS;
  const probeAfterMs = timings.probeAfterMs ?? PROBE_AFTER_MS;
  // a statement waits at least long enough for its probe to answer, so an unreachable database is never reported as a slow statement
  const statementMs = Math.max(timings.statementMs ?? STATEMENT_TIMEOUT_MS, probeAfterMs + PROBE_TIMEOUT_MS + 100);
  const transactionMs = timings.transactionMs ?? TRANSACTION_TIMEOUT_MS;
  const unavailable = (operation: string, reason: string, cause: unknown): StoreError => new StoreError({ operation, cause: new DatabaseUnavailable({ reason, cause }) });

  /**
   * Set once this guard has closed its own connections to end a transaction that ran out of time on a database that
   * answers: the connection errors that follow are its own doing, not the database's, and mark nothing down.
   */
  let closedByUs = false;

  const down = (reason: string): void => {
    markDown(url, reason, windowMs);

    for (const socket of open) socket.destroy();
  };

  const failure = (operation: string, error: SqlError): StoreError => {
    if (!meansUnreachable(error) || closedByUs) return new StoreError({ operation, cause: error });
    const reason = `the database could not be reached (${error.reason._tag})`;
    down(reason);

    return unavailable(operation, reason, error);
  };

  const ready = (operation: string): Effect.Effect<void, StoreError> =>
    Effect.suspend(() => {
      const down = downReason(url);

      return down === null ? Effect.void : Effect.fail(unavailable(operation, `${down}; not tried again yet`, null));
    });

  /** Fails with the database marked down when a probe finds it unreachable; never ends otherwise. */
  const unreachableOnProbe = (operation: string): Effect.Effect<never, StoreError> =>
    Effect.flatMap(
      Effect.promise(() => probe(url, PROBE_TIMEOUT_MS, timings.stallMs ?? STALL_MS)),
      (answers) => {
        if (answers) return Effect.never;
        const reason = "the database did not answer a statement, nor a check on a connection of its own";
        down(reason);

        return Effect.fail(unavailable(operation, reason, null));
      },
    );

  return {
    failure,
    ready,
    statement: <A>(operation: string, effect: Effect.Effect<A, SqlError>) =>
      Effect.andThen(
        ready(operation),
        Effect.flatMap(Effect.forkDetach(effect.pipe(Effect.mapError((e) => failure(operation, e)))), (fiber) => {
          const join = Fiber.join(fiber);

          return Effect.gen(function* () {
            const early = yield* Effect.timeoutOption(join, Duration.millis(probeAfterMs));

            if (Option.isSome(early)) return early.value;

            // still running: the rest of its time, unless a probe finds the database unreachable first
            return yield* Effect.raceFirst(join, unreachableOnProbe(operation)).pipe(
              Effect.timeoutOrElse({ duration: Duration.millis(statementMs - probeAfterMs), orElse: () => Effect.fail(new StoreError({ operation, cause: new StatementTimeout({ ms: statementMs }) })) }),
            );
            // whatever ended the wait, a statement still running is stopped without waiting for it
          }).pipe(Effect.onExit(() => Effect.asVoid(Effect.forkDetach(Fiber.interrupt(fiber)))));
        }),
      ),
    transaction: <A, E, R>(operation: string, effect: Effect.Effect<A, E | SqlError, R>) =>
      Effect.andThen(
        ready(operation),
        // a transaction still open after probeAfterMs is checked like a statement: a database that does not answer a
        // probe is taken as down, which closes the transaction's connection (its BEGIN or COMMIT may be what waits)
        Effect.raceFirst(detached(effect), Effect.andThen(Effect.sleep(Duration.millis(probeAfterMs)), unreachableOnProbe(operation))).pipe(
          Effect.catchIf(
            (e): e is SqlError => Predicate.isTagged(e, "SqlError"),
            (e) => Effect.fail(failure(operation, e)),
          ),
          Effect.timeoutOrElse({
            duration: Duration.millis(transactionMs),
            // the probe that ran after probeAfterMs found the database answering (a failed one ends the race first),
            // so this is a slow transaction, a publish's long R2 upload say, not an outage: its connection is closed to
            // stop it, and the breaker stays shut
            orElse: () =>
              Effect.suspend(() => {
                closedByUs = true;

                for (const socket of open) socket.destroy();

                return Effect.fail(new StoreError({ operation, cause: new TransactionTimeout({ ms: transactionMs }) }));
              }),
          }),
        ),
      ),
  };
}
