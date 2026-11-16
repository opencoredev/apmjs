// How long the registry waits on Postgres, and what a request does when Postgres does not answer.
//
// - Connecting is bounded (CONNECT_TIMEOUT), and so is every statement the Store and the AI review send
//   (STATEMENT_TIMEOUT_MS). The connection itself gives up on a database that went silent (watchedSocket): a write
//   that gets no byte back within STALL_MS destroys the socket, which is what bounds a transaction's BEGIN, COMMIT and
//   ROLLBACK. `transaction` bounds the whole transaction too, as a backstop: past it, the transaction is ended by
//   closing its connection and fails as a TransactionTimeout (a plain store error).
// - Every failure that says the database is not there for this request is this request's alone: a connection error
//   the driver reports (refused, reset, DNS, TLS, closed by the server), an authentication failure, a server shutting
//   down or out of connections, a network error code anywhere in its causes (ETIMEDOUT and the like), a stall kill, a
//   statement that ran out of time, or one of the request's connections closing under it. The request takes the
//   database as unavailable (DatabaseUnavailable): its connections are closed, its later statements fail at once, its
//   install routes answer from the degraded route (degraded.ts) and its other routes 503 (worker.ts). Nothing is
//   remembered past the request: the next one tries the database again. An SQL error on a database that answered stays
//   an ordinary store error (a 500).
// - Nothing is shared between requests. An isolate-wide breaker (until 2026-11-16) took a Postgres that was answering
//   as down whenever a resolve kept an isolate's CPU busy, since Workers' clocks do not move while code runs and a busy
//   isolate leaves an answer unread exactly as a silent database does; every request that isolate served then answered
//   503 or degraded for 15 s. What that costs: in an outage every request pays its own attempt, up to its bound (the
//   connect timeout when the database cannot be reached, the statement timeout when it accepts and never answers).
// - A statement or transaction is run on a fiber of its own, and a caller that gives up on it does not wait for it to
//   stop: interrupting a statement on a silent connection waits for a cancel request, up to 5 s more.
import * as Net from "node:net";
import { PgClient } from "@effect/sql-pg";
import { Context, Data, Duration, Effect, Exit, Fiber, Predicate, Redacted } from "effect";
import * as SqlClient from "effect/sql/SqlClient";
import type { SqlError } from "effect/sql/SqlError";
import { z } from "zod";
import { StoreError } from "./errors.ts";

/** Opening a connection, through Hyperdrive, including the startup and authentication exchange. */
export const CONNECT_TIMEOUT = Duration.millis(3_000);

/** One statement, from sending it to its last row. The registry's statements are small; the slowest take well under a second. */
export const STATEMENT_TIMEOUT_MS = 8_000;

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

/**
 * Error codes, anywhere in a failure's causes, that say the network or the connection failed: Node's and Bun's socket
 * and DNS codes, undici's, and the stream errors a destroyed socket gives.
 */
const NETWORK_CODES: ReadonlySet<string> = new Set([
  "ETIMEDOUT",
  "ESOCKETTIMEDOUT",
  "ECONNREFUSED",
  "ECONNRESET",
  "ECONNABORTED",
  "EPIPE",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EHOSTUNREACH",
  "EHOSTDOWN",
  "ENETUNREACH",
  "ENETDOWN",
  "ENETRESET",
  "ERR_SOCKET_CLOSED",
  "ERR_STREAM_DESTROYED",
  "ERR_STREAM_PREMATURE_CLOSE",
  "UND_ERR_SOCKET",
  "UND_ERR_CONNECT_TIMEOUT",
]);

const WithCode = z.object({ code: z.string() });
const WithCause = z.object({ cause: z.unknown() });

/** A failure and its causes, outermost first, at most eight deep. */
function causesOf(cause: unknown): unknown[] {
  const out: unknown[] = [];
  let c: unknown = cause;

  for (let depth = 0; depth < 8 && c !== undefined && c !== null; depth++) {
    out.push(c);
    const next = WithCause.safeParse(c);

    c = next.success ? next.data.cause : undefined;
  }

  return out;
}

/** The connection gave up on a database that went silent (watchedSocket). */
export class StalledConnection extends Error {}

/**
 * Whether a failed statement says the database is not there for this request: a connection or authentication failure
 * the driver reports (its timeouts included), a server that is shutting down or out of connections, or a network error
 * code or a stall kill anywhere in its causes. An SQL error on a database that answered is not one.
 */
export function meansUnreachable(error: SqlError): boolean {
  const reason = error.reason;

  if (Predicate.isTagged(reason, "ConnectionError") || Predicate.isTagged(reason, "AuthenticationError")) return true;

  return causesOf(reason.cause).some((c) => {
    if (c instanceof StalledConnection) return true;
    const code = WithCode.safeParse(c);

    return code.success && (UNAVAILABLE_STATES.has(code.data.code) || NETWORK_CODES.has(code.data.code));
  });
}

/**
 * One request's connections to the database: the guard closes them when the request takes the database as
 * unavailable, and learns when one closes without it (the server or the network ended the session). The pool keeps an
 * idle connection for 60 s, longer than a request, so within a request a connection closing is not the pool's doing.
 */
export class RequestConnections {
  readonly open = new Set<Net.Socket>();
  /** A connection closed while the guard had not closed it. */
  lost = false;
  #closing = false;

  track(socket: Net.Socket): void {
    this.open.add(socket);
    socket.on("close", () => {
      this.open.delete(socket);

      if (!this.#closing) this.lost = true;
    });
  }

  /** Closes every connection; what still waits on one ends now. */
  closeAll(): void {
    this.#closing = true;

    for (const socket of this.open) socket.destroy();
  }
}

/**
 * A TCP connection to the database that destroys itself when a write gets no byte back within `stallMs`. Only a write
 * arms it and any byte read clears it, so an idle connection (a transaction waiting on an R2 upload) is never cut.
 * sql-pg uses it as its stream (PgConnection's `stream`) with the same options it would connect with itself.
 */
export function watchedSocket(host: string, port: number, stallMs: number = STALL_MS, conns: RequestConnections | null = null): Net.Socket {
  const socket = Net.connect({ host, port, noDelay: true });

  conns?.track(socket);
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
 * The connection options for `url`: the connect timeout and the watched socket, recorded in `conns` so its guard can
 * close it. With TLS the driver wraps that same socket (as it wraps the one it would open itself), so destroying it ends
 * the TLS connection too; the stall timer only sees the bytes before TLS takes the socket over, so a TLS connection is
 * bounded by the statement and transaction deadlines, and closed by the guard.
 */
export function connectionOptions(url: string, conns: RequestConnections | null = null, stallMs: number = STALL_MS) {
  const parsed = new URL(url);
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  const port = Number(parsed.port || "5432");

  return { url: Redacted.make(url), connectTimeout: CONNECT_TIMEOUT, stream: () => watchedSocket(host, port, stallMs, conns) };
}

/**
 * One query on a connection of its own, all of it (connecting, the query and closing) within `deadlineMs`: its rows,
 * or null when it failed or ran out of time. At the deadline its connection is destroyed and its fiber interrupted, and
 * nothing waits for either, so a server that answers one byte and stops costs nothing past the deadline. The rollback
 * tools read the migration ledger with it; requests never do.
 */
export async function queryOnce(url: string, text: string, deadlineMs: number, stallMs: number = STALL_MS): Promise<ReadonlyArray<unknown> | null> {
  const conns = new RequestConnections();
  const abort = new AbortController();

  const program = Effect.flatMap(SqlClient.SqlClient, (sql) => sql.unsafe(text)).pipe(
    Effect.provide(PgClient.layer({ ...connectionOptions(url, conns, stallMs), maxConnections: 1, connectTimeout: Duration.millis(deadlineMs) })),
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
    conns.closeAll();
    abort.abort();
  }

  return rows;
}

/**
 * Runs `effect` on a fiber of its own and waits for it. A caller that stops waiting (a timeout) is not held up while
 * the fiber stops: it is interrupted in the background.
 */
const detached = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
  Effect.flatMap(Effect.forkDetach(effect), (fiber) => Fiber.join(fiber).pipe(Effect.onInterrupt(() => Effect.asVoid(Effect.forkDetach(Fiber.interrupt(fiber))))));

/** The guard every statement of one request goes through. */
export type DatabaseGuard = {
  /** Runs one statement within STATEMENT_TIMEOUT_MS, or fails at once once this request has taken the database as unavailable. */
  readonly statement: <A>(operation: string, effect: Effect.Effect<A, SqlError>) => Effect.Effect<A, StoreError>;
  /** Runs a transaction within TRANSACTION_TIMEOUT_MS (past it, its connection is closed and it fails as a TransactionTimeout), classifying its own BEGIN, COMMIT and ROLLBACK failures. */
  readonly transaction: <A, E, R>(operation: string, effect: Effect.Effect<A, E | SqlError, R>) => Effect.Effect<A, E | StoreError, R>;
  /** The StoreError for a failure from a transaction's own BEGIN or COMMIT; it takes the database as unavailable for this request when it says so. */
  readonly failure: (operation: string, error: SqlError) => StoreError;
  /** Fails at once once this request has taken the database as unavailable (or lost a connection); for work that opens a transaction, or acts on what it read. */
  readonly ready: (operation: string) => Effect.Effect<void, StoreError>;
};

/** The guard of the request's database, beside its SqlClient: for modules that send their own statements (review.ts). */
export class Guard extends Context.Service<Guard, DatabaseGuard>()("@apm/registry/DatabaseGuard") {}

/** A statement that ran past its timeout. The cause of the DatabaseUnavailable it fails with. */
export class StatementTimeout extends Data.TaggedError("StatementTimeout")<{ readonly ms: number }> {}

/**
 * A transaction that ran past its deadline (a publish's long R2 upload, say): a store error, not an outage. Its
 * connection was closed to end it.
 */
export class TransactionTimeout extends Data.TaggedError("TransactionTimeout")<{ readonly ms: number }> {}

export type GuardTimings = { readonly statementMs?: number; readonly transactionMs?: number; readonly stallMs?: number };

/**
 * One request's guard. `conns` holds the request's connections (connectionOptions): once it takes the database as
 * unavailable it closes them, so statements it gave up on end now and the request's connections close without waiting
 * for them. It keeps nothing past the request.
 */
export function guardFor(timings: GuardTimings = {}, conns: RequestConnections = new RequestConnections()): DatabaseGuard {
  const statementMs = timings.statementMs ?? STATEMENT_TIMEOUT_MS;
  const transactionMs = timings.transactionMs ?? TRANSACTION_TIMEOUT_MS;
  const unavailableError = (operation: string, reason: string, cause: unknown): StoreError => new StoreError({ operation, cause: new DatabaseUnavailable({ reason, cause }) });

  /**
   * Set once this guard has closed its connections to end a transaction past its deadline: the connection errors that
   * follow are its own doing, and stay plain store errors.
   */
  let closedByUs = false;

  /** Why this request takes the database as unavailable; null while it has not. */
  let unavailable: string | null = null;

  const giveUp = (reason: string): string => {
    unavailable ??= reason;
    conns.closeAll();

    return unavailable;
  };

  const failure = (operation: string, error: SqlError): StoreError => {
    if (closedByUs) return new StoreError({ operation, cause: error });

    // the connection errors that follow closing this request's connections are this guard's own doing
    if (unavailable !== null) return unavailableError(operation, unavailable, error);

    if (meansUnreachable(error)) return unavailableError(operation, giveUp(`the database could not be reached (${error.reason._tag})`), error);

    return new StoreError({ operation, cause: error });
  };

  const ready = (operation: string): Effect.Effect<void, StoreError> =>
    Effect.suspend(() => {
      if (unavailable === null && conns.lost && !closedByUs) giveUp("the connection to the database closed during this request");

      return unavailable === null ? Effect.void : Effect.fail(unavailableError(operation, `${unavailable}; not tried again in this request`, null));
    });

  return {
    failure,
    ready,
    statement: <A>(operation: string, effect: Effect.Effect<A, SqlError>) =>
      Effect.andThen(
        ready(operation),
        detached(effect.pipe(Effect.mapError((e) => failure(operation, e)))).pipe(
          Effect.timeoutOrElse({
            duration: Duration.millis(statementMs),
            orElse: () => Effect.suspend(() => Effect.fail(unavailableError(operation, giveUp(`the database did not finish a statement within ${statementMs / 1000} s`), new StatementTimeout({ ms: statementMs })))),
          }),
        ),
      ),
    transaction: <A, E, R>(operation: string, effect: Effect.Effect<A, E | SqlError, R>) =>
      Effect.andThen(
        ready(operation),
        detached(effect).pipe(
          Effect.catchIf(
            (e): e is SqlError => Predicate.isTagged(e, "SqlError"),
            (e) => Effect.fail(failure(operation, e)),
          ),
          Effect.timeoutOrElse({
            duration: Duration.millis(transactionMs),
            // a silent connection is ended by its stall timer first (STALL_MS), so this is a slow transaction, a
            // publish's long R2 upload say: its connection is closed to stop it, a plain store error
            orElse: () =>
              Effect.suspend(() => {
                closedByUs = true;
                conns.closeAll();

                return Effect.fail(new StoreError({ operation, cause: new TransactionTimeout({ ms: transactionMs }) }));
              }),
          }),
        ),
      ),
  };
}
