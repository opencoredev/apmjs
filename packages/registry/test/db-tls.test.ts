// The database guard (db-health.ts) on a TLS connection to a real Postgres: the guard owns the TLS connection's socket
// as it owns a plain one, so a transaction whose BEGIN gets no answer is ended at the guard's deadline and its
// connection closed, and a connection that only sat idle between answered statements is never cut.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { Socket } from "node:net";
import { Cause, Effect, Exit, Option } from "effect";
import * as SqlClient from "effect/sql/SqlClient";
import { startDatabaseLink, type DatabaseLink } from "../../../tests/acceptance/db-link.ts";
import { startTlsPostgres, type TlsPostgres } from "../../../tests/acceptance/tls-postgres.ts";
import { connectionOptions, downReason, forgetDowns, Guard, TransactionTimeout } from "../src/db-health.ts";
import { Store } from "../src/db.ts";

let pg: TlsPostgres;
let link: DatabaseLink;
let accepted: string | undefined;

beforeAll(async () => {
  pg = startTlsPostgres();
  link = await startDatabaseLink(pg.url);
  // the test server's certificate is self-signed; only this file's connections see this
  accepted = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
});

afterAll(async () => {
  if (accepted === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = accepted;
  forgetDowns();
  await link?.stop();
  pg?.stop();
});

describe("a TLS connection", () => {
  test("goes through the guard's own socket, and an idle one is never cut", async () => {
    const open = new Set<Socket>();
    const options = connectionOptions(pg.url, open);

    expect(options.stream).toBeInstanceOf(Function);

    const rows = await Effect.runPromise(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        const guard = yield* Guard;
        const first = yield* guard.statement("tls", sql`SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`);

        // idle past the stall time: nothing was written, so nothing is waited for
        yield* Effect.sleep("700 millis");
        yield* guard.statement("tls", sql`SELECT 1`);

        return first;
      }).pipe(Effect.provide(Store.postgres(pg.url, new Set(), { stallMs: 300 })), Effect.scoped),
    );

    expect(rows).toEqual([{ ssl: true }]);
  }, 30_000);

  test("a transaction whose BEGIN gets no answer ends at the guard's deadline, with its connection closed", async () => {
    link.set("up");
    const t0 = performance.now();
    let end = 0;

    const exit = await Effect.runPromiseExit(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        const guard = yield* Guard;
        const store = yield* Store;

        yield* guard.statement("warm", sql`SELECT 1`);
        link.set("stall");

        return yield* store.tx(guard.statement("inside", sql`SELECT 2`));
      }).pipe(
        // no probe and no stall timer in time: only the transaction's own deadline can end it
        Effect.provide(Store.postgres(link.url, new Set(), { transactionMs: 500, probeAfterMs: 60_000, statementMs: 120_000, stallMs: 60_000 })),
        Effect.scoped,
        Effect.ensuring(Effect.sync(() => (end = performance.now()))),
      ),
    );

    const ms = end - t0;
    const err = Exit.isFailure(exit) ? Option.getOrNull(Cause.findErrorOption(exit.cause)) : null;

    process.stdout.write(`[db-tls] stalled BEGIN, scope closed after ${ms.toFixed(0)} ms\n`);
    // with no probe in time it cannot tell an outage from a slow transaction: it ends it, and keeps the breaker shut
    expect(err?.cause).toBeInstanceOf(TransactionTimeout);
    expect(downReason(link.url)).toBeNull();
    // the warm statement and the 500 ms deadline, then closing: never the stalled connection's own time
    expect(ms).toBeLessThan(1_500);
  }, 30_000);
});
