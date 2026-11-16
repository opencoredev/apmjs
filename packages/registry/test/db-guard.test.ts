// The database guard (db-health.ts) on a real Postgres, directly and through a link the test stalls (db-link.ts): a
// slow statement on a database that answers fails on its own without taking the database as down, while a statement
// or a transaction whose connection went silent, BEGIN included, fails within the probe's time as unreachable and
// leaves nothing for the request to wait on.
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { Cause, Effect, Exit, Option } from "effect";
import * as SqlClient from "effect/sql/SqlClient";
import { startDatabaseLink, type DatabaseLink } from "../../../tests/acceptance/db-link.ts";
import { halfAnswering } from "../../../tests/acceptance/half-answering.ts";
import { emptyDatabase } from "../../../tests/acceptance/postgres.ts";
import { downReason, forgetDowns, Guard, isDatabaseUnavailable, probe, StatementTimeout, TransactionTimeout, type GuardTimings } from "../src/db-health.ts";
import { Store } from "../src/db.ts";
import { StoreError } from "../src/errors.ts";

let db: { url: string; drop: () => Promise<void> };
let link: DatabaseLink;

beforeAll(async () => {
  db = await emptyDatabase();
});

afterAll(async () => {
  await db?.drop();
});

afterEach(async () => {
  forgetDowns();
  await link?.stop();
});

const FAST: GuardTimings = { statementMs: 3_000, probeAfterMs: 300, windowMs: 60_000 };

/** Runs `use` on a request's Store over `url`, and says how long it took to fail or succeed, scope close included. */
async function timed<A>(url: string, use: Effect.Effect<A, StoreError, SqlClient.SqlClient | Guard | Store>, timings: GuardTimings = FAST) {
  const t0 = performance.now();
  const exit = await Effect.runPromiseExit(use.pipe(Effect.provide(Store.postgres(url, new Set(), timings)), Effect.scoped));

  return { exit, ms: performance.now() - t0 };
}

function storeError(exit: Exit.Exit<unknown, StoreError>): StoreError | null {
  if (Exit.isSuccess(exit)) return null;
  const failure = Cause.findErrorOption(exit.cause);

  return Option.getOrNull(failure);
}

const statement = (text: "SELECT pg_sleep(4)" | "SELECT 1") =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    return yield* (yield* Guard).statement("test", text === "SELECT 1" ? sql`SELECT 1` : sql`SELECT pg_sleep(4)`);
  });

describe("a database that answers", () => {
  test("a statement that runs past its timeout fails alone: the database is not taken as down", async () => {
    // its probe answers after 0.2 s; the statement goes on to its 2.5 s timeout
    const slow = await timed(db.url, statement("SELECT pg_sleep(4)"), { ...FAST, statementMs: 2_500, probeAfterMs: 200 });
    const err = storeError(slow.exit);

    expect(err?.cause).toBeInstanceOf(StatementTimeout);
    expect(err === null ? null : isDatabaseUnavailable(err)).toBe(false);
    expect(downReason(db.url)).toBeNull();
    // and the next statement runs
    expect(Exit.isSuccess((await timed(db.url, statement("SELECT 1"))).exit)).toBe(true);
  });
});

describe("a slow transaction on a database that answers", () => {
  test("its deadline ends it with its connection closed, as a timeout: the breaker stays shut and the next query runs", async () => {
    // a publish that spends past the deadline uploading to R2 inside its transaction: the probe after 0.2 s answers
    const slow = Effect.flatMap(Store, (store) => store.tx(Effect.andThen(statement("SELECT 1"), Effect.sleep("1500 millis"))));
    const t0 = performance.now();
    const { exit } = await timed(db.url, slow, { ...FAST, probeAfterMs: 200, transactionMs: 800 });
    const err = storeError(exit);

    expect(err?.cause).toBeInstanceOf(TransactionTimeout);
    expect(err === null ? null : isDatabaseUnavailable(err)).toBe(false);
    expect(performance.now() - t0).toBeLessThan(1_400);
    expect(downReason(db.url)).toBeNull();
    // the next ordinary query, in the next request, is answered
    expect(Exit.isSuccess((await timed(db.url, statement("SELECT 1"))).exit)).toBe(true);
  }, 20_000);
});

describe("a connection that goes silent", () => {
  /** A Store through the link, warmed with one statement, then the link stalled under it before `next` runs. */
  const stallThen = <A>(next: Effect.Effect<A, StoreError, SqlClient.SqlClient | Guard | Store>) =>
    Effect.gen(function* () {
      yield* statement("SELECT 1");
      link.set("stall");

      return yield* next;
    });

  test("a statement fails as unreachable once a probe finds no answer either, and the request closes at once", async () => {
    link = await startDatabaseLink(db.url);
    const { exit, ms } = await timed(link.url, stallThen(statement("SELECT 1")));
    const err = storeError(exit);

    process.stdout.write(`[db-guard] stalled statement: ${ms.toFixed(0)} ms\n`);
    expect(err === null ? null : isDatabaseUnavailable(err)).toBe(true);
    expect(downReason(link.url)).not.toBeNull();
    // probe after 0.3 s, probe budget 2 s
    expect(ms).toBeLessThan(3_000);
  }, 20_000);

  test("a transaction whose BEGIN gets no answer fails as unreachable within the same bound, cleanup included", async () => {
    link = await startDatabaseLink(db.url);
    const tx = Effect.flatMap(Store, (store) => store.tx(statement("SELECT 1")));
    const { exit, ms } = await timed(link.url, stallThen(tx));
    const err = storeError(exit);

    process.stdout.write(`[db-guard] stalled BEGIN: ${ms.toFixed(0)} ms\n`);
    expect(err === null ? null : isDatabaseUnavailable(err)).toBe(true);
    expect(ms).toBeLessThan(3_000);
  }, 20_000);
});

describe("a probe", () => {
  test("a server that answers one byte and stops: the probe gives up at its deadline and closes its connection", async () => {
    const server = await halfAnswering();

    try {
      const t0 = performance.now();
      // the stall timer is longer than the test: only the probe's own deadline can end the connection
      const answered = await probe(server.url, 500, 60_000);
      const ms = performance.now() - t0;

      process.stdout.write(`[db-guard] half-answering probe: ${answered} after ${ms.toFixed(0)} ms\n`);
      expect(answered).toBe(false);
      expect(ms).toBeLessThan(900);
      // its connection is closed, not left waiting for the rest of the answer
      await Bun.sleep(200);
      expect(server.open()).toBe(0);
    } finally {
      await server.stop();
    }
  }, 20_000);
});
