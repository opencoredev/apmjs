// The database guard (db-health.ts) on a real Postgres, directly and through a link the test cuts or stalls
// (db-link.ts). Nothing is shared between requests: every failure that says the database is not there (refused, hung,
// stalled, a session closed, a statement past its time) fails only the request that met it, within its bound, with no
// connection beyond its own; the next request tries the database again. An SQL error stays an ordinary store error.
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { Cause, Effect, Exit, Option } from "effect";
import * as SqlClient from "effect/sql/SqlClient";
import { Client } from "pg";
import { z } from "zod";
import { startDatabaseLink, type DatabaseLink } from "../../../tests/acceptance/db-link.ts";
import { halfAnswering } from "../../../tests/acceptance/half-answering.ts";
import { emptyDatabase } from "../../../tests/acceptance/postgres.ts";
import { Guard, isDatabaseUnavailable, queryOnce, StatementTimeout, TransactionTimeout, type GuardTimings } from "../src/db-health.ts";
import { Store } from "../src/db.ts";
import { StoreError } from "../src/errors.ts";

let db: { url: string; drop: () => Promise<void> };
let link: DatabaseLink | undefined;

beforeAll(async () => {
  db = await emptyDatabase();
});

afterAll(async () => {
  await db?.drop();
});

afterEach(async () => {
  await link?.stop();
  link = undefined;
});

const FAST: GuardTimings = { statementMs: 3_000, stallMs: 1_000 };

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

const unavailable = (exit: Exit.Exit<unknown, StoreError>): boolean => {
  const err = storeError(exit);

  return err !== null && isDatabaseUnavailable(err);
};

const statement = (text: "SELECT pg_sleep(4)" | "SELECT pg_sleep(1)" | "SELECT 1") =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const guard = yield* Guard;

    switch (text) {
      case "SELECT 1":
        return yield* guard.statement("test", sql`SELECT 1`);
      case "SELECT pg_sleep(1)":
        return yield* guard.statement("test", sql`SELECT pg_sleep(1)`);
      case "SELECT pg_sleep(4)":
        return yield* guard.statement("test", sql`SELECT pg_sleep(4)`);
      default: {
        const _exhaustive: never = text;

        return _exhaustive;
      }
    }
  });

/** The next request, on a fresh Store: answered by the database. */
async function nextRequestAnswers(url: string): Promise<boolean> {
  return Exit.isSuccess((await timed(url, statement("SELECT 1"))).exit);
}

/**
 * Keeps this thread busy for `ms`, as a resolve parsing big packuments kept a production isolate (2026-11-16), with the
 * clock frozen meanwhile, as Workers' is while code runs: Date.now() reads the time the stall began until it ends.
 */
function busyFrozen(ms: number): void {
  const real = Date.now;
  const frozenAt = real();

  Date.now = () => frozenAt;

  try {
    const end = performance.now() + ms;

    while (performance.now() < end) {
      // spin: nothing else on this thread runs meanwhile
    }
  } finally {
    Date.now = real;
  }
}

describe("a database that answers", () => {
  test("a statement past its timeout fails its own request as unavailable; the next request is answered", async () => {
    const slow = await timed(db.url, statement("SELECT pg_sleep(4)"), { ...FAST, statementMs: 500 });
    const err = storeError(slow.exit);

    expect(err !== null && isDatabaseUnavailable(err)).toBe(true);
    expect(err?.cause instanceof Error ? err.cause.cause : null).toBeInstanceOf(StatementTimeout);
    expect(slow.ms).toBeLessThan(1_500);
    expect(await nextRequestAnswers(db.url)).toBe(true);
  });

  test("an SQL error is an ordinary store error, and the request goes on", async () => {
    const run = Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const guard = yield* Guard;
      const failed = yield* Effect.exit(guard.statement("bad", sql`SELECT * FROM no_such_table`));

      expect(Exit.isFailure(failed)).toBe(true);
      expect(unavailable(failed)).toBe(false);

      return yield* guard.statement("after", sql`SELECT 1 AS one`);
    });

    expect(Exit.isSuccess((await timed(db.url, run)).exit)).toBe(true);
  });

  test("a slow transaction ends at its deadline with its connection closed, as a plain store error; the next request is answered", async () => {
    // a publish that spends past the deadline uploading to R2 inside its transaction
    const slow = Effect.flatMap(Store, (store) => store.tx(Effect.andThen(statement("SELECT 1"), Effect.sleep("1500 millis"))));
    const t0 = performance.now();
    const { exit } = await timed(db.url, slow, { ...FAST, transactionMs: 800 });
    const err = storeError(exit);

    expect(err?.cause).toBeInstanceOf(TransactionTimeout);
    expect(err === null ? null : isDatabaseUnavailable(err)).toBe(false);
    expect(performance.now() - t0).toBeLessThan(1_400);
    expect(await nextRequestAnswers(db.url)).toBe(true);
  }, 20_000);

  test("a busy isolate, its clock frozen, never fails a later request", async () => {
    // the thread is busy, its clock frozen, from 2 s into a statement for 2.6 s: on 4f4205b the guard sent its probe
    // at 2 s, the probe's answer could not be read in time, and the whole isolate took the database as down for 15 s
    const run = Effect.gen(function* () {
      setTimeout(() => busyFrozen(2_600), 2_002);

      return yield* statement("SELECT pg_sleep(4)");
    });

    const busy = await timed(db.url, run, { statementMs: 8_000 });

    expect(Exit.isSuccess(busy.exit)).toBe(true);

    for (let i = 0; i < 3; i++) expect(await nextRequestAnswers(db.url)).toBe(true);
  }, 20_000);

  test("a session the server closes fails only its own request", async () => {
    const admin = new Client({ connectionString: db.url });
    await admin.connect();

    try {
      const run = Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        const guard = yield* Guard;
        const [row] = z.array(z.object({ pid: z.number() })).parse(yield* guard.statement("pid", sql`SELECT pg_backend_pid() AS pid`));

        // another session ends this one while it waits on a statement
        setTimeout(() => void admin.query("SELECT pg_terminate_backend($1)", [row?.pid]), 200);

        return yield* statement("SELECT pg_sleep(4)");
      });

      const killed = await timed(db.url, run, { statementMs: 6_000 });

      expect(unavailable(killed.exit)).toBe(true);
      expect(killed.ms).toBeLessThan(2_000);
      expect(await nextRequestAnswers(db.url)).toBe(true);
    } finally {
      await admin.end();
    }
  }, 20_000);
});

describe("a database that is not there", () => {
  test("refused: each request fails as unavailable within the connect bound, on its own connection attempt", async () => {
    const l = await startDatabaseLink(db.url);
    link = l;
    l.set("refuse");

    for (const n of [1, 2]) {
      const before = l.accepted();
      const { exit, ms } = await timed(l.url, statement("SELECT 1"));

      process.stdout.write(`[db-guard] refused, request ${n}: ${ms.toFixed(0)} ms, ${l.accepted() - before} connection\n`);
      expect(unavailable(exit)).toBe(true);
      expect(ms).toBeLessThan(3_500);
      expect(l.accepted() - before).toBe(1);
    }

    l.set("up");
    expect(await nextRequestAnswers(l.url)).toBe(true);
  }, 30_000);

  test("hung (accepts and never answers): each request fails as unavailable within its bound, opens only its own connection, and the database is used again once it answers", async () => {
    const l = await startDatabaseLink(db.url);
    link = l;
    l.set("hang");

    for (const n of [1, 2]) {
      const before = l.accepted();
      const { exit, ms } = await timed(l.url, statement("SELECT 1"));

      process.stdout.write(`[db-guard] hung, request ${n}: ${ms.toFixed(0)} ms, ${l.accepted() - before} connection\n`);
      expect(unavailable(exit)).toBe(true);
      // the connect timeout (3 s), inside the statement bound
      expect(ms).toBeLessThan((FAST.statementMs ?? 0) + 500);
      // no probe connections: only its own
      expect(l.accepted() - before).toBe(1);
    }

    l.set("up");
    expect(await nextRequestAnswers(l.url)).toBe(true);
  }, 30_000);

  test("stalled under a session: the statement fails as unavailable within its bound, on the request's one connection", async () => {
    const l = await startDatabaseLink(db.url);
    link = l;
    const before = l.accepted();

    const run = Effect.gen(function* () {
      yield* statement("SELECT 1");
      l.set("stall");

      return yield* statement("SELECT 1");
    });

    const { exit, ms } = await timed(l.url, run);

    process.stdout.write(`[db-guard] stalled statement: ${ms.toFixed(0)} ms\n`);
    expect(unavailable(exit)).toBe(true);
    // the stall kill after 1 s, inside the 3 s statement bound
    expect(ms).toBeLessThan(3_500);
    expect(l.accepted() - before).toBe(1);
  }, 20_000);

  test("a transaction whose BEGIN gets no answer fails as unavailable within the stall bound, cleanup included", async () => {
    const l = await startDatabaseLink(db.url);
    link = l;

    const run = Effect.gen(function* () {
      yield* statement("SELECT 1");
      l.set("stall");

      return yield* Effect.flatMap(Store, (store) => store.tx(statement("SELECT 1")));
    });

    const { exit, ms } = await timed(l.url, run);

    process.stdout.write(`[db-guard] stalled BEGIN: ${ms.toFixed(0)} ms\n`);
    expect(unavailable(exit)).toBe(true);
    expect(ms).toBeLessThan(3_000);
  }, 20_000);
});

describe("queryOnce (the rollback tools' ledger read)", () => {
  test("a server that answers one byte and stops: it gives up at its deadline and closes its connection", async () => {
    const server = await halfAnswering();

    try {
      const t0 = performance.now();
      // the stall timer is longer than the test: only the deadline can end the connection
      const rows = await queryOnce(server.url, "SELECT 1", 500, 60_000);
      const ms = performance.now() - t0;

      process.stdout.write(`[db-guard] half-answering query: ${rows === null ? "null" : "rows"} after ${ms.toFixed(0)} ms\n`);
      expect(rows).toBeNull();
      expect(ms).toBeLessThan(900);
      // its connection is closed, not left waiting for the rest of the answer
      await Bun.sleep(200);
      expect(server.open()).toBe(0);
    } finally {
      await server.stop();
    }
  }, 20_000);
});
