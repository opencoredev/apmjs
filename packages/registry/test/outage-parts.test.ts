// The parts the registry keeps working on through a database outage, one at a time: the block list's merges (it is
// never less strict than the database), the database guard (bounded waits, and a failure that stays the request's
// own), and the health answer's summary.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { ConnectionError, SqlError, UnknownError } from "effect/sql/SqlError";
import { reconciled, SYNC_GRACE_MS, verdictFor, withBlocks, type BlocklistBody } from "../src/blocklist.ts";
import { guardFor, isDatabaseUnavailable, meansUnreachable, StalledConnection, STATEMENT_TIMEOUT_MS } from "../src/db-health.ts";
import { summarize, type Check, type Health } from "../src/health.ts";

const EMPTY: BlocklistBody = { format: 1, syncedAt: null, local: [], confirmed: [] };
const T = 1_800_000_000_000;

describe("the block list", () => {
  test("a write adds what it blocks, and asserting an entry again renews it", () => {
    const one = withBlocks(EMPTY, { local: ["@a/x"], confirmed: [{ name: "ms", version: "2.1.2", digest: "sha512-aa" }] }, T);
    const two = withBlocks(one, { local: ["@a/x", "@a/y"] }, T + 5);

    expect(two.local).toEqual([
      { name: "@a/x", addedAt: T + 5 },
      { name: "@a/y", addedAt: T + 5 },
    ]);
    expect(two.confirmed).toEqual([{ name: "ms", version: "2.1.2", digest: "sha512-aa", addedAt: T }]);
    expect(two.syncedAt).toBeNull();
  });

  test("a sync keeps what the database holds and what was added within the grace, and drops the rest", () => {
    const list = withBlocks(
      withBlocks(EMPTY, { local: ["@old/gone"], confirmed: [{ name: "ms", version: "1.0.0", digest: "sha512-dismissed" }] }, T - SYNC_GRACE_MS - 1),
      // a block whose transaction may still be committing: the database does not show it yet
      { local: ["@new/pending"], confirmed: [{ name: "ms", version: "2.1.2", digest: "sha512-pending" }] },
      T - 1_000,
    );

    const synced = reconciled(list, { local: ["@kept/one"], confirmed: [{ name: "lodash", version: "4.0.0", digest: "sha512-db" }] }, T);

    expect(synced.syncedAt).toBe(T);
    expect(synced.local.map((e) => e.name).sort()).toEqual(["@kept/one", "@new/pending"]);
    expect(synced.confirmed.map((e) => `${e.name}@${e.version}`).sort()).toEqual(["lodash@4.0.0", "ms@2.1.2"]);
    // an entry the database still holds keeps its first time, so the grace never makes it young again
    const again = reconciled(synced, { local: ["@kept/one", "@new/pending"], confirmed: [] }, T + SYNC_GRACE_MS * 2);

    expect(again.local.find((e) => e.name === "@new/pending")?.addedAt).toBe(T - 1_000);
    expect(again.confirmed).toEqual([]);
  });

  test("a package published here is local; anything else carries only its confirmed versions", () => {
    const list = withBlocks(EMPTY, { local: ["@a/x"], confirmed: [{ name: "ms", version: "2.1.2", digest: "sha512-aa" }] }, T);

    expect(verdictFor(list, "@a/x")).toEqual({ kind: "local" });
    const ms = verdictFor(list, "ms");

    expect(ms.kind === "upstream" ? ms.confirmed.map((c) => `${c.version} ${c.digest}`) : null).toEqual(["2.1.2 sha512-aa"]);
    expect(verdictFor(list, "react")).toEqual({ kind: "upstream", confirmed: [] });
  });
});

describe("the database guard", () => {
  const connection = new SqlError({ reason: new ConnectionError({ cause: new Error("ECONNREFUSED"), message: "refused", operation: "connect" }) });
  const syntax = new SqlError({ reason: new UnknownError({ cause: { code: "22P02" }, message: "invalid input", operation: "execute" }) });
  const shutdown = new SqlError({ reason: new UnknownError({ cause: { code: "57P01" }, message: "terminating connection due to administrator command", operation: "execute" }) });
  // a network timeout reported by its code only, wrapped twice, as a driver or runtime may hand it on
  const etimedout = new SqlError({ reason: new UnknownError({ cause: new Error("query failed", { cause: Object.assign(new Error("read timed out"), { code: "ETIMEDOUT" }) }), message: "failed", operation: "execute" }) });

  test("connection failures of every kind, timeouts included, and a server that cannot serve mean unavailable; a failed statement does not", () => {
    const timeout = (cause: Error, operation: string) => new SqlError({ reason: new ConnectionError({ cause, message: "timed out", operation }) });

    expect(meansUnreachable(connection)).toBe(true);
    expect(meansUnreachable(shutdown)).toBe(true);
    expect(meansUnreachable(etimedout)).toBe(true);
    // @effect/sql-pg 4.1.2's own wording for its connect and pool timeouts, and this module's stall kill
    expect(meansUnreachable(timeout(new Error("Connection timed out"), "connect"))).toBe(true);
    expect(meansUnreachable(timeout(new Error("Timed out waiting for a pooled connection"), "acquireConnection"))).toBe(true);
    expect(meansUnreachable(new SqlError({ reason: new UnknownError({ cause: new StalledConnection("the database sent nothing for 9 s after a write"), message: "x", operation: "query" }) }))).toBe(true);
    expect(meansUnreachable(syntax)).toBe(false);
  });

  for (const [label, error] of [
    ["a refused connection", connection],
    ["ETIMEDOUT by code", etimedout],
  ] as const) {
    test(`${label} fails this request's statement and its later ones at once, and nothing else: the next request tries the database`, async () => {
      const guard = guardFor();
      let ran = 0;

      const failing = Effect.suspend(() => {
        ran++;

        return Effect.fail(error);
      });

      const first = await Effect.runPromise(Effect.flip(guard.statement("getPackage", failing)));

      expect(isDatabaseUnavailable(first)).toBe(true);
      const second = await Effect.runPromise(Effect.flip(guard.statement("getPackage", failing)));

      expect(isDatabaseUnavailable(second)).toBe(true);
      // the second statement of the same request was never sent
      expect(ran).toBe(1);
      // the next request's guard knows nothing of it
      expect(await Effect.runPromise(guardFor().statement("getPackage", Effect.succeed(7)))).toBe(7);
    });
  }

  test("a statement that fails on a reachable database is an ordinary store error, and the request goes on", async () => {
    const guard = guardFor();
    const err = await Effect.runPromise(Effect.flip(guard.statement("insert", Effect.fail(syntax))));

    expect(isDatabaseUnavailable(err)).toBe(false);
    expect(await Effect.runPromise(guard.statement("next", Effect.succeed(1)))).toBe(1);
  });

  test("a statement that does not answer is stopped at the statement timeout, as unavailable for this request only", async () => {
    const guard = guardFor({ statementMs: 300 });
    const t0 = performance.now();
    const err = await Effect.runPromise(Effect.flip(guard.statement("hang", Effect.never)));

    expect(isDatabaseUnavailable(err)).toBe(true);
    expect(performance.now() - t0).toBeLessThan(1_000);
    expect(await Effect.runPromise(guardFor().statement("next request", Effect.succeed(2)))).toBe(2);
  });

  test("the default statement timeout is the documented 8 s", () => {
    expect(STATEMENT_TIMEOUT_MS).toBe(8_000);
  });
});

describe("the health summary", () => {
  const up: Check = { status: "up", ms: 1, detail: "answers" };
  const down: Check = { status: "down", ms: 1, detail: "does not answer" };

  function checks(over: Partial<Record<"database" | "r2" | "blocklist" | "queue" | "upstream", Check>>): Health["checks"] {
    return {
      database: over.database ?? up,
      r2: over.r2 ?? up,
      blocklist: { ...(over.blocklist ?? up), syncedAt: null },
      queue: { ...(over.queue ?? up), lastConsumedAt: null },
      upstream: over.upstream ?? up,
    };
  }

  test("installs work with the database, or for npm's packages with the synced block list, and need npm", () => {
    expect(summarize(checks({}), true)).toEqual({ status: "ok", installs: "working" });
    expect(summarize(checks({ queue: down }), true)).toEqual({ status: "degraded", installs: "working" });
    expect(summarize(checks({ database: down }), true)).toEqual({ status: "degraded", installs: "npm-only" });
    expect(summarize(checks({ database: down, blocklist: down }), true)).toEqual({ status: "down", installs: "down" });
    expect(summarize(checks({ database: down, r2: down }), true)).toEqual({ status: "down", installs: "down" });
    expect(summarize(checks({ upstream: down }), true)).toEqual({ status: "down", installs: "down" });
    // a registry that proxies nothing needs only its database
    expect(summarize(checks({ upstream: { status: "unknown", ms: null, detail: "none" } }), false)).toEqual({ status: "ok", installs: "working" });
  });
});
