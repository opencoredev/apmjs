// Launch review item 7: wrong passwords checked at the same time are all counted.
import { expect, test } from "bun:test";
import { Effect } from "effect";
import { hashPassword } from "better-auth/crypto";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store } from "../src/db.ts";
import { checkPassword, MAX_PASSWORD_FAILURES } from "../src/passwords.ts";

test("concurrent wrong passwords each count, and the next attempt is locked", async () => {
  const db = await freshDatabase();

  try {
    const hash = await hashPassword("correct-horse-battery");
    const now = Date.parse("2026-11-12T00:00:00Z");
    const store = Store.postgres(db.url);
    // each guess on its own connection, as concurrent Worker requests would be
    const guess = (password: string) => Effect.runPromise(checkPassword({ user: "racer", password, hash, now }).pipe(Effect.provide(store), Effect.scoped));
    const results = await Promise.all(Array.from({ length: MAX_PASSWORD_FAILURES }, (_, i) => guess(`wrong-${i}`)));

    expect(results.every((r) => r === "bad")).toBe(true);
    const failures = await Effect.runPromise(Effect.flatMap(Store, (s) => s.passwordFailures("racer")).pipe(Effect.provide(store), Effect.scoped));

    expect(failures?.count).toBe(MAX_PASSWORD_FAILURES);
    expect(await guess("correct-horse-battery")).toBe("locked");
  } finally {
    await db.drop();
  }
});
