// Launch review item 7: wrong passwords checked at the same time are all counted.
import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/db.ts";
import { checkPassword, MAX_PASSWORD_FAILURES } from "../src/passwords.ts";

const dir = mkdtempSync(join(tmpdir(), "apm-passwords-unit-"));
const store = new Store(dir);

afterAll(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("concurrent wrong passwords each count, and the next attempt is locked", async () => {
  const hash = await Bun.password.hash("correct-horse-battery");
  const now = Date.parse("2026-11-12T00:00:00Z");
  const results = await Promise.all(Array.from({ length: MAX_PASSWORD_FAILURES }, (_, i) => checkPassword({ store, user: "racer", password: `wrong-${i}`, hash, now })));

  expect(results.every((r) => r === "bad")).toBe(true);
  expect(store.passwordFailures("racer")?.count).toBe(MAX_PASSWORD_FAILURES);
  expect(await checkPassword({ store, user: "racer", password: "correct-horse-battery", hash, now })).toBe("locked");
});
