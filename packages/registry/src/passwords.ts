// Password checks for legacy accounts (npm adduser, and the password second factor). Wrong guesses are counted
// per account in Postgres, so neither a restart nor another Worker isolate resets them. Hashes are scrypt, in
// Better Auth's format.
import { Effect } from "effect";
import { verifyPassword } from "better-auth/crypto";
import { Store } from "./db.ts";
import type { StoreError } from "./errors.ts";

/** Wrong passwords allowed per account within PASSWORD_WINDOW_MS before every attempt is refused. */
export const MAX_PASSWORD_FAILURES = 10;
export const PASSWORD_WINDOW_MS = 15 * 60 * 1000;

export type PasswordCheck = "ok" | "bad" | "locked";

/** Checks `password` against `hash` unless the account is locked out; counts a wrong one and clears the count on success. */
export const checkPassword = (input: { user: string; password: string; hash: string; now: number }): Effect.Effect<PasswordCheck, StoreError, Store> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const { user, now } = input;
    const f = yield* store.passwordFailures(user);
    const live = f !== null && now - f.since < PASSWORD_WINDOW_MS;

    if (live && f.count >= MAX_PASSWORD_FAILURES) return "locked";
    const ok = input.hash !== "" && (yield* Effect.promise(() => verifyPassword({ hash: input.hash, password: input.password }).catch(() => false)));

    if (ok) {
      if (f) yield* store.setPasswordFailures(user, null);

      return "ok";
    }

    yield* store.setPasswordFailures(user, live ? { count: f.count + 1, since: f.since } : { count: 1, since: now });

    return "bad";
  });

export const LOCKED_MESSAGE = `Too many wrong passwords for this account. Wait ${PASSWORD_WINDOW_MS / 60_000} minutes and try again.`;
