// Password checks for legacy accounts (npm adduser, and the password second factor). Wrong guesses are
// counted per account in the database, so a restart does not reset them.
import type { Store } from "./db.ts";

/** Wrong passwords allowed per account within PASSWORD_WINDOW_MS before every attempt is refused. */
export const MAX_PASSWORD_FAILURES = 10;
export const PASSWORD_WINDOW_MS = 15 * 60 * 1000;

export type PasswordCheck = "ok" | "bad" | "locked";

/**
 * Checks `password` against `hash` unless the account is locked out. The attempt is counted as a failure before
 * the (slow) hash check, atomically, so concurrent wrong guesses are all counted; a correct one clears the count.
 */
export async function checkPassword(input: { store: Store; user: string; password: string; hash: string; now: number }): Promise<PasswordCheck> {
  const { store, user, now } = input;

  if (store.reservePasswordAttempt({ user, now, max: MAX_PASSWORD_FAILURES, windowMs: PASSWORD_WINDOW_MS }) === "locked") return "locked";
  const ok = input.hash !== "" && (await Bun.password.verify(input.password, input.hash));

  if (ok) store.setPasswordFailures(user, null);

  return ok ? "ok" : "bad";
}

export const LOCKED_MESSAGE = `Too many wrong passwords for this account. Wait ${PASSWORD_WINDOW_MS / 60_000} minutes and try again.`;
