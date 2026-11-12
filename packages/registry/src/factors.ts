// The second-factor ledger, in the registry's SQLite file so every process sees the same state:
// - one attempt budget per account across every TOTP and recovery-code check, reserved before verifying;
// - the last accepted TOTP time step, so a code (or an older one still in the window) works once;
// - passkey checks, bound to the session the passkey sign-in made and used for one action;
// - website confirmations of one named CLI command, used once.
import type { Database } from "bun:sqlite";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";

export const MAX_FAILURES = 5;
export const FAILURE_WINDOW_MS = 15 * 60_000;

/** How long a passkey check on the website stays usable for the one action it is spent on. */
export const PASSKEY_PROOF_MS = 5 * 60_000;

/** How long a website confirmation of a CLI command waits for that command. */
export const GRANT_MS = 10 * 60_000;
const STEP_MS = 30_000;

export type SixDigits = string & { readonly __brand: "SixDigits" };

/** Exactly six ASCII digits once surrounding whitespace is trimmed. */
export function parseSixDigits(raw: string): SixDigits | null {
  const t = raw.trim();

  return isSixDigits(t) ? t : null;
}

function isSixDigits(s: string): s is SixDigits {
  return /^[0-9]{6}$/.test(s);
}

/** RFC 4226 HOTP, SHA-1, six digits. */
export function hotp(key: Uint8Array, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", key).update(msg).digest();
  const offset = (h[h.length - 1] ?? 0) & 0x0f;

  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** The 30s time step this code belongs to (one step of drift either way), or null. */
export function matchingStep(input: { key: Uint8Array; code: SixDigits; at: number }): number | null {
  const now = Math.floor(input.at / STEP_MS);
  const given = Buffer.from(input.code);
  let found: number | null = null;

  for (const step of [now - 1, now, now + 1]) {
    // compare every candidate so timing does not say which step matched
    if (timingSafeEqual(Buffer.from(hotp(input.key, step)), given) && found === null) found = step;
  }

  return found;
}

function hashOf(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS factor_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_user_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS factor_attempts_user ON factor_attempts(auth_user_id, at);
CREATE TABLE IF NOT EXISTS totp_steps (
  auth_user_id TEXT PRIMARY KEY,
  step INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS passkey_proofs (
  session_hash TEXT PRIMARY KEY,
  auth_user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  used_for TEXT
);
CREATE TABLE IF NOT EXISTS cli_grants (
  id TEXT PRIMARY KEY,
  auth_user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS cli_grants_user ON cli_grants(auth_user_id, action);
`;

export type Reservation = { kind: "locked" } | { kind: "reserved"; id: number };

export class FactorLedger {
  constructor(private readonly db: Database) {
    db.exec("PRAGMA busy_timeout = 5000;");
    db.exec(SCHEMA);
  }

  /**
   * Takes one attempt from the account's budget before a code is checked. Unsettled attempts count, so
   * concurrent guesses cannot all see a fresh budget; an attempt left pending by a crash expires with the window.
   */
  reserve(input: { authUserId: string; at: number }): Reservation {
    const run = this.db.transaction((): Reservation => {
      const row = this.db
        .query("SELECT count(*) AS n FROM factor_attempts WHERE auth_user_id = ? AND at > ? AND outcome != 'ok'")
        .get(input.authUserId, input.at - FAILURE_WINDOW_MS);

      const used = z.object({ n: z.number() }).parse(row).n;

      if (used >= MAX_FAILURES) return { kind: "locked" };
      const ins = this.db.query("INSERT INTO factor_attempts (auth_user_id, at, outcome) VALUES (?, ?, 'pending')").run(input.authUserId, input.at);

      return { kind: "reserved", id: Number(ins.lastInsertRowid) };
    });

    return run.immediate();
  }

  /** Records how a reserved attempt ended. A success clears the account's earlier failures. */
  settle(input: { id: number; authUserId: string; ok: boolean }): void {
    this.db.transaction(() => {
      this.db.query("UPDATE factor_attempts SET outcome = ? WHERE id = ?").run(input.ok ? "ok" : "bad", input.id);

      if (input.ok) this.db.query("DELETE FROM factor_attempts WHERE auth_user_id = ? AND outcome = 'bad'").run(input.authUserId);
    }).immediate();
  }

  /** Accepts a TOTP time step once: false when this step, or a later one, was already accepted. */
  acceptStep(input: { authUserId: string; step: number }): boolean {
    return this.db
      .transaction((): boolean => {
        const moved = this.db.query("UPDATE totp_steps SET step = ? WHERE auth_user_id = ? AND step < ?").run(input.step, input.authUserId, input.step);

        if (moved.changes === 1) return true;
        const inserted = this.db.query("INSERT OR IGNORE INTO totp_steps (auth_user_id, step) VALUES (?, ?)").run(input.authUserId, input.step);

        return inserted.changes === 1;
      })
      .immediate();
  }

  /** A passkey check made the session `sessionToken`; it can authorize one action from that session. */
  recordPasskeyProof(input: { sessionToken: string; authUserId: string; at: number }): void {
    this.db
      .query("INSERT OR REPLACE INTO passkey_proofs (session_hash, auth_user_id, created_at, expires_at, used_at, used_for) VALUES (?, ?, ?, ?, NULL, NULL)")
      .run(hashOf(input.sessionToken), input.authUserId, input.at, input.at + PASSKEY_PROOF_MS);
  }

  /** Spends this session's passkey check on `purpose`. False when there is none, it expired, or it was spent. */
  consumePasskeyProof(input: { sessionToken: string; authUserId: string; purpose: string; at: number }): boolean {
    const r = this.db
      .query("UPDATE passkey_proofs SET used_at = ?, used_for = ? WHERE session_hash = ? AND auth_user_id = ? AND used_at IS NULL AND created_at <= ? AND expires_at > ?")
      .run(input.at, input.purpose, hashOf(input.sessionToken), input.authUserId, input.at, input.at);

    return r.changes === 1;
  }

  /** A person confirmed one CLI command on the website. */
  grant(input: { authUserId: string; action: string; at: number }) {
    const expiresAt = input.at + GRANT_MS;
    this.db
      .query("INSERT INTO cli_grants (id, auth_user_id, action, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)")
      .run(randomBytes(16).toString("base64url"), input.authUserId, input.action, input.at, expiresAt);

    return { expiresAt };
  }

  /** Uses a confirmation of exactly this command, once. */
  consumeGrant(input: { authUserId: string; action: string; at: number }): boolean {
    return this.db
      .transaction((): boolean => {
        const row = this.db
          .query("SELECT id FROM cli_grants WHERE auth_user_id = ? AND action = ? AND used_at IS NULL AND created_at <= ? AND expires_at > ? ORDER BY created_at LIMIT 1")
          .get(input.authUserId, input.action, input.at, input.at);

        if (!row) return false;
        const { id } = z.object({ id: z.string() }).parse(row);

        return this.db.query("UPDATE cli_grants SET used_at = ? WHERE id = ? AND used_at IS NULL").run(input.at, id).changes === 1;
      })
      .immediate();
  }
}
