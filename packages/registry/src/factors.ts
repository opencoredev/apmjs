// Second-factor codes: parsing, RFC 4226/6238 checks and the proof a person offers for one action. Pure; the
// ledger that remembers attempts, accepted steps, passkey checks and confirmations is ledger.ts.
import { createHmac, timingSafeEqual } from "node:crypto";

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

/** A second factor offered for one action: a TOTP code, a recovery code, or this session's passkey check. */
export type FactorProof = { kind: "totp"; code: SixDigits } | { kind: "recovery"; code: string } | { kind: "passkey" };

export type ProofCheck = { kind: "ok" } | { kind: "bad" } | { kind: "reused" } | { kind: "none" } | { kind: "locked" };

/** The header the website sends the existing factor in, for account changes that need it. */
export const PROOF_HEADER = "x-apm-second-factor";

/** Parses the proof header: `totp:123456`, `recovery:abcde-12345` or `passkey`. */
export function parseProofHeader(value: string | null): FactorProof | null {
  if (value === null) return null;
  const v = value.trim();

  if (v === "passkey") return { kind: "passkey" };

  if (v.startsWith("totp:")) {
    const code = parseSixDigits(v.slice(5));

    return code ? { kind: "totp", code } : null;
  }

  if (v.startsWith("recovery:")) {
    const code = v.slice(9).trim();

    return /^[A-Za-z0-9-]{6,64}$/.test(code) ? { kind: "recovery", code } : null;
  }

  return null;
}
