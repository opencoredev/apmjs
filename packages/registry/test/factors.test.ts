import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FactorLedger, GRANT_MS, MAX_FAILURES, PASSKEY_PROOF_MS, matchingStep, parseSixDigits, type SixDigits } from "../src/factors.ts";
import { actionKey, commandLine, confirmUrl, LiveAction } from "../src/actions.ts";
import { parseProofHeader } from "../src/auth.ts";
import { legacyAuthRefusal, isPublicHttps } from "../src/startup.ts";
import { typedConfirmationReason } from "../src/account.ts";

function withDb<T>(fn: (path: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "apm-factors-"));

  try {
    return fn(join(dir, "registry.sqlite"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function sixDigits(s: string): SixDigits {
  const c = parseSixDigits(s);

  if (!c) throw new Error(`not six digits: ${s}`);

  return c;
}

/** RFC 6238 reference: what an authenticator app shows. */
function referenceTotp(key: Uint8Array, at: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const offset = (h[h.length - 1] ?? 0) & 0x0f;

  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

describe("six-digit codes", () => {
  test("only exactly six ASCII digits after trimming", () => {
    expect(parseSixDigits(" 123456 ")).toBe(sixDigits("123456"));

    for (const bad of ["", " ", "12345", "1234567", "12 3456", "abcdef", "１２３４５６", "12345\n6"]) expect(parseSixDigits(bad)).toBeNull();
  });
});

describe("TOTP steps", () => {
  test("matches the current step and one either side, nothing further", () => {
    const key = new TextEncoder().encode("a-secret-of-thirty-two-characters");
    const at = Date.parse("2026-05-01T12:00:10Z");
    const step = Math.floor(at / 30_000);
    expect(matchingStep({ key, code: sixDigits(referenceTotp(key, at)), at })).toBe(step);
    expect(matchingStep({ key, code: sixDigits(referenceTotp(key, at - 30_000)), at })).toBe(step - 1);
    expect(matchingStep({ key, code: sixDigits(referenceTotp(key, at + 30_000)), at })).toBe(step + 1);
    const far = referenceTotp(key, at - 90_000);
    const near = new Set([-1, 0, 1].map((d) => referenceTotp(key, at + d * 30_000)));

    if (!near.has(far)) expect(matchingStep({ key, code: sixDigits(far), at })).toBeNull();
  });
});

describe("attempt budget", () => {
  test("reserved attempts count before they settle, so concurrent guesses share one budget", () => {
    withDb((path) => {
      const ledger = new FactorLedger(new Database(path, { create: true }));
      const at = 1_000_000;
      const held = Array.from({ length: MAX_FAILURES }, () => ledger.reserve({ authUserId: "u", at }));
      expect(held.every((r) => r.kind === "reserved")).toBe(true);
      expect(ledger.reserve({ authUserId: "u", at }).kind).toBe("locked");
      expect(ledger.reserve({ authUserId: "other", at }).kind).toBe("reserved");
    });
  });

  test("the budget survives a restart and frees up after the window", () => {
    withDb((path) => {
      const first = new Database(path, { create: true });
      const ledger = new FactorLedger(first);

      for (let i = 0; i < MAX_FAILURES; i++) {
        const r = ledger.reserve({ authUserId: "u", at: 0 });

        if (r.kind === "reserved") ledger.settle({ id: r.id, authUserId: "u", ok: false });
      }

      first.close();
      const again = new FactorLedger(new Database(path));
      expect(again.reserve({ authUserId: "u", at: 60_000 }).kind).toBe("locked");
      expect(again.reserve({ authUserId: "u", at: 16 * 60_000 }).kind).toBe("reserved");
    });
  });

  test("a success clears earlier failures", () => {
    withDb((path) => {
      const ledger = new FactorLedger(new Database(path, { create: true }));

      for (let i = 0; i < MAX_FAILURES - 1; i++) {
        const r = ledger.reserve({ authUserId: "u", at: 0 });

        if (r.kind === "reserved") ledger.settle({ id: r.id, authUserId: "u", ok: false });
      }

      const ok = ledger.reserve({ authUserId: "u", at: 0 });

      if (ok.kind !== "reserved") throw new Error("expected a reservation");
      ledger.settle({ id: ok.id, authUserId: "u", ok: true });
      expect(ledger.reserve({ authUserId: "u", at: 0 }).kind).toBe("reserved");
    });
  });
});

describe("accepted steps", () => {
  test("a step is accepted once, and an older step after a newer one is refused", () => {
    withDb((path) => {
      const ledger = new FactorLedger(new Database(path, { create: true }));
      expect(ledger.acceptStep({ authUserId: "u", step: 100 })).toBe(true);
      expect(ledger.acceptStep({ authUserId: "u", step: 100 })).toBe(false);
      expect(ledger.acceptStep({ authUserId: "u", step: 99 })).toBe(false);
      expect(ledger.acceptStep({ authUserId: "u", step: 101 })).toBe(true);
      expect(ledger.acceptStep({ authUserId: "v", step: 100 })).toBe(true);
    });
  });
});

describe("passkey proofs and CLI confirmations", () => {
  test("a passkey check is bound to its session and spent on one action", () => {
    withDb((path) => {
      const ledger = new FactorLedger(new Database(path, { create: true }));
      ledger.recordPasskeyProof({ sessionToken: "s1", authUserId: "u", at: 0 });
      expect(ledger.consumePasskeyProof({ sessionToken: "s2", authUserId: "u", purpose: "approve:a", at: 1 })).toBe(false);
      expect(ledger.consumePasskeyProof({ sessionToken: "s1", authUserId: "other", purpose: "approve:a", at: 1 })).toBe(false);
      expect(ledger.consumePasskeyProof({ sessionToken: "s1", authUserId: "u", purpose: "approve:a", at: 1 })).toBe(true);
      expect(ledger.consumePasskeyProof({ sessionToken: "s1", authUserId: "u", purpose: "approve:b", at: 2 })).toBe(false);
      ledger.recordPasskeyProof({ sessionToken: "s3", authUserId: "u", at: 0 });
      expect(ledger.consumePasskeyProof({ sessionToken: "s3", authUserId: "u", purpose: "x", at: PASSKEY_PROOF_MS })).toBe(false);
    });
  });

  test("a CLI confirmation covers its named command once, within its window", () => {
    withDb((path) => {
      const ledger = new FactorLedger(new Database(path, { create: true }));
      const revoke = actionKey({ kind: "revoke", name: "@a/b", version: "1.0.0" });
      const other = actionKey({ kind: "revoke", name: "@a/b", version: "1.0.1" });
      ledger.grant({ authUserId: "u", action: revoke, at: 0 });
      expect(ledger.consumeGrant({ authUserId: "u", action: other, at: 1 })).toBe(false);
      expect(ledger.consumeGrant({ authUserId: "v", action: revoke, at: 1 })).toBe(false);
      expect(ledger.consumeGrant({ authUserId: "u", action: revoke, at: 1 })).toBe(true);
      expect(ledger.consumeGrant({ authUserId: "u", action: revoke, at: 2 })).toBe(false);
      ledger.grant({ authUserId: "u", action: revoke, at: 0 });
      expect(ledger.consumeGrant({ authUserId: "u", action: revoke, at: GRANT_MS })).toBe(false);
    });
  });
});

describe("actions", () => {
  test("keys tell commands apart and the confirm link round-trips", () => {
    const a: LiveAction = { kind: "dist-tag", name: "@a/b", tag: "latest", version: "1.0.0" };
    expect(actionKey(a)).not.toBe(actionKey({ ...a, version: null }));
    expect(commandLine(a)).toBe("npm dist-tag add @a/b@1.0.0 latest");
    const url = new URL(confirmUrl("https://apmjs.dev/", a));
    const back = LiveAction.parse(JSON.parse(Buffer.from(url.searchParams.get("confirm") ?? "", "base64url").toString()));
    expect(actionKey(back)).toBe(actionKey(a));
  });
});

describe("proof header", () => {
  test("parses totp, recovery and passkey proofs and nothing else", () => {
    expect(parseProofHeader("totp:123456")).toEqual({ kind: "totp", code: sixDigits("123456") });
    expect(parseProofHeader("recovery:abCDe-12345")).toEqual({ kind: "recovery", code: "abCDe-12345" });
    expect(parseProofHeader("passkey")).toEqual({ kind: "passkey" });

    for (const bad of [null, "", "totp: ", "totp:12345", "recovery:", "recovery:a b", "password:x"]) expect(parseProofHeader(bad)).toBeNull();
  });
});

describe("startup", () => {
  test("legacy auth on a public https URL needs APM_ALLOW_LEGACY_IN_PROD", () => {
    expect(legacyAuthRefusal({ APM_LEGACY_AUTH: "1", APM_PUBLIC_URL: "https://apmjs.dev/" })).toContain("APM_ALLOW_LEGACY_IN_PROD");
    expect(legacyAuthRefusal({ APM_LEGACY_AUTH: "1", APM_PUBLIC_URL: "https://apmjs.dev/", APM_ALLOW_LEGACY_IN_PROD: "1" })).toBeNull();
    expect(legacyAuthRefusal({ APM_LEGACY_AUTH: "1", APM_PUBLIC_URL: "http://apmjs.dev/" })).toBeNull();
    expect(legacyAuthRefusal({ APM_LEGACY_AUTH: "0", APM_PUBLIC_URL: "https://apmjs.dev/" })).toBeNull();
    expect(legacyAuthRefusal({ APM_LEGACY_AUTH: "1" })).toBeNull();

    for (const local of ["https://localhost:3000/", "https://127.0.0.1/", "https://[::1]:8443/", "https://app.localhost/"]) expect(isPublicHttps(local)).toBe(false);
    expect(isPublicHttps("not a url")).toBe(false);
  });
});

describe("typed confirmation", () => {
  test("needed when the analysis is incomplete or the score is under the floor", () => {
    expect(typedConfirmationReason({ report: null, filesListed: true })).toMatch(/did not finish/);
    expect(typedConfirmationReason({ report: { score: 90 }, filesListed: false })).toMatch(/did not finish/);
    expect(typedConfirmationReason({ report: { score: 12 }, filesListed: true })).toMatch(/under the floor/);
    expect(typedConfirmationReason({ report: { score: 90 }, filesListed: true })).toBeNull();
  });
});
