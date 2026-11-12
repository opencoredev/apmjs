import { describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { Effect } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { CHALLENGE_MS, CONFIRMATION_MS, GRANT_MS, MAX_FAILURES, matchingStep, parseProofHeader, parseSixDigits, type SixDigits } from "../src/factors.ts";
import { actionKey, commandLine, confirmUrl, LiveAction, sessionActionKey, type SessionAction } from "../src/actions.ts";
import { Store, type StoreApi } from "../src/db.ts";
import type { StoreError } from "../src/errors.ts";
import { legacyAuthRefusal, isPublicHttps } from "../src/startup.ts";
import { typedConfirmationReason } from "../src/approval.ts";

/** The second-factor ledger lives in the registry's Postgres: each test gets a fresh, migrated database. */
async function withLedger(fn: (ledger: StoreApi) => Promise<void>): Promise<void> {
  const db = await freshDatabase();

  try {
    await Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* Store;
        yield* Effect.promise(() => fn(store));
      }).pipe(Effect.provide(Store.postgres(db.url)), Effect.scoped),
    );
  } finally {
    await db.drop();
  }
}

/** A second connection to the same database, as another Worker isolate (or a restart) would open. */
async function otherConnection<A>(url: string, fn: (ledger: StoreApi) => Effect.Effect<A, StoreError>): Promise<A> {
  return Effect.runPromise(Effect.flatMap(Store, fn).pipe(Effect.provide(Store.postgres(url)), Effect.scoped));
}

const run = <A>(effect: Effect.Effect<A, StoreError>): Promise<A> => Effect.runPromise(effect);

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
  test("reserved attempts count before they settle, so concurrent guesses share one budget", async () => {
    await withLedger(async (ledger) => {
      const at = 1_000_000;
      const held = await Promise.all(Array.from({ length: MAX_FAILURES }, () => run(ledger.reserveAttempt({ authUserId: "u", at }))));
      expect(held.every((r) => r.kind === "reserved")).toBe(true);
      expect((await run(ledger.reserveAttempt({ authUserId: "u", at }))).kind).toBe("locked");
      expect((await run(ledger.reserveAttempt({ authUserId: "other", at }))).kind).toBe("reserved");
    });
  });

  test("the budget is shared by every connection and frees up after the window", async () => {
    const db = await freshDatabase();

    try {
      await otherConnection(db.url, (ledger) =>
        Effect.gen(function* () {
          for (let i = 0; i < MAX_FAILURES; i++) {
            const r = yield* ledger.reserveAttempt({ authUserId: "u", at: 0 });

            if (r.kind === "reserved") yield* ledger.settleAttempt({ id: r.id, authUserId: "u", ok: false });
          }
        }),
      );
      expect((await otherConnection(db.url, (ledger) => ledger.reserveAttempt({ authUserId: "u", at: 60_000 }))).kind).toBe("locked");
      expect((await otherConnection(db.url, (ledger) => ledger.reserveAttempt({ authUserId: "u", at: 16 * 60_000 }))).kind).toBe("reserved");
    } finally {
      await db.drop();
    }
  });

  test("a success clears earlier failures", async () => {
    await withLedger(async (ledger) => {
      for (let i = 0; i < MAX_FAILURES - 1; i++) {
        const r = await run(ledger.reserveAttempt({ authUserId: "u", at: 0 }));

        if (r.kind === "reserved") await run(ledger.settleAttempt({ id: r.id, authUserId: "u", ok: false }));
      }

      const ok = await run(ledger.reserveAttempt({ authUserId: "u", at: 0 }));

      if (ok.kind !== "reserved") throw new Error("expected a reservation");
      await run(ledger.settleAttempt({ id: ok.id, authUserId: "u", ok: true }));
      expect((await run(ledger.reserveAttempt({ authUserId: "u", at: 0 }))).kind).toBe("reserved");
    });
  });
});

describe("accepted steps", () => {
  test("a step is accepted once, and an older step after a newer one is refused", async () => {
    await withLedger(async (ledger) => {
      expect(await run(ledger.acceptStep({ authUserId: "u", step: 100 }))).toBe(true);
      expect(await run(ledger.acceptStep({ authUserId: "u", step: 100 }))).toBe(false);
      expect(await run(ledger.acceptStep({ authUserId: "u", step: 99 }))).toBe(false);
      expect(await run(ledger.acceptStep({ authUserId: "u", step: 101 }))).toBe(true);
      expect(await run(ledger.acceptStep({ authUserId: "v", step: 100 }))).toBe(true);
    });
  });
});

const evidence = { name: "a", version: "1.0.0", digest: "sha512-x", scorer: "apm-score-v8", signal: "credential-access", file: "index.js", line: 1 };

describe("confirmations of one website action", () => {
  test("a confirmation is spent only by its own session and action, once, within its window", async () => {
    await withLedger(async (ledger) => {
      const dismissA = sessionActionKey({ kind: "evidence-dismiss", ...evidence, reason: "a deny list" });
      const dismissB = sessionActionKey({ kind: "evidence-dismiss", ...evidence, line: 2, reason: "a deny list" });
      const c = await run(ledger.issueConfirmation({ sessionToken: "s1", authUserId: "u", action: dismissA, factor: "passkey", at: 0 }));

      expect(c.expiresAt).toBe(CONFIRMATION_MS);
      expect(await run(ledger.consumeConfirmation({ id: c.id, sessionToken: "s2", authUserId: "u", action: dismissA, at: 1 }))).toBe(false);
      expect(await run(ledger.consumeConfirmation({ id: c.id, sessionToken: "s1", authUserId: "other", action: dismissA, at: 1 }))).toBe(false);
      expect(await run(ledger.consumeConfirmation({ id: c.id, sessionToken: "s1", authUserId: "u", action: dismissB, at: 1 }))).toBe(false);
      expect(await run(ledger.consumeConfirmation({ id: c.id, sessionToken: "s1", authUserId: "u", action: dismissA, at: 1 }))).toBe(true);
      expect(await run(ledger.consumeConfirmation({ id: c.id, sessionToken: "s1", authUserId: "u", action: dismissA, at: 2 }))).toBe(false);
      const late = await run(ledger.issueConfirmation({ sessionToken: "s1", authUserId: "u", action: dismissA, factor: "totp", at: 0 }));

      expect(await run(ledger.consumeConfirmation({ id: late.id, sessionToken: "s1", authUserId: "u", action: dismissA, at: CONFIRMATION_MS }))).toBe(false);
    });
  });

  test("a passkey challenge is answerable once, for the session and action it was made for", async () => {
    await withLedger(async (ledger) => {
      const approve = sessionActionKey({ kind: "approve", id: "abc" });
      const id = await run(ledger.addPasskeyChallenge({ sessionToken: "s1", authUserId: "u", action: approve, challenge: "ch", at: 0 }));

      expect(await run(ledger.takePasskeyChallenge({ id, sessionToken: "s1", authUserId: "u", action: sessionActionKey({ kind: "approve", id: "abd" }), at: 1 }))).toBeNull();
      expect(await run(ledger.takePasskeyChallenge({ id, sessionToken: "s2", authUserId: "u", action: approve, at: 1 }))).toBeNull();
      expect(await run(ledger.takePasskeyChallenge({ id, sessionToken: "s1", authUserId: "u", action: approve, at: 1 }))).toBe("ch");
      expect(await run(ledger.takePasskeyChallenge({ id, sessionToken: "s1", authUserId: "u", action: approve, at: 2 }))).toBeNull();
      const old = await run(ledger.addPasskeyChallenge({ sessionToken: "s1", authUserId: "u", action: approve, challenge: "ch2", at: 0 }));

      expect(await run(ledger.takePasskeyChallenge({ id: old, sessionToken: "s1", authUserId: "u", action: approve, at: CHALLENGE_MS }))).toBeNull();
    });
  });

  test("expired challenges and confirmations are purged; live ones stay usable", async () => {
    await withLedger(async (ledger) => {
      const approve = sessionActionKey({ kind: "approve", id: "abc" });
      const old = await run(ledger.issueConfirmation({ sessionToken: "s1", authUserId: "u", action: approve, factor: "totp", at: 0 }));
      const live = await run(ledger.issueConfirmation({ sessionToken: "s1", authUserId: "u", action: approve, factor: "totp", at: 10 * CONFIRMATION_MS }));
      const challenge = await run(ledger.addPasskeyChallenge({ sessionToken: "s1", authUserId: "u", action: approve, challenge: "ch", at: 10 * CONFIRMATION_MS }));

      await run(ledger.purgeConfirmations(10 * CONFIRMATION_MS));
      expect(await run(ledger.consumeConfirmation({ id: old.id, sessionToken: "s1", authUserId: "u", action: approve, at: 1 }))).toBe(false);
      expect(await run(ledger.consumeConfirmation({ id: live.id, sessionToken: "s1", authUserId: "u", action: approve, at: 10 * CONFIRMATION_MS + 1 }))).toBe(true);
      expect(await run(ledger.takePasskeyChallenge({ id: challenge, sessionToken: "s1", authUserId: "u", action: approve, at: 10 * CONFIRMATION_MS + 1 }))).toBe("ch");
    });
  });

  test("keys tell every parameter apart: the evidence key, the reason, the decision, the command", () => {
    const keys = (
      [
        { kind: "evidence-dismiss", ...evidence, reason: "r" },
        { kind: "evidence-dismiss", ...evidence, reason: "r2" },
        { kind: "evidence-dismiss", ...evidence, digest: "sha512-y", reason: "r" },
        { kind: "evidence-dismiss", ...evidence, scorer: "apm-score-v7", reason: "r" },
        { kind: "evidence-dismiss", ...evidence, signal: "network", reason: "r" },
        { kind: "evidence-dismiss", ...evidence, file: "b.js", reason: "r" },
        { kind: "evidence-restore", ...evidence, reason: "r" },
        { kind: "review-decision", name: "a", version: "1.0.0", digest: "d", decision: "confirm", note: "" },
        { kind: "review-decision", name: "a", version: "1.0.0", digest: "d", decision: "dismiss", note: "" },
        { kind: "approve", id: "abc" },
        { kind: "cli-confirm", command: { kind: "revoke", name: "a", version: "1.0.0" } },
        { kind: "cli-confirm", command: { kind: "restore", name: "a", version: "1.0.0" } },
        { kind: "account", change: "two-factor/disable" },
        { kind: "account", change: "link-social" },
      ] satisfies SessionAction[]
    ).map(sessionActionKey);

    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("CLI confirmations", () => {
  test("a CLI confirmation covers its named command once, within its window", async () => {
    await withLedger(async (ledger) => {
      const revoke = actionKey({ kind: "revoke", name: "@a/b", version: "1.0.0" });
      const other = actionKey({ kind: "revoke", name: "@a/b", version: "1.0.1" });
      await run(ledger.grant({ authUserId: "u", action: revoke, at: 0 }));
      expect(await run(ledger.consumeGrant({ authUserId: "u", action: other, at: 1 }))).toBe(false);
      expect(await run(ledger.consumeGrant({ authUserId: "v", action: revoke, at: 1 }))).toBe(false);
      expect(await run(ledger.consumeGrant({ authUserId: "u", action: revoke, at: 1 }))).toBe(true);
      expect(await run(ledger.consumeGrant({ authUserId: "u", action: revoke, at: 2 }))).toBe(false);
      await run(ledger.grant({ authUserId: "u", action: revoke, at: 0 }));
      expect(await run(ledger.consumeGrant({ authUserId: "u", action: revoke, at: GRANT_MS }))).toBe(false);
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
  test("parses totp, recovery and confirmation proofs and nothing else", () => {
    expect(parseProofHeader("totp:123456")).toEqual({ kind: "totp", code: sixDigits("123456") });
    expect(parseProofHeader("recovery:abCDe-12345")).toEqual({ kind: "recovery", code: "abCDe-12345" });
    expect(parseProofHeader("confirmation:AAAAAAAAAAAAAAAAAAAAAA")).toMatchObject({ kind: "confirmation", id: "AAAAAAAAAAAAAAAAAAAAAA" });

    // a bare "passkey" no longer stands for a check the session made at some point
    for (const bad of [null, "", "passkey", "confirmation:", "confirmation:short", "totp: ", "totp:12345", "recovery:", "recovery:a b", "password:x"]) expect(parseProofHeader(bad)).toBeNull();
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
