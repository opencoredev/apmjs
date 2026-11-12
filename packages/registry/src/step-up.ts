// A fresh second factor from a website session, for one action: a code typed now, or the passkey check this
// session just made. Shared by the account routes (approvals, CLI confirmations) and the review decisions.
import { Effect } from "effect";
import { z } from "zod";
import { Auth, type SignedIn } from "./auth.ts";
import { refuse } from "./errors.ts";
import { parseSixDigits, type FactorProof, type ProofCheck } from "./factors.ts";

/** The proof fields a website request carries. */
export const ProofFields = { code: z.string().optional(), passkey: z.literal(true).optional() };

export type ProofInput = { code?: string | undefined; passkey?: true | undefined };

/** The website's proof fields as a proof: a malformed code is an error, not "no code". */
function proofOf(body: ProofInput): { kind: "ok"; proof: FactorProof } | { kind: "missing" } | { kind: "malformed" } {
  if (body.code !== undefined) {
    const code = parseSixDigits(body.code);

    return code ? { kind: "ok", proof: { kind: "totp", code } } : { kind: "malformed" };
  }

  if (body.passkey) return { kind: "ok", proof: { kind: "passkey" } };

  return { kind: "missing" };
}

function refusedProof(check: Exclude<ProofCheck, { kind: "ok" }>) {
  switch (check.kind) {
    case "bad":
      return refuse(401, "That code is not valid. Use the current 6-digit code from your authenticator app.");
    case "reused":
      return refuse(401, "That code was already used. Wait for the next code from your authenticator app.");
    case "locked":
      return refuse(429, "Too many wrong codes. Wait 15 minutes and try again.");
    case "none":
      return refuse(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey.");
    default: {
      const _exhaustive: never = check;

      return _exhaustive;
    }
  }
}

/** Succeeds when `body` carries a fresh factor for `purpose` from this session; otherwise fails with the refusal to send. */
export const secondFactor = (input: { session: SignedIn; body: ProofInput; purpose: string }) =>
  Effect.gen(function* () {
    const p = proofOf(input.body);

    if (p.kind === "malformed") return yield* Effect.fail(refuse(400, "Send the 6-digit code from your authenticator app."));

    if (p.kind === "missing") return yield* Effect.fail(refuse(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey."));
    const check = yield* (yield* Auth).checkProof({ authUserId: input.session.authUserId, sessionToken: input.session.sessionToken, proof: p.proof, purpose: input.purpose });

    if (check.kind !== "ok") return yield* Effect.fail(refusedProof(check));
  });
