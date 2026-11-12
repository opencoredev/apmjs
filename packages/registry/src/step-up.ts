// A fresh second factor from a website session, for one action: a code typed for it and sent with it, or a
// confirmation this session got for exactly that action (a code or a passkey check made for it, /-/apm/v1/factor/*).
// Shared by the account routes (approvals, CLI confirmations), the review decisions and evidence dismissals.
import { Effect } from "effect";
import { z } from "zod";
import { sessionActionKey, type SessionAction } from "./actions.ts";
import { Auth, type SignedIn } from "./auth.ts";
import { refuse } from "./errors.ts";
import { isConfirmationId, parseSixDigits, type FactorProof, type ProofCheck } from "./factors.ts";

/** The proof fields a website request carries. */
export const ProofFields = { code: z.string().optional(), confirmation: z.string().optional() };

export type ProofInput = { code?: string | undefined; confirmation?: string | undefined };

/** The website's proof fields as a proof: a malformed code or confirmation is an error, not "no proof". */
function proofOf(body: ProofInput): { kind: "ok"; proof: FactorProof } | { kind: "missing" } | { kind: "malformed"; message: string } {
  if (body.confirmation !== undefined) {
    return isConfirmationId(body.confirmation) ? { kind: "ok", proof: { kind: "confirmation", id: body.confirmation } } : { kind: "malformed", message: "That confirmation is not one the registry issued." };
  }

  if (body.code !== undefined) {
    const code = parseSixDigits(body.code);

    return code ? { kind: "ok", proof: { kind: "totp", code } } : { kind: "malformed", message: "Send the 6-digit code from your authenticator app." };
  }

  return { kind: "missing" };
}

/** The refusal a failed check gets on the website routes. */
export function refusedProof(check: Exclude<ProofCheck, { kind: "ok" }>) {
  switch (check.kind) {
    case "bad":
      return refuse(401, "That code or passkey check is not valid. Use the current 6-digit code from your authenticator app, or try your passkey again.");
    case "reused":
      return refuse(401, "That code was already used. Wait for the next code from your authenticator app.");
    case "locked":
      return refuse(429, "Too many wrong codes. Wait 15 minutes and try again.");
    case "none":
      return refuse(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey.");
    case "stale":
      return refuse(401, "That confirmation is for another change, was already used, or expired. Confirm this change again.");
    default: {
      const _exhaustive: never = check;

      return _exhaustive;
    }
  }
}

/** Succeeds when `body` carries a fresh factor for exactly `action` from this session, spending it; otherwise fails with the refusal to send. */
export const secondFactor = (input: { session: SignedIn; body: ProofInput; action: SessionAction }) =>
  Effect.gen(function* () {
    const p = proofOf(input.body);

    if (p.kind === "malformed") return yield* Effect.fail(refuse(400, p.message));

    if (p.kind === "missing") return yield* Effect.fail(refuse(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey."));
    const check = yield* (yield* Auth).authorize({ session: input.session, action: sessionActionKey(input.action), proof: p.proof });

    if (check.kind !== "ok") return yield* Effect.fail(refusedProof(check));
  });
