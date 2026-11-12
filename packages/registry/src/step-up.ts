// A fresh second factor from a website session, for one action: a code typed now, or the passkey check this
// session just made. Shared by the account routes (approvals, CLI confirmations) and the review decisions.
import { z } from "zod";
import type { ApmAuth, FactorProof, ProofCheck, SignedIn } from "./auth.ts";
import { parseSixDigits } from "./factors.ts";
import { fail } from "./server.ts";

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

export function refusedProof(check: Exclude<ProofCheck, { kind: "ok" }>): Response {
  switch (check.kind) {
    case "bad":
      return fail(401, "That code is not valid. Use the current 6-digit code from your authenticator app.");
    case "reused":
      return fail(401, "That code was already used. Wait for the next code from your authenticator app.");
    case "locked":
      return fail(429, "Too many wrong codes. Wait 15 minutes and try again.");
    case "none":
      return fail(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey.");
    default: {
      const _exhaustive: never = check;

      return _exhaustive;
    }
  }
}

/** Null when `body` carries a fresh factor for `purpose` from this session; otherwise the refusal to send. */
export async function secondFactor(input: { auth: ApmAuth; session: SignedIn; body: ProofInput; purpose: string }): Promise<Response | null> {
  const p = proofOf(input.body);

  if (p.kind === "malformed") return fail(400, "Send the 6-digit code from your authenticator app.");

  if (p.kind === "missing") return fail(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey.");
  const check = await input.auth.checkProof({ authUserId: input.session.authUserId, sessionToken: input.session.sessionToken, proof: p.proof, purpose: input.purpose });

  return check.kind === "ok" ? null : refusedProof(check);
}
