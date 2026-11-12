// What a reviewer's dismiss or undo sends: the item, the public reason both need, and the action a passkey check
// confirms (the same item and reason, so the confirmation fits only this request).
import type { EvidenceKey, SessionAction } from "./account";

export type EvidenceMode = "dismiss" | "restore";

export type EvidenceRequest = { kind: "ok"; action: SessionAction; body: EvidenceKey & { reason: string } } | { kind: "error"; message: string };

export function evidenceRequest(input: { mode: EvidenceMode; item: EvidenceKey; reason: string }): EvidenceRequest {
  const reason = input.reason.trim();

  if (reason === "") {
    return {
      kind: "error",
      message: input.mode === "dismiss" ? "Say why this evidence is wrong; the reason is shown in public." : "Say why you are undoing this dismissal; the reason is shown in public.",
    };
  }

  return { kind: "ok", action: { kind: input.mode === "dismiss" ? "evidence-dismiss" : "evidence-restore", ...input.item, reason }, body: { ...input.item, reason } };
}
