// Why apm will not install the version a page shows: the registry withholds it (an apm reviewer confirmed it malicious,
// or the OSSF malicious-packages feed lists it), or it was revoked or yanked. The package page and its Markdown view
// lead with this instead of offering install commands. Pure, so both views and the tests share it.
import type { Refused } from "./registry";

export type Refusal = Refused | { kind: "revoked"; pending: boolean } | { kind: "yanked" };

/** A version row's refusal, or null when apm installs it. The registry's `refused` comes first: it names the advisory. */
export function refusalOf(v: { status: string; refused?: Refused | null }): Refusal | null {
  if (v.refused) return v.refused;

  switch (v.status) {
    case "revoked":
      return { kind: "revoked", pending: false };
    case "revoke-pending":
      return { kind: "revoked", pending: true };
    case "yanked":
      return { kind: "yanked" };
    default:
      return null;
  }
}

/** Where an advisory id is published. */
export const advisoryUrl = (id: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;

/** The sentence after "Do not install <name> <version>.", in apm's words; advisory ids are the only external text. */
export function refusalReason(r: Refusal): string {
  switch (r.kind) {
    case "known-malicious":
      return `The OSSF malicious-packages feed lists it as malicious (${r.ids.join(", ")}), so apm does not serve it.`;
    case "confirmed-malicious":
      return "apm reviewers confirmed it is malicious, so apm does not serve it.";
    case "revoked":
      return r.pending ? "Its revoke is pending, so apm does not serve it." : "It was revoked, so apm does not serve it.";
    case "yanked":
      return "It was yanked, so apm add refuses it and new installs skip it.";
    default: {
      const _exhaustive: never = r;

      return _exhaustive;
    }
  }
}
