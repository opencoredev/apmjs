// Why apm will not install the version a page shows. Its status says so (revoked, a revoke pending, yanked), or the
// registry's install policy refuses it: resolve, asked for exactly that version (the read /api/explain makes), names
// it among the versions it skipped, with the reason, the OSSF advisories that list it or an apm reviewer's
// confirmation. The package page, its Markdown view and the MCP tool lead with this instead of install commands.
import type { ResolveOutcome } from "./agent/source";

export type Refusal =
  | { readonly kind: "revoked"; readonly pending: boolean }
  | { readonly kind: "yanked" }
  | { readonly kind: "known-malicious"; readonly ids: string[] }
  | { readonly kind: "confirmed-malicious" }
  /** resolve skipped it for another reason, in the registry's words */
  | { readonly kind: "policy"; readonly reason: string };

/** What apm says about installing the shown version. `bareGets`: what a bare install gets instead, when the refused version is the default. */
export type PolicyRead = { readonly kind: "installs" } | { readonly kind: "refused"; readonly refusal: Refusal; readonly bareGets: string | null } | { readonly kind: "unknown" };

/** The refusal a version's own status gives, or null when its status does not refuse it. */
export function statusRefusal(status: string): Refusal | null {
  switch (status) {
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

/** resolve's answer for exactly `version`: refused only when it skipped that version; unknown when the registry could not say. */
export function resolveRefusal(input: { name: string; version: string; outcome: ResolveOutcome }): Refusal | null | "unknown" {
  const { name, version, outcome } = input;

  switch (outcome.kind) {
    case "ok":
      return null;
    case "missing":
    case "unavailable":
      return "unknown";
    case "refused": {
      const skipped = outcome.skipped.find((s) => s.version === version);

      if (skipped === undefined) return null;
      const listed = outcome.knownMalicious?.find((k) => k.name === name && k.version === version);

      if (listed) return { kind: "known-malicious", ids: listed.ids };

      if (outcome.confirmed.some((c) => c.name === name && c.version === version)) return { kind: "confirmed-malicious" };

      return { kind: "policy", reason: skipped.reason };
    }

    default: {
      const _exhaustive: never = outcome;

      return _exhaustive;
    }
  }
}

/**
 * Whether apm installs `version`: its status when that refuses it, else resolve for exactly that version. A refused
 * default (`isDefault`) asks resolve once more, for latest, to say what a bare install gets instead; only that rare path
 * makes the second read.
 */
export async function readPolicy(input: { name: string; version: string; status: string; isDefault: boolean; resolve: (input: { name: string; range: string }) => Promise<ResolveOutcome> }): Promise<PolicyRead> {
  const { name, version } = input;
  const refusal = statusRefusal(input.status) ?? resolveRefusal({ name, version, outcome: await input.resolve({ name, range: version }) });

  if (refusal === "unknown") return { kind: "unknown" };

  if (refusal === null) return { kind: "installs" };

  if (!input.isDefault) return { kind: "refused", refusal, bareGets: null };
  const bare = await input.resolve({ name, range: "latest" });

  return { kind: "refused", refusal, bareGets: bare.kind === "ok" && bare.version !== version ? bare.version : null };
}

/**
 * Why a package has no version to show by name, for its default page and Markdown view: nothing is published, or no
 * dist-tag names an active version.
 */
export type NoInstallable = { readonly kind: "unpublished" } | { readonly kind: "untagged" };

export function noInstallable(pkg: { versions: readonly unknown[] }): NoInstallable {
  return pkg.versions.length === 0 ? { kind: "unpublished" } : { kind: "untagged" };
}

/** The sentence a page with no version to show leads with. */
export function noInstallableReason(input: { name: string; why: NoInstallable }): string {
  const { name, why } = input;

  switch (why.kind) {
    case "unpublished":
      return `No version of ${name} is published, so there is nothing to install.`;
    case "untagged":
      return `No dist-tag names an active version of ${name}, so installing it by name finds nothing. Name an exact version to install one.`;
    default: {
      const _exhaustive: never = why;

      return _exhaustive;
    }
  }
}

/** Where an advisory id is published. */
export const advisoryUrl = (id: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;

/** The sentence after "Do not install <name> <version>.", in apm's words; advisory ids and a policy reason are the only external text. */
export function refusalReason(r: Refusal): string {
  switch (r.kind) {
    case "known-malicious":
      return `The OSSF malicious-packages feed lists it as malicious (${r.ids.join(", ")}), so apm add refuses it.`;
    case "confirmed-malicious":
      return "apm reviewers confirmed it is malicious, so apm add refuses it.";
    case "revoked":
      return r.pending ? "Its revoke is pending, so apm does not serve it." : "It was revoked, so apm does not serve it.";
    case "yanked":
      return "It was yanked, so apm add refuses it and new installs skip it.";
    case "policy":
      return `apm's install policy refuses it: ${r.reason.replace(/\.?$/, ".")}`;
    default: {
      const _exhaustive: never = r;

      return _exhaustive;
    }
  }
}
