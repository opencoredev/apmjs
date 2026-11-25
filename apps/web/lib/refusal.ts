// Why apm will not install the version a page shows. Its status says so (revoked, a revoke pending, yanked), or the
// registry's install policy refuses it: resolve, asked for exactly that version (the read /api/explain makes), either
// names it among the versions it skipped, with the reason, or picks it and refuses what its tree would install (a
// dependency the OSSF feed lists or an apm reviewer confirmed). The package page, its Markdown view and the MCP tool
// lead with this instead of install commands.
import type { ResolveOutcome } from "./agent/source";

export type Refusal =
  | { readonly kind: "revoked"; readonly pending: boolean }
  | { readonly kind: "yanked" }
  | { readonly kind: "known-malicious"; readonly ids: string[] }
  | { readonly kind: "confirmed-malicious" }
  /** resolve picked it and refused its tree: these dependencies would be installed with it */
  | { readonly kind: "dependency"; readonly deps: MaliciousDependency[] }
  /** resolve refused it for another reason, in the registry's words */
  | { readonly kind: "policy"; readonly reason: string };

/** A dependency resolve refused: `ids` are the OSSF advisories that list it, null when an apm reviewer confirmed it. */
export type MaliciousDependency = { readonly name: string; readonly version: string; readonly ids: string[] | null };

/** What apm says about installing the shown version. */
export type PolicyRead = { readonly kind: "installs" } | { readonly kind: "refused"; readonly refusal: Refusal } | { readonly kind: "unknown" };

// the registry's skipped reason for a version an apm reviewer confirmed (packages/registry: confirmed malicious by an apm reviewer)
const CONFIRMED_REASON = /^confirmed malicious\b/;

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

/**
 * resolve's answer for exactly `version`. A 422 refuses it when it skipped that version, or when it picked it
 * (`newest`) and refused its tree; a 422 that says neither is not about this version, so the answer is unknown, as it is
 * when the registry could not say.
 */
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

      if (skipped !== undefined) {
        const listed = outcome.knownMalicious?.find((k) => k.name === name && k.version === version);

        if (listed) return { kind: "known-malicious", ids: listed.ids };

        if (CONFIRMED_REASON.test(skipped.reason) || outcome.confirmed.some((c) => c.name === name && c.version === version)) return { kind: "confirmed-malicious" };

        return { kind: "policy", reason: skipped.reason };
      }

      if (outcome.newest !== version) return "unknown";
      const deps: MaliciousDependency[] = [...(outcome.knownMalicious ?? []).map((k) => ({ name: k.name, version: k.version, ids: k.ids })), ...outcome.confirmed.map((c) => ({ name: c.name, version: c.version, ids: null }))];

      return deps.length > 0 ? { kind: "dependency", deps } : { kind: "policy", reason: outcome.reason };
    }

    default: {
      const _exhaustive: never = outcome;

      return _exhaustive;
    }
  }
}

/** Whether apm installs `version`: its status when that refuses it, else one resolve for exactly that version. */
export async function readPolicy(input: { name: string; version: string; status: string; resolve: (input: { name: string; range: string }) => Promise<ResolveOutcome> }): Promise<PolicyRead> {
  const { name, version } = input;
  const refusal = statusRefusal(input.status) ?? resolveRefusal({ name, version, outcome: await input.resolve({ name, range: version }) });

  if (refusal === "unknown") return { kind: "unknown" };

  return refusal === null ? { kind: "installs" } : { kind: "refused", refusal };
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
      return `No dist-tag names an active version of ${name}, so installing it by name finds nothing. Check an exact version before installing.`;
    default: {
      const _exhaustive: never = why;

      return _exhaustive;
    }
  }
}

/** Why a refused dependency is refused, after "which": the advisories quoted, or an apm reviewer's confirmation. */
export function dependencyWhy(d: MaliciousDependency): string {
  return d.ids === null ? "apm reviewers confirmed is malicious" : `the OSSF malicious-packages feed lists as malicious (${d.ids.join(", ")})`;
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
    case "dependency":
      return `It depends on ${r.deps.map((d) => `${d.name}@${d.version}, which ${dependencyWhy(d)}`).join("; and on ")}, so apm add refuses it.`;
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
