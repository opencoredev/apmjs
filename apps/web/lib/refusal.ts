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

/** Whether apm installs a version: it is active and the registry does not withhold it. */
export const isInstallable = (v: { status: string; refused?: Refused | null }): boolean => v.status === "active" && !v.refused;

/**
 * Why a package has no version to install, for its default page and Markdown view: nothing is published, every
 * published version is refused (each with its refusal), or no dist-tag names one apm serves.
 */
export type NoInstallable =
  | { readonly kind: "unpublished" }
  | { readonly kind: "none-served"; readonly versions: readonly { readonly version: string; readonly refusal: Refusal }[] }
  | { readonly kind: "untagged" };

/** Why none of the package answer's versions installs by name; call it only once no tag names an installable version. */
export function noInstallable(pkg: { versions: readonly { version: string; status: string; refused?: Refused | null }[] }): NoInstallable {
  if (pkg.versions.length === 0) return { kind: "unpublished" };

  const versions = pkg.versions.flatMap((v) => {
    const refusal = refusalOf(v);

    return refusal === null ? [] : [{ version: v.version, refusal }];
  });

  return versions.length === pkg.versions.length ? { kind: "none-served", versions } : { kind: "untagged" };
}

/** The sentence a page with no installable version leads with. */
export function noInstallableReason(input: { name: string; why: NoInstallable }): string {
  const { name, why } = input;

  switch (why.kind) {
    case "unpublished":
      return `No version of ${name} is published, so there is nothing to install.`;
    case "none-served":
      return `apm serves no version of ${name}: every published version is withheld, revoked or yanked.`;
    case "untagged":
      return `No dist-tag names a version of ${name} that apm serves, so installing it by name finds nothing. Name an exact version to install one.`;
    default: {
      const _exhaustive: never = why;

      return _exhaustive;
    }
  }
}

/** A refused version's state in a few words, after its version number; advisory ids are the only external text. */
export function refusalLabel(r: Refusal): string {
  switch (r.kind) {
    case "known-malicious":
      return `listed as malicious by the OSSF malicious-packages feed (${r.ids.join(", ")})`;
    case "confirmed-malicious":
      return "confirmed malicious by apm reviewers";
    case "revoked":
      return r.pending ? "revoke pending" : "revoked";
    case "yanked":
      return "yanked";
    default: {
      const _exhaustive: never = r;

      return _exhaustive;
    }
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
