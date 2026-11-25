// Why apm will not install the version a page shows. Its status says so (revoked, a revoke pending, yanked), or the
// registry's install policy refuses it: resolve, asked for exactly that version (the read /api/explain makes), either
// names it among the versions it skipped, with the reason, or picks it and refuses what its tree would install (a
// dependency the OSSF feed lists or an apm reviewer confirmed). The package page, its Markdown view and the MCP tool
// lead with this instead of install commands.
import { POLICY_RESOLVE_TIMEOUT_MS } from "./agent/resolve-budget";
import type { ResolveOutcome } from "./agent/source";
import type { PublicState } from "./review-schema";

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

/**
 * What apm says about installing the shown version. "not-asked": nothing the page has marks it risky (looksRisky), so
 * resolve was not asked and the install box is the usual one; apm add still checks it when it installs.
 */
export type PolicyRead = { readonly kind: "installs" } | { readonly kind: "not-asked" } | { readonly kind: "refused"; readonly refusal: Refusal } | { readonly kind: "unknown" };

/**
 * What the page already has of the shown version, which decides whether resolve is asked about it (looksRisky): its
 * score, whether it runs install scripts, and its public AI review's state (null when it has none or it was not read).
 */
export type RiskInput = {
  readonly score: { readonly score: number; readonly grade: string; readonly signals: readonly { readonly id: string }[] } | null;
  readonly installScripts: boolean | null;
  readonly review: PublicState | null;
};

// a signal about install scripts (install-script, install-download, install-network, install-shell) or malware
const RISKY_SIGNAL = /^install-|malicious/;

/**
 * Whether the shown version looks risky from what the page has: no score yet, a score under 40 (grade F), an install
 * script, a signal about install scripts or malware, or an AI review flag a person is checking. Only then is resolve asked: one resolve is a dependency walk on
 * the registry, too much to add to every view of react or next. A clean, scored version that the registry refuses
 * anyway (a malicious release with a high score) is refused by apm add, as before.
 */
export function looksRisky(input: RiskInput): boolean {
  const { score } = input;

  if (score === null || input.installScripts === true || input.review === "under-review") return true;

  return score.score < 40 || score.grade === "F" || score.signals.some((s) => RISKY_SIGNAL.test(s.id));
}

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

/** The refusal resolve gives a version it skipped: listed by the OSSF feed, confirmed by a reviewer, or its own words. */
function skipRefusal(input: { name: string; version: string; reason: string; knownMalicious?: readonly { name: string; version: string; ids: string[] }[]; confirmed?: readonly { name: string; version: string }[] }): Refusal {
  const { name, version } = input;
  const listed = input.knownMalicious?.find((k) => k.name === name && k.version === version);

  if (listed) return { kind: "known-malicious", ids: listed.ids };

  if (CONFIRMED_REASON.test(input.reason) || input.confirmed?.some((c) => c.name === name && c.version === version)) return { kind: "confirmed-malicious" };

  return { kind: "policy", reason: input.reason };
}

/**
 * resolve's answer for exactly `version`. Any answer that skipped that version refuses it, a 200 among them (it can pick
 * a sibling of equal precedence, 1.0.0+b for 1.0.0+a). A 200 installs it only when it picked exactly that version. A 422
 * also refuses it when it picked it (`newest`) and refused its tree. Any other answer is not about this version, so it is
 * unknown, as it is when the registry could not say.
 */
export function resolveRefusal(input: { name: string; version: string; outcome: ResolveOutcome }): Refusal | null | "unknown" {
  const { name, version, outcome } = input;

  switch (outcome.kind) {
    case "ok": {
      const skipped = outcome.skipped.find((s) => s.version === version);

      if (skipped !== undefined) return skipRefusal({ name, version, reason: skipped.reason });

      return outcome.version === version ? null : "unknown";
    }

    case "missing":
    case "unavailable":
      return "unknown";
    case "refused": {
      const skipped = outcome.skipped.find((s) => s.version === version);

      if (skipped !== undefined) return skipRefusal({ name, version, reason: skipped.reason, knownMalicious: outcome.knownMalicious, confirmed: outcome.confirmed });

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

/** `read`, or "unavailable" once `ms` have passed without an answer. */
function withinBudget(read: Promise<ResolveOutcome>, ms: number): Promise<ResolveOutcome> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  const late = new Promise<ResolveOutcome>((done) => {
    timer = setTimeout(() => done({ kind: "unavailable" }), ms);
  });

  return Promise.race([read, late]).finally(() => clearTimeout(timer));
}

/**
 * Whether apm installs `version`: its status when that refuses it, then a public review apm reviewers confirmed, else,
 * when it looks risky (looksRisky, from `risk`), one resolve for exactly that version; otherwise resolve is not asked.
 * A resolve that takes longer than `timeoutMs` (POLICY_RESOLVE_TIMEOUT_MS) counts as not answering.
 */
export async function readPolicy(input: { name: string; version: string; status: string; risk: Promise<RiskInput>; resolve: (input: { name: string; range: string }) => Promise<ResolveOutcome>; timeoutMs?: number }): Promise<PolicyRead> {
  const { name, version } = input;
  const byStatus = statusRefusal(input.status);

  if (byStatus) return { kind: "refused", refusal: byStatus };
  const risk = await input.risk;

  // apm reviewers confirmed it, as the page's header says: resolve skips such a version whatever its score
  if (risk.review === "confirmed") return { kind: "refused", refusal: { kind: "confirmed-malicious" } };

  if (!looksRisky(risk)) return { kind: "not-asked" };
  const outcome = await withinBudget(input.resolve({ name, range: version }), input.timeoutMs ?? POLICY_RESOLVE_TIMEOUT_MS);
  const refusal = resolveRefusal({ name, version, outcome });

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
function dependencyWhy(d: MaliciousDependency): string {
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
