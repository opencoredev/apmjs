// What a revoked version's answers may say. Its files, excerpts and readme answer 410 (files.ts). Its review, score and
// package answers are rebuilt from an allowlist: paths, line numbers, rule ids, kinds, a reviewer's sentence and the
// revoke's reason. Nothing is cut out of a string, because the package's own text can sit anywhere in one (a script name
// with a colon, a nested `npm run`, a shell wrapper). A field this file does not name is not sent.
import type { DismissedEvidence, Signal } from "@apm/core";

/** A revoked version, or one whose revoke is pending: its source is not shown anywhere. */
export function isWithheld(status: string): boolean {
  return status === "revoked" || status === "revoke-pending";
}

/** What a withheld version's score says per signal: the rule, its points, and no evidence but the revoke's reason. */
export type WithheldSignal = Pick<Signal, "id" | "label" | "points" | "confidence" | "evidence">;

/**
 * One signal of a withheld version. Evidence lines quote the package (a code line, a script, a gyp command), so they
 * all go; the `revoked` signal's one line is the revoke's reason, which is the registry's own text, and stays.
 */
export function withheldSignal(s: Signal): WithheldSignal {
  return { id: s.id, label: s.label, points: s.points, confidence: s.confidence, evidence: s.id === "revoked" ? [...s.evidence] : [] };
}

/** A dismissed item of a withheld version: the signal, file, line and the reviewer's reason; the quoted evidence goes. */
export function withheldDismissal(d: DismissedEvidence): DismissedEvidence {
  return { signal: d.signal, file: d.file, line: d.line, reason: d.reason, at: d.at, evidence: [] };
}

/** The package row fields that say whose readme it is. */
type ReadmeOwner = { readme: string; readme_version: string | null };

/** The readme an answer may show, and the version whose publish wrote it (null when unknown or hidden). */
export type ShownReadme = { text: string; version: string | null };

/**
 * The package's readme, or "" when the version whose publish wrote it is withheld. A publish without a readme keeps the
 * previous text, so the owner is the recorded `readme_version`, not the newest publish. When the owner is unknown (a
 * row from before migration 0008, or npm's packument for an upstream package) the readme is hidden while any version
 * is withheld.
 */
export function readmeShown(pkg: ReadmeOwner, versions: readonly { version: string; status: string }[]): ShownReadme {
  if (pkg.readme === "") return { text: "", version: null };

  if (pkg.readme_version === null) return versions.some((v) => isWithheld(v.status)) ? { text: "", version: null } : { text: pkg.readme, version: null };
  const owner = versions.find((v) => v.version === pkg.readme_version);

  // an owner that is gone or withheld takes its readme with it
  return owner && !isWithheld(owner.status) ? { text: pkg.readme, version: owner.version } : { text: "", version: null };
}
