// What a revoked version's answers leave out. Its files, excerpts and readme answer 410 (files.ts). Its review, score
// and package answers still say what was found (paths, line numbers, rule ids, the reviewer's sentence, the revoke's
// reason) but not the package's own text: no AI review quote or excerpt, no source line or script in score evidence.
import { citedSource, evidenceAt } from "@apm/core";

/** A revoked version, or one whose revoke is pending: its source is not shown anywhere. */
export function isWithheld(status: string): boolean {
  return status === "revoked" || status === "revoke-pending";
}

/** Evidence that quotes the package after what it cites: a code line (`lib/a.js:4: …`), a script or a node-gyp command. */
const QUOTES_AFTER_CITE = /^(?:package\.json scripts\.[^:\s]+|binding\.gyp): /;

/**
 * One piece of score evidence without the package's text: `lib/a.js:4: eval(x)` becomes `lib/a.js:4`, and
 * `package.json scripts.postinstall: curl …` becomes `package.json scripts.postinstall`. Evidence the scorer writes
 * from metadata alone (a binary's path, a missing license, a new publisher) is kept as written.
 */
export function evidenceWithoutSource(evidence: string): string {
  const at = evidenceAt(evidence);

  if (at) return `${at.file}:${at.line}`;

  return QUOTES_AFTER_CITE.test(evidence) ? citedSource(evidence) : evidence;
}

/** A score's signals and dismissed items with every evidence line cut to what it cites. */
export function scoreWithoutSource<S extends { evidence: string[] }, D extends { evidence: string[] }>(input: { signals: S[]; dismissed: D[] }) {
  const cut = <T extends { evidence: string[] }>(item: T): T => ({ ...item, evidence: item.evidence.map(evidenceWithoutSource) });

  return { signals: input.signals.map(cut), dismissed: input.dismissed.map(cut) };
}

/**
 * The package's readme, or "" when the newest publish, the one that last wrote it, is withheld: a package keeps one
 * readme, taken from its latest publish, so a revoke of that version takes its readme with it.
 */
export function readmeShown(readme: string, versions: readonly { status: string; published_at: number }[]): string {
  const newest = versions.reduce<{ status: string; published_at: number } | null>((a, v) => (a === null || v.published_at > a.published_at ? v : a), null);

  return newest !== null && isWithheld(newest.status) ? "" : readme;
}
