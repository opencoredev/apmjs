// Installs are never refused for a score (the project owner's policy since 2026-11): a score under the floor, an
// analysis that is incomplete, a version apm cannot score or has not scored yet, a dependency the registry could not
// look up and a tree the check stopped short of are each a warning every surface shows, and the install goes ahead.
// Strict mode (the CLI's --strict or APM_STRICT=1, APM_SCANNER_STRICT=1, the ~safe view) refuses them as before.
// What still refuses in every mode is not a score: a revoked or yanked version, and one an apm reviewer confirmed
// malicious. Pure, so resolve, scan and their tests build the same warning from the same facts.
import type { ScoreReport } from "@apm/core";

/** What a warning is about. `unchecked`: the dependency walk stopped at one of its limits before this part of the tree. */
export type WarningKind = "low-score" | "incomplete" | "unscorable" | "pending" | "unavailable" | "unchecked";

type WarningBase = {
  /** The package, and the version that installs (for `unavailable`, the range the registry could not look up). */
  name: string;
  version: string;
  /** One line that says what is wrong, without the name: "scores 30/100 (F), under the floor of 40". */
  text: string;
  /** At most three reasons, the heaviest first, each with the file and line its evidence cites. */
  reasons: string[];
  /** The package page, or the version's page. */
  url: string;
  /** The dependency path from the package asked for; empty for that package itself. */
  via: string[];
};

/** A warning on an install that goes ahead. A scored version carries its score and grade; the rest have none. */
export type InstallWarning = (WarningBase & { kind: "low-score" | "incomplete"; score: number; grade: string }) | (WarningBase & { kind: "unscorable" | "pending" | "unavailable" | "unchecked"; score: null; grade: null });

/** The words every surface uses for a dependency whose metadata could not be fetched, kept apart from `unchecked`. */
export const UNAVAILABLE_TEXT = "could not be checked: registry or upstream unavailable";

/** At most this many reasons per warning. */
export const MAX_REASONS = 3;

/** The website's page for a version. */
export function versionUrl(webUrl: string, name: string, version: string): string {
  return `${webUrl}package/${name}/v/${encodeURIComponent(version)}`;
}

/** The heaviest signals that cost points, each as its label and its first piece of evidence (`file:line: …`). */
export function topReasons(r: Pick<ScoreReport, "signals">): string[] {
  return r.signals
    .filter((s) => s.points < 0)
    .toSorted((a, b) => a.points - b.points)
    .slice(0, MAX_REASONS)
    .map((s) => (s.evidence[0] ? `${s.label}: ${s.evidence[0]}` : s.label));
}

/** A scored version's warning: incomplete whatever its score, or a score under `floor`; null when neither. */
export function scoreWarning(input: { name: string; version: string; report: ScoreReport; floor: number; url: string; via: string[] }): InstallWarning | null {
  const { report } = input;
  const incomplete = report.signals.some((s) => s.id === "incomplete");

  if (!incomplete && report.score >= input.floor) return null;
  const base = { name: input.name, version: input.version, reasons: topReasons(report), url: input.url, via: input.via, score: report.score, grade: report.grade };

  return incomplete
    ? { ...base, kind: "incomplete", text: `apm could not fully analyse it (scores ${report.score}/100, ${report.grade})` }
    : { ...base, kind: "low-score", text: `scores ${report.score}/100 (${report.grade}), under the floor of ${input.floor}` };
}

/** A warning with no score: a version apm cannot score or has not scored yet, a lookup that failed, a walk cut short. */
export function stateWarning(input: { kind: "unscorable" | "pending" | "unavailable" | "unchecked"; name: string; version: string; text: string; url: string; via: string[] }): InstallWarning {
  return { ...input, reasons: [], score: null, grade: null };
}

/** The warning as one line: `name@version: text`, then its reasons and link, for a terminal or an advisory. */
export function warningLines(w: InstallWarning): string[] {
  return [`${w.name}@${w.version}: ${w.text}${w.via.length > 0 ? ` (via ${w.via.join(" > ")})` : ""}`, ...w.reasons.map((r) => `  - ${r}`), `  ${w.url}`];
}
