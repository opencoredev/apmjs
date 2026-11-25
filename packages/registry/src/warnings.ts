// Installs are never refused for a score (the project owner's policy since 2026-11): a score under the floor, an
// analysis that is incomplete, a version apm cannot score or has not scored yet, a dependency the registry could not
// look up and a tree the check stopped short of are each a warning every surface shows, and the install goes ahead.
// Strict mode (the CLI's --strict or APM_STRICT=1, APM_SCANNER_STRICT=1, the ~safe view) refuses them as before.
// A version inside apm's cooldown (published under 24 hours ago) is a warning too, the version the package manager
// installs is still the one checked, and strict mode and the ~safe view refuse it.
// What still refuses in every mode is not a score: a revoked or yanked version, and one an apm reviewer confirmed
// malicious. Pure, so resolve, scan and their tests build the same warning from the same facts.
import { coverageText, readingOf, type Coverage, type Reading, type ScoreReport } from "@apm/core";
import type { Unscorable } from "./db.ts";

/**
 * What a warning is about. `unchecked`: the dependency walk stopped at one of its limits before this part of the tree.
 * `cooldown`: the version was published inside apm's cooldown.
 */
export type WarningKind = "low-score" | "incomplete" | "unscorable" | "pending" | "unavailable" | "unchecked" | "cooldown";

/** The kinds with no score. */
type StateKind = Exclude<WarningKind, "low-score" | "incomplete">;

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
  /**
   * Every signal that cost a scored version points, by id: the install verdict reads them for a risk signal (a fresh
   * dependency apm scored and found nothing in is a note there, one it has not read a person's call). Absent when the
   * version has no score.
   */
  signals?: WarningSignal[];
  /** The scorer that wrote that score's analysis; sent with `signals`, whose ids are its own. */
  scorer?: string;
  /**
   * How much of the version that score's analysis read, as it stored it; sent with `signals`, absent when it stored
   * none. The install verdict lets a partial reading install only on this positive record (core readingOf).
   */
  coverage?: Coverage;
  /** For `unscorable`: why the version will never be scored, when the registry decided it (db.ts UnscorableReason). */
  unscorable?: Unscorable["reason"];
};

/** A signal as a warning carries it: its id and what it cost, never its evidence. */
export type WarningSignal = { id: string; points: number };

/** What a warning carries of a score for the install verdict: its lost signals, scorer and coverage. */
function scoredFields(report: Pick<ScoreReport, "signals" | "scorer" | "coverage">): Pick<WarningBase, "signals" | "scorer" | "coverage"> {
  const out: Pick<WarningBase, "signals" | "scorer" | "coverage"> = { signals: lostSignals(report), scorer: report.scorer };

  if (report.coverage) out.coverage = report.coverage;

  return out;
}

/** The signals of `report` that cost points, heaviest first. */
export function lostSignals(report: Pick<ScoreReport, "signals">): WarningSignal[] {
  return report.signals
    .filter((s) => s.points < 0)
    .toSorted((a, b) => a.points - b.points)
    .map((s) => ({ id: s.id, points: s.points }));
}

/** A warning on an install that goes ahead. A scored version carries its score and grade; the rest have none. */
export type InstallWarning = (WarningBase & { kind: "low-score" | "incomplete"; score: number; grade: string }) | (WarningBase & { kind: StateKind; score: null; grade: null });

/** The words every surface uses for a dependency whose metadata could not be fetched, kept apart from `unchecked`. */
export const UNAVAILABLE_TEXT = "could not be checked: registry or upstream unavailable";

/** At most this many reasons per warning. */
export const MAX_REASONS = 3;

/** The website's page for a version. A name ending in ".md" gets its dot escaped, or the site would serve another name's Markdown view. */
export function versionUrl(webUrl: string, name: string, version: string): string {
  return `${webUrl}package/${name.replace(/\.md$/, "%2Emd")}?v=${encodeURIComponent(version)}`;
}

/** The heaviest signals that cost points, each as its label and its first piece of evidence (`file:line: …`). */
export function topReasons(r: Pick<ScoreReport, "signals">): string[] {
  return r.signals
    .filter((s) => s.points < 0)
    .toSorted((a, b) => a.points - b.points)
    .slice(0, MAX_REASONS)
    .map((s) => (s.evidence[0] ? `${s.label}: ${s.evidence[0]}` : s.label));
}

/**
 * What an incomplete reading (core readingOf) is, in the words every install surface uses, without the score: an
 * `incomplete` signal; an earlier scorer's `unanalyzed-files`; the current scorer's analysis with no coverage record;
 * partial coverage that is not only size or budget (a stop, a reason apm does not clear, another scorer's record).
 */
export function incompleteText(reading: Extract<Reading, { kind: "incomplete" }>): string {
  switch (reading.why) {
    case "signal":
      return "apm could not fully analyse it";
    case "legacy-gap":
      return "apm did not analyse every file in it";
    case "no-coverage":
      return "apm could not fully analyse it: its analysis does not record how much of it was read";
    case "coverage":
      return reading.coverage.reasons.includes("stopped") ? `apm could not fully analyse it: ${coverageText(reading.coverage)}` : `apm read only part of it, and its analysis does not record that size was the only reason: ${coverageText(reading.coverage)}`;
    default: {
      const _exhaustive: never = reading;

      return _exhaustive;
    }
  }
}

/**
 * A scored version's warning: incomplete whatever its score, for every reading core readingOf calls incomplete (the
 * install verdict holds those) and for a partial one (files left unread for their size or the byte budget, which cost
 * no points and so can score well; the verdict installs it with a note, read from the coverage this carries); or a
 * score under `floor`; null when none. Strict mode and the ~safe view refuse what this warns about (policyBlock).
 */
export function scoreWarning(input: { name: string; version: string; report: Pick<ScoreReport, "score" | "grade" | "signals" | "scorer" | "coverage">; floor: number; url: string; via: string[] }): InstallWarning | null {
  const { report } = input;
  const reading = readingOf(report);

  if (reading.kind === "complete" && report.score >= input.floor) return null;
  const base = { name: input.name, version: input.version, reasons: topReasons(report), url: input.url, via: input.via, score: report.score, grade: report.grade, ...scoredFields(report) };

  switch (reading.kind) {
    case "incomplete":
      return { ...base, kind: "incomplete", text: `${incompleteText(reading)} (scores ${report.score}/100, ${report.grade})` };
    case "partial":
      return { ...base, kind: "incomplete", text: `apm read only part of it: ${coverageText(reading.coverage)} (scores ${report.score}/100 on what it read)` };
    case "complete":
      return { ...base, kind: "low-score", text: `scores ${report.score}/100 (${report.grade}), under the floor of ${input.floor}` };
    default: {
      const _exhaustive: never = reading;

      return _exhaustive;
    }
  }
}

/** A warning with no score: a version apm cannot score or has not scored yet, a lookup that failed, a walk cut short. */
export function stateWarning(input: { kind: StateKind; name: string; version: string; text: string; url: string; via: string[]; unscorable?: Unscorable["reason"] }): InstallWarning {
  return { ...input, reasons: [], score: null, grade: null };
}

const HOUR = 3_600_000;

/** A duration as the cooldown is named: "24-hour", or "90-minute" when it is not whole hours. */
function cooldownName(ms: number): string {
  return ms % HOUR === 0 ? `${ms / HOUR}-hour` : `${Math.round(ms / 60_000)}-minute`;
}

/** How long ago a version was published, in whole hours: "published 5 hours ago", "published under an hour ago". */
function publishedAgo(ageMs: number): string {
  const hours = Math.floor(Math.max(0, ageMs) / HOUR);

  return hours === 0 ? "published under an hour ago" : `published ${hours} ${hours === 1 ? "hour" : "hours"} ago`;
}

/** The words for a version inside the cooldown: "published 5 hours ago, inside apm's 24-hour cooldown". */
export function cooldownText(ageMs: number, cooldownMs: number): string {
  return `${publishedAgo(ageMs)}, inside apm's ${cooldownName(cooldownMs)} cooldown`;
}

/**
 * A version inside the cooldown, which installs with this warning (strict mode refuses it): the package manager reads
 * the plain registry and installs it whatever its age, so it is the version checked and warned about. null when it is
 * past the cooldown. `report`: the version's score, when it has one, whose lost signals the warning carries.
 */
export function cooldownWarning(input: { name: string; version: string; ageMs: number; cooldownMs: number; url: string; via: string[]; report?: Pick<ScoreReport, "signals" | "scorer" | "coverage"> | null }): InstallWarning | null {
  if (input.ageMs >= input.cooldownMs) return null;
  const w = stateWarning({ kind: "cooldown", name: input.name, version: input.version, text: cooldownText(input.ageMs, input.cooldownMs), url: input.url, via: input.via });

  return input.report ? { ...w, ...scoredFields(input.report) } : w;
}

/** The warning as one line: `name@version: text`, then its reasons and link, for a terminal or an advisory. */
export function warningLines(w: InstallWarning): string[] {
  return [`${w.name}@${w.version}: ${w.text}${w.via.length > 0 ? ` (via ${w.via.join(" > ")})` : ""}`, ...w.reasons.map((r) => `  - ${r}`), `  ${w.url}`];
}
