// `apm explain <pkg>[@range]`: a short verdict an agent (or a person) can act on before an install. Pure.
// The website's explain_install MCP tool and GET /api/explain use the same rules (apps/web/lib/agent/verdict.ts);
// change both together: tests/fixtures/explain-verdicts.json holds the cases both must answer the same way.
//
// The rule: "install" only when apm knows the version and everything it brings in is fine. Anything apm could not
// read is "unknown"; anything it read but has not finished checking is "review-first". Like the rest of apm it never
// calls a version "safe".
import type { Report } from "./api.ts";

export const VERDICTS = ["install", "review-first", "do-not-install", "not-found", "unknown"] as const;

export type VerdictKind = (typeof VERDICTS)[number];

/** Scores at or above this are clean (the site's green badge); below it the lost points are worth a look. */
export const CLEAN_SCORE = 75;

/** Exit codes, so a script can branch without parsing: 2 stays the CLI's usage error. */
export const EXIT: Record<VerdictKind, number> = { install: 0, "do-not-install": 1, "not-found": 1, "review-first": 3, unknown: 4 };

export type DepRef = { name: string; version: string };

/** How the AI reviews of the dependencies stand; "unknown" when the registry did not say. */
export type DepReviews = { kind: "off" } | { kind: "unknown" } | { kind: "on"; confirmed: DepRef[]; underReview: DepRef[]; pending: DepRef[]; noAnswer: DepRef[] };

/** The dependency walk: what apm could not score (the registry's total, and up to 50 named) and the AI reviews. */
export type DepCheck = { unchecked: number; uncheckedDeps: { dependency: string; reason: string }[]; reviews: DepReviews };

export type ResolvedInput =
  | { kind: "ok"; version: string; report: Report | null; skipped: { version: string; reason: string }[]; deps: DepCheck }
  | { kind: "refused"; reason: string; newest: string | null; skipped: { version: string; reason: string }[] }
  | { kind: "missing"; reason: string }
  | { kind: "unavailable"; reason: string };

export type ReviewState = "found-nothing" | "under-review" | "no-answer" | "confirmed" | "cleared";

/**
 * Why the registry no longer offers a version its install policy picked a moment before: it was yanked or revoked,
 * a revocation is pending, or the registry withholds it (a redacted answer that names no state).
 */
export type PulledStatus = "yanked" | "revoke-pending" | "revoked" | "withheld";

/**
 * Where the AI review of the picked version stands. queued and leased are a review in progress; failed and a
 * no-answer result ended without one; not-reviewed means the version was never picked; off means the registry runs
 * none; unreadable means apm could not ask; pulled means the review answer said the version is no longer offered,
 * whatever its review says.
 */
export type ReviewInput =
  | { kind: "pulled"; status: PulledStatus }
  | { kind: "reviewed"; state: ReviewState; findings: number }
  | { kind: "queued" }
  | { kind: "leased" }
  | { kind: "failed" }
  | { kind: "not-reviewed" }
  | { kind: "off" }
  | { kind: "unreadable" };

/**
 * How far the AI review of the picked version got. reviewed: it has a result. in-progress: queued or running.
 * no-answer: it ended without a usable result. not-selected: apm never picked this version for one. disabled: this
 * registry runs none. unreadable: apm could not read it. not-read: the verdict was decided before the review was read.
 */
export const AI_REVIEW_COVERAGE = ["reviewed", "in-progress", "no-answer", "not-selected", "disabled", "unreadable", "not-read"] as const;

export type AiReviewCoverage = (typeof AI_REVIEW_COVERAGE)[number];

/** Whether apm scored every dependency the install would bring in; not-read when the verdict never got that far. */
export const DEPENDENCY_COVERAGE = ["complete", "incomplete", "not-read"] as const;

export type DependencyCoverage = (typeof DEPENDENCY_COVERAGE)[number];

/** What the verdict rests on, as data: a client can tell "install, with no AI review" from "install, reviewed". */
export type Coverage = { aiReview: AiReviewCoverage; dependencies: DependencyCoverage };

export type Verdict = {
  verdict: VerdictKind;
  name: string;
  range: string;
  version: string | null;
  score: { score: number; grade: string } | null;
  summary: string;
  reasons: string[];
  commands: { apm: string; bun: string; npm: string; pnpm: string } | null;
  coverage: Coverage;
};

const SHOWN = 3;

/** Control characters (a terminal's escapes included), line breaks and bidi overrides: what can fake a line. */
// oxlint-disable-next-line eslint/no-control-regex -- matching control characters is the point: they are removed
const LINE_BREAKERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]+/g;

/** Registry text (which carries publisher text, such as a yank reason) on one line, so none can pose as apm's. */
export function oneLine(text: string): string {
  return text.replace(LINE_BREAKERS, " ").replace(/\s+/g, " ").trim();
}

/** The longest run of backticks in `text`, in one pass: a spread into Math.max overflows the stack on big input. */
function longestBacktickRun(text: string): number {
  let longest = 0;
  let run = 0;

  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 96) {
      run++;

      if (run > longest) longest = run;
    } else run = 0;
  }

  return longest;
}

/** Most characters of one registry or publisher string the verdict quotes; the rest is cut, and a note says so. */
const MAX_QUOTED = 300;

/**
 * Registry text that can come from a publisher (a yank reason, a dependency spec, a version) as a Markdown code span
 * on one line, fenced by more backticks than any run inside: an agent reading the verdict as Markdown sees data, never
 * a link, an image or HTML. The website quotes the same way (apps/web/lib/agent/text.ts inlineCode).
 */
export function quoted(text: string): string {
  const flat0 = oneLine(text);
  const end = flat0.length > MAX_QUOTED && /[\uD800-\uDBFF]/.test(flat0.charAt(MAX_QUOTED - 1)) ? MAX_QUOTED - 1 : MAX_QUOTED;
  const cut = Math.max(0, flat0.length - end);
  const flat = (cut > 0 ? flat0.slice(0, end) : flat0).trim();

  if (flat === "") return "(empty)";
  const fence = "`".repeat(longestBacktickRun(flat) + 1);
  const pad = flat.startsWith("`") || flat.endsWith("`") ? " " : "";

  return `${fence}${pad}${flat}${pad}${fence}${cut > 0 ? ` (cut: ${cut} more character${cut === 1 ? "" : "s"} not shown)` : ""}`;
}

/** A version or range as written when it is a plain one, else quoted. */
const plain = (text: string): string => (/^[0-9A-Za-z.+~^-]{1,64}$/.test(text) ? text : quoted(text));

function commands(name: string, version: string): NonNullable<Verdict["commands"]> {
  const spec = `${name}@${version}`;

  return { apm: `apm add ${spec}`, bun: `bun add ${spec}`, npm: `npm install ${spec}`, pnpm: `pnpm add ${spec}` };
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

const listed = (deps: readonly DepRef[]): string => `${deps.slice(0, SHOWN).map((d) => quoted(`${d.name}@${d.version}`)).join(", ")}${deps.length > SHOWN ? ` and ${deps.length - SHOWN} more` : ""}`;

const skippedText = (skipped: readonly { version: string; reason: string }[]): string => skipped.slice(0, SHOWN).map((s) => `${quoted(s.version)} (${quoted(s.reason)})`).join("; ");

/** How far the picked version's AI review got, for the coverage field. */
export function aiReviewCoverage(review: ReviewInput): AiReviewCoverage {
  switch (review.kind) {
    // the verdict is decided by the version's state before its review is looked at
    case "pulled":
      return "not-read";
    case "reviewed":
      return review.state === "no-answer" ? "no-answer" : "reviewed";
    case "queued":
    case "leased":
      return "in-progress";
    case "failed":
      return "no-answer";
    case "not-reviewed":
      return "not-selected";
    case "off":
      return "disabled";
    case "unreadable":
      return "unreadable";
    default: {
      const _exhaustive: never = review;

      return _exhaustive;
    }
  }
}

/** The words the summary ends with when no AI review stands behind the verdict; "" when one does or is under way. */
function noReviewNote(coverage: AiReviewCoverage): string {
  switch (coverage) {
    case "not-selected":
      return " No AI review: apm never picked this version for one.";
    case "disabled":
      return " No AI review: this registry runs none.";
    case "reviewed":
    case "in-progress":
    case "no-answer":
    case "unreadable":
    case "not-read":
      return "";
    default: {
      const _exhaustive: never = coverage;

      return _exhaustive;
    }
  }
}

const NOT_READ: Coverage = { aiReview: "not-read", dependencies: "not-read" };

/** What became of a version the policy picked, as the end of "it ...". */
function pulledText(status: PulledStatus): string {
  switch (status) {
    case "yanked":
      return "was yanked";
    case "revoke-pending":
      return "is being revoked";
    case "revoked":
      return "was revoked";
    case "withheld":
      return "is withheld by the registry, which means it was revoked or is being revoked";
    default: {
      const _exhaustive: never = status;

      return _exhaustive;
    }
  }
}

function reviewReason(review: ReviewInput): string {
  switch (review.kind) {
    case "pulled":
      return `The registry's answer about this version's AI review says it ${pulledText(review.status)}.`;
    case "not-reviewed":
      return "No AI review of this version.";
    case "off":
      return "This registry runs no AI review.";
    case "unreadable":
      return "apm could not read the AI review of this version.";
    case "queued":
      return "The AI review of this version is queued and has not started.";
    case "leased":
      return "The AI review of this version is running.";
    case "failed":
      return "The AI review of this version could not run.";
    case "reviewed":
      switch (review.state) {
        case "found-nothing":
          return "The AI review found nothing in the files it read.";
        case "cleared":
          return "The AI review flagged this version; a person at apm checked and dismissed the flag.";
        case "no-answer":
          return "The AI review gave no usable answer for this version.";
        case "under-review":
          return `The AI review flagged this version (${plural(review.findings, "finding", "findings")}); a person at apm is checking it.`;
        case "confirmed":
          return "apm reviewers confirmed this version is malicious.";
        default: {
          const _exhaustive: never = review.state;

          return _exhaustive;
        }
      }

    default: {
      const _exhaustive: never = review;

      return _exhaustive;
    }
  }
}

/** Why the picked version itself needs a look before an install, or null when its review is settled or absent. */
function reviewHold(review: ReviewInput): string | null {
  switch (review.kind) {
    case "queued":
    case "leased":
      return "its AI review has not finished";
    case "failed":
      return "its AI review ended without an answer";
    case "reviewed":
      return review.state === "under-review" ? "the AI review flagged it and a person has not decided yet" : review.state === "no-answer" ? "its AI review ended without an answer" : null;
    case "pulled":
    case "not-reviewed":
    case "off":
    case "unreadable":
      return null;
    default: {
      const _exhaustive: never = review;

      return _exhaustive;
    }
  }
}

export function explain(input: { name: string; range: string | null; resolved: ResolvedInput; review: ReviewInput }): Verdict {
  const { name, resolved, review } = input;
  const range = input.range ?? "latest";
  const asked = range === "latest" ? name : `${name}@${plain(range)}`;
  const base = { name, range };

  // registry text can carry publisher text (a yank reason, an error): the summary is apm's words only, the reasons quote it
  switch (resolved.kind) {
    case "unavailable":
      return { ...base, verdict: "unknown", version: null, score: null, summary: `apm could not check ${asked}: the registry did not answer. Nothing was checked; try again.`, reasons: [`What happened: ${quoted(resolved.reason)}`], commands: null, coverage: NOT_READ };
    case "missing":
      return { ...base, verdict: "not-found", version: null, score: null, summary: `No package named ${name} on apm or npm. Check the spelling: a near miss can be a typosquat.`, reasons: [`The registry said: ${quoted(resolved.reason)}`], commands: null, coverage: NOT_READ };
    case "refused": {
      const skips = resolved.skipped.slice(0, SHOWN).map((s) => `Skipped ${quoted(s.version)}: ${quoted(s.reason)}.`);

      return { ...base, verdict: "do-not-install", version: resolved.newest, score: null, summary: `Do not install ${asked}: apm's install policy refused it. The reasons say why.`, reasons: [`The registry said: ${quoted(resolved.reason)}`, ...skips], commands: null, coverage: NOT_READ };
    }

    case "ok":
      break;
    default: {
      const _exhaustive: never = resolved;

      return _exhaustive;
    }
  }

  const { version, report, deps } = resolved;
  const id = `${name}@${plain(version)}`;

  // 0. a version the registry stopped offering after the policy picked it: neither its review nor its score counts
  if (review.kind === "pulled") {
    return {
      ...base,
      verdict: "do-not-install",
      version,
      score: null,
      summary: `Do not install ${id}: it ${pulledText(review.status)}. The registry said so after its install policy picked this version, so apm's checks of it no longer count.`,
      reasons: [reviewReason(review)],
      commands: null,
      coverage: NOT_READ,
    };
  }

  const score = report ? { score: report.score, grade: report.grade } : null;
  const aiReview = aiReviewCoverage(review);
  const known = { ...base, version, score, coverage: { aiReview, dependencies: deps.unchecked > 0 ? "incomplete" : "complete" } satisfies Coverage };

  // 1. confirmed malicious, the version or anything it installs
  if (review.kind === "reviewed" && review.state === "confirmed") {
    return { ...known, verdict: "do-not-install", summary: `Do not install ${id}: apm reviewers confirmed it is malicious.`, reasons: [reviewReason(review)], commands: null };
  }

  if (deps.reviews.kind === "on" && deps.reviews.confirmed.length > 0) {
    const bad = deps.reviews.confirmed;

    return {
      ...known,
      verdict: "do-not-install",
      summary: `Do not install ${id}: it depends on ${listed(bad)}, which apm reviewers confirmed ${bad.length === 1 ? "is" : "are"} malicious.`,
      reasons: [`apm reviewers confirmed ${bad.length === 1 ? "this dependency is" : "these dependencies are"} malicious: ${listed(bad)}.`],
      commands: null,
    };
  }

  // 2. what apm could not read: it cannot say
  if (review.kind === "unreadable") {
    return { ...known, verdict: "unknown", summary: `apm could not read the AI review of ${id}, so it cannot say. Nothing was decided; try again.`, reasons: [reviewReason(review)], commands: null };
  }

  if (deps.reviews.kind === "unknown") {
    return { ...known, verdict: "unknown", summary: `apm could not read the AI reviews of ${id}'s dependencies, so it cannot say. Nothing was decided; try again.`, reasons: [], commands: null };
  }

  // 3. what apm read but has not finished checking, most serious first
  const lost = (report?.signals ?? []).filter((s) => s.points < 0).sort((a, b) => a.points - b.points);
  const holds: { why: string; reason: string }[] = [];
  const own = reviewHold(review);

  if (own) holds.push({ why: own, reason: reviewReason(review) });
  const depReviews: DepReviews = deps.reviews;

  if (depReviews.kind === "on") {
    const { underReview, pending, noAnswer } = depReviews;

    if (underReview.length > 0) holds.push({ why: "the AI review flagged a dependency and a person has not decided yet", reason: `The AI review flagged ${plural(underReview.length, "dependency", "dependencies")}; a person at apm is checking: ${listed(underReview)}.` });

    if (pending.length > 0) holds.push({ why: "the AI review of a dependency has not finished", reason: `The AI review of ${plural(pending.length, "dependency", "dependencies")} has not finished: ${listed(pending)}.` });

    if (noAnswer.length > 0) holds.push({ why: "the AI review of a dependency ended without an answer", reason: `The AI review of ${plural(noAnswer.length, "dependency", "dependencies")} ended without an answer: ${listed(noAnswer)}.` });
  }

  if (report !== null && report.score < CLEAN_SCORE) holds.push({ why: `it lost points: ${oneLine(lost[0]?.label ?? "see the signals")}`, reason: "" });

  if (deps.unchecked > 0) {
    holds.push({
      why: `apm could not score ${deps.unchecked} of its dependencies`,
      reason: `${plural(deps.unchecked, "dependency", "dependencies")} apm could not score: ${deps.uncheckedDeps.slice(0, SHOWN).map((d) => quoted(d.dependency)).join(", ")}.`,
    });
  }

  const reasons = holds.slice(0, 1).flatMap((h) => (h.reason ? [h.reason] : []));

  for (const s of lost.slice(0, SHOWN)) reasons.push(`${oneLine(s.label)} (${s.points} points${s.confidence === "possible" ? ", possible" : ""}).`);

  if (lost.length > SHOWN) reasons.push(`${plural(lost.length - SHOWN, "more signal", "more signals")} lost points.`);

  for (const h of holds.slice(1)) if (h.reason) reasons.push(h.reason);

  if (!own) reasons.push(reviewReason(review));

  if (resolved.skipped.length > 0) reasons.push(`Newer versions were skipped: ${skippedText(resolved.skipped)}.`);
  const run = commands(name, version);
  const note = noReviewNote(aiReview);

  if (report === null) return { ...known, verdict: "review-first", summary: `Review ${id} before installing: it passes apm's install policy and is not scored yet, so nothing has read its code.${note}`, reasons, commands: run };
  const scoreText = `scores ${report.score}/100 (${oneLine(report.grade)})`;
  const first = holds[0];

  if (first) return { ...known, verdict: "review-first", summary: `Review ${id} before installing: it passes apm's install policy and ${scoreText}, but ${first.why}.${note}`, reasons, commands: run };

  // a version apm never picked for AI review, or a registry that runs none, still installs on the static checks and a
  // fully scored tree; the summary says so in its own words, and coverage says it as data
  return {
    ...known,
    verdict: "install",
    summary: `${id} passes apm's checks: it ${scoreText}, is past the 24-hour cooldown, nothing in its dependency tree was refused or flagged, and apm scored every dependency.${note}`,
    reasons,
    commands: run,
  };
}
