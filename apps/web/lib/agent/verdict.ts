// The short answer an agent acts on before an install: what the registry's install policy picked for a range,
// what the AI review says about that version and about every dependency the policy walked, and what to run. Pure,
// so the MCP tool, GET /api/explain and the tests share it. packages/cli/src/explain.ts mirrors these rules for
// `apm explain`; tests/fixtures/explain-verdicts.json holds the cases both must answer the same way.
//
// The rule: "install" only when apm knows the version and everything it brings in is fine. Anything apm could not
// read is "unknown"; anything it read but has not finished checking is "review-first". Like the rest of the site it
// never calls a version "safe": "install" means it passed apm's checks, and the limits of those checks travel with it.
import { installCommand, INSTALL_CLIENTS, type InstallClient } from "../install-note";
import type { Fetched } from "../registry";
import type { PublicReview, ReviewAnswer } from "../review-schema";
import type { DepRef, DepReviews, ResolveOutcome } from "./source";
import { oneLine } from "./text";

export const VERDICTS = ["install", "review-first", "do-not-install", "not-found", "unknown"] as const;

export type VerdictKind = (typeof VERDICTS)[number];

/** Scores at or above this read as clean on the site (the green badge); below it, the lost points are worth a look. */
export const CLEAN_SCORE = 75;

/**
 * Where the AI review of the picked version stands. queued and leased are a review in progress; failed and a
 * no-answer result ended without one; not-reviewed means the version was never picked for review; off means the
 * registry runs none; unreadable means apm could not ask.
 */
export type ReviewInput =
  | { kind: "reviewed"; state: PublicReview["state"]; findings: number }
  | { kind: "queued" }
  | { kind: "leased" }
  | { kind: "failed" }
  | { kind: "not-reviewed" }
  | { kind: "off" }
  | { kind: "unreadable" };

export type Verdict = {
  verdict: VerdictKind;
  name: string;
  /** The range asked about ("latest" when none was given). */
  range: string;
  /** The version the policy picked, or the newest one it refused; null when there is none. */
  version: string | null;
  score: { score: number; grade: string } | null;
  /** One sentence an agent can repeat to a person. */
  summary: string;
  /** Why, most important first. */
  reasons: string[];
  /** What to run, by client; null when nothing should be installed yet. */
  commands: Record<InstallClient, string> | null;
};

const SHOWN = 3;

function commandsFor(name: string, version: string): Record<InstallClient, string> {
  const out: Partial<Record<InstallClient, string>> = {};

  // apm add takes the exact version the policy picked, like the package manager it hands off to
  for (const client of INSTALL_CLIENTS) out[client] = client === "apm" ? `apm add ${name}@${version}` : installCommand({ client, name, version });

  return { apm: out.apm ?? "", bun: out.bun ?? "", npm: out.npm ?? "", pnpm: out.pnpm ?? "" };
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

const listed = (deps: readonly DepRef[]): string => `${deps.slice(0, SHOWN).map((d) => oneLine(`${d.name}@${d.version}`)).join(", ")}${deps.length > SHOWN ? ` and ${deps.length - SHOWN} more` : ""}`;

function reviewReason(review: ReviewInput): string {
  switch (review.kind) {
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

/** The verdict for `name@range`, from the registry's resolve answer and the AI review of the version it picked. */
export function explainInstall(input: { name: string; range: string | null; resolve: ResolveOutcome; review: ReviewInput }): Verdict {
  const { name, resolve, review } = input;
  const range = input.range ?? "latest";
  const asked = range === "latest" ? name : `${name}@${range}`;
  const base = { name, range };

  switch (resolve.kind) {
    case "unavailable":
      return { ...base, verdict: "unknown", version: null, score: null, summary: `apm could not check ${asked}: the registry did not answer. Nothing was checked; try again.`, reasons: [], commands: null };
    // the registry's reasons carry publisher text (a yank reason): one line each, so none can pose as a line of apm's
    case "missing":
      return { ...base, verdict: "not-found", version: null, score: null, summary: `No package named ${name} on apm or npm. Check the spelling: a near miss can be a typosquat.`, reasons: [oneLine(resolve.reason)], commands: null };
    case "refused": {
      const skips = resolve.skipped.slice(0, SHOWN).map((s) => `Skipped ${oneLine(s.version)}: ${oneLine(s.reason)}.`);

      return { ...base, verdict: "do-not-install", version: resolve.newest, score: null, summary: `Do not install ${asked}: ${oneLine(resolve.reason)}`, reasons: [oneLine(resolve.reason), ...skips], commands: null };
    }

    case "ok":
      break;
    default: {
      const _exhaustive: never = resolve;

      return _exhaustive;
    }
  }

  const { version, report, deps } = resolve;
  const id = `${name}@${version}`;
  const score = report ? { score: report.score, grade: report.grade } : null;
  const known = { ...base, version, score };

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
      reason: `${plural(deps.unchecked, "dependency", "dependencies")} apm could not score: ${deps.uncheckedDeps.slice(0, SHOWN).map((d) => oneLine(d.dependency)).join(", ")}.`,
    });
  }

  const reasons = holds.slice(0, 1).flatMap((h) => (h.reason ? [h.reason] : []));

  for (const s of lost.slice(0, SHOWN)) reasons.push(`${oneLine(s.label)} (${s.points} points${s.confidence === "possible" ? ", possible" : ""}).`);

  if (lost.length > SHOWN) reasons.push(`${plural(lost.length - SHOWN, "more signal", "more signals")} lost points.`);

  for (const h of holds.slice(1)) if (h.reason) reasons.push(h.reason);

  if (!own) reasons.push(reviewReason(review));

  if (resolve.skipped.length > 0) reasons.push(`Newer versions were skipped: ${resolve.skipped.slice(0, SHOWN).map((s) => `${oneLine(s.version)} (${oneLine(s.reason)})`).join("; ")}.`);
  const commands = commandsFor(name, version);

  if (report === null) return { ...known, verdict: "review-first", summary: `Review ${id} before installing: it passes apm's install policy and is not scored yet, so nothing has read its code.`, reasons, commands };
  const scoreText = `scores ${report.score}/100 (${report.grade})`;
  const first = holds[0];

  if (first) return { ...known, verdict: "review-first", summary: `Review ${id} before installing: it passes apm's install policy and ${scoreText}, but ${first.why}.`, reasons, commands };

  return {
    ...known,
    verdict: "install",
    summary: `${id} passes apm's checks: it ${scoreText}, is past the 24-hour cooldown, nothing in its dependency tree was refused or flagged, and apm scored every dependency.`,
    reasons,
    commands,
  };
}

/**
 * The review input for the verdict, from GET /-/apm/v1/review read without a cache. A 404 means this registry has AI
 * review off (the resolve answer already showed the version exists); a read that failed is unreadable, never "none".
 */
export function reviewInput(answer: Fetched<Pick<ReviewAnswer, "status" | "review" | "job">>): ReviewInput {
  switch (answer.kind) {
    case "unavailable":
      return { kind: "unreadable" };
    case "missing":
      return { kind: "off" };
    case "ok":
      break;
    default: {
      const _exhaustive: never = answer;

      return _exhaustive;
    }
  }

  const a = answer.value;

  if (a.review !== null) return { kind: "reviewed", state: a.review.state, findings: a.review.findings.length };

  if (a.job === "leased") return { kind: "leased" };

  switch (a.status) {
    case "queued":
      return { kind: "queued" };
    case "failed":
      return { kind: "failed" };
    case "not-reviewed":
      return { kind: "not-reviewed" };
    // "reviewed" with no review cannot be acted on: treat it as unreadable
    case "reviewed":
      return { kind: "unreadable" };
    default: {
      const _exhaustive: never = a.status;

      return _exhaustive;
    }
  }
}

/** The verdict as a few plain lines: the summary, the reasons, and the apm command. */
export function verdictText(v: Verdict): string {
  const lines = [`Verdict: ${v.verdict}`, v.summary];

  if (v.reasons.length > 0) lines.push("", ...v.reasons.map((r) => `- ${r}`));

  if (v.commands) {
    lines.push("", `Run: ${v.commands.apm}`, `(or ${v.commands.bun}, ${v.commands.npm}, ${v.commands.pnpm}; plain bun, npm and pnpm only get apm's checks when their registry is set to apm)`);
  }

  return lines.join("\n");
}
