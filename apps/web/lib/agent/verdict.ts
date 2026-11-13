// The short answer an agent acts on before an install: what the registry's install policy picked for a range,
// what the AI review says about that version and about every dependency the policy walked, and what to run. Pure,
// so the MCP tool, GET /api/explain and the tests share it. packages/cli/src/explain.ts mirrors these rules for
// `apm explain`; tests/fixtures/explain-verdicts.json holds the cases both must answer the same way.
//
// The rule: "install" only when apm knows the version and everything it brings in is fine. Anything apm could not
// read is "unknown"; anything it read but has not finished checking is "review-first". Like the rest of the site it
// never calls a version "safe": "install" means it passed apm's checks, and the limits of those checks travel with it.
// A score never makes it "do-not-install" (the owner's warn-not-block policy, 2026-11): a low or incomplete score, no
// score, or a dependency apm flagged installs with a warning, so it is "review-first", and the summary says it installs
// and why. "do-not-install" is only for a revoked or yanked version and one an apm reviewer confirmed malicious, the
// version or anything in its tree.
import { installCommand, INSTALL_CLIENTS, type InstallClient } from "../install-note";
import type { Fetched } from "../registry";
import type { PublicReview, ReviewAnswer } from "../review-schema";
import type { DepRef, DepReviews, ResolveOutcome } from "./source";
import { inlineCode, oneLine, UNTRUSTED_NOTE } from "./text";

export const VERDICTS = ["install", "review-first", "do-not-install", "not-found", "unknown"] as const;

export type VerdictKind = (typeof VERDICTS)[number];

/** Scores at or above this read as clean on the site (the green badge); below it, the lost points are worth a look. */
export const CLEAN_SCORE = 75;

/** The registry's score floor: below it an install warns (and `apm add --strict` refuses). */
export const SCORE_FLOOR = 40;

/** A skip that is a version pulled from installs (revoked, being revoked, yanked): not a score. */
const PULLED_REASON = /^(?:revoked by its owner|revocation pending|yanked|confirmed malicious by an apm reviewer)/;

/** Whether the registry refused because a version was pulled: every version it skipped was revoked or yanked. */
export function refusedAsPulled(skipped: readonly { reason: string }[]): boolean {
  return skipped.length > 0 && skipped.every((s) => PULLED_REASON.test(s.reason));
}

/**
 * Why the registry no longer offers a version its install policy picked a moment before: it was yanked or revoked,
 * a revocation is pending, or the registry withholds it (a redacted answer that names no state).
 */
export type PulledStatus = "yanked" | "revoke-pending" | "revoked" | "withheld";

/**
 * Where the AI review of the picked version stands. queued and leased are a review in progress; failed and a
 * no-answer result ended without one; not-reviewed means the version was never picked for review; off means the
 * registry runs none; unreadable means apm could not ask; pulled means the review answer said the version is no
 * longer offered, whatever its review says.
 */
export type ReviewInput =
  | { kind: "pulled"; status: PulledStatus }
  | { kind: "reviewed"; state: PublicReview["state"]; findings: number }
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
  coverage: Coverage;
  /**
   * What the version lost points for, with the file and line each cites: the registry's warning reasons (at most
   * three), else the heaviest signals' first evidence. Publisher text, so each is quoted as a code span.
   */
  evidence: string[];
  /** The version's page (or the package's) on the website, from the registry's warning; null when it sent none. */
  url: string | null;
};

const SHOWN = 3;

function commandsFor(name: string, version: string): Record<InstallClient, string> {
  const out: Partial<Record<InstallClient, string>> = {};

  // apm add takes the exact version the policy picked, like the package manager it hands off to
  for (const client of INSTALL_CLIENTS) out[client] = client === "apm" ? `apm add ${name}@${version}` : installCommand({ client, name, version });

  return { apm: out.apm ?? "", bun: out.bun ?? "", npm: out.npm ?? "", pnpm: out.pnpm ?? "" };
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

// Text the registry passes on (a yank reason, a dependency spec, a version) can come from a publisher: it is quoted as
// a code span, so a Markdown reader sees data, never a link, an image, HTML or a line of apm's
const quoted = (text: string): string => inlineCode(text, { max: 300 });

/** A version or range as written when it is a plain one, else quoted. */
const plain = (text: string): string => (/^[0-9A-Za-z.+~^-]{1,64}$/.test(text) ? text : quoted(text));

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

/** The verdict for `name@range`, from the registry's resolve answer and the AI review of the version it picked. */
/**
 * The verdict, with the evidence behind it and the version's page: what the version lost points for (the registry's
 * warning reasons, at most three, else its heaviest signals' first evidence, each with its file and line) and the
 * link the registry's warning gives. Before this (review of a76b9fc, finding 4) a score of 30 with
 * `index.js:7: eval(body)` and a version page came back as review-first with only the score and the signal's label.
 */
export function explainInstall(input: { name: string; range: string | null; resolve: ResolveOutcome; review: ReviewInput }): Verdict {
  // a review read that says the version is pulled (revoked, yanked or withheld) came after the resolve: the resolve's
  // evidence lines quote the package's source, which a withheld version no longer shows (review of b725ce9, finding 2)
  const shown = input.review.kind === "pulled" ? { evidence: [], url: null } : evidenceOf(input.resolve);

  return { ...decide(input), ...shown };
}

/** The page link the registry gave, when it is a web address; anything else is dropped rather than shown. */
function pageUrl(raw: string | undefined): string | null {
  if (raw === undefined) return null;

  try {
    const u = new URL(raw);

    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

function evidenceOf(resolve: { name: string; range: string | null; resolve: ResolveOutcome; review: ReviewInput }["resolve"]): Pick<Verdict, "evidence" | "url"> {
  if (resolve.kind !== "ok") return { evidence: [], url: null };

  // the version's own score warning, not its cooldown one: the evidence is the score's
  const own = resolve.deps.warnings.find((w) => w.via.length === 0 && w.kind !== "cooldown");

  const fromSignals = (resolve.report?.signals ?? [])
    .filter((s) => s.points < 0)
    .toSorted((a, b) => a.points - b.points)
    .slice(0, SHOWN)
    .flatMap((s) => (s.evidence[0] === undefined ? [] : [`${s.label}: ${s.evidence[0]}`]));

  const lines = own?.reasons !== undefined && own.reasons.length > 0 ? own.reasons.slice(0, SHOWN) : fromSignals;

  return { evidence: lines.map((l) => quoted(l)), url: pageUrl(own?.url) };
}

/** A verdict before its evidence and link are added (explainInstall). */
type Decided = Omit<Verdict, "evidence" | "url">;

function decide(input: { name: string; range: string | null; resolve: ResolveOutcome; review: ReviewInput }): Decided {
  const { name, resolve, review } = input;
  const range = input.range ?? "latest";
  const asked = range === "latest" ? name : `${name}@${plain(range)}`;
  const base = { name, range };

  switch (resolve.kind) {
    case "unavailable":
      return { ...base, verdict: "unknown", version: null, score: null, summary: `apm could not check ${asked}: the registry did not answer. Nothing was checked; try again.`, reasons: [], commands: null, coverage: NOT_READ };
    // the registry's reasons carry publisher text (a yank reason): the summary is apm's words only, the reasons quote it
    case "missing":
      return { ...base, verdict: "not-found", version: null, score: null, summary: `No package named ${name} on apm or npm. Check the spelling: a near miss can be a typosquat.`, reasons: [`The registry said: ${quoted(resolve.reason)}`], commands: null, coverage: NOT_READ };
    case "refused": {
      const skips = resolve.skipped.slice(0, SHOWN).map((s) => `Skipped ${quoted(s.version)}: ${quoted(s.reason)}.`);
      const reasons = [`The registry said: ${quoted(resolve.reason)}`, ...skips];

      if (resolve.confirmed.length > 0) {
        return { ...base, verdict: "do-not-install", version: resolve.newest, score: null, summary: `Do not install ${asked}: it would install ${listed(resolve.confirmed)}, which apm reviewers confirmed ${resolve.confirmed.length === 1 ? "is" : "are"} malicious.`, reasons, commands: null, coverage: NOT_READ };
      }

      if (refusedAsPulled(resolve.skipped)) return { ...base, verdict: "do-not-install", version: resolve.newest, score: null, summary: `Do not install ${asked}: apm's install policy refused it. The reasons say why.`, reasons, commands: null, coverage: NOT_READ };

      // held back for another reason (strict mode's cooldown or score floor): not a sign of malice, so a look first,
      // and no command to run now
      return { ...base, verdict: "review-first", version: resolve.newest, score: null, summary: `Review ${asked} before installing: apm's install policy holds it back for now, and nothing in its answer says it is malicious. The reasons say why.`, reasons, commands: null, coverage: NOT_READ };
    }

    case "ok":
      break;
    default: {
      const _exhaustive: never = resolve;

      return _exhaustive;
    }
  }

  const { version, report, deps } = resolve;
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
  // a version published inside apm's cooldown installs with a warning (strict mode refuses it): a look first
  const fresh = deps.warnings.find((w) => w.via.length === 0 && w.kind === "cooldown");

  if (fresh) holds.push({ why: "it was published inside apm's 24-hour cooldown, so it has had little time to be looked at", reason: `The registry said: ${quoted(`${name}@${version}: ${fresh.text}`)}` });
  const depReviews: DepReviews = deps.reviews;

  if (depReviews.kind === "on") {
    const { underReview, pending, noAnswer } = depReviews;

    if (underReview.length > 0) holds.push({ why: "the AI review flagged a dependency and a person has not decided yet", reason: `The AI review flagged ${plural(underReview.length, "dependency", "dependencies")}; a person at apm is checking: ${listed(underReview)}.` });

    if (pending.length > 0) holds.push({ why: "the AI review of a dependency has not finished", reason: `The AI review of ${plural(pending.length, "dependency", "dependencies")} has not finished: ${listed(pending)}.` });

    if (noAnswer.length > 0) holds.push({ why: "the AI review of a dependency ended without an answer", reason: `The AI review of ${plural(noAnswer.length, "dependency", "dependencies")} ended without an answer: ${listed(noAnswer)}.` });
  }

  // what the registry warned about in the tree: it installs, but each was flagged
  const flaggedDeps = deps.warnings.filter((w) => w.via.length > 0);

  if (flaggedDeps.length > 0) {
    holds.push({
      why: `it brings in ${plural(flaggedDeps.length, "dependency", "dependencies")} apm flagged (published inside the cooldown, a score under ${SCORE_FLOOR}, an incomplete analysis, no score, or a lookup that failed)`,
      reason: `apm flagged ${plural(flaggedDeps.length, "dependency", "dependencies")}: ${flaggedDeps
        .slice(0, SHOWN)
        .map((w) => quoted(`${w.name}@${w.version}: ${w.text}`))
        .join(", ")}${flaggedDeps.length > SHOWN ? ` and ${flaggedDeps.length - SHOWN} more` : ""}.`,
    });
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

  if (resolve.skipped.length > 0) reasons.push(`Newer versions were skipped: ${skippedText(resolve.skipped)}.`);
  const commands = commandsFor(name, version);
  const note = noReviewNote(aiReview);

  const ownWarning = deps.warnings.find((w) => w.via.length === 0 && w.kind !== "cooldown");

  // the version itself has no score: it installs, and nothing has read its code
  if (report === null) {
    if (ownWarning?.kind === "unscorable") reasons.unshift(`The registry said: ${quoted(ownWarning.text)}`);

    return { ...known, verdict: "review-first", summary: ownWarning?.kind === "pending" ? `Installs, but ${id} is still being analysed: apm has no score for it yet, so nothing has read its code. Review it before installing, or ask again in a minute.${note}` : `Installs, but apm ${ownWarning?.kind === "unscorable" ? "cannot score" : "has not scored"} ${id}${ownWarning?.kind === "unscorable" ? "" : " yet"}, so nothing has read its code. Review it before installing.${note}`, reasons, commands };
  }

  const scoreText = `scores ${report.score}/100 (${oneLine(report.grade)})`;
  const incomplete = report.signals.find((s) => s.id === "incomplete");

  // an analysis that did not read everything, or a score under the floor: it installs with a warning
  if (incomplete) {
    reasons.unshift(...incomplete.evidence.slice(0, SHOWN).map((e) => `apm did not read: ${quoted(e)}`));

    return { ...known, verdict: "review-first", summary: `Installs, but apm could not fully analyse ${id}: it ${scoreText}, and the reasons say what apm did not read. Review it before installing.${note}`, reasons, commands };
  }

  if (report.score < SCORE_FLOOR) return { ...known, verdict: "review-first", summary: `Installs, but ${id} ${scoreText}: it lost points: ${oneLine(lost[0]?.label ?? "see the signals")}. Review it before installing.${note}`, reasons, commands };
  const first = holds[0];

  if (first) return { ...known, verdict: "review-first", summary: `Review ${id} before installing: it passes apm's install policy and ${scoreText}, but ${first.why}.${note}`, reasons, commands };

  // a version apm never picked for AI review, or a registry that runs none, still installs on the static checks and a
  // fully scored tree; the summary says so in its own words, and coverage says it as data
  return {
    ...known,
    verdict: "install",
    summary: `${id} passes apm's checks: it ${scoreText}, is past the 24-hour cooldown, nothing in its dependency tree was refused or flagged, and apm scored every dependency.${note}`,
    reasons,
    commands,
  };
}

/**
 * Whether a review answer says the version is no longer offered: any state but active, or a redacted answer (the
 * registry withholds a revoked version's source) even when it names no state. null when it is still offered.
 */
export function pulledStatus(answer: Pick<ReviewAnswer, "versionStatus" | "redacted">): PulledStatus | null {
  const status = answer.versionStatus;

  if (status !== undefined && status !== "active") return status;

  return answer.redacted === true ? "withheld" : null;
}

/**
 * The review input for the verdict, from GET /-/apm/v1/review read without a cache. A 404 means this registry has AI
 * review off (the resolve answer already showed the version exists); a read that failed is unreadable, never "none".
 * An answer that says the version was yanked, revoked or withheld is "pulled" before anything else in it is read.
 */
export function reviewInput(answer: Fetched<Pick<ReviewAnswer, "status" | "review" | "job" | "versionStatus" | "redacted">>): ReviewInput {
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
  const pulled = pulledStatus(a);

  if (pulled !== null) return { kind: "pulled", status: pulled };

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

/**
 * The verdict as a few plain lines: apm's verdict and summary first, on lines of their own, then the reasons (where
 * anything the registry passed on from a publisher sits in code spans), the coverage and the apm command.
 */
export function verdictText(v: Verdict): string {
  const lines = [`Verdict: ${v.verdict}`, v.summary, `AI review: ${v.coverage.aiReview}. Dependencies scored: ${v.coverage.dependencies}.`];

  if (v.reasons.length > 0) lines.push("", "Reasons:", ...v.reasons.map((r) => `- ${r}`));

  if (v.evidence.length > 0) lines.push("", "Evidence:", ...v.evidence.map((e) => `- ${e}`));

  if (v.reasons.length > 0 || v.evidence.length > 0) lines.push("", UNTRUSTED_NOTE);

  if (v.url) lines.push("", `Details: ${v.url}`);

  if (v.commands) {
    lines.push("", `Run: ${v.commands.apm}`, `(or ${v.commands.bun}, ${v.commands.npm}, ${v.commands.pnpm}; plain bun, npm and pnpm only get apm's checks when their registry is set to apm)`);
  }

  return lines.join("\n");
}
