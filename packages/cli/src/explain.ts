// `apm explain <pkg>[@range]`: a short verdict an agent (or a person) can act on before an install. Pure.
// The website's explain_install MCP tool and GET /api/explain use the same rules (apps/web/lib/agent/verdict.ts);
// change both together: tests/fixtures/explain-verdicts.json holds the cases both must answer the same way.
//
// The rule (the owner's agent-native policy, 2026-11; docs/AGENTS.md "The verdict"): "review-first" means a person
// should look: a risk signal the scorer found (the RISK_SIGNALS list), a score under the floor, an AI review flag a
// person has not decided, a dependency flagged the same way, a version (the one picked, or a dependency) published
// inside the 24-hour cooldown that apm cannot clear, or an analysis apm could not finish. The last is fail-closed: an
// analysis that did not read everything installs only when it positively records that the one gap is whole files left
// unread for their size or the byte budget (readingOf); every other gap, or a record that does not say, holds. apm's
// own work that has not started never interrupts anyone: an AI review not finished or not picked, a dependency not
// scored yet, too large to score or not looked up installs, and the answer lists each in
// `notes` for the agent to mention after installing. A version inside the cooldown is replaced by the newest one in range
// past it (agent.ts), so only a range with no such version stays review-first for its age. Anything apm could not read
// is "unknown", and so is a version apm has no score for (queued, recorded as never scorable, or no word on why): a queued version is pending,
// never clean; "do-not-install" is only for a revoked or yanked version and one an apm reviewer confirmed malicious,
// the version or anything in its tree. Like the rest of apm it never calls a version "safe".
import type { DistTag, Report, ReportCoverage } from "./api.ts";

/** "2,656 files (74.0 MB)": what a version apm did not read in full left out. */
function omittedText(c: { omittedFiles: number; omittedBytes: number }): string {
  return `${c.omittedFiles.toLocaleString("en-US")} file${c.omittedFiles === 1 ? "" : "s"} (${(c.omittedBytes / 1_000_000).toFixed(1)} MB)`;
}

/** Why apm skips whole files, in the words every explain answer uses. */
const SKIPPED_WHY = "over what apm reads of one file or of one package";

/**
 * The grade of a version apm did not read in full (packages/core readingOf). It stays "P" in `grade` for agents; the
 * answer's text never shows the letter.
 */
const NOT_ALL_READ_GRADE = "P";

/** A registry's count of the unchecked dependencies it did not list by name: "36 more". */
const COUNTED_REST = /^\d+ more$/;


export const VERDICTS = ["install", "review-first", "do-not-install", "not-found", "unknown"] as const;

export type VerdictKind = (typeof VERDICTS)[number];

/** Scores at or above this are clean (the site's green badge); below it the lost points are a note. */
export const CLEAN_SCORE = 75;

/** The registry's score floor: below it `apm add` warns (and `--strict` refuses). */
export const SCORE_FLOOR = 40;

/**
 * Scorer signals (packages/core SIGNAL_IDS) that make an install review-first wherever they cost points, in the version
 * or in a dependency the registry flagged: what droppers and stealers do (a remote shell, a capture endpoint, secrets
 * sent out, a credential file read, code run from decoded strings, obfuscator output, the pairings malware has),
 * install hooks that reach the network or download, and a look-alike name. Picked against tools/score-eval: every one
 * of the 40 and 113 malicious samples the old rule (under 75) sent to a person still goes there, and of the 70 popular
 * tarballs only bun and esbuild (a binary downloaded at install) and @sentry/node (code kept in base64) do. Install
 * scripts that only build, a new publisher, a new dependency and what an SDK names are notes, not holds.
 */
export const RISK_SIGNALS = ["remote-shell", "capture-endpoint", "exfiltration", "credential-read", "install-download", "install-network", "runs-decoded-code", "obfuscated", "suspicious-combination", "typosquat"] as const;

/**
 * Signals a scorer before CURRENT_SCORER gave a risk's meaning that it later split up: v9's credential-access is v10's
 * credential-read and exfiltration. A stored analysis keeps its scorer's ids until it is analysed again, so in one from
 * an earlier scorer, or one whose scorer the registry did not say, these are risks too. packages/core holds the list.
 */
export const LEGACY_RISK_SIGNALS = ["credential-access"] as const;

/** Risk signals about the name rather than the code: they count unless the name is an established one. */
export const NAME_RISK_SIGNALS = ["typosquat"] as const;

/**
 * Dependency names the look-alike rule flags that are long-established packages in their own right, each checked by
 * hand: safer-buffer (express installs it; one edit from safe-buffer, published by a Node.js core contributor since
 * 2018). Only as a dependency, never as the name an agent asks for, and only the name signal: any other risk counts.
 * packages/core holds the list; add to it only with the package's own record checked.
 */
export const ESTABLISHED_DEPENDENCY_NAMES = ["safer-buffer"] as const;

/** What the risk rules read: the version asked for, or a dependency it brings in, by name. */
export type RiskOf = { kind: "version" } | { kind: "dependency"; name: string };

export const AS_VERSION: RiskOf = { kind: "version" };

/** Whether a name signal is set aside for `of`: a dependency whose name is an established one. */
const nameExempt = (of: RiskOf): boolean => of.kind === "dependency" && ESTABLISHED_DEPENDENCY_NAMES.some((n) => n === of.name);

/** The scorer whose signal ids RISK_SIGNALS names (packages/core SCORER). */
export const CURRENT_SCORER = "apm-score-v11";

/** The scorers whose signal ids are RISK_SIGNALS': apm-score-v10, which split v9's, and every one since (apm-score-v12 before any registry writes it). */
const SPLIT_SCORERS: readonly string[] = ["apm-score-v10", CURRENT_SCORER, "apm-score-v12"];

/** The scorers that always state coverage and grade a partial reading "P": apm-score-v11 and every one since (packages/core COVERAGE_SCORERS). */
export const COVERAGE_SCORERS: readonly string[] = [CURRENT_SCORER, "apm-score-v12"];

const statesCoverage = (scorer: string | null): boolean => scorer !== null && COVERAGE_SCORERS.includes(scorer);

/** Signals that say apm did not read or finish everything: every analysis with one holds (packages/core GAP_SIGNALS). */
export const GAP_SIGNALS = ["incomplete", "unanalyzed-files"] as const;

/**
 * The one gap a reading may have and still install: whole files left unread for their size or the bytes one analysis
 * reads (packages/core BENIGN_OMISSIONS). Anything not on it holds.
 */
export const BENIGN_OMISSIONS = ["too-large", "over-budget"] as const;

/** A scored signal as the risk rules read it: its id and what it cost. */
export type ScoredSignal = { id: string; points: number };

/** A score as the risk rules read it; `scorer` null when the registry did not say which scorer wrote it. */
export type Scored = { score: number | null; signals: readonly ScoredSignal[]; scorer: string | null };

const isGap = (id: string): boolean => GAP_SIGNALS.some((g) => g === id);

/**
 * The risk signals that cost points, heaviest first: RISK_SIGNALS (less NAME_RISK_SIGNALS for a dependency whose name
 * is in ESTABLISHED_DEPENDENCY_NAMES), and LEGACY_RISK_SIGNALS unless `scorer` is apm-score-v10 or later.
 */
export function riskSignalsOf<S extends ScoredSignal>(signals: readonly S[], scorer: string | null, of: RiskOf): S[] {
  const legacy = scorer === null || !SPLIT_SCORERS.includes(scorer);
  const counts = (id: string): boolean => (RISK_SIGNALS.some((r) => r === id) && !(nameExempt(of) && NAME_RISK_SIGNALS.some((n) => n === id))) || (legacy && LEGACY_RISK_SIGNALS.some((r) => r === id));

  return signals.filter((s) => s.points < 0 && counts(s.id)).toSorted((a, b) => a.points - b.points);
}

/** Whether a scored version carries a real risk: a risk signal, or a score under the floor. */
export function isRisky(input: Scored, of: RiskOf): boolean {
  return riskSignalsOf(input.signals, input.scorer, of).length > 0 || (input.score !== null && input.score < SCORE_FLOOR);
}

/**
 * How much of a version apm read (packages/core readingOf, which grades only `partial` "P"), fail-closed:
 * complete, nothing left unread and no GAP_SIGNALS (an earlier scorer, which stored no coverage, counted every file it
 * left unread as one); partial, the current scorer recorded whole files left unread, every reason on BENIGN_OMISSIONS,
 * and nothing else unfinished; incomplete, anything else: a gap signal, a stop, an empty, unknown or unreadable list of
 * reasons, an earlier scorer's partial reading, or the current scorer's analysis with no coverage at all.
 */
export type Reading = { kind: "complete" } | { kind: "partial"; omittedFiles: number; omittedBytes: number } | { kind: "incomplete" };

export function readingOf(input: { scorer: string | null; signals: readonly { id: string }[]; coverage: ReportCoverage | null }): Reading {
  if (input.signals.some((s) => isGap(s.id))) return { kind: "incomplete" };
  const c = input.coverage;

  if (c === null) return statesCoverage(input.scorer) ? { kind: "incomplete" } : { kind: "complete" };

  switch (c.kind) {
    case "complete":
      return c;
    case "partial": {
      const benign = c.reasons.length > 0 && c.reasons.every((r) => BENIGN_OMISSIONS.some((b) => b === r));

      return statesCoverage(input.scorer) && benign ? { kind: "partial", omittedFiles: c.omittedFiles, omittedBytes: c.omittedBytes } : { kind: "incomplete" };
    }

    case "unreadable":
      return { kind: "incomplete" };
    default: {
      const _exhaustive: never = c;

      return _exhaustive;
    }
  }
}

/**
 * Older versions `apm explain` asks for when the one picked is inside the cooldown, before it gives up: each is a
 * resolve of its own, so a burst of releases costs at most this many more.
 */
export const MAX_OLDER_LOOKUPS = 5;

/** A dist-tag (latest, next, beta) rather than a semver range: a name, not a version, `x` or a `v1`. */
const TAG = /^(?!v?\d)(?![xX]$)[A-Za-z][\w.-]*$/;

/** A hyphen range, `1.0.0 - 2.0.0`, as one comparator set: node-semver takes it only when it is the whole set. */
const HYPHEN = /^(\S+)\s+-\s+(\S+)$/;

/**
 * One `||` alternative as a comparator set another comparator can be added to: a hyphen range becomes `>=low <=high`,
 * which node-semver reads the same way for full and partial versions (`<=2.3` is `<2.4.0-0`, as `- 2.3` is).
 */
function comparatorSet(part: string): string {
  const hyphen = HYPHEN.exec(part);

  return hyphen ? `>=${hyphen[1] ?? ""} <=${hyphen[2] ?? ""}` : part;
}

/**
 * The range `range` less `version` and everything newer: a tag keeps its channel under `<version` (as the registry
 * reads a tag: in-channel versions up to its target, prereleases only of the target's own release), a range gets
 * `<version` added to each of its `||` alternatives, each made a plain comparator set first (a hyphen range is not).
 */
export function olderRange(range: string, version: string): string {
  if (TAG.test(range.trim())) return `<${version}`;

  return range
    .split("||")
    .map((part) => `${comparatorSet(part.trim())} <${version}`.trim())
    .join(" || ");
}

/**
 * The resolve the verdict rests on: the registry's pick for `range`, or, when that version is inside the cooldown, the
 * newest older one in range past it (asked as `olderRange`, at most MAX_OLDER_LOOKUPS times). An older lookup the
 * registry does not answer makes the whole answer unavailable; no older version in range, or only fresh ones, keeps
 * the fresh pick, which the verdict sends to a person.
 */
export async function resolveForVerdict(input: { range: string; resolve: (range: string) => Promise<ResolvedInput> }): Promise<{ resolved: ResolvedInput; older: OlderSearch }> {
  const first = await input.resolve(input.range);

  if (first.kind !== "ok") return { resolved: first, older: { kind: "not-needed" } };
  let current = first;
  const passedOver: { version: string; text: string }[] = [];

  for (let looked = 0; ; looked++) {
    const fresh = current.deps.warnings.find((w) => w.via.length === 0 && w.kind === "cooldown");

    if (fresh === undefined) return { resolved: current, older: passedOver.length > 0 ? { kind: "picked", passedOver } : { kind: "not-needed" } };

    if (looked >= MAX_OLDER_LOOKUPS) return { resolved: first, older: { kind: "gave-up", looked: looked + 1 } };
    const older = await input.resolve(olderRange(input.range, current.version));

    // nothing older in range passes (or matches): the fresh version is all there is
    if (older.kind === "refused" || older.kind === "missing") return { resolved: first, older: { kind: "none" } };

    if (older.kind === "unavailable") return { resolved: older, older: { kind: "not-needed" } };
    passedOver.push({ version: current.version, text: fresh.text });
    current = older;
  }
}

/** Exit codes, so a script can branch without parsing: 2 stays the CLI's usage error. */
export const EXIT: Record<VerdictKind, number> = { install: 0, "do-not-install": 1, "not-found": 1, "review-first": 3, unknown: 4 };

export type DepRef = { name: string; version: string };

/** How the AI reviews of the dependencies stand; "unknown" when the registry did not say. */
export type DepReviews = { kind: "off" } | { kind: "unknown" } | { kind: "on"; confirmed: DepRef[]; underReview: DepRef[]; flagged?: DepRef[] | undefined; pending: DepRef[]; noAnswer: DepRef[] };

/**
 * One of the registry's warnings on an install that goes ahead (resolve's `warnings`): `via` empty for the version
 * itself, the dependency path for one it brings in. Older registries send none.
 */
export type WarningInput = {
  name: string;
  version: string;
  kind: "low-score" | "incomplete" | "unscorable" | "pending" | "unavailable" | "unchecked" | "cooldown";
  text: string;
  /** At most three, each a signal's label and the file and line its evidence cites; older registries send none. */
  reasons?: string[];
  /** The package's or the version's page on the website. */
  url?: string;
  via: string[];
  /**
   * A scored version's score, and every signal that cost it points (id and points); the verdict reads them for a risk
   * signal. Absent when the version has no score, and from registries before the agent-native verdict.
   */
  score?: number | null;
  signals?: { id: string; points: number }[];
  /** The scorer whose ids `signals` are. */
  scorer?: string | null;
  /** How much that score's analysis read, as stored: a partial reading installs only on this record (readingOf). */
  coverage?: ReportCoverage | null;
  /** For unscorable: why the registry decided the version will never be scored; older registries send none. */
  unscorable?: string;
};

/** A dependency the registry scored with a risk signal, whatever the score (resolve's tree.risks); `scorer` null when unsaid. */
export type RiskyDep = { name: string; version: string; via: string[]; scorer: string | null; score: number; signals: { id: string; points: number }[] };

/**
 * The dependency walk: what apm could not score (the registry's total, and up to 50 named), the AI reviews, and the
 * registry's warnings on the install.
 */
export type DepCheck = { unchecked: number; uncheckedDeps: { dependency: string; reason: string }[]; reviews: DepReviews; warnings: WarningInput[]; risks: RiskyDep[] };

/** `confirmed`: what an apm reviewer confirmed malicious, when that is why the registry refused (older registries send none). */
export type ResolvedInput =
  | { kind: "ok"; version: string; report: Report | null; skipped: { version: string; reason: string }[]; deps: DepCheck }
  | { kind: "refused"; reason: string; newest: string | null; skipped: { version: string; reason: string }[]; confirmed: DepRef[]; knownMalicious?: { name: string; version: string; ids: string[] }[]; tags?: DistTag[] }
  | { kind: "missing"; reason: string }
  | { kind: "unavailable"; reason: string };

/** flagged: an open AI flag while apm's "AI flags hold installs" switch is off, a note rather than a hold. */
export type ReviewState = "found-nothing" | "under-review" | "flagged" | "no-answer" | "confirmed" | "cleared";

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

/**
 * What a note is about. older-version: the version picked is not the newest in range, which is inside the cooldown.
 * ai-review-pending, ai-review-no-answer, no-ai-review: the picked version's AI review is under way, ended without an
 * answer, or was never run. dependency-ai-review: a dependency's is under way or ended without one. not-scored: no longer
 * sent (a version with no score is unknown); kept so older answers still read. partial-analysis: apm left whole files
 * unread for their size or the bytes one analysis reads, and recorded that this was all (readingOf). lost-points: it scores under 75 for signals that are not risks. dependency-gaps: dependencies apm could not score
 * or look up. dependency-cooldown: dependencies published inside the cooldown that apm scored and found no risk in.
 */
export const NOTE_KINDS = ["older-version", "ai-review-pending", "ai-review-no-answer", "ai-review-flagged", "no-ai-review", "dependency-ai-review", "not-scored", "partial-analysis", "lost-points", "dependency-gaps", "dependency-cooldown"] as const;

export type NoteKind = (typeof NOTE_KINDS)[number];

/** Something apm did not finish or did differently: never a reason to stop, said so the agent can mention it. */
export type Note = { kind: NoteKind; text: string };

/**
 * What explainFor did about a picked version inside the cooldown: nothing, as it is past the cooldown (not-needed);
 * picked an older one (each newer version it passed over, newest first, with the registry's words); found none in
 * range; or stopped after `looked` versions, each fresh.
 */
export type OlderSearch = { kind: "not-needed" } | { kind: "picked"; passedOver: { version: string; text: string }[] } | { kind: "none" } | { kind: "gave-up"; looked: number };

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
  /**
   * What the version lost points for, with the file and line each cites: the registry's warning reasons (at most
   * three), else the heaviest signals' first evidence. Publisher text, so each is quoted as a code span.
   */
  evidence: string[];
  /** The version's page (or the package's) on the website, from the registry's warning; null when it sent none. */
  url: string | null;
  /**
   * What apm did not finish or did differently (an AI review not finished, a dependency not scored, an older version
   * picked past the cooldown): never a reason to stop, for the agent to mention after installing. Empty when nothing.
   */
  notes: Note[];
};

const SHOWN = 3;

/** Control characters (a terminal's escapes included), line breaks and bidi overrides: what can fake a line. */
// oxlint-disable-next-line eslint/no-control-regex -- matching control characters is the point: they are removed
const BREAKER = "[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069\\u061c]";
const LINE_BREAKERS = new RegExp(`${BREAKER}+`, "g");

/** Registry text (which carries publisher text, such as a yank reason) on one line, so none can pose as apm's. */
export function oneLine(text: string): string {
  return text.replace(LINE_BREAKERS, " ").replace(/\s+/g, " ").trim();
}

/** A local path for the terminal: line breaks, controls and bidi overrides shown as escapes, so the path stays readable and none can pose as apm's. */
export function escapedPath(path: string): string {
  return path.replace(new RegExp(BREAKER, "g"), (c) => `\\u{${(c.codePointAt(0) ?? 0).toString(16)}}`);
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

const scoreTextOf = (report: { score: number; grade: string }): string =>
  report.grade === NOT_ALL_READ_GRADE ? `scores ${report.score}/100 on the files apm read` : `scores ${report.score}/100 (${oneLine(report.grade)})`;

/**
 * The note for a version apm did not read in full: what it skipped, why, that nothing in it was checked, and what the
 * files it read scored.
 */
function partialText(input: { id: string; reading: { omittedFiles: number; omittedBytes: number }; report: { score: number; grade: string } }): string {
  const one = input.reading.omittedFiles === 1;

  return `apm did not read all of ${input.id}: it skipped ${omittedText(input.reading)} ${one ? "that was" : "that were"} ${SKIPPED_WHY}, so nothing in ${one ? "it" : "them"} was checked. It ${scoreTextOf(input.report)}.`;
}

/**
 * The note for dependencies apm could not score: the first few by name, then how many more. A registry that stopped its
 * walk before naming any sends only a count ("36 more"), so the note says so, with its reason.
 */
function uncheckedText(deps: Pick<DepCheck, "unchecked" | "uncheckedDeps">): string {
  const shown = deps.uncheckedDeps.filter((d) => !COUNTED_REST.test(d.dependency)).slice(0, SHOWN);
  const head = `${plural(deps.unchecked, "dependency", "dependencies")} apm could not score`;

  if (shown.length === 0) {
    const reason = deps.uncheckedDeps[0]?.reason;

    return `${head}. The registry did not name ${deps.unchecked === 1 ? "it" : "them"}${reason ? `; its reason: ${quoted(reason)}` : ""}.`;
  }

  const rest = deps.unchecked - shown.length;

  return `${head}: ${shown.map((d) => quoted(d.dependency)).join(", ")}${rest > 0 ? ` and ${rest} more` : ""}.`;
}

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
        case "flagged":
          // "AI flags hold installs" is off at apm: a flag nobody has looked at is a note, not a hold
          return "An AI review flagged this version; a person at apm has not looked yet. apm does not hold installs on these flags right now.";
        case "under-review":
          // the registry withholds a flag's findings until a person at apm confirms them, so none is not "no finding"
          return review.findings === 0
            ? "The AI review flagged this version; its findings are withheld until a person at apm reviews them."
            : `The AI review flagged this version (${plural(review.findings, "finding", "findings")}); a person at apm is checking it.`;
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

/** The picked version's AI review as a note when it is under way, ended without an answer or never ran; null otherwise. */
function reviewNote(review: ReviewInput): Note | null {
  switch (review.kind) {
    case "queued":
    case "leased":
      return { kind: "ai-review-pending", text: reviewReason(review) };
    case "failed":
      return { kind: "ai-review-no-answer", text: reviewReason(review) };
    case "not-reviewed":
    case "off":
      return { kind: "no-ai-review", text: reviewReason(review) };
    case "reviewed":
      if (review.state === "flagged") return { kind: "ai-review-flagged", text: reviewReason(review) };

      return review.state === "no-answer" ? { kind: "ai-review-no-answer", text: reviewReason(review) } : null;
    case "pulled":
    case "unreadable":
      return null;
    default: {
      const _exhaustive: never = review;

      return _exhaustive;
    }
  }
}

/** The words a summary uses for a note, as the end of "but ...". */
function noteWhy(note: Note, id: string): string {
  switch (note.kind) {
    case "older-version":
      return "it is not the newest version: that one is inside apm's 24-hour cooldown";
    case "ai-review-pending":
      return "its AI review has not finished";
    case "ai-review-no-answer":
      return "its AI review ended without an answer";
    case "ai-review-flagged":
      return "an AI review flagged it and a person at apm has not looked yet";
    case "no-ai-review":
      return "it has no AI review";
    case "dependency-ai-review":
      return "the AI review of a dependency has not given an answer yet";
    case "not-scored":
      return `apm has no score for ${id}, so nothing has read its code`;
    case "partial-analysis":
      return `apm did not read all of ${id}: it skipped files ${SKIPPED_WHY}`;
    case "lost-points":
      return "it lost points for signals that are not risks";
    case "dependency-gaps":
      return "apm could not fully check some of its dependencies";
    case "dependency-cooldown":
      return "some of its dependencies were published inside apm's 24-hour cooldown";
    default: {
      const _exhaustive: never = note.kind;

      return _exhaustive;
    }
  }
}

/**
 * How the verdict reads one of the registry's warnings about a dependency. risk: a risk signal or a score under the
 * floor (a low-score warning is one). unfinished: apm could not finish its analysis (any gap but whole files left unread
 * for their size or the byte budget, on the warning's own record; a warning with no such record, from an older
 * registry, is one) or decided it can never score it for a reason other than its size. fresh-unread: published inside
 * the cooldown with no complete or partial reading apm could check. fresh-clear: inside the cooldown, read, no risk.
 * gap: apm has not got to it (no score yet, too large to score, a lookup that failed, the walk's limit) or read only
 * part of it for its size, with no risk in what it read.
 */
type DepClass = "risk" | "unfinished" | "fresh-unread" | "fresh-clear" | "gap";

function classifyDep(w: WarningInput): DepClass {
  const scored = w.signals === undefined ? null : { score: w.score ?? null, signals: w.signals, scorer: w.scorer ?? null };
  const reading = scored === null ? null : readingOf({ ...scored, coverage: w.coverage ?? null });
  const of: RiskOf = { kind: "dependency", name: w.name };

  switch (w.kind) {
    case "low-score":
      return "risk";
    case "incomplete":
      // a risk signal in what apm read is a risk whatever else; a score under the floor is one only on a partial
      // reading, which loses no points for what it did not read (an incomplete one's -61 is its gap, said as such)
      if (scored !== null && riskSignalsOf(scored.signals, scored.scorer, of).length > 0) return "risk";

      if (reading?.kind !== "partial") return "unfinished";

      return scored !== null && isRisky(scored, of) ? "risk" : "gap";
    case "cooldown":
      if (scored === null || reading?.kind === "incomplete") return "fresh-unread";

      return isRisky(scored, of) ? "risk" : "fresh-clear";
    case "unscorable":
      // only a size apm cannot read is apm's own gap; any other decision (the analysis limit, unreadable bytes) holds
      return w.unscorable === "too-large" ? "gap" : "unfinished";
    case "pending":
    case "unavailable":
    case "unchecked":
      return "gap";
    default: {
      const _exhaustive: never = w.kind;

      return _exhaustive;
    }
  }
}

/** Warnings as a list for a reason or a note: each `name@version: text` quoted, at most three. */
const warningList = (ws: readonly Pick<WarningInput, "name" | "version" | "text">[]): string => `${ws
  .slice(0, SHOWN)
  .map((w) => quoted(`${w.name}@${w.version}: ${w.text}`))
  .join(", ")}${ws.length > SHOWN ? ` and ${ws.length - SHOWN} more` : ""}`;

/** One warning per name@version, the first kept. */
function uniqueWarnings(ws: readonly WarningInput[]): WarningInput[] {
  const seen = new Set<string>();

  return ws.filter((w) => {
    const key = `${w.name}@${w.version}`;

    if (seen.has(key)) return false;
    seen.add(key);

    return true;
  });
}

/** A skip that is a version pulled from installs (revoked, being revoked, yanked) or confirmed malicious: not a score. */
const PULLED_REASON = /^(?:revoked by its owner|revocation pending|yanked|confirmed malicious by an apm reviewer|known malicious)/;

/** Whether the registry refused because a version was pulled: every version it skipped was revoked or yanked. */
export function refusedAsPulled(skipped: readonly { reason: string }[]): boolean {
  return skipped.length > 0 && skipped.every((s) => PULLED_REASON.test(s.reason));
}

/**
 * The verdict, with the evidence behind it and the version's page: what the version lost points for (the registry's
 * warning reasons, at most three, else its heaviest signals' first evidence, each with its file and line) and the
 * link the registry's warning gives. Before this (review of a76b9fc, finding 4) a score of 30 with
 * `index.js:7: eval(body)` and a version page came back as review-first with only the score and the signal's label.
 * `older` is what agent.ts did about a picked version inside the cooldown; absent, nothing was looked for.
 */
export function explain(input: ExplainInput): Verdict {
  // a review read that says the version is pulled (revoked, yanked or withheld) came after the resolve: the resolve's
  // evidence lines quote the package's source, which a withheld version no longer shows (review of b725ce9, finding 2)
  const shown = input.review.kind === "pulled" ? { evidence: [], url: null } : evidenceOf(input.resolved);

  return { ...decide(input), ...shown };
}

type ExplainInput = { name: string; range: string | null; resolved: ResolvedInput; review: ReviewInput; older?: OlderSearch };

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

function evidenceOf(resolve: ResolvedInput): Pick<Verdict, "evidence" | "url"> {
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

function decide(input: ExplainInput): Decided {
  const { name, resolved, review } = input;
  const range = input.range ?? "latest";
  const asked = range === "latest" ? name : `${name}@${plain(range)}`;
  // every verdict that stops before the notes are worked out has none
  const base = { name, range, notes: [] };

  // registry text can carry publisher text (a yank reason, an error): the summary is apm's words only, the reasons quote it
  switch (resolved.kind) {
    case "unavailable":
      return { ...base, verdict: "unknown", version: null, score: null, summary: `apm could not check ${asked}: the registry did not answer. Nothing was checked; try again.`, reasons: [`What happened: ${quoted(resolved.reason)}`], commands: null, coverage: NOT_READ };
    case "missing":
      return { ...base, verdict: "not-found", version: null, score: null, summary: `No package named ${name} on apm or npm. Check the spelling: a near miss can be a typosquat.`, reasons: [`The registry said: ${quoted(resolved.reason)}`], commands: null, coverage: NOT_READ };
    case "refused": {
      const skips = resolved.skipped.slice(0, SHOWN).map((s) => `Skipped ${quoted(s.version)}: ${quoted(s.reason)}.`);
      const reasons = [`The registry said: ${quoted(resolved.reason)}`, ...skips];

      if (resolved.confirmed.length > 0) {
        return { ...base, verdict: "do-not-install", version: resolved.newest, score: null, summary: `Do not install ${asked}: it would install ${listed(resolved.confirmed)}, which apm reviewers confirmed ${resolved.confirmed.length === 1 ? "is" : "are"} malicious.`, reasons, commands: null, coverage: NOT_READ };
      }

      const bad = resolved.knownMalicious ?? [];

      if (bad.length > 0) {
        const cited = bad.map((m) => `${m.name}@${m.version} (${m.ids.join(", ")})`).join(", ");

        return { ...base, verdict: "do-not-install", version: resolved.newest, score: null, summary: `Do not install ${asked}: the OSSF malicious-packages feed lists ${quoted(cited)} as malicious.`, reasons: [...reasons, ...bad.flatMap((m) => m.ids.map((id) => `Advisory: https://osv.dev/vulnerability/${id}`))], commands: null, coverage: NOT_READ };
      }

      if (refusedAsPulled(resolved.skipped)) return { ...base, verdict: "do-not-install", version: resolved.newest, score: null, summary: `Do not install ${asked}: apm's install policy refused it. The reasons say why.`, reasons, commands: null, coverage: NOT_READ };

      // no version tagged latest, but others tagged (a package with only a prerelease, tagged next): name them
      const [tagged] = resolved.tags ?? [];

      if (resolved.skipped.length === 0 && resolved.newest === null && tagged !== undefined) {
        const tags = (resolved.tags ?? []).map((t) => `${quoted(t.tag)} (${quoted(t.version)})`).join(", ");

        return { ...base, verdict: "not-found", version: null, score: null, summary: `No version of ${name} is tagged latest, the tag apm installs when no version is named. Ask about one of its other tags: the reasons list them.`, reasons: [...reasons, `Its tags: ${tags}.`, `To check what the tag ${quoted(tagged.tag)} resolves to: apm explain ${name}@${tagged.tag}`], commands: null, coverage: NOT_READ };
      }

      if (resolved.skipped.length === 0 && resolved.newest === null) {
        return { ...base, verdict: "not-found", version: null, score: null, summary: `No version of ${name} matches ${plain(range)}. Check the version or range.`, reasons, commands: null, coverage: NOT_READ };
      }

      // held back for another reason (strict mode's cooldown or score floor): not a sign of malice, so a look first,
      // and no command to run now
      return { ...base, verdict: "review-first", version: resolved.newest, score: null, summary: `Review ${asked} before installing: apm's install policy holds it back for now, and nothing in its answer says it is malicious. The reasons say why.`, reasons, commands: null, coverage: NOT_READ };
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

  // no score: nothing has read its code, so apm cannot say and gives no command. A queued version is pending, never
  // clean, and asking again gets its score; one the registry recorded it can never score (with the reason why) stays
  // without one, so a person decides
  const ownWarning = deps.warnings.find((w) => w.via.length === 0 && w.kind !== "cooldown");

  if (report === null) {
    const never = ownWarning?.kind === "unscorable" && ownWarning.unscorable !== undefined;
    const state = ownWarning?.kind === "pending" ? `apm has not scored ${id} yet: it is still being analysed` : never ? `apm cannot score ${id}` : `apm has not scored ${id}`;
    const next = never ? "Nothing was decided, and asking again will not change that: a person has to decide." : ownWarning?.kind === "pending" ? "Nothing was decided; scoring is usually ready within about 5 minutes, so ask again in a few minutes." : "Nothing was decided; ask again after about 1, 2 and 4 minutes.";

    return { ...known, verdict: "unknown", summary: `${state}, so nothing has read its code and apm cannot say whether to install it. ${next}`, reasons: ownWarning ? [`The registry said: ${quoted(ownWarning.text)}`] : [], commands: null };
  }

  // 3. a real risk in what would be installed: a person should look first (holds, most serious first). What apm did
  // not finish is a note: the install goes ahead and the agent mentions it
  const signals = report.signals;
  const lost = signals.filter((s) => s.points < 0).sort((a, b) => a.points - b.points);
  const scorer = report.scorer ?? null;
  const risks = riskSignalsOf(signals, scorer, AS_VERSION);
  // `scored`: the why already gives the score, so the summary does not repeat it
  const holds: { why: string; reason: string; scored?: true }[] = [];
  const depReviewNotes: Note[] = [];
  const scoreText = scoreTextOf(report);
  const fresh = deps.warnings.find((w) => w.via.length === 0 && w.kind === "cooldown");

  if (review.kind === "reviewed" && review.state === "under-review") holds.push({ why: "the AI review flagged it and a person at apm has not decided yet", reason: reviewReason(review) });

  if (risks[0]) {
    const more = risks.length > 1 ? ` and ${plural(risks.length - 1, "more risk signal", "more risk signals")}` : "";

    holds.push({ why: `apm found a risk signal in it: ${oneLine(risks[0].label)}${more}`, reason: "" });
  }

  // fail-closed: an analysis that did not read everything holds unless it records that its one gap is whole files left
  // unread for their size or the byte budget
  const reading = readingOf({ scorer, signals, coverage: report.coverage ?? null });

  if (reading.kind === "incomplete") {
    const unread = report.signals.find((s) => isGap(s.id))?.evidence[0];

    holds.push({ why: `apm could not fully analyse it (it ${scoreText})`, reason: unread === undefined ? "apm could not fully analyse it, and its analysis does not record that the only gap is files left unread for their size." : `apm could not fully analyse it: ${quoted(unread)}.`, scored: true });
  }

  // under the floor for what apm read: an incomplete analysis's -61 is said by its own hold above
  if (report.score < SCORE_FLOOR && reading.kind !== "incomplete") {
    const label = oneLine(lost.find((s) => !isGap(s.id))?.label ?? "see the signals");

    holds.push({ why: `it ${scoreText}, under apm's floor of ${SCORE_FLOOR}, most of it for: ${label}`, reason: "", scored: true });
  }

  const depReviews: DepReviews = deps.reviews;

  if (depReviews.kind === "on") {
    const { underReview, pending, noAnswer } = depReviews;
    const flagged = depReviews.flagged ?? [];

    if (underReview.length > 0) holds.push({ why: "the AI review flagged a dependency and a person at apm has not decided yet", reason: `The AI review flagged ${plural(underReview.length, "dependency", "dependencies")}; a person at apm is checking: ${listed(underReview)}.` });

    if (pending.length > 0) depReviewNotes.push({ kind: "dependency-ai-review", text: `The AI review of ${plural(pending.length, "dependency", "dependencies")} has not finished: ${listed(pending)}.` });

    if (noAnswer.length > 0) depReviewNotes.push({ kind: "dependency-ai-review", text: `The AI review of ${plural(noAnswer.length, "dependency", "dependencies")} ended without an answer: ${listed(noAnswer)}.` });

    // open flags while apm's "AI flags hold installs" switch is off: a note; a registry from before it sends none
    if (flagged.length > 0) depReviewNotes.push({ kind: "dependency-ai-review", text: `An AI review flagged ${plural(flagged.length, "dependency", "dependencies")}; a person at apm has not looked yet: ${listed(flagged)}.` });
  }

  // what the registry warned about in the tree, each read for a real risk or a gap in apm's work
  const flagged = deps.warnings.filter((w) => w.via.length > 0);
  const byClass = (c: DepClass): WarningInput[] => uniqueWarnings(flagged.filter((w) => classifyDep(w) === c));
  // a scored dependency the registry lists for a risk signal: over the floor it has no warning, and is still a risk
  const listedRisks = deps.risks.filter((r) => isRisky(r, { kind: "dependency", name: r.name }) && !flagged.some((w) => w.name === r.name && w.version === r.version && classifyDep(w) === "risk"));

  const riskyDeps: Pick<WarningInput, "name" | "version" | "text">[] = [
    ...byClass("risk"),
    ...listedRisks.map((r) => ({ name: r.name, version: r.version, text: `scores ${r.score}/100, and apm found: ${riskSignalsOf(r.signals, r.scorer, { kind: "dependency", name: r.name }).map((x) => x.id).join(", ") || "a score under the floor for what it read"}` })),
  ];

  const unreadFresh = byClass("fresh-unread").filter((w) => !riskyDeps.some((r) => r.name === w.name && r.version === w.version));
  const unfinished = byClass("unfinished").filter((w) => !riskyDeps.some((r) => r.name === w.name && r.version === w.version));

  if (riskyDeps.length > 0) {
    holds.push({
      why: `it brings in ${plural(riskyDeps.length, "dependency", "dependencies")} apm flagged for a risk signal or a score under ${SCORE_FLOOR}`,
      reason: `apm flagged ${plural(riskyDeps.length, "dependency", "dependencies")} for a risk: ${warningList(riskyDeps)}.`,
    });
  }

  if (unfinished.length > 0) {
    holds.push({
      why: `it brings in ${plural(unfinished.length, "dependency", "dependencies")} apm could not fully analyse or score`,
      reason: `apm could not fully analyse or score ${plural(unfinished.length, "dependency", "dependencies")}: ${warningList(unfinished)}.`,
    });
  }

  // the cooldown is apm's main defence against a fresh malicious release: a version inside it that apm cannot clear
  // stays with a person. explainFor already looked for an older version of the one picked
  if (fresh) {
    const older = input.older ?? { kind: "none" };
    const why = older.kind === "gave-up" ? `it and the ${plural(older.looked - 1, "version", "versions")} before it in range were all published inside apm's 24-hour cooldown` : "it was published inside apm's 24-hour cooldown and no older version in range is past it";

    holds.push({ why: `${why}, so it has had little time to be looked at`, reason: `The registry said: ${quoted(`${name}@${version}: ${fresh.text}`)}` });
  }

  if (unreadFresh.length > 0) {
    holds.push({
      why: `it brings in ${plural(unreadFresh.length, "dependency", "dependencies")} published inside apm's 24-hour cooldown with no score apm could check`,
      reason: `Published inside the cooldown, with no score apm could check for a risk: ${warningList(unreadFresh)}.`,
    });
  }

  // 4. the notes, in order: an older version picked, the version's AI review and score, then its dependencies
  const notes: Note[] = [];

  if (input.older?.kind === "picked") {
    const passed = input.older.passedOver;

    notes.push({ kind: "older-version", text: `apm picked ${id}, the newest version in range past its 24-hour cooldown. Newer, inside it: ${passed.slice(0, SHOWN).map((p) => quoted(`${name}@${p.version}: ${p.text}`)).join(", ")}.` });
  }

  const own = reviewNote(review);

  if (own) notes.push(own);

  // whole files left unread for their size or the byte budget, and recorded as the only gap: apm's own gap, not a risk,
  // so the install goes ahead with what was not read said here
  if (reading.kind === "partial") notes.push({ kind: "partial-analysis", text: partialText({ id, reading, report }) });

  if (reading.kind !== "incomplete" && report.score < CLEAN_SCORE && holds.length === 0) notes.push({ kind: "lost-points", text: `${id} ${scoreTextOf(report)}, under the ${CLEAN_SCORE} the site shows as clean, for signals that are not risks; the reasons list them.` });

  notes.push(...depReviewNotes);
  const gaps = byClass("gap");

  if (gaps.length > 0) notes.push({ kind: "dependency-gaps", text: `apm could not fully check ${plural(gaps.length, "dependency", "dependencies")}: ${warningList(gaps)}.` });

  if (deps.unchecked > 0) {
    notes.push({ kind: "dependency-gaps", text: uncheckedText(deps) });
  }

  const clearFresh = byClass("fresh-clear");

  if (clearFresh.length > 0) notes.push({ kind: "dependency-cooldown", text: `${plural(clearFresh.length, "dependency was", "dependencies were")} published inside apm's 24-hour cooldown; apm scored ${clearFresh.length === 1 ? "it" : "them"} and found no risk: ${warningList(clearFresh)}.` });

  // 5. the reasons: the first hold's, what the version lost points for, the other holds', then its review
  const reasons = holds.slice(0, 1).flatMap((h) => (h.reason ? [h.reason] : []));

  for (const s of lost.slice(0, SHOWN)) reasons.push(`${oneLine(s.label)} (${s.points} points${s.confidence === "possible" ? ", possible" : ""}).`);

  if (lost.length > SHOWN) reasons.push(`${plural(lost.length - SHOWN, "more signal", "more signals")} lost points.`);

  for (const h of holds.slice(1)) if (h.reason) reasons.push(h.reason);

  if (!holds.some((h) => h.reason === reviewReason(review))) reasons.push(reviewReason(review));

  if (resolved.skipped.length > 0) reasons.push(`Newer versions were skipped: ${skippedText(resolved.skipped)}.`);
  const run = commands(name, version);
  const note = noReviewNote(aiReview);
  const first = holds[0];

  if (first) {
    const standing = first.scored ? "It passes apm's install policy." : `It passes apm's install policy and ${scoreText}.`;

    return { ...known, verdict: "review-first", summary: `Review ${id} before installing: ${first.why}. ${standing}${note}`, reasons, commands: run, notes };
  }

  // a version apm never picked for AI review, or a registry that runs none, still installs on the static checks; the
  // summary says so in its own words, and coverage and the notes say it as data
  const shown = notes.filter((n) => n.kind !== "no-ai-review");
  const head = shown[0];

  // nothing apm left unfinished
  if (head === undefined) {
    return {
      ...known,
      verdict: "install",
      summary: `${id} passes apm's checks: it ${scoreText}, is past the 24-hour cooldown, nothing in its dependency tree was refused or flagged, and apm scored every dependency.${note}`,
      reasons,
      commands: run,
      notes,
    };
  }

  const more = (n: number): string => (n > 0 ? `, and ${plural(n, "more note", "more notes")}` : "");

  // a partial reading says how much apm left unread
  const why = head.kind === "partial-analysis" && reading.kind === "partial" ? `apm did not read all of ${id}: it skipped ${omittedText(reading)}, ${SKIPPED_WHY}` : noteWhy(head, id);

  return { ...known, verdict: "install", summary: `Install ${id}: it ${scoreTextOf(report)} and nothing apm found needs a person to look first, but ${why}${more(shown.length - 1)}.${note}`, reasons, commands: run, notes };
}
