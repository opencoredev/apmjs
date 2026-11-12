// The short answer an agent acts on before an install: what the registry's install policy picked for a range,
// what the AI review says about that version, and what to run. Pure, so the MCP tool, GET /api/explain and the
// tests share it. packages/cli/src/explain.ts mirrors these rules for `apm explain`.
//
// Like the rest of the site, it never calls a version "safe": "install" means it passed apm's checks, and the
// limits of those checks travel with every answer.
import { installCommand, INSTALL_CLIENTS, type InstallClient } from "../install-note";
import type { PublicReview } from "../review-schema";
import type { ResolveOutcome } from "./source";

export const VERDICTS = ["install", "review-first", "do-not-install", "not-found", "unknown"] as const;

export type VerdictKind = (typeof VERDICTS)[number];

/** Scores at or above this read as clean on the site (the green badge); below it, the lost points are worth a look. */
export const CLEAN_SCORE = 75;

/** What the AI review said about the picked version, as far as the verdict needs it. */
export type ReviewInput = { kind: "reviewed"; state: PublicReview["state"]; findings: number } | { kind: "queued" } | { kind: "none" };

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
  /** What to run, by client; null when nothing should be installed. */
  commands: Record<InstallClient, string> | null;
};

const SHOWN_SKIPS = 3;

function commandsFor(name: string, version: string): Record<InstallClient, string> {
  const out: Partial<Record<InstallClient, string>> = {};

  // apm add takes the exact version the policy picked, like the package manager it hands off to
  for (const client of INSTALL_CLIENTS) out[client] = client === "apm" ? `apm add ${name}@${version}` : installCommand({ client, name, version });

  return { apm: out.apm ?? "", bun: out.bun ?? "", npm: out.npm ?? "", pnpm: out.pnpm ?? "" };
}

function reviewReason(review: ReviewInput): string | null {
  switch (review.kind) {
    case "none":
      return "No AI review of this version.";
    case "queued":
      return "The AI review of this version is still running.";
    case "reviewed":
      switch (review.state) {
        case "found-nothing":
          return "The AI review found nothing in the files it read.";
        case "cleared":
          return "The AI review flagged this version; a person at apm checked and dismissed the flag.";
        case "no-answer":
          return "The AI review gave no usable answer for this version.";
        case "under-review":
          return `The AI review flagged this version (${review.findings} finding${review.findings === 1 ? "" : "s"}); a person at apm is checking it.`;
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

/** The verdict for `name@range`, from the registry's resolve answer and the AI review of the version it picked. */
export function explainInstall(input: { name: string; range: string | null; resolve: ResolveOutcome; review: ReviewInput }): Verdict {
  const { name, resolve, review } = input;
  const range = input.range ?? "latest";
  const asked = range === "latest" ? name : `${name}@${range}`;
  const base = { name, range };

  switch (resolve.kind) {
    case "unavailable":
      return { ...base, verdict: "unknown", version: null, score: null, summary: `apm could not check ${asked}: the registry did not answer. Nothing was checked; try again.`, reasons: [], commands: null };
    case "missing":
      return { ...base, verdict: "not-found", version: null, score: null, summary: `No package named ${name} on apm or npm. Check the spelling: a near miss can be a typosquat.`, reasons: [resolve.reason], commands: null };
    case "refused": {
      const skips = resolve.skipped.slice(0, SHOWN_SKIPS).map((s) => `Skipped ${s.version}: ${s.reason}.`);

      return {
        ...base,
        verdict: "do-not-install",
        version: resolve.newest,
        score: null,
        summary: `Do not install ${asked}: ${resolve.reason}`,
        reasons: [resolve.reason, ...skips],
        commands: null,
      };
    }

    case "ok":
      break;
    default: {
      const _exhaustive: never = resolve;

      return _exhaustive;
    }
  }

  const { version, report } = resolve;
  const id = `${name}@${version}`;
  const score = report ? { score: report.score, grade: report.grade } : null;
  const lost = (report?.signals ?? []).filter((s) => s.points < 0).sort((a, b) => a.points - b.points);
  const reasons: string[] = [];
  const fromReview = reviewReason(review);

  if (review.kind === "reviewed" && review.state === "confirmed") {
    return { ...base, verdict: "do-not-install", version, score, summary: `Do not install ${id}: apm reviewers confirmed it is malicious.`, reasons: fromReview ? [fromReview] : [], commands: null };
  }

  const flagged = review.kind === "reviewed" && review.state === "under-review";
  const lowScore = report !== null && report.score < CLEAN_SCORE;

  if (flagged && fromReview) reasons.push(fromReview);

  for (const s of lost.slice(0, 3)) reasons.push(`${s.label} (${s.points} points${s.confidence === "possible" ? ", possible" : ""}).`);

  if (lost.length > 3) reasons.push(`${lost.length - 3} more signal${lost.length - 3 === 1 ? "" : "s"} lost points.`);

  if (!flagged && fromReview) reasons.push(fromReview);

  if (resolve.uncheckedDeps.length > 0) reasons.push(`${resolve.uncheckedDeps.length} dependenc${resolve.uncheckedDeps.length === 1 ? "y" : "ies"} apm could not score: ${resolve.uncheckedDeps.slice(0, 3).map((d) => d.dependency).join(", ")}.`);

  if (resolve.skipped.length > 0) reasons.push(`Newer versions were skipped: ${resolve.skipped.slice(0, SHOWN_SKIPS).map((s) => `${s.version} (${s.reason})`).join("; ")}.`);
  const scoreText = score ? `scores ${score.score}/100 (${score.grade})` : "is not scored yet";

  if (flagged || lowScore || report === null) {
    const why = flagged ? "the AI review flagged it and a person has not decided yet" : lowScore ? `it lost points: ${lost[0]?.label ?? "see the signals"}` : "apm has no score for it yet";

    return { ...base, verdict: "review-first", version, score, summary: `Review ${id} before installing: it passes apm's install policy and ${scoreText}, but ${why}.`, reasons, commands: commandsFor(name, version) };
  }

  return { ...base, verdict: "install", version, score, summary: `${id} passes apm's checks: it ${scoreText}, is past the 24-hour cooldown, and nothing in its dependency tree was refused.`, reasons, commands: commandsFor(name, version) };
}

/** The review input for the verdict, from GET /-/apm/v1/review: none when AI review is off or the version is unknown. */
export function reviewInput(answer: { status: "reviewed" | "queued" | "failed" | "not-reviewed"; review: PublicReview | null } | null): ReviewInput {
  if (answer === null) return { kind: "none" };

  if (answer.review !== null) return { kind: "reviewed", state: answer.review.state, findings: answer.review.findings.length };

  return answer.status === "queued" ? { kind: "queued" } : { kind: "none" };
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
