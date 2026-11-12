// `apm explain <pkg>[@range]`: a short verdict an agent (or a person) can act on before an install. Pure.
// The website's explain_install MCP tool and GET /api/explain use the same rules (apps/web/lib/agent/verdict.ts);
// change both together. Like the rest of apm it never calls a version "safe".
import type { Report } from "./api.ts";

export const VERDICTS = ["install", "review-first", "do-not-install", "not-found", "unknown"] as const;

export type VerdictKind = (typeof VERDICTS)[number];

/** Scores at or above this are clean (the site's green badge); below it the lost points are worth a look. */
export const CLEAN_SCORE = 75;

/** Exit codes, so a script can branch without parsing: 2 stays the CLI's usage error. */
export const EXIT: Record<VerdictKind, number> = { install: 0, "do-not-install": 1, "not-found": 1, "review-first": 3, unknown: 4 };

export type ResolvedInput =
  | { kind: "ok"; version: string; report: Report | null; skipped: { version: string; reason: string }[]; unchecked: { dependency: string; reason: string }[] }
  | { kind: "refused"; reason: string; newest: string | null; skipped: { version: string; reason: string }[] }
  | { kind: "missing"; reason: string }
  | { kind: "unavailable"; reason: string };

export type ReviewState = "found-nothing" | "under-review" | "no-answer" | "confirmed" | "cleared";

export type ReviewInput = { kind: "reviewed"; state: ReviewState; findings: number } | { kind: "queued" } | { kind: "none" };

export type Verdict = {
  verdict: VerdictKind;
  name: string;
  range: string;
  version: string | null;
  score: { score: number; grade: string } | null;
  summary: string;
  reasons: string[];
  commands: { apm: string; bun: string; npm: string; pnpm: string } | null;
};

function commands(name: string, version: string): NonNullable<Verdict["commands"]> {
  const spec = `${name}@${version}`;

  return { apm: `apm add ${spec}`, bun: `bun add ${spec}`, npm: `npm install ${spec}`, pnpm: `pnpm add ${spec}` };
}

function reviewReason(review: ReviewInput): string {
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

export function explain(input: { name: string; range: string | null; resolved: ResolvedInput; review: ReviewInput }): Verdict {
  const { name, resolved, review } = input;
  const range = input.range ?? "latest";
  const asked = range === "latest" ? name : `${name}@${range}`;
  const base = { name, range };

  switch (resolved.kind) {
    case "unavailable":
      return { ...base, verdict: "unknown", version: null, score: null, summary: `apm could not check ${asked}: ${resolved.reason}. Nothing was checked; try again.`, reasons: [], commands: null };
    case "missing":
      return { ...base, verdict: "not-found", version: null, score: null, summary: `No package named ${name} on apm or npm. Check the spelling: a near miss can be a typosquat.`, reasons: [resolved.reason], commands: null };
    case "refused":
      return {
        ...base,
        verdict: "do-not-install",
        version: resolved.newest,
        score: null,
        summary: `Do not install ${asked}: ${resolved.reason}`,
        reasons: [resolved.reason, ...resolved.skipped.slice(0, 3).map((s) => `Skipped ${s.version}: ${s.reason}.`)],
        commands: null,
      };
    case "ok":
      break;
    default: {
      const _exhaustive: never = resolved;

      return _exhaustive;
    }
  }

  const { version, report } = resolved;
  const id = `${name}@${version}`;
  const score = report ? { score: report.score, grade: report.grade } : null;
  const lost = (report?.signals ?? []).filter((s) => s.points < 0).sort((a, b) => a.points - b.points);

  if (review.kind === "reviewed" && review.state === "confirmed") {
    return { ...base, verdict: "do-not-install", version, score, summary: `Do not install ${id}: apm reviewers confirmed it is malicious.`, reasons: [reviewReason(review)], commands: null };
  }

  const flagged = review.kind === "reviewed" && review.state === "under-review";
  const lowScore = report !== null && report.score < CLEAN_SCORE;
  const reasons: string[] = [];

  if (flagged) reasons.push(reviewReason(review));

  for (const s of lost.slice(0, 3)) reasons.push(`${s.label} (${s.points} points${s.confidence === "possible" ? ", possible" : ""}).`);

  if (lost.length > 3) reasons.push(`${lost.length - 3} more signal${lost.length - 3 === 1 ? "" : "s"} lost points.`);

  if (!flagged) reasons.push(reviewReason(review));

  if (resolved.unchecked.length > 0) reasons.push(`${resolved.unchecked.length} dependenc${resolved.unchecked.length === 1 ? "y" : "ies"} apm could not score: ${resolved.unchecked.slice(0, 3).map((d) => d.dependency).join(", ")}.`);

  if (resolved.skipped.length > 0) reasons.push(`Newer versions were skipped: ${resolved.skipped.slice(0, 3).map((s) => `${s.version} (${s.reason})`).join("; ")}.`);
  const scoreText = score ? `scores ${score.score}/100 (${score.grade})` : "is not scored yet";

  if (flagged || lowScore || report === null) {
    const why = flagged ? "the AI review flagged it and a person has not decided yet" : lowScore ? `it lost points: ${lost[0]?.label ?? "see the signals"}` : "apm has no score for it yet";

    return { ...base, verdict: "review-first", version, score, summary: `Review ${id} before installing: it passes apm's install policy and ${scoreText}, but ${why}.`, reasons, commands: commands(name, version) };
  }

  return { ...base, verdict: "install", version, score, summary: `${id} passes apm's checks: it ${scoreText}, is past the 24-hour cooldown, and nothing in its dependency tree was refused.`, reasons, commands: commands(name, version) };
}
