// The policy that turns one or two model answers into a review outcome.
//
// One answer settles a benign result. A flagged or empty answer gets one retry, because the eval saw
// verdicts flip on about 6% of identical requests and two of three benign first-publish flags vanish on
// a second ask. A flag that turns benign on the retry is a flip: not settled, and not called clean.
import type { DroppedFinding, Finding } from "./citations.ts";
import { MAX_FINDINGS } from "./citations.ts";
import type { EmptyReason, ModelVerdict } from "./reply.ts";

/** One request's answer after the citation check. */
export type Attempt =
  | { kind: "answer"; verdict: ModelVerdict; summary: string; findings: Finding[]; dropped: DroppedFinding[] }
  | { kind: "empty"; reason: EmptyReason };

/**
 * flagged: malicious or suspicious with at least one citation that checked out.
 * empty: no usable answer, or a flag none of whose citations checked out.
 */
export type AttemptClass = "benign" | "flagged" | "empty";

export function classify(a: Attempt): AttemptClass {
  if (a.kind === "empty") return "empty";

  if (a.verdict === "benign") return "benign";

  return a.findings.length > 0 ? "flagged" : "empty";
}

export type NoAnswerReason = "empty" | "unsettled";

export type Decision =
  | { outcome: "benign"; summary: string }
  | { outcome: "flagged"; verdict: "malicious" | "suspicious"; summary: string; findings: Finding[] }
  | { outcome: "no-answer"; reason: NoAnswerReason; summary: string; findings: Finding[] };

export type Step = { kind: "retry" } | { kind: "done"; decision: Decision };

function flagVerdict(attempts: readonly Attempt[]): "malicious" | "suspicious" {
  return attempts.some((a) => a.kind === "answer" && a.verdict === "malicious" && a.findings.length > 0) ? "malicious" : "suspicious";
}

/** Verified findings of every flagged attempt, one per file:line, most severe first. */
function mergedFindings(attempts: readonly Attempt[]): Finding[] {
  const out: Finding[] = [];
  const rank = { high: 0, medium: 1, low: 2 } as const;

  for (const a of attempts) {
    if (a.kind !== "answer" || classify(a) !== "flagged") continue;

    for (const f of a.findings) if (!out.some((o) => o.file === f.file && o.line === f.line)) out.push(f);
  }

  return out.sort((x, y) => rank[x.severity] - rank[y.severity]).slice(0, MAX_FINDINGS);
}

function summaryOf(attempts: readonly Attempt[], cls: AttemptClass): string {
  for (const a of attempts) if (a.kind === "answer" && classify(a) === cls) return a.summary;

  return "";
}

/** What to do after the attempts so far: retry once, or the decision. */
export function decide(attempts: readonly [Attempt] | readonly [Attempt, Attempt]): Step {
  const [first, second] = attempts;
  const c1 = classify(first);

  if (c1 === "benign") return { kind: "done", decision: { outcome: "benign", summary: summaryOf([first], "benign") } };

  if (second === undefined) return { kind: "retry" };
  const c2 = classify(second);
  const both = [first, second];

  // a flag on either answer with nothing contradicting it
  if ((c1 === "flagged" && c2 !== "benign") || (c1 === "empty" && c2 === "flagged")) {
    return { kind: "done", decision: { outcome: "flagged", verdict: flagVerdict(both), summary: summaryOf(both, "flagged"), findings: mergedFindings(both) } };
  }

  if (c1 === "flagged" && c2 === "benign") {
    return { kind: "done", decision: { outcome: "no-answer", reason: "unsettled", summary: summaryOf(both, "flagged"), findings: mergedFindings(both) } };
  }

  if (c2 === "benign") return { kind: "done", decision: { outcome: "benign", summary: summaryOf([second], "benign") } };

  return { kind: "done", decision: { outcome: "no-answer", reason: "empty", summary: "", findings: [] } };
}
