// One review run: build the messages, ask the model (once, or twice when the policy wants a retry),
// check every citation, and decide. The model call is passed in, so this stays free of I/O.
import { verifyCitations } from "./citations.ts";
import { decide, type Attempt, type Decision } from "./decide.ts";
import type { ReviewInput } from "./input.ts";
import type { PackageFiles } from "./manifest.ts";
import { reviewMessages, type ChatMessage } from "./prompt.ts";
import { parseReply } from "./reply.ts";

export type Usage = { promptTokens: number; completionTokens: number; reasoningTokens: number; latencyMs: number };

/** What a model call returns. A failed request is an empty answer, not an exception. */
export type ModelAnswer = { kind: "ok"; content: string; finishReason: string | null; usage: Usage } | { kind: "failed"; error: string; usage: Usage };

export type Ask = (messages: readonly ChatMessage[]) => Promise<ModelAnswer>;

export type AttemptLog = { result: "benign" | "malicious" | "suspicious" | "empty"; kept: number; dropped: number; usage: Usage };

export type ReviewRun = { decision: Decision; attempts: AttemptLog[] };

function attemptOf(answer: ModelAnswer, pkg: PackageFiles): Attempt {
  if (answer.kind === "failed") return { kind: "empty", reason: "request-failed" };
  const reply = parseReply(answer.content, answer.finishReason);

  if (reply.kind === "empty") return reply;
  const { kept, dropped } = verifyCitations(reply.findings, pkg.files);

  return { kind: "answer", verdict: reply.verdict, summary: reply.summary, findings: kept, dropped };
}

function logOf(a: Attempt, usage: Usage): AttemptLog {
  if (a.kind === "empty") return { result: "empty", kept: 0, dropped: 0, usage };

  return { result: a.verdict, kept: a.findings.length, dropped: a.dropped.length, usage };
}

export async function runReview(input: { review: ReviewInput; pkg: PackageFiles; ask: Ask }): Promise<ReviewRun> {
  const messages = reviewMessages(input.review);
  const firstAnswer = await input.ask(messages);
  const first = attemptOf(firstAnswer, input.pkg);
  const logs = [logOf(first, firstAnswer.usage)];
  const step = decide([first]);

  if (step.kind === "done") return { decision: step.decision, attempts: logs };
  const secondAnswer = await input.ask(messages);
  const second = attemptOf(secondAnswer, input.pkg);

  logs.push(logOf(second, secondAnswer.usage));
  const final = decide([first, second]);

  // two attempts always settle
  if (final.kind === "retry") return { decision: { outcome: "no-answer", reason: "empty", summary: "", findings: [] }, attempts: logs };

  return { decision: final.decision, attempts: logs };
}
