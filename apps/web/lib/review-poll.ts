// When the package page's AI review card asks the registry again, and when it offers a review request. Pure, so the
// unit tests can drive the clock.
import type { ReviewAnswer } from "./review-schema";

/** A queued review is asked for every 5 seconds, for up to 3 minutes; most finish in under one. */
export const POLL_EVERY_MS = 5_000;
export const POLL_FOR_MS = 3 * 60_000;

export type PollStep = { kind: "wait"; ms: number } | { kind: "stop"; reason: "settled" | "gave-up" };

/** What to do after an answer: wait and ask again while it is queued, or stop. */
export function pollStep(input: { status: ReviewAnswer["status"]; startedAt: number; now: number }): PollStep {
  if (input.status !== "queued") return { kind: "stop", reason: "settled" };
  const left = input.startedAt + POLL_FOR_MS - input.now;

  return left > 0 ? { kind: "wait", ms: Math.min(POLL_EVERY_MS, left) } : { kind: "stop", reason: "gave-up" };
}

/**
 * Whether the card offers "Request an AI review": a version the automatic review did not take (not reviewed, failed,
 * or a review with no answer). The registry's request route decides the rest: sign-in, the hourly budget, a checksum.
 */
export function offersRequest(a: ReviewAnswer): boolean {
  if (a.status === "queued") return false;

  if (a.review) return a.review.state === "no-answer";

  return a.status === "not-reviewed" || a.status === "failed";
}
