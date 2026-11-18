// The admin review queue's data and the pure rules its page follows: the answer's shape, the row labels, and how long
// the decision window has left. Parsed in the browser; the registry builds it (packages/registry/src/review.ts).
import { z } from "zod";
import { PrivateReview, PublicReview } from "./review-schema";

const Attempt = z.object({ result: z.string(), kept: z.number(), dropped: z.number(), promptTokens: z.number(), completionTokens: z.number(), latencyMs: z.number() });

export const QueueItem = z.object({
  name: z.string(),
  version: z.string(),
  digest: z.string(),
  reviewedAt: z.string(),
  // an older registry sends none of the triage fields
  weeklyDownloads: z.number().nullable().default(null),
  summaryLine: z.string().default(""),
  public: PublicReview,
  private: PrivateReview.extend({ attempts: z.array(Attempt) }),
  decidedBy: z.string().nullable(),
});

export type QueueItem = z.infer<typeof QueueItem>;

export const SwitchState = z.object({
  hold: z.boolean(),
  source: z.enum(["set", "default"]),
  defaultHold: z.boolean(),
  changedBy: z.string().nullable(),
  changedAt: z.string().nullable(),
  history: z.array(z.object({ hold: z.boolean(), by: z.string(), at: z.string() })),
});

export type SwitchState = z.infer<typeof SwitchState>;

export const Queue = z.object({
  pending: z.array(QueueItem),
  decided: z.array(QueueItem),
  secondStage: z.string().nullable(),
  flagsHold: SwitchState.nullable().default(null),
  unlockedUntil: z.string().nullable().default(null),
  windowMs: z.number().default(10 * 60_000),
});

export type Queue = z.infer<typeof Queue>;

/** The key of one review: a version's bytes, as the registry stores it. */
export const itemKey = (i: Pick<QueueItem, "name" | "version" | "digest">): string => `${i.name}@${i.version}:${i.digest}`;

export type Verdict = { label: string; tone: "bad" | "warn" | "muted" };

/** What the model said, in a word or two, for the row's chip. */
export function verdictOf(i: QueueItem): Verdict {
  if (i.private.outcome === "flagged") return i.private.verdict === "malicious" ? { label: "malicious", tone: "bad" } : { label: "suspicious", tone: "warn" };

  return i.private.reason === "unsettled" ? { label: "flagged once", tone: "warn" } : { label: "no answer", tone: "muted" };
}

/** "9:41" left in the window, or null once it has ended. */
export function windowLeft(untilIso: string | null, now: number): string | null {
  if (untilIso === null) return null;
  const ms = Date.parse(untilIso) - now;

  if (!(ms > 0)) return null;
  const s = Math.ceil(ms / 1000);

  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** The row a key press moves to: j and ArrowDown go down, k and ArrowUp go up, clamped to the list. */
export function moveFocus(input: { key: string; at: number; count: number }): number | null {
  if (input.count === 0) return null;

  if (input.key === "j" || input.key === "ArrowDown") return Math.min(input.count - 1, input.at < 0 ? 0 : input.at + 1);

  if (input.key === "k" || input.key === "ArrowUp") return Math.max(0, input.at < 0 ? 0 : input.at - 1);

  if (input.key === "Home") return 0;

  if (input.key === "End") return input.count - 1;

  return null;
}

/** The most flags one bulk dismiss request takes (the registry's BulkBody). */
export const BULK_LIMIT = 100;

export type ReviewKey = Pick<QueueItem, "name" | "version" | "digest">;

export type BatchAnswer = { kind: "ok"; dismissed: number } | { kind: "error"; message: string };

/**
 * Dismisses a selection of any size in requests of at most BULK_LIMIT, one after another, so "Select all" on a long
 * queue works. Stops at the first failed request and says how many were dismissed before it.
 */
export async function dismissInBatches(input: { items: readonly ReviewKey[]; send: (batch: ReviewKey[]) => Promise<BatchAnswer> }): Promise<{ kind: "ok"; dismissed: number } | { kind: "error"; message: string; dismissed: number }> {
  let dismissed = 0;

  for (let at = 0; at < input.items.length; at += BULK_LIMIT) {
    const r = await input.send(input.items.slice(at, at + BULK_LIMIT));

    if (r.kind === "error") return { kind: "error", message: r.message, dismissed };
    dismissed += r.dismissed;
  }

  return { kind: "ok", dismissed };
}
