// The AI review answer (GET /-/apm/v1/review/:name/:version), parsed on both server and client, and
// the sentences the page shows for it. The copy never calls a version "safe": a clean result is
// described as what the model read and found nothing in.
import { z } from "zod";

export const Finding = z.object({ file: z.string(), line: z.number(), excerpt: z.string(), issue: z.string(), severity: z.enum(["high", "medium", "low"]) });

export type Finding = z.infer<typeof Finding>;

const NotRead = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("file"), path: z.string(), reason: z.enum(["budget", "partial", "binary", "too-large"]) }),
  z.object({ kind: z.literal("dependency"), name: z.string() }),
]);

export type NotRead = z.infer<typeof NotRead>;

export const Coverage = z.object({ mode: z.enum(["diff", "files"]), previousVersion: z.string().nullable(), filesInScope: z.number(), filesRead: z.number() });

export type Coverage = z.infer<typeof Coverage>;

export const PUBLIC_STATES = ["found-nothing", "under-review", "no-answer", "confirmed", "cleared"] as const;

export type PublicState = (typeof PUBLIC_STATES)[number];

export const PublicReview = z.object({
  state: z.enum(PUBLIC_STATES),
  model: z.string(),
  reviewedAt: z.string(),
  coverage: Coverage,
  read: z.array(z.string()),
  notRead: z.array(NotRead),
  findings: z.array(Finding),
  decidedAt: z.string().nullable(),
  note: z.string().nullable(),
});

export type PublicReview = z.infer<typeof PublicReview>;

export const PrivateReview = z.object({
  outcome: z.enum(["benign", "flagged", "no-answer"]),
  verdict: z.enum(["malicious", "suspicious"]).nullable(),
  reason: z.enum(["empty", "unsettled"]).nullable(),
  summary: z.string(),
  findings: z.array(Finding),
  humanState: z.enum(["none", "pending", "confirmed", "dismissed"]),
});

export type PrivateReview = z.infer<typeof PrivateReview>;

export const ReviewAnswer = z.object({
  name: z.string(),
  version: z.string(),
  status: z.enum(["reviewed", "queued", "failed", "not-reviewed"]),
  review: PublicReview.nullable(),
  /**
   * The version is revoked: findings keep their file, line and sentence, with no excerpt. Required: a registry too old
   * to send it may not redact either, so its answer is refused as unreadable rather than shown (packages/infra/deploy.ts).
   */
  redacted: z.boolean(),
  viewer: z.enum(["public", "maintainer", "admin"]),
  private: PrivateReview.nullable(),
  canRequest: z.boolean(),
});

export type ReviewAnswer = z.infer<typeof ReviewAnswer>;

/** "Read 2 of 2 changed files", or the files-mode equivalent. */
export function coverageText(c: Coverage): string {
  const one = c.mode === "diff" ? "changed file" : "file";

  if (c.filesInScope === 0) return c.mode === "diff" ? "No code or data files changed" : "No code or data files to read";

  if (c.filesInScope === 1) return c.filesRead === 1 ? `Read the 1 ${one}` : `Did not read the 1 ${one}`;

  return `Read ${c.filesRead} of ${c.filesInScope} ${one}s`;
}

const REASON: Record<Extract<NotRead, { kind: "file" }>["reason"], string> = {
  budget: "budget",
  partial: "partly, budget",
  binary: "binary",
  "too-large": "too large",
};

export function notReadText(n: Extract<NotRead, { kind: "file" }>): string {
  return `${n.path} (${REASON[n.reason]})`;
}

/** The one-line result. */
export function headline(r: PublicReview): string {
  switch (r.state) {
    case "found-nothing": {
      // A partial read must not sound like full coverage: say what was read, and that it was partial.
      const partial = r.coverage.filesRead < r.coverage.filesInScope;

      if (partial) return `Partial AI review: no findings in the ${r.coverage.filesRead} of ${r.coverage.filesInScope} files it read`;

      return r.coverage.mode === "diff" && r.coverage.previousVersion !== null ? `AI review found nothing in the change from ${r.coverage.previousVersion}` : "AI review found nothing in this version's files";
    }

    case "under-review":
      return "Under review";
    case "no-answer":
      return "AI review gave no answer";
    case "confirmed":
      return "Confirmed malicious by apm reviewers";
    case "cleared":
      return "Checked by a person, no action needed";
    default: {
      const _exhaustive: never = r.state;

      return _exhaustive;
    }
  }
}

export function explanation(r: PublicReview): string | null {
  switch (r.state) {
    case "found-nothing":
      return null;
    case "under-review":
      return "The AI review raised a question about this version. A person at apm is checking it. Nothing has been confirmed.";
    case "no-answer":
      return "The model did not return a usable answer for this version. A person at apm will look at it.";
    case "confirmed":
      return "A person at apm checked the lines below and confirmed them.";
    case "cleared":
      return "The AI review flagged this version. A person at apm checked the flagged lines and dismissed the flag.";
    default: {
      const _exhaustive: never = r.state;

      return _exhaustive;
    }
  }
}

/**
 * What the package header says about the AI review, so a reader sees an open or confirmed flag before
 * the install command. Nothing for a clean, cleared or unanswered review: the section below covers those.
 */
export function headerNotice(r: PublicReview): { tone: "warn" | "bad"; text: string } | null {
  switch (r.state) {
    case "under-review":
      return { tone: "warn", text: "AI review flagged this version, pending confirmation" };
    case "confirmed":
      return { tone: "bad", text: "Confirmed malicious by apm reviewers" };
    case "found-nothing":
    case "no-answer":
    case "cleared":
      return null;
    default: {
      const _exhaustive: never = r.state;

      return _exhaustive;
    }
  }
}
