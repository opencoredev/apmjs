// The AI review's public status (GET /-/apm/v1/reviews): counts and the versions waiting for a person. Names,
// versions and times only; the registry never sends what a model found in an open flag.
import { z } from "zod";

export const ReviewStatus = z.object({
  counts: z.object({ reviewed: z.number(), flagged: z.number(), waiting: z.number(), dismissed: z.number(), confirmed: z.number() }),
  /** Whether an open flag holds installs (review-first for agents) right now. */
  flagsHold: z.boolean(),
  waiting: z.array(z.object({ name: z.string(), version: z.string(), since: z.string(), weeklyDownloads: z.number().nullable() })),
});

export type ReviewStatus = z.infer<typeof ReviewStatus>;

/** 207M, 4.1M, 12k, 950: a weekly download count in a narrow column. */
export function compactCount(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(n >= 1e10 ? 0 : 1)}B`;

  if (n >= 1e6) return `${(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)}M`;

  if (n >= 1e3) return `${(n / 1e3).toFixed(n >= 1e4 ? 0 : 1)}k`;

  return String(n);
}
