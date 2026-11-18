// One sample's install verdict as verdicts.ts records it and verdict-diff.ts reads it.
import { z } from "zod";

export const VerdictRow = z.object({
  set: z.string(),
  id: z.string(),
  score: z.number(),
  verdict: z.enum(["install", "review-first", "error"]),
  reading: z.string(),
  risks: z.array(z.string()),
  signals: z.array(z.object({ id: z.string(), points: z.number(), confidence: z.string().optional(), evidence: z.array(z.string()) })),
});
