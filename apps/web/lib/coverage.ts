// How much of a version apm read, as the registry sends it with a score (apm-score-v11). Not server-only: the score
// components render it.
import { z } from "zod";

/**
 * How much of the version apm read (apm-score-v11; earlier scorers and registries send none). A partial reading scores
 * only what was read, so the page leads with "Partial analysis", never the number alone.
 */
export const Coverage = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("complete") }),
  z.object({ kind: z.literal("partial"), omittedFiles: z.number(), omittedBytes: z.number(), reasons: z.array(z.string()), notes: z.array(z.string()).default([]) }),
]);

export type Coverage = z.infer<typeof Coverage>;
