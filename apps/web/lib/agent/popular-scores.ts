// The home page's popular list reads every score in one request: GET /-/apm/v1/popular-scores?names=a,b,c. This is
// the part without I/O: one shared load for all the badges, kept for a while, and a miss remembered briefly so a
// registry that is down or still scoring is not asked again on every view. lib/agent/popular.ts does the reading.
import { z } from "zod";
import { createSharedCache } from "../rate-limit";
import type { Fetched } from "../registry-fetch";

export const PopularScoresAnswer = z.object({
  packages: z.array(z.object({ name: z.string(), version: z.string().nullable(), score: z.number().nullable(), grade: z.string().nullable() })),
});

export type PopularScoresAnswer = z.infer<typeof PopularScoresAnswer>;

export type PopularScore = { version: string; score: number; grade: string };

export type PopularScores = { score: (name: string, now?: number) => Promise<PopularScore | null> };

/** One load serves every name: twelve badges on a cold isolate make one request, and none while it is fresh. */
export function popularScores(input: { load: () => Promise<Fetched<PopularScoresAnswer>>; ttlMs: number; missTtlMs: number }): PopularScores {
  const all = createSharedCache<Map<string, PopularScore>>({ ttlMs: input.ttlMs, maxEntries: 1 });
  let missedUntil = 0;

  return {
    async score(name, now = Date.now()) {
      if (missedUntil > now) return null;

      const scores = await all.get(
        "all",
        async () => {
          // a load that rejects (the 12 badges of a HEAD and a GET of / on 2026-11-25 did) is a miss like an outage,
          // so no badge throws into the render
          let r: Fetched<PopularScoresAnswer>;

          try {
            r = await input.load();
          } catch (error) {
            console.error(JSON.stringify({ event: "popular_scores_failed", error: error instanceof Error ? `${error.name}: ${error.message}` : "not an Error" }));

            return null;
          }

          if (r.kind !== "ok") return null;
          const out = new Map<string, PopularScore>();

          for (const p of r.value.packages) if (p.version !== null && p.score !== null && p.grade !== null) out.set(p.name, { version: p.version, score: p.score, grade: p.grade });

          return out;
        },
        now,
      );

      if (scores === null) missedUntil = now + input.missTtlMs;

      return scores?.get(name) ?? null;
    },
  };
}
