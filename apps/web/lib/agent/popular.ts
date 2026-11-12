// Scores for the home page's popular packages: one request for all of them, through the shared edge cache, so a cold
// isolate makes at most one registry read (none when the data center already holds the answer). Kept for an hour in
// this isolate; a miss is remembered for a minute. The pure part is ./popular-scores.ts.
import "server-only";
import type { CachePolicy } from "../edge-cache";
import { fetchCachedJson } from "../registry-fetch";
import { REGISTRY } from "../registry-url";
import { PopularScoresAnswer, popularScores, type PopularScore } from "./popular-scores";
import { POPULAR_PACKAGES } from "./site";

/** The badges stream in after the grid; none of them waits longer than this. */
const READ_BUDGET_MS = 4_000;

/** Popular packages' latest scores move slowly; every isolate in a data center shares one answer. */
const POPULAR_POLICY: CachePolicy = { freshMs: 10 * 60_000, staleMs: 60 * 60_000 };

const url = `${REGISTRY}-/apm/v1/popular-scores?${new URLSearchParams({ names: POPULAR_PACKAGES.map((p) => p.name).join(",") })}`;

const popular = popularScores({
  load: () => fetchCachedJson({ url, schema: PopularScoresAnswer, timeoutMs: READ_BUDGET_MS, cache: POPULAR_POLICY }),
  ttlMs: 60 * 60_000,
  missTtlMs: 60_000,
});

/** The latest version's score, or null when the registry has none yet or did not answer in time. */
export function popularScore(name: string): Promise<PopularScore | null> {
  return popular.score(name);
}
