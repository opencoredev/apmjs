// Scores for the home page's popular packages: one small read per package, in parallel, cached per package so a
// busy home page costs the registry a dozen reads an hour. A miss is remembered for a minute, so a registry
// that is down or still scoring a tarball is not asked again on every view.
import "server-only";
import { createSharedCache } from "../rate-limit";
import { latestScore, type LatestScore } from "./registry-source";

const SCORE_TTL_MS = 60 * 60 * 1000;
const MISS_TTL_MS = 60 * 1000;

/** The badges stream in after the grid; none of them waits longer than this. */
const READ_BUDGET_MS = 4_000;

const scores = createSharedCache<LatestScore>({ ttlMs: SCORE_TTL_MS, maxEntries: 200 });
const misses = new Map<string, number>();

/** The latest version's score, or null when the registry has none yet or did not answer in time. */
export async function popularScore(name: string, now = Date.now()): Promise<LatestScore | null> {
  const missedUntil = misses.get(name);

  if (missedUntil !== undefined && missedUntil > now) return null;

  const value = await scores.get(name, async () => {
    const r = await latestScore(name, READ_BUDGET_MS);

    return r.kind === "ok" ? r.value : null;
  });

  if (value === null) misses.set(name, now + MISS_TTL_MS);
  else misses.delete(name);

  return value;
}
