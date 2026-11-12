// Small shared helpers for the AI review experiment.
import { homedir } from "node:os";
import { join } from "node:path";

/** Samples and run output live here, never inside the repo. */
export const CACHE_DIR = join(homedir(), ".cache", "apm-ai-review-samples");

/** Runs `fn` over `items` with at most `limit` in flight; keeps input order. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      const item = items[i];
      if (item === undefined) continue;
      out[i] = await fn(item, i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** Deterministic PRNG (mulberry32) so sample selection is reproducible. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function shuffle<T>(items: readonly T[], rand: () => number): T[] {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const x = a[i];
    const y = a[j];
    if (x === undefined || y === undefined) continue;
    a[i] = y;
    a[j] = x;
  }
  return a;
}
