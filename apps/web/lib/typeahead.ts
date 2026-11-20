// The header search's dropdown, as pure functions: which hits it shows, how the arrow keys move through them and
// where Enter goes. components/search-bar.tsx is the shell around these.

import type { SearchHit } from "./search-schema";

/** How many hits the dropdown shows. The home page shows the full list. */
export const TYPEAHEAD_LIMIT = 6;

/** What a query is compared and fetched as: /api/search lowercases and trims the same way. */
export function normalizeQuery(q: string): string {
  return q.trim().toLowerCase();
}

export function packageHref(name: string): string {
  return `/package/${name}`;
}

/** The home page's results for `q`, or the home page itself for an empty query. */
export function searchHref(q: string): string {
  return q ? `/?q=${encodeURIComponent(q)}` : "/";
}

/** The first `limit` hits in npm's order, except that a package named exactly `q` always comes first. */
export function topHits(input: { hits: readonly SearchHit[]; q: string; limit?: number }): SearchHit[] {
  const { hits, q, limit = TYPEAHEAD_LIMIT } = input;
  const exact = hits.find((h) => h.name === q);
  const ordered = exact ? [exact, ...hits.filter((h) => h !== exact)] : [...hits];

  return ordered.slice(0, limit);
}

/**
 * The highlighted row after an arrow key. -1 is the input itself (nothing highlighted). Down from the last row and up
 * from the first go back to the input; up from the input goes to the last row.
 */
export function moveActive(input: { active: number; count: number; key: "ArrowDown" | "ArrowUp" }): number {
  const { active, count, key } = input;

  if (count === 0) return -1;

  if (key === "ArrowDown") return active >= count - 1 ? -1 : active + 1;

  return active <= -1 ? count - 1 : active - 1;
}

/** Where Enter goes: the highlighted package, or the home page's results for what is typed. */
export function submitHref(input: { q: string; hits: readonly SearchHit[]; active: number }): string {
  const hit = input.active >= 0 ? input.hits[input.active] : undefined;

  return hit ? packageHref(hit.name) : searchHref(normalizeQuery(input.q));
}
