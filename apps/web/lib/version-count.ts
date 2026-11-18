// How the package page words its version count. The registry's package answer lists at most the newest
// LISTED_VERSIONS versions (KEPT_VERSIONS in packages/registry/src/kept-package.ts), so a full list says "newest",
// not "total": react has thousands of versions, and "200 total" read as a fact about the package.

/** The most versions the package answer lists. */
export const LISTED_VERSIONS = 200;

/** True when the list may be cut short: it holds as many versions as the package answer ever lists. */
export function isCapped(listed: number): boolean {
  return listed >= LISTED_VERSIONS;
}

/** The count beside the Versions heading: "12 total", or "newest 200" when the list may be cut short. */
export function versionCountLabel(listed: number): string {
  return isCapped(listed) ? `newest ${listed}` : `${listed} total`;
}

/** The button that opens the whole list. */
export function showAllLabel(listed: number): string {
  return isCapped(listed) ? `Show the newest ${listed} versions` : `Show all ${listed} versions`;
}
