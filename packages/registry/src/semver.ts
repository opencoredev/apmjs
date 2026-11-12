// Version ordering and range matching (node-semver), total over any string a packument can hold.
import semver from "semver";

/** Like Bun.semver.order: negative when a < b. Invalid versions sort below valid ones, then by text. */
export function order(a: string, b: string): number {
  const va = semver.valid(a);
  const vb = semver.valid(b);

  if (va !== null && vb !== null) return semver.compare(va, vb);

  if (va !== null) return 1;

  if (vb !== null) return -1;

  return a < b ? -1 : a > b ? 1 : 0;
}

export function satisfies(version: string, range: string): boolean {
  try {
    return semver.satisfies(version, range);
  } catch {
    return false;
  }
}

export function newestFirst(a: string, b: string): number {
  return order(b, a);
}
