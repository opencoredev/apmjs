// Package-name checks: validity and typo distance to popular names.
import { POPULAR_NAMES } from "./popular.ts";

const NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._-]*$/;

export function isValidPackageName(name: string): boolean {
  return name.length > 0 && name.length <= 214 && NAME_RE.test(name);
}

export function isScoped(name: string): boolean {
  return name.startsWith("@");
}

/** Optimal string alignment distance: insert, delete, substitute, swap adjacent. */
export function editDistance(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const d: number[][] = Array.from({ length: rows }, (_, i) => Array.from({ length: cols }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  const at = (i: number, j: number): number => d[i]?.[j] ?? Number.POSITIVE_INFINITY;
  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(at(i - 1, j) + 1, at(i, j - 1) + 1, at(i - 1, j - 1) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, at(i - 2, j - 2) + 1);
      const row = d[i];
      if (row) row[j] = v;
    }
  }
  return at(a.length, b.length);
}

function squash(name: string): string {
  return name.replace(/[-_.]/g, "");
}

export type TypoConflict = { name: string; distance: number; reason: string };

/** Popular names that `candidate` could be mistaken for. Empty when the name is itself popular. */
export function typoConflicts(candidate: string, popular: readonly string[] = POPULAR_NAMES): TypoConflict[] {
  if (isScoped(candidate)) return [];
  if (popular.includes(candidate)) return [];
  const out: TypoConflict[] = [];
  for (const p of popular) {
    if (isScoped(p) || p.length < 4 || candidate.length < 4) continue;
    if (squash(p) === squash(candidate)) {
      out.push({ name: p, distance: 0, reason: `differs from "${p}" only by separators` });
      continue;
    }
    const dist = editDistance(candidate, p);
    if (dist === 1) out.push({ name: p, distance: 1, reason: `one edit away from "${p}"` });
  }
  return out;
}
