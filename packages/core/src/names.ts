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

/** Endings people add to a popular name when they guess at it: `react.js`, `expressjs`, `lodash-js`. */
const GUESSED_SUFFIXES = [".js", "js", "-js", ".mjs"] as const;

/** Names this long are allowed two dropped or two added letters: `typscrip` still reads as `typescript`. */
const LONG_NAME = 8;

function scopeOf(name: string): string {
  return isScoped(name) ? name.slice(1, name.indexOf("/")) : "";
}

function bareOf(name: string): string {
  return isScoped(name) ? name.slice(name.indexOf("/") + 1) : name;
}

/** Swaps of two neighbouring letters, the commonest typo: `raect` for `react`. */
function isTransposition(a: string, b: string): boolean {
  if (a.length !== b.length || a === b) return false;
  const diff: number[] = [];

  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diff.push(i);
  const [i, j] = diff;

  return diff.length === 2 && i !== undefined && j === i + 1 && a[i] === b[j] && a[j] === b[i];
}

function guessedSuffix(candidate: string, p: string): string | null {
  if (p.length < 3) return null;

  return GUESSED_SUFFIXES.find((s) => candidate === `${p}${s}`) ?? null;
}

/** How an unscoped `bare` could be mistaken for the unscoped popular name `p`, or null. */
function unscopedConflict(bare: string, p: string): TypoConflict | null {
  const suffix = guessedSuffix(bare, p);

  if (suffix) return { name: p, distance: 0, reason: `is "${p}" with "${suffix}" added` };

  if (p.length < 4 || bare.length < 4) return null;

  if (squash(p) === squash(bare)) return { name: p, distance: 0, reason: `differs from "${p}" only by separators` };
  const dist = editDistance(bare, p);
  // two substitutions turn one real word into another (commondir, commander), so two edits count only as two letters dropped or added
  const twoAway = dist === 2 && p.length >= LONG_NAME && bare.length >= LONG_NAME && Math.abs(p.length - bare.length) === 2;

  if (dist > 1 && !twoAway) return null;

  return { name: p, distance: dist, reason: dist === 1 ? `one edit away from "${p}"` : `two edits away from "${p}"` };
}

/**
 * How the scoped `candidate` could be mistaken for a popular name, or null. Scopes exist so names can be
 * reused (@sentry/react, @types/node), so a popular bare name under another scope is not a lookalike.
 * What is: a near miss of a popular scoped name (`@type/node`), and a scoped name whose bare part is a
 * typo of a popular one (`@evil/raect`, `@evil/expressjs`). Generic bare parts one edit from a popular
 * name (`core`/`cors`, `server`/`serve`) are real everywhere, so only swaps and added suffixes count there.
 */
function scopedConflict(candidate: string, p: string): TypoConflict | null {
  const bare = bareOf(candidate);

  if (isScoped(p)) {
    if (squash(p) === squash(candidate)) return { name: p, distance: 0, reason: `differs from "${p}" only by separators` };
    const [scope, pScope] = [scopeOf(candidate), scopeOf(p)];
    // a short scope is one edit from many real ones (@trpc, @orpc), so only longer scopes are compared
    const nearScope = bare === bareOf(p) && pScope.length >= 5 && editDistance(scope, pScope) === 1;
    const nearBare = scope === pScope && bare.length >= 4 && editDistance(bare, bareOf(p)) === 1;

    return nearScope || nearBare ? { name: p, distance: 1, reason: `one edit away from "${p}"` } : null;
  }

  if (bare === p) return null;
  const suffix = guessedSuffix(bare, p);

  if (suffix) return { name: p, distance: 0, reason: `is "${p}" with "${suffix}" added, under another scope` };

  if (p.length >= 4 && isTransposition(bare, p)) return { name: p, distance: 1, reason: `swaps two letters of "${p}", under another scope` };

  return null;
}

/** Popular names that `candidate` could be mistaken for. Empty when the name is itself popular. */
export function typoConflicts(candidate: string, popular: readonly string[] = POPULAR_NAMES): TypoConflict[] {
  if (popular.includes(candidate)) return [];
  const out: TypoConflict[] = [];

  for (const p of popular) {
    const c = isScoped(candidate) ? scopedConflict(candidate, p) : isScoped(p) ? null : unscopedConflict(candidate, p);

    if (c) out.push(c);
  }

  return out;
}
