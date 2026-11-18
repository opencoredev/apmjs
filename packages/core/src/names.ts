// Package-name checks: validity and typo distance to popular names.
import { POPULAR_NAMES } from "./popular.ts";

const NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._-]*$/;

export function isValidPackageName(name: string): boolean {
  return name.length > 0 && name.length <= 214 && NAME_RE.test(name);
}

/**
 * Whether npm could hold a package of this name, old names included (validate-npm-package-name's rules for old
 * packages: uppercase and URL-safe punctuation pass): an optional `@scope/` and a name, each URL-safe as written, not
 * starting with "." or "_", no surrounding spaces. Anything else npm refuses itself (a 405 for an encoded slash), so
 * there is nothing to ask it about.
 */
export function isPossibleNpmName(name: string): boolean {
  const m = /^(?:@([^/]+)\/)?([^/]+)$/.exec(name);

  if (!m || name.startsWith(".") || name.startsWith("_") || name.trim() !== name) return false;
  const [, scope, base] = m;

  return [scope, base].every((part) => part === undefined || encodeURIComponent(part) === part);
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

/**
 * What npm's record of a package says about the age of its name (the upstream packument's version times): when its
 * first listed version was published, and when its fifth was (null with fewer than five). Times npm did not give
 * (zero or less) are left out, so a missing time never makes a name look old.
 */
export type NameHistory = { first: number; fifth: number | null };

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * How old a name must be to be established in its own right (isEstablishedName): first published at least two years
 * ago, with at least five versions published at least a year ago. A typosquat is a new name, and npm's publish times
 * cannot be backdated, so a look-alike would have had to be published, and kept publishing, years before it is used.
 * The checked look-alikes popular packages depend on clear it with room (safer-buffer 2018 with 7, querystring 2011
 * with 5, merge2 2014 with 23, pathe 2021 with 25); npm's placeholder for a removed name has one version.
 */
export const ESTABLISHED_NAME = { minAgeMs: 2 * 365 * DAY_MS, minVersions: 5, versionAgeMs: 365 * DAY_MS } as const;

/** A name's history from the publish times of its listed versions (any order), or null when npm gave none. */
export function nameHistoryOf(publishedAt: Iterable<number>): NameHistory | null {
  const times = [...publishedAt].filter((t) => Number.isFinite(t) && t > 0).toSorted((a, b) => a - b);
  const first = times[0];

  if (first === undefined) return null;

  return { first, fifth: times[ESTABLISHED_NAME.minVersions - 1] ?? null };
}

/** Whether a name npm has this history for is long established at `now` (ESTABLISHED_NAME). */
export function isEstablishedName(history: NameHistory, now: number): boolean {
  return now - history.first >= ESTABLISHED_NAME.minAgeMs && history.fifth !== null && now - history.fifth >= ESTABLISHED_NAME.versionAgeMs;
}
