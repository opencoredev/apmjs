// semver precedence, for the places the website orders version numbers itself: explain's look below a fresh run and
// the package page's choice of which off-list tag targets to read. Build metadata does not count, as in semver.
const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export type Parsed = { core: [number, number, number]; pre: string[] };

export function parseVersion(v: string): Parsed | null {
  const m = SEMVER.exec(v.trim());

  if (!m) return null;

  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] === undefined ? [] : m[4].split(".") };
}

/** One prerelease identifier against another, as semver orders them: numbers by value and before words. */
function compareIdentifier(a: string, b: string): number {
  const [na, nb] = [/^\d+$/.test(a), /^\d+$/.test(b)];

  if (na && nb) return Number(a) - Number(b);

  if (na !== nb) return na ? -1 : 1;

  return a < b ? -1 : a > b ? 1 : 0;
}

/** semver's order: the numbers, then a prerelease before its release, then the prerelease identifiers in turn. */
export function compareVersions(a: Parsed, b: Parsed): number {
  for (let i = 0; i < 3; i++) if (a.core[i] !== b.core[i]) return (a.core[i] ?? 0) - (b.core[i] ?? 0);

  if (a.pre.length === 0 || b.pre.length === 0) return b.pre.length - a.pre.length;

  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const [x, y] = [a.pre[i], b.pre[i]];

    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    const c = compareIdentifier(x, y);

    if (c !== 0) return c;
  }

  return 0;
}

/** Highest first, by semver precedence; a string that is not a version sorts after every version. */
export function bySemverDesc(a: string, b: string): number {
  const [x, y] = [parseVersion(a), parseVersion(b)];

  if (x === null || y === null) return (x === null ? 1 : 0) - (y === null ? 1 : 0);

  return compareVersions(y, x);
}
