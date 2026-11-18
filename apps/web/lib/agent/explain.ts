// Reads what an install verdict needs (the registry's resolve answer with its dependency walk, then the AI review of
// the version it picked) and returns the verdict. Shared by GET /api/explain and the explain_install MCP tool. Both
// reads skip every cache (see AgentSource): a version confirmed malicious a second ago must not get "install".
import { looksLikePackageName } from "../search-schema";
import type { AgentSource, ResolveOutcome } from "./source";
import { explainInstall, reviewInput, type OlderSearch, type Verdict } from "./verdict";

/** "zod", "zod@^4", "@scope/name@1.2.3" → name and range; null when the name can't be a package name. */
export function parsePackageSpec(spec: string): { name: string; range: string | null } | null {
  const s = spec.trim();
  const at = s.lastIndexOf("@");
  const name = (at > 0 ? s.slice(0, at) : s).toLowerCase();
  const range = at > 0 ? s.slice(at + 1).trim() : "";

  if (!looksLikePackageName(name) || range.length > 256) return null;

  return { name, range: range === "" ? null : range };
}

/**
 * Older versions explain asks for when the one picked is inside the cooldown, before it gives up: each is a resolve
 * of its own (RESOLVE_TIMEOUT_MS at most), so a burst of releases costs at most this many more. Each asks below the
 * whole run of fresh versions the pick heads (belowFreshRun), not one version at a time, so a package that publishes
 * several times a day (ai, openai, @trpc/server) needs one.
 */
export const MAX_OLDER_LOOKUPS = 2;

/** apm's cooldown, as explain reads a version list (packages/core COOLDOWN_MS; the registry decides what is fresh). */
export const COOLDOWN_MS = 24 * 60 * 60 * 1000;

/** A version as the package answer lists it: its number and when it was published. */
export type ListedVersion = { version: string; publishedAt: string };

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

type Parsed = { core: [number, number, number]; pre: string[] };

function parseVersion(v: string): Parsed | null {
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
function compareVersions(a: Parsed, b: Parsed): number {
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

/**
 * Where to ask below when `version` is inside the cooldown: the lowest version of the run of fresh versions it heads,
 * by version number, in the package's version list. Every version between that one and `version` was published inside
 * the cooldown, so the range below it passes over none apm could pick. `version` itself when the list does not have
 * it. Only the number to ask below: what the registry then picks is checked for the cooldown again, so a list that is
 * stale or short costs a lookup, never a fresh version.
 */
export function belowFreshRun(input: { version: string; listed: readonly ListedVersion[]; now: number }): string {
  const sorted = input.listed.flatMap((l) => {
    const parsed = parseVersion(l.version);

    return parsed ? [{ ...l, parsed }] : [];
  }).toSorted((a, b) => compareVersions(b.parsed, a.parsed));

  const at = sorted.findIndex((l) => l.version === input.version);

  if (at < 0) return input.version;
  let low = input.version;

  for (const l of sorted.slice(at + 1)) {
    const published = Date.parse(l.publishedAt);

    if (!Number.isFinite(published) || input.now - published >= COOLDOWN_MS) break;
    low = l.version;
  }

  return low;
}

/** A dist-tag (latest, next, beta) rather than a semver range: a name, not a version, `x` or a `v1`. */
const TAG = /^(?!v?\d)(?![xX]$)[A-Za-z][\w.-]*$/;

/** A hyphen range, `1.0.0 - 2.0.0`, as one comparator set: node-semver takes it only when it is the whole set. */
const HYPHEN = /^(\S+)\s+-\s+(\S+)$/;

/**
 * One `||` alternative as a comparator set another comparator can be added to: a hyphen range becomes `>=low <=high`,
 * which node-semver reads the same way for full and partial versions (`<=2.3` is `<2.4.0-0`, as `- 2.3` is).
 */
function comparatorSet(part: string): string {
  const hyphen = HYPHEN.exec(part);

  return hyphen ? `>=${hyphen[1] ?? ""} <=${hyphen[2] ?? ""}` : part;
}

/**
 * The range `range` less `version` and everything newer: a tag keeps its channel under `<version` (as the registry
 * reads a tag: in-channel versions up to its target, prereleases only of the target's own release), a range gets
 * `<version` added to each of its `||` alternatives, each made a plain comparator set first (a hyphen range is not).
 */
export function olderRange(range: string, version: string): string {
  if (TAG.test(range.trim())) return `<${version}`;

  return range
    .split("||")
    .map((part) => `${comparatorSet(part.trim())} <${version}`.trim())
    .join(" || ");
}

/** The picked version's own cooldown warning, when it was published inside the cooldown. */
function freshOf(resolve: Extract<ResolveOutcome, { kind: "ok" }>): { text: string } | null {
  return resolve.deps.warnings.find((w) => w.via.length === 0 && w.kind === "cooldown") ?? null;
}

/**
 * The resolve the verdict rests on: the registry's pick for `range`, or, when that version is inside the cooldown, the
 * newest older one in range past it (asked as `olderRange`, at most MAX_OLDER_LOOKUPS times). An older lookup the
 * registry does not answer makes the whole answer unavailable: apm cannot say whether an older version passes. No older
 * version in range, or only fresh ones, keeps the fresh pick, which the verdict sends to a person.
 */
export async function resolveForVerdict(input: { name: string; range: string; source: AgentSource; now?: number }): Promise<{ resolve: ResolveOutcome; older: OlderSearch }> {
  const first = await input.source.resolve({ name: input.name, range: input.range });

  if (first.kind !== "ok") return { resolve: first, older: { kind: "not-needed" } };
  let current = first;
  const passedOver: { version: string; text: string }[] = [];
  // the package's version list, read once and only when the pick is fresh; none when the registry did not answer
  let listed: readonly ListedVersion[] | null = null;

  for (let looked = 0; ; looked++) {
    const fresh = freshOf(current);

    if (fresh === null) return { resolve: current, older: passedOver.length > 0 ? { kind: "picked", passedOver } : { kind: "not-needed" } };

    if (looked >= MAX_OLDER_LOOKUPS) return { resolve: first, older: { kind: "gave-up", looked: looked + 1 } };

    if (listed === null) {
      const pkg = await input.source.package(input.name);

      listed = pkg.kind === "ok" ? pkg.value.versions : [];
    }

    const below = belowFreshRun({ version: current.version, listed, now: input.now ?? Date.now() });
    const older = await input.source.resolve({ name: input.name, range: olderRange(input.range, below) });

    // nothing older in range passes (or matches): the fresh version is all there is
    if (older.kind === "refused" || older.kind === "missing") return { resolve: first, older: { kind: "none" } };

    if (older.kind === "unavailable") return { resolve: older, older: { kind: "not-needed" } };
    passedOver.push({ version: current.version, text: fresh.text });
    current = older;
  }
}

export async function explainFor(input: { name: string; range: string | null; source: AgentSource }): Promise<Verdict> {
  const { name, range, source } = input;
  const { resolve, older } = await resolveForVerdict({ name, range: range ?? "latest", source });
  // only an "ok" resolve reads the review; the other verdicts never look at it
  const review = resolve.kind === "ok" ? reviewInput(await source.review({ name, version: resolve.version })) : ({ kind: "unreadable" } as const);

  return explainInstall({ name, range, resolve, review, older });
}
