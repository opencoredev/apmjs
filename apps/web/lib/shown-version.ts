// Which version a package page shows for its `?v=`, and how its install commands name it. The package answer lists
// only the newest 200 versions (version-count.ts), so a version missing from that list may still exist: the page asks
// the registry's per-version endpoint (getVersionInfo) before it decides, and says "no such version" when that answers
// 404. Pure apart from that read, which the caller passes in, so the page, its Markdown view and the tests share it.
import type { InstallSpec } from "./install-note";
import type { Fetched, PackageInfo, Refused } from "./registry";
import { isInstallable, noInstallable, type NoInstallable } from "./refusal";

type Answer = Pick<PackageInfo, "versions" | "latest" | "distTags">;

/** A dist-tag naming an installable version, with when that version was published (0 when unknown). */
type Tagged = { readonly tag: string; readonly version: string; readonly at: number };

/** What the page knows about `?v=` from the package answer alone. */
export type VersionChoice =
  /**
   * no `?v=`: latest, when apm installs it. Otherwise the installable version a tag names that was published last, and
   * that `tag`, which installs need: a bare name resolves to latest only.
   */
  | { readonly kind: "latest"; readonly version: string; readonly tag: string | null }
  /**
   * no `?v=`, no installable latest, and some tags name versions the list does not hold: those are read before the
   * newest of all eligible targets, `listed` and `unlisted` alike, is picked
   */
  | { readonly kind: "tagged-unlisted"; readonly listed: readonly Tagged[]; readonly unlisted: readonly { readonly tag: string; readonly version: string }[] }
  /** no `?v=`, and nothing installs by name */
  | { readonly kind: "none" }
  /** a version the package answer lists, asked by number or by dist-tag */
  | { readonly kind: "listed"; readonly version: string }
  /** a version string the list does not hold: older than the newest 200, or not a version of this package */
  | { readonly kind: "unlisted"; readonly version: string }
  /** not a version number and not a dist-tag of this package: no registry read can find it */
  | { readonly kind: "invalid"; readonly asked: string };

// A semver version as npm stores it: three numbers, an optional prerelease and optional build metadata.
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const PRERELEASE = /^\d+\.\d+\.\d+-/;

/** Whether `asked` is a version number rather than a dist-tag: one the per-version endpoint can be asked about as it is. */
export const isVersionNumber = (asked: string): boolean => VERSION.test(asked);

/** Whether apm installs latest: it is tagged and its row is installable (a latest older than the list is taken as served). */
function latestInstalls(pkg: Answer): pkg is Answer & { latest: string } {
  if (pkg.latest === null) return false;
  const row = pkg.versions.find((v) => v.version === pkg.latest);

  return row === undefined || isInstallable(row);
}

/** The one rule for picking among tag targets: published last, then by tag name so the pick never depends on order. */
function newest<T extends Tagged>(tagged: readonly T[]): T | undefined {
  return tagged.toSorted((a, b) => b.at - a.at || a.tag.localeCompare(b.tag))[0];
}

/** The tags naming an installable listed version, and the tags naming a version the list does not hold. */
function tagTargets(pkg: Answer) {
  const rows = new Map(pkg.versions.map((v) => [v.version, v]));
  const listed: Tagged[] = [];
  const unlisted: { tag: string; version: string }[] = [];

  for (const [tag, version] of Object.entries(pkg.distTags)) {
    const row = rows.get(version);

    if (row === undefined) {
      if (VERSION.test(version)) unlisted.push({ tag, version });
    } else if (isInstallable(row)) listed.push({ tag, version, at: Date.parse(row.publishedAt) || 0 });
  }

  return { listed, unlisted };
}

/** Decides from the package answer; `unlisted` and `tagged-unlisted` still need the per-version endpoint. */
export function chooseVersion(input: { pkg: Answer; asked: string | undefined }): VersionChoice {
  const { pkg, asked } = input;

  if (asked === undefined) {
    if (latestInstalls(pkg)) return { kind: "latest", version: pkg.latest, tag: null };
    const { listed, unlisted } = tagTargets(pkg);

    if (unlisted.length > 0) return { kind: "tagged-unlisted", listed, unlisted };
    const pick = newest(listed);

    return pick ? { kind: "latest", version: pick.version, tag: pick.tag } : { kind: "none" };
  }

  const tagged = Object.hasOwn(pkg.distTags, asked) ? pkg.distTags[asked] : undefined;
  const version = tagged ?? asked;

  if (pkg.versions.some((v) => v.version === version)) return { kind: "listed", version };

  return VERSION.test(version) ? { kind: "unlisted", version } : { kind: "invalid", asked };
}

/**
 * A package whose latest apm does not install (none tagged, only a prerelease tagged next, or latest yanked): the
 * installable listed version a tag names that was published last, with that tag. Null when latest installs or no tag
 * names an installable listed version. A target the list does not hold needs a read: see selectVersion.
 */
export function taggedDefault(pkg: Answer): { tag: string; version: string } | null {
  if (latestInstalls(pkg)) return null;
  const pick = newest(tagTargets(pkg).listed);

  return pick ? { tag: pick.tag, version: pick.version } : null;
}

/**
 * How the version latest names installs. A stable release installs by name. A prerelease never does: when a packument
 * withheld the stable release it can tag a surviving prerelease latest, and apm's resolver refuses a bare install of a
 * prerelease. So name another tag that names it (next first), else pin it.
 */
function latestInstall(input: { pkg: Answer; version: string }): InstallSpec {
  const { pkg, version } = input;

  if (!PRERELEASE.test(version)) return { kind: "default", version };

  const tags = Object.entries(pkg.distTags)
    .filter(([tag, v]) => tag !== "latest" && v === version)
    .map(([tag]) => tag)
    .toSorted((a, b) => Number(b === "next") - Number(a === "next") || a.localeCompare(b));

  return tags[0] === undefined ? { kind: "exact", version } : { kind: "tag", tag: tags[0] };
}

/** How an explicit `?v=` installs: by the tag it names (latest's as latest installs), or pinned to the number it names. */
function askedInstall(input: { pkg: Answer; asked: string; version: string }): InstallSpec {
  const { pkg, asked, version } = input;

  if (!Object.hasOwn(pkg.distTags, asked)) return { kind: "exact", version };

  return asked === "latest" ? latestInstall({ pkg, version }) : { kind: "tag", tag: asked };
}

/**
 * The version a page shows for `?v=` and how its install commands name it, the same on the page and in its Markdown
 * view. `read` is the version answer when the package answer does not list the version (null when it does).
 */
export type Selection<V> =
  | { readonly kind: "shown"; readonly version: string; readonly install: InstallSpec; readonly read: V | null }
  | { readonly kind: "none"; readonly why: NoInstallable }
  | { readonly kind: "no-such-version"; readonly asked: string }
  | { readonly kind: "unavailable"; readonly version: string };

/** Resolves `?v=`: the package answer decides when it can, and `read` (the per-version endpoint) when it can't. */
export async function selectVersion<V extends { version: string; status: string; refused?: Refused | null; publishedAt?: string | null }>(input: {
  pkg: Answer;
  asked: string | undefined;
  read: (version: string) => Promise<Fetched<V>>;
}): Promise<Selection<V>> {
  const { pkg, asked } = input;
  const choice = chooseVersion({ pkg, asked });

  switch (choice.kind) {
    case "latest":
      return { kind: "shown", version: choice.version, install: choice.tag === null ? latestInstall({ pkg, version: choice.version }) : { kind: "tag", tag: choice.tag }, read: null };
    case "none":
      return { kind: "none", why: noInstallable(pkg) };
    case "tagged-unlisted": {
      const eligible: (Tagged & { read: V | null })[] = choice.listed.map((t) => ({ ...t, read: null }));
      const reads = new Map<string, Fetched<V>>();

      for (const t of choice.unlisted) {
        const info = reads.get(t.version) ?? (await input.read(t.version));

        reads.set(t.version, info);

        if (info.kind === "unavailable") return { kind: "unavailable", version: t.version };

        if (info.kind === "ok" && isInstallable(info.value)) eligible.push({ tag: t.tag, version: info.value.version, at: Date.parse(info.value.publishedAt ?? "") || 0, read: info.value });
      }

      const pick = newest(eligible);

      return pick ? { kind: "shown", version: pick.version, install: { kind: "tag", tag: pick.tag }, read: pick.read } : { kind: "none", why: noInstallable(pkg) };
    }

    case "listed":
      return { kind: "shown", version: choice.version, install: askedInstall({ pkg, asked: asked ?? choice.version, version: choice.version }), read: null };
    case "invalid":
      return { kind: "no-such-version", asked: choice.asked };
    case "unlisted": {
      const info = await input.read(choice.version);

      switch (info.kind) {
        case "ok":
          return { kind: "shown", version: info.value.version, install: askedInstall({ pkg, asked: asked ?? choice.version, version: info.value.version }), read: info.value };
        case "missing":
          return { kind: "no-such-version", asked: choice.version };
        case "unavailable":
          return { kind: "unavailable", version: choice.version };
        default: {
          const _exhaustive: never = info;

          return _exhaustive;
        }
      }
    }

    default: {
      const _exhaustive: never = choice;

      return _exhaustive;
    }
  }
}

/** The version and score a share of the package page names (title, description, card, JSON-LD); nulls when none. */
export type Shared = { readonly version: string | null; readonly score: { readonly score: number; readonly grade: string } | null };

/** A listed version's share: latest's full score, else the score its row carries. */
export function sharedVersion(input: { pkg: Answer & Pick<PackageInfo, "score">; version: string }): Shared {
  const { pkg, version } = input;

  if (version === pkg.latest && pkg.score) return { version, score: { score: pkg.score.score, grade: pkg.score.grade } };
  const row = pkg.versions.find((v) => v.version === version);

  return { version, score: row && row.score !== null && row.grade !== null ? { score: row.score, grade: row.grade } : null };
}

/** A selected version's share: from its own version answer when the package answer does not list it (`read`). */
export function sharedShown(input: { pkg: Answer & Pick<PackageInfo, "score">; version: string; read: { score: { score: number; grade: string } | null } | null }): Shared {
  const { read, version } = input;

  if (read === null) return sharedVersion(input);

  return { version, score: read.score ? { score: read.score.score, grade: read.score.grade } : null };
}

/**
 * The share of the default page: the version installs get by name, with that version's own score. A default that may
 * be a version the package answer does not list (an old tagged version) is shared without a version or a score rather
 * than another's.
 */
export function sharedDefault(pkg: Answer & Pick<PackageInfo, "score">): Shared {
  const choice = chooseVersion({ pkg, asked: undefined });

  return choice.kind === "latest" ? sharedVersion({ pkg, version: choice.version }) : { version: null, score: null };
}

/** What the page's helpers (shownOf, unscoredNotice) read from a version row. */
export type VersionState = { readonly version: string; readonly status: string; readonly unscorable?: string | null };

/** The rows those helpers look the shown version up in: the package answer's, plus the one read from the per-version endpoint. */
export function rowsWith(versions: readonly VersionState[], extra: VersionState | null): readonly VersionState[] {
  return extra === null ? versions : [...versions, extra];
}
