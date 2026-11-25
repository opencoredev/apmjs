// Which version a package page shows for its `?v=`. The package answer lists only the newest 200 versions
// (version-count.ts), so a version missing from that list may still exist: the page asks the registry's per-version
// endpoint (getVersionInfo) before it decides, and says "no such version" when that answers 404. Pure, so the page
// and the tests share it.
import type { PackageInfo } from "./registry";

/** What the page knows about `?v=` from the package answer alone. */
export type VersionChoice =
  /**
   * no `?v=`: latest (null when the package has no versions to show). With no latest tag, the newest version another
   * tag names, and that `tag`, which installs need: a bare name resolves to latest only.
   */
  | { readonly kind: "latest"; readonly version: string | null; readonly tag: string | null }
  /** a version the package answer lists, asked by number or by dist-tag */
  | { readonly kind: "listed"; readonly version: string }
  /** a version string the list does not hold: older than the newest 200, or not a version of this package */
  | { readonly kind: "unlisted"; readonly version: string }
  /** not a version number and not a dist-tag of this package: no registry read can find it */
  | { readonly kind: "invalid"; readonly asked: string };

// A semver version as npm stores it: three numbers, an optional prerelease and optional build metadata.
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** Whether `asked` is a version number rather than a dist-tag: one the per-version endpoint can be asked about as it is. */
export const isVersionNumber = (asked: string): boolean => VERSION.test(asked);

/** Decides from the package answer; `unlisted` still needs the per-version endpoint to say whether it exists. */
export function chooseVersion(input: { pkg: Pick<PackageInfo, "versions" | "latest" | "distTags">; asked: string | undefined }): VersionChoice {
  const { pkg, asked } = input;

  if (asked === undefined) {
    const tagged = pkg.latest === null ? taggedDefault(pkg) : null;

    return { kind: "latest", version: pkg.latest ?? tagged?.version ?? null, tag: tagged?.tag ?? null };
  }

  const tagged = Object.hasOwn(pkg.distTags, asked) ? pkg.distTags[asked] : undefined;
  const version = tagged ?? asked;

  if (pkg.versions.some((v) => v.version === version)) return { kind: "listed", version };

  return VERSION.test(version) ? { kind: "unlisted", version } : { kind: "invalid", asked };
}

/**
 * A package with no latest tag (only a prerelease, tagged next): the listed version a tag names that was published
 * last, with that tag. Null when the package has a latest or no tag names a listed version.
 */
export function taggedDefault(pkg: Pick<PackageInfo, "versions" | "latest" | "distTags">): { tag: string; version: string } | null {
  if (pkg.latest !== null) return null;

  const published = new Map(pkg.versions.map((v) => [v.version, Date.parse(v.publishedAt) || 0]));

  const tagged = Object.entries(pkg.distTags).flatMap(([tag, version]) => {
    const at = published.get(version);

    return at === undefined ? [] : [{ tag, version, at }];
  });

  const newest = tagged.toSorted((a, b) => b.at - a.at)[0];

  return newest ? { tag: newest.tag, version: newest.version } : null;
}

/** What the page's helpers (shownOf, unscoredNotice) read from a version row. */
export type VersionState = { readonly version: string; readonly status: string; readonly unscorable?: string | null };

/** The rows those helpers look the shown version up in: the package answer's, plus the one read from the per-version endpoint. */
export function rowsWith(versions: readonly VersionState[], extra: VersionState | null): readonly VersionState[] {
  return extra === null ? versions : [...versions, extra];
}
