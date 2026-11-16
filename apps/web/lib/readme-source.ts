// Where a package page's readme comes from. npm's packument carries a readme for most packages, but not all
// (react's has none), so the page falls back to the README in the shown version's tarball, which the registry
// picks the way npm does and reads through the same checksum-verified path as the file view. A version apm recorded
// too large to analyze is not asked about: the readme route reads the tarball under the same caps (32 MiB downloaded,
// 48 MiB unpacked), so it can only refuse, after asking npm for the version and the tarball (next 16.4.6 is 43.7 MB).
import type { PackageInfo } from "./registry";
import type { Fetched } from "./registry-fetch";

/** What the registry's /-/apm/v1/readme answer carries; the same shape as a file view answer. */
export type TarballReadme =
  | { kind: "text"; path: string; size: number; text: string }
  | { kind: "binary"; path: string; size: number }
  | { kind: "too-large"; path: string; size: number; limit: number };

/** The tarball readme read: the registry's answer, or "not-opened" when the page did not ask (tarballTooLarge). */
export type TarballRead = Fetched<TarballReadme> | { kind: "not-opened" };

export type ReadmeSource =
  | { kind: "packument"; text: string }
  | { kind: "tarball"; text: string; path: string; version: string }
  /** A README file is there but can't be rendered: over the size cap, or not text. */
  | { kind: "unreadable"; path: string; version: string; size: number; reason: "too-large" | "binary" }
  | { kind: "none" }
  /** The version's tarball is too large for apm to open, so its README could not be looked for. */
  | { kind: "not-opened"; version: string }
  /** The registry did not answer the tarball lookup, so whether there is one is unknown. */
  | { kind: "unknown" };

/** What npm's packument says for some packages published without a readme. */
const NPM_PLACEHOLDER = "ERROR: No README data found!";

/** Whether the packument's readme is missing: empty, blank, or npm's placeholder. The page then asks for the tarball's. */
export const needsTarballReadme = (packument: string): boolean => {
  const text = packument.trim();

  return text === "" || text === NPM_PLACEHOLDER;
};

/**
 * Whether the shown version's tarball is one the registry cannot open: the package answer says apm recorded it too
 * large to analyze, for the very tarball latest names now (`sameTarball`: a version npm moved to other bytes, or an
 * outcome bound to none, is asked about). Only latest carries the reason; an older version's row has only the
 * sentence, and is asked about.
 */
export function tarballTooLarge(input: { pkg: Pick<PackageInfo, "unscored" | "latest">; version: string | null }): boolean {
  const { pkg, version } = input;

  return version !== null && version === pkg.latest && pkg.unscored?.kind === "unscorable" && pkg.unscored.reason === "too-large" && pkg.unscored.sameTarball;
}

/** The readme to show: the packument's when it has one, else the tarball's README, else none. */
export function readmeSource(input: { packument: string; version: string | null; tarball: TarballRead | null }): ReadmeSource {
  if (!needsTarballReadme(input.packument)) return { kind: "packument", text: input.packument };
  const { version, tarball } = input;

  if (version === null || tarball === null || tarball.kind === "missing") return { kind: "none" };

  if (tarball.kind === "not-opened") return { kind: "not-opened", version };

  if (tarball.kind === "unavailable") return { kind: "unknown" };
  const file = tarball.value;

  switch (file.kind) {
    case "text":
      return file.text.trim() === "" ? { kind: "none" } : { kind: "tarball", text: file.text, path: file.path, version };
    case "binary":
    case "too-large":
      return { kind: "unreadable", path: file.path, version, size: file.size, reason: file.kind };
    default: {
      const _exhaustive: never = file;

      return _exhaustive;
    }
  }
}
