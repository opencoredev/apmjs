// What the score section says for a version with no score. Waiting for the analysis queue and "can never be scored"
// are different answers: the first passes in a minute, the second never does, and installs through apm refuse both.
import type { PackageInfo } from "./registry";

export type UnscoredNotice = { kind: "queued" | "unknown"; text: string } | { kind: "unscorable"; text: string };

/**
 * The notice for the shown version: the package answer's `unscored` for latest, the version row's `unscorable` for an
 * older one. A registry from before these fields sends neither, and gets the old wording.
 */
export function unscoredNotice(input: { pkg: Pick<PackageInfo, "unscored" | "versions" | "latest">; version: string | null }): UnscoredNotice {
  const { pkg, version } = input;
  const isLatest = version === pkg.latest;

  if (isLatest && pkg.unscored) {
    switch (pkg.unscored.kind) {
      case "unscorable":
        return { kind: "unscorable", text: `${pkg.unscored.text}. Installs through apm refuse it.` };
      case "queued":
        return { kind: "queued", text: "Not scored yet: its tarball is queued for analysis." };
      case "unreadable":
        return { kind: "unknown", text: "Not scored: its tarball could not be analyzed." };
      default: {
        const _exhaustive: never = pkg.unscored;

        return _exhaustive;
      }
    }
  }

  const row = pkg.versions.find((v) => v.version === version);

  // the registry's sentence starts with "apm", which stays lowercase
  if (row?.unscorable) return { kind: "unscorable", text: `${row.unscorable}. Installs through apm refuse it.` };

  return { kind: "unknown", text: "Not scored yet." };
}
