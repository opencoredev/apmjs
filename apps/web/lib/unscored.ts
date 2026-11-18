// What the score section says for a version with no score. Waiting for the analysis queue and "can never be scored"
// are different answers: the first passes in a minute, the second never does. Neither stops an install through apm's
// registry: apm add and the Bun scanner warn about both, and only strict mode and the ~safe view refuse them
// (docs/ARCHITECTURE.md, "Scoring npm packages").
import type { PackageInfo } from "./registry";

export type UnscoredNotice = { kind: "queued" | "unknown"; text: string } | { kind: "unscorable"; text: string };

/** What an install through apm does with a version apm cannot score, after the registry's reason. */
export const UNSCORABLE_INSTALLS = "Installs through apm still work, and apm add warns about it; strict mode and the ~safe view refuse it.";

/** The registry's reason, as a sentence, followed by what installs do with the version. */
const unscorableText = (reason: string): string => `${reason}. ${UNSCORABLE_INSTALLS}`;

/**
 * The notice for the shown version: the package answer's `unscored` for latest, the version row's `unscorable` for an
 * older one. A registry from before these fields sends neither, and gets the old wording.
 */
export function unscoredNotice(input: {
  pkg: Pick<PackageInfo, "unscored" | "latest"> & { versions: readonly { version: string; unscorable?: string | null }[] };
  version: string | null;
}): UnscoredNotice {
  const { pkg, version } = input;
  const isLatest = version === pkg.latest;

  if (isLatest && pkg.unscored) {
    switch (pkg.unscored.kind) {
      case "unscorable":
        return { kind: "unscorable", text: unscorableText(pkg.unscored.text) };
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
  if (row?.unscorable) return { kind: "unscorable", text: unscorableText(row.unscorable) };

  return { kind: "unknown", text: "Not scored yet." };
}
