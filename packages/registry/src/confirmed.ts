// Versions an apm reviewer confirmed malicious (the AI review's human decision, review.ts) are not served, like revoked
// ones: dropped from every packument (plain and ~safe, local and upstream) and from dist-tags, 404 for the version's
// manifest, 410 for its tarball. Before this (review of a76b9fc, finding 1) resolve refused such a version and scan
// reported it fatal, but the packuments still listed it and both tarball routes served its bytes, so a plain
// `npm install` or a lockfile fetched it. A reviewer who later dismisses the flag makes the version served again on the
// next request: nothing here is cached.
import { Effect } from "effect";
import { Store } from "./db.ts";
import { digestLabel, digestOf } from "./digest.ts";

/** The versions among `versions` whose tarball an apm reviewer confirmed malicious. A review names one digest. */
export const confirmedVersions = (name: string, versions: readonly { version: string; integrity: string; shasum: string }[]) =>
  Effect.gen(function* () {
    const rows = yield* (yield* Store).confirmedReviews(name);
    const out = new Set<string>();

    if (rows.length === 0) return out;
    const wanted = new Set(rows.map((r) => `${r.version} ${r.digest}`));

    for (const v of versions) {
      const d = digestOf(v);

      if (d && wanted.has(`${v.version} ${digestLabel(d)}`)) out.add(v.version);
    }

    return out;
  });

/** What the tarball routes answer for one: 410, as for a revoked version, with the reason. */
export function confirmedText(name: string, version: string): string {
  return `${name}@${version} was confirmed malicious by an apm reviewer, so the registry does not serve it.`;
}
