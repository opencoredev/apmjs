// Who published a package before a version: what the new-publisher signal (@apm/core) compares the version's account
// against. For a package on npm the history is every version npm lists (cachedPackage reads the whole packument,
// prereleases and nightlies included) published before this one, by npm's `time`.
import { z } from "zod";
import type { AnalyzeInput } from "@apm/core";
import type { VersionRecord } from "./db.ts";

/** One version's publish: the account that published it (null when none was recorded) and when. */
export type Publication = { readonly publisher: string | null; readonly at: number };

/** The accounts among `earlier`, newest publish first, each once; a publish with no recorded account adds none. */
export function newestPublishersFirst(earlier: readonly Publication[]): string[] {
  return [...new Set(earlier.toSorted((a, b) => b.at - a.at).flatMap((p) => (p.publisher === null ? [] : [p.publisher])))];
}

/** What cachedPackage records as an upstream version's `published_by` when npm's document has no `_npmUser`. */
export const NO_RECORDED_PUBLISHER = "upstream";

const NpmUser = z.object({ _npmUser: z.object({ name: z.string() }) });

type Upstream = Pick<VersionRecord, "manifest" | "published_by" | "published_at">;

/**
 * The account that published upstream version `v`, or null when npm recorded none: versions published before npm
 * recorded `_npmUser` (typescript 0.8.1, 2012) have none, and cachedPackage gives them NO_RECORDED_PUBLISHER, which is
 * not an account. A `published_by` of "upstream" is that placeholder only when the record's manifest (where cachedPackage
 * keeps the document's `_npmUser`) names no publisher, so an account of that name is still one.
 */
export function recordedPublisher(v: Upstream): string | null {
  return v.published_by === NO_RECORDED_PUBLISHER && !NpmUser.safeParse(v.manifest).success ? null : v.published_by;
}

/**
 * How new-publisher names a publish npm recorded no account for. npm usernames have no spaces, so it never equals an
 * account: an unknown publisher is never taken to be one that published before.
 */
export const UNRECORDED_PUBLISHER = "an account npm did not record";

/**
 * The publisher fields `analyze` reads for upstream version `v` of a package whose versions npm lists as `versions`:
 * `previousPublishers` is every account that published a version before `v` (newestPublishersFirst). Unknown publishers
 * fail closed: never more permissive than comparing the old placeholder as an account, and stricter in one case.
 * - `v` with no recorded account is UNRECORDED_PUBLISHER, so it is a new publisher whenever an earlier version names
 *   one, even when unrecorded versions also came before (alice, then unrecorded, then unrecorded: the last is flagged,
 *   where the placeholder matched itself and was not; an unknown account is not shown to be one seen before);
 * - earlier versions that name no account at all leave the history as [UNRECORDED_PUBLISHER], so a named account
 *   publishing after them is a new publisher, and an unrecorded one after them is not (nothing to tell apart).
 */
export function upstreamPublishers(versions: readonly Upstream[], v: Upstream): Pick<AnalyzeInput, "publisher" | "previousPublishers"> {
  const earlier = versions.flatMap((x) => (x.published_at < v.published_at ? [{ publisher: recordedPublisher(x), at: x.published_at }] : []));
  const named = newestPublishersFirst(earlier);
  const previousPublishers = named.length > 0 || earlier.length === 0 ? named : [UNRECORDED_PUBLISHER];

  return { publisher: recordedPublisher(v) ?? UNRECORDED_PUBLISHER, previousPublishers };
}
