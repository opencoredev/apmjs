// The signed-in person's packages, for the website's "Your packages" page (GET /-/apm/v1/account/packages): every
// package under their scope, every one they own, and any new name whose first version is still waiting for approval
// (a package row is made only when its first version is approved). Store reads only; account.ts answers the route.
import { Effect } from "effect";
import { compactScore } from "./apm.ts";
import { Clock } from "./clock.ts";
import { Store, type StagedRecord, type VersionHead, type VersionStatus } from "./db.ts";
import type { StoreError } from "./errors.ts";
import { atTime } from "./lifecycle.ts";

/** Packages one answer lists at most. Nobody has this many yet; the cap keeps one answer's reads bounded. */
export const MY_PACKAGES_LIMIT = 500;

/** Score lookups one answer runs at once. */
const SCORE_READS = 8;

/** A version waiting for the person's approval, with the link that approves it. */
export type PendingVersion = { id: string; version: string; url: string; expiresAt: string };

export type MyPackage = {
  name: string;
  /** The `latest` dist-tag's version (or the newest version when the tag is missing), as installs see it now; null before the first approval. */
  latest: { version: string; status: VersionStatus; publishedAt: string } | null;
  /** When any version of the package was last published; null before the first approval. */
  lastPublishedAt: string | null;
  /** The latest version's score as the registry reads it now; null when it has none (not scored yet, or never). */
  score: { score: number; grade: string } | null;
  pending: PendingVersion[];
};

const iso = (ms: number): string => new Date(ms).toISOString();

/** The version a package's row points installs at: its `latest` tag, else its newest version. */
function latestHead(distTags: Record<string, string>, heads: readonly VersionHead[]): VersionHead | null {
  return heads.find((h) => h.version === distTags.latest) ?? heads.at(-1) ?? null;
}

/** Waiting versions first (newest upload first), then the most recently published, then by name. */
function order(a: MyPackage, b: MyPackage): number {
  const waiting = Number(b.pending.length > 0) - Number(a.pending.length > 0);

  if (waiting !== 0) return waiting;

  return (b.lastPublishedAt ?? "").localeCompare(a.lastPublishedAt ?? "") || a.name.localeCompare(b.name);
}

export const packagesFor = (input: { user: string; webUrl: string }): Effect.Effect<MyPackage[], StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const now = yield* (yield* Clock).now;
    const [named, staged] = yield* Effect.all([store.packagesOf({ user: input.user, limit: MY_PACKAGES_LIMIT }), store.pendingFor(input.user, now)]);
    const pendingBy = new Map<string, StagedRecord[]>();

    for (const row of staged) pendingBy.set(row.package, [...(pendingBy.get(row.package) ?? []), row]);
    const names = [...new Set([...named, ...pendingBy.keys()])].slice(0, MY_PACKAGES_LIMIT);
    const local = yield* store.localHeadsOf(names);

    return (yield* Effect.forEach(
      names,
      (name) =>
        Effect.gen(function* () {
          const found = local.get(name);
          const heads = (found?.heads ?? []).map((h) => atTime(h, now));
          const head = found ? latestHead(found.pkg.distTags, heads) : null;
          const record = head ? yield* store.getVersion(name, head.version) : null;
          const compact = record ? compactScore(atTime(record, now), now) : null;
          const newest = heads.reduce<number | null>((max, h) => (max === null || h.published_at > max ? h.published_at : max), null);

          return {
            name,
            latest: head ? { version: head.version, status: head.status, publishedAt: iso(head.published_at) } : null,
            lastPublishedAt: newest === null ? null : iso(newest),
            score: compact ? { score: compact.score, grade: compact.grade } : null,
            pending: (pendingBy.get(name) ?? []).map((r) => ({ id: r.id, version: r.version, url: `${input.webUrl}approve/${r.id}`, expiresAt: iso(r.expires_at) })),
          } satisfies MyPackage;
        }),
      { concurrency: SCORE_READS },
    )).sort(order);
  });
