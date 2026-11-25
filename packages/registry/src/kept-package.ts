// What a package page needs of an upstream package, kept in Postgres (migration 0020) so a view reads one row instead of
// npm's whole packument (next: 26 MiB parsed, seconds). A summary holds npm's own data only: the dist-tags, the
// description, the readme, the maintainers, latest's repository and links, the newest versions with their checksums,
// and npm's ETag for the packument it was cut from. Scores, dismissals, reviews and a version's state are apm's and
// are read live on every view, so a new score or a dismissal shows at once. A package published on apm is never kept:
// its page reads its rows, so a revoke shows at once.
//
// A summary holds the newest KEPT_VERSIONS versions by version number (the package answer's list), the newest
// KEPT_VERSIONS by publish time and every dist-tag's target. A read it cannot answer exactly (an older version, the
// version before one past its publish-time window) reads npm as before.
//
// How old a summary may be, and when npm is asked:
//  - A summary younger than KEPT_PACKAGE_FRESH_MS is used as it is; one older is first checked against npm's ETag (a
//    GET with If-None-Match, the one validation resolve's kept choices use too: Upstream.listingIfChanged) and used
//    only when npm still sends the packument it was cut from. When it changed, npm's answer to that same request is
//    the packument, and the read is answered from it: npm is asked once, not for an ETag and then for the packument.
//    When it did not, the summary is marked worked out now after the response (KeptRefresh.touch), so the answer
//    does not also wait on that write.
//  - A page's read gets its kept row with the package row and the scores, in one statement (Store.pageRead, PageFirst).
//  - Every read that shows a version's source or offers it (its score's evidence, its files and readme, the review)
//    first asks npm for that version's document (a few KiB, kept for the TTL) and goes on from the summary only when
//    npm still lists the version with the same checksums. A version npm removed is never shown from a summary.
//  - When npm cannot be asked, or says anything else, the read goes to npm's packument as it did before summaries
//    were kept, so it answers as it did then.
//  - A summary older than KEPT_PACKAGE_REFRESH_MS that a view used is worked out again after the response
//    (KeptRefresh), one refresh per package at a time, and the cron's sweep refreshes the ones asked about in the last
//    day. A refresh is the same conditional read: a 304 only marks the summary worked out now.
//
// Only a package apm stored a score of gets a row, and one of the few the operator lists in KEPT_WITHOUT_SCORE once apm
// recorded it can never score a version of it (next: every recent tarball is over the 32 MiB analysis cap, so it has
// no score at all, and its packument is the largest a page reads, 31.5 MB). An outcome alone is not enough: anyone can
// have apm analyze any package, and a package made to be unscorable is easy to publish (review of e4f97b2). A row is
// at most KEPT_PACKAGE_MAX_BYTES of JSON, and the table holds at most KEPT_PACKAGE_CAPACITY.
import { Cause, Context, Effect, Exit, Option } from "effect";
import semver from "semver";
import { z } from "zod";
import { Clock } from "./clock.ts";
import { Store, type KeptPackageRow, type PageScores, type UpstreamAnalyses, type VersionRecord } from "./db.ts";
import { digestOf } from "./digest.ts";
import type { StoreError } from "./errors.ts";
import { RequestMemory, type Lease } from "./memory.ts";
import { newestFirst } from "./semver.ts";
import { scoredPackage, Upstream, upstreamBlobKey, wantedAnalyses, RECORD_WEIGHT, SCORED_WEIGHT, type CachedPackage, type Probe, type UpstreamApi, type UpstreamListing, type UpstreamPackage, type Wanted } from "./upstream.ts";
import { RECENT_SEED_MS } from "./analysis.ts";

/** Versions a summary keeps by version number, and again by publish time: the package answer lists the newest 200. */
export const KEPT_VERSIONS = 200;

/**
 * The most JSON one summary may be; a package whose summary is larger (a huge readme) is not kept. next's is 77 KiB and
 * react's 121 KiB, so a full table is about 100 MB and at most 256 MB.
 */
export const KEPT_PACKAGE_MAX_BYTES = 256 * 1024;

/** Rows kept_packages holds at most: anyone can name any package, so this bounds the table however many are asked about. */
export const KEPT_PACKAGE_CAPACITY = 1_000;

/** A summary younger than this is used without asking npm whether its packument changed; an older one is checked first. */
export const KEPT_PACKAGE_FRESH_MS = 5 * 60_000;

/** A summary this old is worked out again: after a view that used it, or by the sweep. */
export const KEPT_PACKAGE_REFRESH_MS = 3 * 60_000;

/**
 * How long the sweep waits after a refresh npm did not answer, doubled for each failure in a row, at most
 * KEPT_PACKAGE_RETRY_MAX_MS: longer than the sweep's 10 minutes, so a failed one sits out the next sweep at least.
 */
export const KEPT_PACKAGE_RETRY_MS = 15 * 60_000;

export const KEPT_PACKAGE_RETRY_MAX_MS = 6 * 60 * 60_000;

/** A refresh claimed this long ago that wrote nothing (the platform stopped it) may be claimed again. */
export const KEPT_PACKAGE_CLAIM_MS = 2 * 60_000;

/** The sweep refreshes the summaries asked about in this window and drops the ones nobody asked about for KEPT_PACKAGE_DROP_MS. */
export const KEPT_PACKAGE_ASKED_WINDOW_MS = 24 * 60 * 60_000;

export const KEPT_PACKAGE_DROP_MS = 7 * 24 * 60 * 60_000;

/** Summaries one sweep works out at most, one packument at a time. */
export const KEPT_PACKAGE_REFRESH_LIMIT = 24;

const KeptVersion = z.object({
  version: z.string(),
  seq: z.number().int(),
  publishedAt: z.number(),
  publishedBy: z.string(),
  deprecated: z.string().nullable(),
  integrity: z.string(),
  shasum: z.string(),
  tarball: z.string(),
});

/** latest's manifest fields the package answer reads (repositoryOf, linksOf), as npm wrote them. */
const LatestLinks = z.object({ repository: z.unknown().optional(), homepage: z.unknown().optional(), bugs: z.unknown().optional() });

export const KeptPackage = z.object({
  name: z.string(),
  distTags: z.record(z.string(), z.string()),
  description: z.string(),
  readme: z.string(),
  maintainers: z.array(z.string()),
  latest: LatestLinks,
  /** Every version npm lists published at or after this is kept; null when every version is. */
  completeSince: z.number().nullable(),
  /** npm's ETag for the packument this was cut from; null when npm sent none, so it can never be revalidated. */
  etag: z.string().nullable(),
  /** In publish order. */
  versions: z.array(KeptVersion),
  /** npm's record of the name, from every version it lists (upstream.ts); absent in a summary kept before this. */
  history: z.object({ first: z.number(), fifth: z.number().nullable() }).optional(),
});

export type KeptPackage = z.infer<typeof KeptPackage>;

/** What a summary is cut from: a package as npm lists it, with or without when it was fetched (a summary never reads that). */
type SummarySource = Omit<CachedPackage, "fetchedAt" | "readAt">;

/** The summary of a package as npm lists it now; null when its JSON is more than KEPT_PACKAGE_MAX_BYTES as UTF-8. */
/**
 * The versions a summary of `pkg` keeps, in publish order (pkg.versions is): the last KEPT_VERSIONS published, the newest
 * KEPT_VERSIONS by number and every one a dist-tag names; and the publish time from which it keeps every one (null when
 * it keeps them all).
 */
function keptVersionsOf<V extends Pick<VersionRecord, "version" | "published_at">>(pkg: { readonly distTags: Record<string, string>; readonly versions: readonly V[] }) {
  const all = pkg.versions;
  const cut = all.length > KEPT_VERSIONS ? (all[all.length - KEPT_VERSIONS]?.published_at ?? null) : null;
  const byNumber = new Set(all.map((v) => v.version).toSorted(newestFirst).slice(0, KEPT_VERSIONS));
  const tagged = new Set(Object.values(pkg.distTags));

  return { kept: all.filter((v) => cut === null || v.published_at >= cut || byNumber.has(v.version) || tagged.has(v.version)), cut };
}

export function summarize(pkg: SummarySource): KeptPackage | null {
  const all = pkg.versions;
  const { kept, cut } = keptVersionsOf(pkg);
  const latest = all.find((v) => v.version === pkg.distTags.latest);
  // every version carries the same record of the name, made from all of them, kept or not
  const history = all[0]?.history;

  const summary: KeptPackage = {
    name: pkg.name,
    distTags: pkg.distTags,
    description: pkg.description,
    readme: pkg.readme,
    maintainers: pkg.maintainers,
    latest: latest ? { repository: latest.manifest.repository, homepage: latest.manifest.homepage, bugs: latest.manifest.bugs } : {},
    completeSince: cut,
    etag: pkg.etag,
    versions: kept.map((v) => ({
      version: v.version,
      seq: v.seq,
      publishedAt: v.published_at,
      publishedBy: v.published_by,
      deprecated: v.deprecated,
      integrity: v.integrity,
      shasum: v.shasum,
      tarball: pkg.tarballs.get(v.version) ?? "",
    })),
  };

  if (history) summary.history = history;

  // bytes, not string length: a character outside ASCII is up to 3 bytes in UTF-8, and Postgres stores bytes
  return new TextEncoder().encode(JSON.stringify(summary)).byteLength > KEPT_PACKAGE_MAX_BYTES ? null : summary;
}

/** latest's manifest as the summary has it: only the fields it kept, and only those npm set. */
function latestManifest(links: z.infer<typeof LatestLinks>): VersionRecord["manifest"] {
  return Object.fromEntries(Object.entries(links).filter(([, v]) => v !== undefined));
}

/**
 * The summary as a cached package: only the versions it kept, each with no manifest but latest's links. Never served
 * as a packument (installs read every version from npm); only the page reads in this file use it.
 */
export function expand(kept: KeptPackage): CachedPackage {
  const versions = kept.versions.map((v): Omit<VersionRecord, "score"> => {
    const digest = digestOf(v);
    const history = kept.history ? { history: kept.history } : {};

    return {
      ...history,
      package: kept.name,
      version: v.version,
      manifest: v.version === kept.distTags.latest ? latestManifest(kept.latest) : {},
      shasum: v.shasum,
      integrity: v.integrity,
      size: 0,
      tarball_key: digest ? upstreamBlobKey(digest) : "",
      published_at: v.publishedAt,
      seq: v.seq,
      published_by: v.publishedBy,
      deprecated: v.deprecated,
      status: "active",
      status_reason: null,
      status_at: null,
      status_by: null,
    };
  });

  return {
    name: kept.name,
    distTags: kept.distTags,
    description: kept.description,
    readme: kept.readme,
    maintainers: kept.maintainers,
    versions,
    tarballs: new Map(kept.versions.filter((v) => v.tarball !== "").map((v) => [v.version, v.tarball])),
    serveCost: { versionDocs: 0, maxPieceChars: 0 },
    etag: kept.etag,
    // not a fetch from npm: a resolve's kept choice is never made young from a summary (kept-choices.ts), nor an
    // install copy (upstream.ts, installCopy)
    fetchedAt: Number.NEGATIVE_INFINITY,
    readAt: Number.NEGATIVE_INFINITY,
  };
}

/**
 * What a page read needs of the package. "page": the package answer (latest and the newest versions). "version": one
 * version, named exactly. "spec": a version or a dist-tag, an exact version first (the review answer). "history": the
 * version a dist-tag names, else the version named (latest when none is), and the one published before it (the score
 * answer's previous version).
 */
export type PageNeed = { kind: "page" } | { kind: "version"; version: string } | { kind: "spec"; spec: string } | { kind: "history"; spec: string | undefined };

type KeptVersion = z.infer<typeof KeptVersion>;

/** The dist-tag's target, own keys only. */
const tagOf = (kept: { readonly distTags: Record<string, string> }, tag: string): string | undefined => (Object.hasOwn(kept.distTags, tag) ? kept.distTags[tag] : undefined);

/**
 * The version `need` names in `kept`, resolved as its route resolves it: latest for the package answer, an exact version
 * first for the review answer, a dist-tag first for the score answer. Undefined when the summary does not hold it.
 */
function versionAsked<V extends { readonly version: string }>(kept: { readonly distTags: Record<string, string>; readonly versions: readonly V[] }, need: PageNeed): V | undefined {
  const has = (version: string | undefined) => (version === undefined ? undefined : kept.versions.find((v) => v.version === version));

  switch (need.kind) {
    case "page":
      return has(tagOf(kept, "latest"));
    case "version":
      return has(need.version);
    case "spec":
      // npm's versions are all valid semver and its tags never are, so a spec that is not a version is a tag
      return has(need.spec) ?? (semver.valid(need.spec) === null ? has(tagOf(kept, need.spec)) : undefined);
    case "history":
      return has(need.spec === undefined ? tagOf(kept, "latest") : (tagOf(kept, need.spec) ?? need.spec));
    default: {
      const _exhaustive: never = need;

      return _exhaustive;
    }
  }
}

/** The version published before `v` among `versions` (publish order), revoked ones left out: the score answer's previous version. */
export function previousVersion<V extends Pick<VersionRecord, "version" | "published_at" | "status">>(versions: readonly V[], v: V): V | null {
  const all = versions.filter((x) => x.version !== v.version && x.published_at <= v.published_at && x.status !== "revoked");

  return all[all.length - 1] ?? null;
}

/**
 * The analyses a page's read of `need` at `at` reads of an upstream package (Upstream.probe's wanted). Whole: the version it
 * shows (versionAsked), latest, and for the score answer the one before it (previousVersion). Trimmed, for their score
 * and grade and whether they have one: the versions a summary of it keeps (summarize; the package answer lists the
 * newest KEPT_VERSIONS, and keepAnalyzed admits a summary by them), and the ones published in the last RECENT_SEED_MS
 * (versionsToSeed). None of the rest of its history.
 */
export const pageWanted =
  (need: PageNeed, at: number): Wanted =>
  (pkg) => {
    const want = new Map<string, "whole" | "trimmed">();

    for (const v of keptVersionsOf(pkg).kept) want.set(v.version, "trimmed");

    for (const v of pkg.versions) if (v.published_at >= at - RECENT_SEED_MS) want.set(v.version, "trimmed");
    const shown = versionAsked(pkg, need);
    const previous = shown !== undefined && need.kind === "history" ? previousVersion(pkg.versions, shown) : null;

    for (const v of [shown?.version, tagOf(pkg, "latest"), previous?.version]) if (v !== undefined) want.set(v, "whole");

    return want;
  };

/** Whether `kept` answers `need` exactly as the whole packument would. */
export function covers(kept: KeptPackage, need: PageNeed): boolean {
  const v = versionAsked(kept, need);

  switch (need.kind) {
    case "page":
      return true;
    case "version":
      return v !== undefined;
    case "spec":
      // a spec the summary does not hold is one only npm's packument can say anything about, unless it holds every version
      return v !== undefined || kept.completeSince === null;
    case "history":
      // every version published at or after completeSince is kept, so the one before a later one is kept too
      return v !== undefined && (kept.completeSince === null || v.publishedAt > kept.completeSince);
    default: {
      const _exhaustive: never = need;

      return _exhaustive;
    }
  }
}

/** A kept row as a summary; null when there is none, or what is stored does not parse (it is then worked out again). */
function parseKept(name: string, row: KeptPackageRow | null): Kept | null {
  if (row === null) return null;
  const parsed = KeptPackage.safeParse(row.summary);

  return parsed.success && parsed.data.name === name ? { kept: parsed.data, computedAt: row.computedAt } : null;
}

/** keptPackage's row for `name`, as a summary (parseKept). */
const keptRow = (name: string, at: number) => Effect.map(Effect.flatMap(Store, (s) => s.keptPackage({ name, at })), (row) => parseKept(name, row));

/**
 * What a page read has of an upstream package before it looks at its summary: "read" when its kept row (null: none)
 * and its scores came with the package row (Store.pageRead, one round trip), "unread" when this file reads them.
 */
export type PageFirst = { kind: "read"; kept: KeptPackageRow | null; analyses: UpstreamAnalyses; whole: ReadonlySet<string> } | { kind: "unread" };

/**
 * Which stored analyses a page's read of `need` asks Store.pageRead for whole: the one of the version it shows (resolved
 * as versionAsked resolves it, the dist-tags from the kept summary). The other versions' are read only for their score
 * and grade, without PAGE_TRIMMED's members.
 */
export function pageScores(need: PageNeed): PageScores {
  switch (need.kind) {
    case "page":
      return { kind: "shown", versions: [], tags: ["latest"] };
    case "version":
      return { kind: "shown", versions: [need.version], tags: [] };
    case "spec":
      return { kind: "shown", versions: [need.spec], tags: [need.spec] };
    case "history":
      return need.spec === undefined ? { kind: "shown", versions: [], tags: ["latest"] } : { kind: "shown", versions: [need.spec], tags: [need.spec] };
    default: {
      const _exhaustive: never = need;

      return _exhaustive;
    }
  }
}

/** The kept row `first` brought, or keptRow's. */
const firstRow = (name: string, at: number, first: PageFirst) => (first.kind === "read" ? Effect.succeed(parseKept(name, first.kept)) : keptRow(name, at));

/**
 * The scores `first` brought when they hold the analysis of `shown` whole (pageScores), else the ones `wanted` names of
 * `pkg`: a read whose shown version came without PAGE_TRIMMED's members reads it again, whole, rather than show it so.
 */
const firstAnalyses = (input: { name: string; first: PageFirst; shown: string; pkg: CachedPackage; wanted: Wanted }) =>
  input.first.kind === "read" && input.first.whole.has(input.shown) ? Effect.succeed(input.first.analyses) : Effect.flatMap(Store, (s) => wantedAnalyses(s, input.name, input.pkg.versions, input.wanted(input.pkg)));

/** What a request holds of an expanded summary: each version's record and its scored copy. */
const expandWeight = (kept: KeptPackage): number => kept.versions.length * (RECORD_WEIGHT + SCORED_WEIGHT);

/** A name the operator lets in without a score: exactly this name, or every name that starts with this prefix. */
export type KeptEligible = { kind: "exact"; name: string } | { kind: "prefix"; prefix: string };

/**
 * Packages kept with no score, once apm recorded it can never score one of their versions: popular, large, and chosen
 * here, by whoever deploys, so a visitor cannot fill the table by naming packages apm will find unscorable. next and its
 * native binaries (next 16.4.6 is 43.7 MB, @next/swc-linux-x64-gnu 35 MB). apm-score-v11 reads tarballs past what a
 * Worker holds as a stream and scores them, so these are admitted by their scores like any package; the list is the
 * fallback for a version v11 still cannot score (a tarball past what it streams, one it cannot read, or a run past the
 * registry's limits). An apm-score-v10 too-large outcome no longer counts: v11 reads that version again (db.ts,
 * apm_v10_outcome_reusable), and until it has, such a package is admitted only by another outcome or a score. Chosen
 * over a weekly-downloads floor read from npm: that is one more request to npm on the read that admits, a failure mode
 * of its own, and a number paid download traffic can move; this list needs none of them, and the one package measured
 * slow is on it.
 */
export const KEPT_WITHOUT_SCORE: readonly KeptEligible[] = [
  { kind: "exact", name: "next" },
  { kind: "prefix", prefix: "@next/swc-" },
];

/** Whether `name` is on `list` (KEPT_WITHOUT_SCORE). */
export function keptWithoutScore(name: string, list: readonly KeptEligible[] = KEPT_WITHOUT_SCORE): boolean {
  return list.some((e) => {
    switch (e.kind) {
      case "exact":
        return name === e.name;
      case "prefix":
        return name.startsWith(e.prefix);
      default: {
        const _exhaustive: never = e;

        return _exhaustive;
      }
    }
  });
}

/**
 * The admission rule: apm stored a score of one of `pkg`'s versions, or `pkg` is on KEPT_WITHOUT_SCORE and apm recorded
 * it can never score one. Names apm never scored, and unscorable ones nobody chose, cost no row.
 */
export const admitted = (pkg: UpstreamPackage): boolean =>
  pkg.versions.some((v) => v.score !== null) || (keptWithoutScore(pkg.name) && pkg.versions.some((v) => v.unscorable !== undefined));

/** Keeps `pkg`'s summary when it is admitted (admitted). Its summary is replaced when it is kept already. */
const keepAnalyzed = (pkg: SummarySource, admit: boolean, at: number) =>
  Effect.gen(function* () {
    if (!admit) return;
    const summary = summarize(pkg);

    if (summary !== null) yield* (yield* Store).keepPackage({ name: pkg.name, summary, at, capacity: KEPT_PACKAGE_CAPACITY });
  });

type Kept = { kept: KeptPackage; computedAt: number };

/** What marks a summary worked out at `at`: npm said the packument with this ETag is still the one it was cut from. */
export type KeptTouch = { name: string; at: number; etag: string };

/**
 * Work on kept summaries after the response, on its own connection and memory lease (worker.ts): `later` works one out
 * again, `touch` marks one worked out now (Store.touchKeptPackage) once npm said it had not changed, so the answer
 * that asked npm does not also wait on that write. Absent outside a Worker request (the sweep, the queue, unit
 * tests): their summaries wait for the sweep, and a touch is written in place.
 */
export class KeptRefresh extends Context.Service<
  KeptRefresh,
  { readonly later: (name: string) => Effect.Effect<void>; readonly touch: (input: KeptTouch) => Effect.Effect<void> }
>()("@apm/registry/KeptRefresh") {}

/**
 * Marks a summary worked out now, after the response when a request can (KeptRefresh), else in place. A later write is
 * harmless: until it lands, another view checks npm again, and the write only moves that summary's time forward.
 */
const touchSoon = (input: KeptTouch) =>
  Effect.gen(function* () {
    const refresh = yield* Effect.serviceOption(KeptRefresh);

    if (Option.isSome(refresh)) return yield* refresh.value.touch(input);

    yield* (yield* Store).touchKeptPackage(input);
  });

/** When this isolate last handed each name to KeptRefresh, so a burst of views of one package starts one refresh. */
const handedOff = new Map<string, number>();

/** A refresh after the response when the summary a view used is older than KEPT_PACKAGE_REFRESH_MS. */
const refreshIfOld = (name: string, row: Kept, at: number) =>
  Effect.gen(function* () {
    if (at - row.computedAt < KEPT_PACKAGE_REFRESH_MS) return;
    const refresh = yield* Effect.serviceOption(KeptRefresh);
    const wall = Date.now();

    if (Option.isNone(refresh) || wall - (handedOff.get(name) ?? Number.NEGATIVE_INFINITY) < KEPT_PACKAGE_CLAIM_MS) return;

    if (handedOff.size >= KEPT_PACKAGE_CAPACITY) handedOff.clear();
    handedOff.set(name, wall);
    yield* refresh.value.later(name);
  });

/**
 * What a stale row's check got from npm when npm sent more than a 304: the package as npm lists it now (held under a
 * child of the read's lease), that npm has no such package, or that npm could not be asked, after the check already
 * read the packument whole as its fallback (Upstream.listingIfChanged). The caller answers from it instead of asking
 * npm again: on an outage, one conditional read and one whole read, then one whole read while the package's failure
 * mark lasts, as with the HEAD before (combined review of 67d8658, finding 2).
 */
type Fetched = UpstreamListing;

/**
 * The kept row for `name` while npm still sends the packument it was cut from: as it is when younger than
 * KEPT_PACKAGE_FRESH_MS, else once npm says the packument did not change (the row is then marked worked out now).
 * That check is one conditional read (Upstream.listingIfChanged): npm's 304, or the packument itself when it changed,
 * which comes back as `fetched`. "stale" when a row is there but npm changed the packument, has no such package (the
 * row is then dropped) or could not be asked (`fetched` says so: the check already tried the whole packument); a row
 * with no ETag can never be checked, so npm is not asked for it and `fetched` is null: the caller reads npm as before
 * summaries were kept. "none" when there is no row.
 */
type Current = { kind: "current"; row: Kept } | { kind: "stale"; fetched: Fetched | null } | { kind: "none" };

const currentRow = (input: { upstream: UpstreamApi; name: string; at: number; lease: Lease; first: PageFirst }) =>
  Effect.gen(function* () {
    const { upstream, name, at } = input;
    const store = yield* Store;
    const row = yield* firstRow(name, at, input.first);

    if (row === null) return { kind: "none" } satisfies Current;

    if (at - row.computedAt < KEPT_PACKAGE_FRESH_MS) {
      yield* refreshIfOld(name, row, at);

      return { kind: "current", row } satisfies Current;
    }

    const etag = row.kept.etag;

    if (etag === null) return { kind: "stale", fetched: null } satisfies Current;
    // a child, given back unless what npm sent is the answer
    const read = input.lease.child();
    const now = yield* upstream.listingIfChanged(name, read, etag);
    const same = now.kind === "not-modified" || (now.kind === "found" && now.pkg.etag === etag);

    if (same || now.kind !== "found") read.release();

    // Accepted (combined review of 67d8658): a package the isolate cache already holds with the summary's ETag counts
    // as unchanged without asking npm, so a package page's npm metadata may be up to the isolate cache's TTL (60 s)
    // older than KEPT_PACKAGE_FRESH_MS; every read that shows a version's source still confirms it (stillListed).
    if (same) {
      // npm's metadata only: apm's scores, dismissals and version states are read live either way
      yield* touchSoon({ name, at, etag });

      return { kind: "current", row: { kept: row.kept, computedAt: at } } satisfies Current;
    }

    switch (now.kind) {
      case "found":
        return { kind: "stale", fetched: now } satisfies Current;
      case "absent":
        yield* store.dropKeptPackages({ kind: "name", name });

        return { kind: "stale", fetched: now } satisfies Current;
      case "unknown":
      case "over-budget":
        // npm was asked (and the packument read whole as the fallback) or the request had no room: not asked again
        return { kind: "stale", fetched: { kind: "unknown" } } satisfies Current;
      default: {
        const _exhaustive: never = now;

        return _exhaustive;
      }
    }
  });

/**
 * Whether npm still lists `v` exactly as the summary has it: the same tarball URL, integrity and shasum in its version
 * document (not its packument). Any difference, a missing field included, is a no.
 */
const stillListed = (upstream: UpstreamApi, name: string, v: KeptVersion) =>
  Effect.map(upstream.versionOf(name, v.version), (now) => now.kind === "found" && now.tarball === v.tarball && now.integrity === v.integrity && now.shasum === v.shasum);

/** The version published before `v` as previousOf in apm.ts picks it from the summary: the last at or before it in publish order. */
function previousKept(kept: KeptPackage, v: KeptVersion): KeptVersion | undefined {
  return kept.versions.filter((x) => x.version !== v.version && x.publishedAt <= v.publishedAt).at(-1);
}

/**
 * Every version a read of `need` would show or offer from `kept`: the one it names, and for the score answer the
 * previous version it compares with. Null when the read cannot name the exact version (no latest tag, a version the
 * summary does not hold): such a read is never answered from a summary.
 */
function versionsShown(kept: KeptPackage, need: PageNeed): KeptVersion[] | null {
  const v = versionAsked(kept, need);

  if (v === undefined) return null;
  const prev = need.kind === "history" ? previousKept(kept, v) : undefined;

  return prev === undefined ? [v] : [v, prev];
}

/** What keptFor found: a summary to answer from, or none, and whether a row was there (one a fallback should refresh). */
type KeptAnswer = { kept: KeptPackage | null; hadRow: boolean; fetched: Fetched | null };

/**
 * The kept summary a page's read of `need` may be answered from: current (currentRow), holding what `need` asks for,
 * naming the exact versions it would show, and with npm still listing each of them as the summary has it. A null
 * summary sends the read to npm's packument.
 */
const keptFor = (input: { upstream: UpstreamApi; name: string; need: PageNeed; lease: Lease; first: PageFirst }) =>
  Effect.gen(function* () {
    const { upstream, name, need, lease, first } = input;
    const at = yield* (yield* Clock).now;
    const current = yield* currentRow({ upstream, name, at, lease, first });

    if (current.kind === "none") return { kept: null, hadRow: false, fetched: null } satisfies KeptAnswer;

    if (current.kind === "stale") return { kept: null, hadRow: true, fetched: current.fetched } satisfies KeptAnswer;
    const { row } = current;
    const shown = covers(row.kept, need) ? versionsShown(row.kept, need) : null;

    if (shown === null) return { kept: null, hadRow: true, fetched: null } satisfies KeptAnswer;
    const listed = yield* Effect.forEach(shown, (v) => stillListed(upstream, name, v), { concurrency: "unbounded" });

    return { kept: listed.every(Boolean) ? row.kept : null, hadRow: true, fetched: null } satisfies KeptAnswer;
  });

/**
 * Replaces a kept row with the summary of `pkg`, read from npm after the row could not answer: the next read uses it.
 * Only a row already kept is replaced, so admission and the table's capacity hold; one too large is dropped.
 */
const refreshFrom = (pkg: SummarySource) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const at = yield* (yield* Clock).now;
    const summary = summarize(pkg);

    if (summary === null) yield* store.dropKeptPackages({ kind: "name", name: pkg.name });
    else yield* store.refreshKeptPackage({ name: pkg.name, summary, at });
  });

/**
 * An upstream package for a page's read, with its scores: from the kept summary when keptFor allows it, else from
 * npm (Upstream.probe) as before summaries were kept, whose answer is then kept.
 */
export const pageProbe = (input: { upstream: UpstreamApi; name: string; need: PageNeed; lease: Lease; first: PageFirst }): Effect.Effect<Probe, StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const { upstream, name, lease, first } = input;
    const store = yield* Store;
    const wanted = pageWanted(input.need, yield* (yield* Clock).now);
    const { kept, fetched } = yield* keptFor(input);

    // the scores read with the row (pageRead) or now: either way after the request began, so a score or a dismissal
    // committed before it is in them. keptFor answers only when the summary holds the version the read shows
    const shown = kept === null ? undefined : versionAsked(kept, input.need);

    if (kept !== null && shown !== undefined) {
      if (!lease.take(expandWeight(kept))) return { kind: "unknown" } satisfies Probe;

      const pkg = expand(kept);

      return scoredPackage(pkg, yield* firstAnalyses({ name, first, shown: shown.version, pkg, wanted }));
    }

    // npm's packument was read instead, which can take seconds: the scores are read again after it, as before
    // summaries were kept. What the row's check already read from npm is the answer: npm is not asked again
    const probe: Probe = fetched === null ? yield* upstream.probeFor(name, wanted, lease) : fetched.kind === "found" ? scoredPackage(fetched.pkg, yield* wantedAnalyses(store, name, fetched.pkg.versions, wanted(fetched.pkg))) : fetched;

    // a kept row is replaced with what npm sent (keepAnalyzed replaces as well as adds)
    if (probe.kind === "found") yield* keepAnalyzed(probe.pkg, admitted(probe.pkg), yield* (yield* Clock).now);

    if (probe.kind === "absent") yield* store.dropKeptPackages({ kind: "name", name });

    return probe;
  });

/** Like pageProbe, without the scores (the review answer reads none): the kept summary, else Upstream.listing. */
export const pageListing = (input: { upstream: UpstreamApi; name: string; need: PageNeed; lease: Lease; first: PageFirst }): Effect.Effect<UpstreamListing, StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const { name, lease } = input;
    const { kept, hadRow, fetched } = yield* keptFor(input);

    if (kept !== null) return lease.take(expandWeight(kept)) ? { kind: "found", pkg: expand(kept) } : { kind: "unknown" };
    // what the row's check already read from npm is the answer: npm is not asked again
    const listed: UpstreamListing = fetched ?? (yield* input.upstream.listing(name, lease));

    yield* afterListing(name, listed, hadRow);

    return listed;
  });

/** After a read went to npm because a kept row could not answer: the row is replaced with what npm sent, or dropped. */
const afterListing = (name: string, listed: UpstreamListing, hadRow: boolean) =>
  Effect.gen(function* () {
    if (!hadRow) return;

    if (listed.kind === "found") yield* refreshFrom(listed.pkg);

    if (listed.kind === "absent") yield* (yield* Store).dropKeptPackages({ kind: "name", name });
  });

/**
 * HEAD /-/apm/v1/packages/<name> for an upstream package: whether npm has it, from a current kept row (currentRow),
 * else from npm's listing as before summaries were kept. A row that could not answer is replaced with that listing (or
 * dropped when npm has no such package), so the next HEAD is answered from the row again instead of asking npm.
 *
 * Accepted (re-check of 1cbdc6c, finding 4): a row younger than KEPT_PACKAGE_FRESH_MS answers yes without asking npm,
 * so for up to five minutes after npm removes the whole package this says it exists. It only decides whether the page
 * renders: the page's version list may be five minutes stale anyway, and every read that shows or offers a version's
 * source confirms that version with npm first (keptFor), so nothing of the removed package is shown.
 */
export const pageExists = (input: { upstream: UpstreamApi; name: string; lease: Lease }): Effect.Effect<UpstreamListing["kind"], StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const { upstream, name, lease } = input;
    const at = yield* (yield* Clock).now;

    const current = yield* currentRow({ upstream, name, at, lease, first: { kind: "unread" } });

    if (current.kind === "current") return "found";
    const listed: UpstreamListing = (current.kind === "stale" ? current.fetched : null) ?? (yield* upstream.listing(name, lease));

    yield* afterListing(name, listed, current.kind === "stale");

    return listed.kind;
  });

/**
 * Works one kept summary out again from npm when it is older than KEPT_PACKAGE_REFRESH_MS and no other refresh claimed
 * it: the sweep's and a view's refresh. When npm's ETag is the summary's, it is only marked worked out now. A name now published on apm, or one npm no longer has, is dropped; one npm did
 * not answer for keeps its summary. True when it was refreshed or dropped.
 */
export const refreshKeptPackage = (name: string): Effect.Effect<boolean, StoreError, Store | Clock | RequestMemory> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const found = yield* Effect.serviceOption(Upstream);
    const at = yield* (yield* Clock).now;

    if (Option.isNone(found)) return false;

    if (yield* store.getPackage(name)) {
      yield* store.dropKeptPackages({ kind: "name", name });

      return true;
    }

    const claim = yield* store.claimKeptRefresh({ name, at, computedBefore: at - KEPT_PACKAGE_REFRESH_MS, claimedBefore: at - KEPT_PACKAGE_CLAIM_MS });

    if (claim === null) return false;
    // under a child lease, given back once the summary is cut from the package. One conditional read: npm's 304 when
    // the packument is still the one the summary was cut from, else that packument from the same answer
    const lease = (yield* RequestMemory).child();
    const etag = claim.etag;

    const listed = yield* found.value.listingIfChanged(name, lease, etag).pipe(
      Effect.map((l) => {
        switch (l.kind) {
          case "not-modified":
            // npm answers 304 only to the ETag it was sent, so there is one here
            return etag === null ? { kind: "unknown" as const } : { kind: "same" as const, etag };
          case "found":
            return etag !== null && l.pkg.etag === etag ? { kind: "same" as const, etag } : { kind: "found" as const, summary: summarize(l.pkg) };
          case "over-budget":
            return { kind: "unknown" as const };
          case "absent":
          case "unknown":
            return l;
          default: {
            const _exhaustive: never = l;

            return _exhaustive;
          }
        }
      }),
      Effect.ensuring(Effect.sync(() => lease.release())),
    );

    switch (listed.kind) {
      case "same":
        yield* store.touchKeptPackage({ name, at, etag: listed.etag });

        return true;
      case "found":
        if (listed.summary === null) yield* store.dropKeptPackages({ kind: "name", name });
        else yield* store.refreshKeptPackage({ name, summary: listed.summary, at });

        return true;
      case "absent":
        yield* store.dropKeptPackages({ kind: "name", name });

        return true;
      case "unknown":
        // the sweep moves on to other summaries until this one is due again
        yield* store.failKeptRefresh({ name, at, retryMs: KEPT_PACKAGE_RETRY_MS, maxRetryMs: KEPT_PACKAGE_RETRY_MAX_MS });

        return false;
      default: {
        const _exhaustive: never = listed;

        return _exhaustive;
      }
    }
  });

/** refreshKeptPackage, with a failure logged instead of failing. */
export const runRefresh = (name: string): Effect.Effect<boolean, never, Store | Clock | RequestMemory> =>
  refreshKeptPackage(name).pipe(
    Effect.exit,
    Effect.map((exit) => {
      if (Exit.isSuccess(exit)) return exit.value;
      console.error(JSON.stringify({ level: "error", event: "kept-package-refresh", name, error: Cause.pretty(exit.cause) }));

      return false;
    }),
  );

/**
 * The cron's part: drops summaries nobody asked about for a week, then works out again the ones asked about in the last
 * day that are older than KEPT_PACKAGE_REFRESH_MS, oldest first and one at a time, skipping ones whose last refresh
 * failed until their retry is due. Returns how many it refreshed.
 */
export const refreshKeptPackages = Effect.gen(function* () {
  const store = yield* Store;
  const at = yield* (yield* Clock).now;

  yield* store.dropKeptPackages({ kind: "asked-before", askedBefore: at - KEPT_PACKAGE_DROP_MS });
  const names = yield* store.keptPackagesToRefresh({ askedSince: at - KEPT_PACKAGE_ASKED_WINDOW_MS, computedBefore: at - KEPT_PACKAGE_REFRESH_MS, at, limit: KEPT_PACKAGE_REFRESH_LIMIT });
  const refreshed = yield* Effect.forEach(names, (name) => runRefresh(name), { concurrency: 1 });

  return refreshed.filter(Boolean).length;
});
