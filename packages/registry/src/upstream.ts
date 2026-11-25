// Read-only proxy of a public registry (registry.npmjs.org in production). Packuments are fetched on demand
// and rewritten so tarballs flow through apm, where they are verified, cached in R2 and scored.
import { Context, Duration, Effect, Exit, Layer, Option } from "effect";
import { z } from "zod";
import { nameHistoryOf } from "@apm/core";
import { Blobs } from "./blobs.ts";
import { CACHE_FIRST_BYTE_MS, CACHE_IDLE_MS, DeadlinePassed, firstChunkWithin, logStall, matchWithin, R2_PUT_MS, within } from "./deadline.ts";
import { digestLabel, digestOf, type Digest } from "./digest.ts";
import { upstreamPuts, type PendingPuts } from "./pending-puts.ts";
import { Store, type AnalysisKey, type KeptChoicesRow, type StoreApi, type UpstreamAnalyses, type VersionRecord } from "./db.ts";
import type { BlobError, StoreError } from "./errors.ts";
import { ReleaseHooks } from "./hooks.ts";
import { readCapped, streamedJson, streamWeight, type StreamOptions } from "./http.ts";
import { CACHE_WEIGHT, RequestMemory, type Block, type Lease, type MemoryPool } from "./memory.ts";
import { DEV_DEPENDENCIES, readPackument, TRIMMED, type KeepProfile, type KeptPackument, type PackumentRead } from "./packument-read.ts";
import { timingOrNull } from "./timing.ts";
import { verifiedStream } from "./verified-stream.ts";
import { NO_RECORDED_PUBLISHER } from "./publishers.ts";
import { ChoicesWriter, choiceHolds, isStrongEtag, KEPT_CHOICES_MAX_AGE_MS, KEPT_TEXT_WEIGHTS, keepPlans, KeptSide, keptPlan, keptRowsWithin, type Choice, type Chosen, type HeldRow, type PlanHandle } from "./kept-choices.ts";
import { Clock } from "./clock.ts";
import { keptHead, keptVersion, parsedWeight, reviewSummary, type Reserve, type Summary } from "./walk-catalog.ts";
import { createHash } from "node:crypto";

const Dist = z.object({ tarball: z.string(), shasum: z.string().optional(), integrity: z.string().optional() }).loose();

// Real packuments carry `deprecated: false` and other odd shapes on old versions (react does),
// so the field is read loosely and one malformed version is skipped, not fatal to the package.
const UpVersion = z
  .object({ name: z.string(), version: z.string(), dist: Dist, deprecated: z.unknown().optional(), _npmUser: z.object({ name: z.string() }).loose().optional() })
  .loose();

const UpPackument = z
  .object({
    name: z.string(),
    "dist-tags": z.record(z.string(), z.string()).default({}),
    versions: z.record(z.string(), z.unknown()).default({}),
    // a package whose every version was unpublished is a 200 from npm whose `time.unpublished` is an object
    // ({ time, versions }): an entry that is not a string reads as "" (no time) instead of refusing the whole
    // packument, which answered 503 "try again shortly" for a name npm answers
    time: z.record(z.string(), z.string().catch("")).default({}),
    description: z.string().optional(),
    readme: z.string().optional(),
    maintainers: z.array(z.object({ name: z.string() }).loose()).optional(),
  })
  .loose();

/** What the DEV_DEPENDENCIES read keeps: `versions`, each with at most its devDependencies (read as they are). */
const DevDependencies = z.object({ versions: z.record(z.string(), z.unknown()).default({}) });

const DevDocument = z.object({ devDependencies: z.unknown().optional() });

/**
 * What serving a package read from npm holds beside it, from the read (PackumentRead): `versionDocs`, what a shallow
 * copy of every version document weighs; `maxPieceChars`, the longest member of its packument as JSON.
 */
export type ServeCost = { readonly versionDocs: number; readonly maxPieceChars: number };

export type UpstreamPackage = {
  name: string;
  distTags: Record<string, string>;
  description: string;
  readme: string;
  maintainers: string[];
  versions: VersionRecord[];
  /** original tarball URL per version */
  tarballs: Map<string, string>;
  serveCost: ServeCost;
  /** npm's ETag for the packument this was read from; null when npm sent none, or it was not read from npm. */
  etag: string | null;
};

/** "unknown" means the upstream could not be asked; it is never treated as "absent". */
export type Probe = { kind: "found"; pkg: UpstreamPackage } | { kind: "absent" } | { kind: "unknown" };

/**
 * A probe made under a request's lease (memory.ts): "over-budget" when the request already holds as much package
 * metadata as it may, or the isolate does, so this one was not read (or not kept). Not the same as "unknown": npm may
 * well have answered.
 */
export type BudgetedProbe = Probe | { kind: "over-budget" };

/**
 * probeWithinFor's answer: a BudgetedProbe, or "unread": npm's listing read and kept, its analyses not, as they did not
 * fit (every version reads unscored, and a reader takes each as not checked, never as one with no score).
 */
export type ListedProbe = BudgetedProbe | { kind: "unread"; pkg: UpstreamPackage };

/** A summaries answer for one name: BudgetedProbe, with what the caller kept in place of the package. */
export type Summarized<S> = { kind: "found"; summary: S } | { kind: "absent" } | { kind: "unknown" } | { kind: "over-budget" };

/**
 * What Upstream.chosen answers for a package: a summary's answer, "out-of-time" when its deadline came first, or
 * "unread": kept, but with none of its analyses, which did not fit the request (every version reads unscored, and a
 * reader must take each as not checked, never as one with no score).
 */
export type ChosenAnswer<S> = Summarized<S> | { kind: "out-of-time" } | { kind: "unread"; summary: S };

/**
 * What Upstream.chosen holds of a package between reading it and keeping it: the versions each choice took, cut down
 * (summaryVersion) and unscored, their weight taken from the lease, and the kept row to plan once they are kept.
 */
type Picked = { readonly name: string; readonly distTags: Record<string, string>; readonly versions: ReadonlyMap<string, readonly VersionRecord[]>; readonly weight: number; readonly plan: { readonly etag: string; readonly at: number } | null };

/** A package as Upstream.chosen reads it: picked from, or the answer it came to instead. */
type Picking = { kind: "picked"; picked: Picked } | { kind: "absent" } | { kind: "unknown" } | { kind: "over-budget" } | { kind: "out-of-time" };

// One object of the upstream's /-/v1/search answer. Read loosely: extra fields (downloads, flags, links)
// pass through untouched so the merged answer keeps npm's wire format.
const UpSearchObject = z
  .object({
    package: z.object({ name: z.string(), version: z.string(), description: z.string().nullish(), date: z.string().nullish() }).loose(),
  })
  .loose();

export type UpSearchObject = z.infer<typeof UpSearchObject>;

const UpSearch = z.object({ objects: z.array(z.unknown()), total: z.number().optional() }).loose();

export type UpstreamSearch = { kind: "ok"; objects: UpSearchObject[]; total: number } | { kind: "unavailable" };

/** The checksum the upstream publishes for a tarball: sha512 when it has one, else the legacy sha1. */
export { digestLabel, digestOf, type Digest } from "./digest.ts";

/** The blob key a verified upstream tarball is cached under: the same content address local tarballs use. */
export function upstreamBlobKey(d: Digest): string {
  return d.algo === "sha512" ? `sha512/${d.hex}` : `sha1/${d.hex}`;
}

function matches(bytes: Uint8Array, d: Digest): boolean {
  return createHash(d.algo).update(bytes).digest("hex") === d.hex;
}

/**
 * The largest upstream tarball apm downloads whole. A Worker has 128 MB of memory, and analysis inflates the tarball
 * next to it; a larger one is served as a stream (verified-stream.ts) and analysed as one (streamed-analysis.ts).
 */
export const MAX_UPSTREAM_TARBALL_BYTES = 32 * 1024 * 1024;

/**
 * "absent": the upstream does not list that version (now). "too-large": the tarball is over
 * MAX_UPSTREAM_TARBALL_BYTES; `bytes` is the size the upstream declared, null when it declared none and the download
 * passed the cap. "unavailable": apm could not get verified bytes; `retryable` when asking again later may work (a
 * network error, a 5xx, a 429, bytes that failed their checksum), not when it cannot (no checksum, a URL apm will not
 * fetch).
 */
export type UpstreamTarball =
  | { kind: "ok"; bytes: Uint8Array; digest: Digest }
  | { kind: "absent" }
  | { kind: "too-large"; bytes: number | null }
  | { kind: "unavailable"; reason: string; retryable: boolean };

/** "a 43.7 MB tarball" or "a tarball", for a refusal that names the size when it is known. */
export function tooLargeText(bytes: number | null): string {
  return `the tarball${bytes === null ? "" : ` (${(bytes / 1_000_000).toFixed(1)} MB)`} is larger than the ${MAX_UPSTREAM_TARBALL_BYTES / (1024 * 1024)} MiB apm downloads`;
}

/**
 * A tarball being served: "ok" holds its verified bytes (any tarball up to MAX_UPSTREAM_TARBALL_BYTES, also kept in
 * the blob store); "stream" is a larger one passed through as it arrives, checked on the way (verifiedStream) and
 * never held, cached or charged to the memory pool. `length` is what the upstream declared, null when it declared none.
 */
export type ServedTarball =
  | Extract<UpstreamTarball, { kind: "ok" | "absent" | "unavailable" }>
  | { kind: "stream"; body: ReadableStream<Uint8Array>; length: number | null; digest: Digest };

/**
 * A tarball opened for a streamed analysis (streamed-analysis.ts), one too large to hold: its bytes as they arrive, not
 * checked yet (the reader hashes every byte against `digest` before it trusts any), and the length its source
 * declared, null when it declared none. Each call opens it again, from the blob store's copy when there is one.
 */
export type OpenedTarball = { kind: "stream"; body: ReadableStream<Uint8Array>; length: number | null; digest: Digest } | Extract<UpstreamTarball, { kind: "absent" | "unavailable" }>;

/** How long a tarball download may take, and how long a streamed one may take to start. */
const TARBALL_TIMEOUT_MS = 30_000;

/**
 * The Content-Length an answer declares, or null when it declares none (or one that is not a byte count), or when the
 * answer was compressed and so its length is not the length of the body fetch hands over.
 */
function declaredLength(res: Response): number | null {
  // fetch hands over a compressed answer decoded, so its Content-Length counts bytes the body does not have
  if (decodedByFetch(res)) return null;
  const raw = res.headers.get("content-length");

  if (raw === null || !/^\d+$/.test(raw)) return null;

  return Number(raw);
}

/** Whether the answer was sent with a Content-Encoding (gzip, br, ...), which fetch decodes before the body is read. */
function decodedByFetch(res: Response): boolean {
  const encoding = (res.headers.get("content-encoding") ?? "").trim().toLowerCase();

  return encoding !== "" && encoding !== "identity";
}

function streamed(res: Response, digest: Digest, length: number | null): ServedTarball {
  const body = res.body ?? new ReadableStream<Uint8Array>({ start: (c) => c.close() });

  return { kind: "stream", body: verifiedStream({ source: body, digest, length, url: res.url }), length, digest };
}

/** A tarball answer opened for a client (Upstream.openTarballUrl): the upstream's 200, its body not read yet. */
export type OpenedUpstream = { kind: "open"; res: Response } | Extract<UpstreamTarball, { kind: "unavailable" }>;

/**
 * An opened upstream answer as the client gets it: its bytes unchanged, passed on as they arrive and checked against
 * `digest` on the way (verifiedStream), with the length the upstream declared.
 */
export function passTarball(res: Response, digest: Digest): Extract<ServedTarball, { kind: "stream" }> {
  const length = declaredLength(res);
  const body = res.body ?? new ReadableStream<Uint8Array>({ start: (c) => c.close() });

  return { kind: "stream", body: verifiedStream({ source: body, digest, length, url: res.url }), length, digest };
}

/** Upstream answers that may succeed when asked again. */
function isTransientStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

/**
 * Answers for the tarball of a version the packument lists that may succeed when asked again: the transient ones, and
 * 404, which npm's CDN answers for a while right after a publish (@firebase/analytics 0.10.26 was stored unscorable
 * for it on its first day, and npm served it later). An analysis still gives up on a tarball that keeps failing after
 * MAX_FETCH_FAILURES runs over FETCH_GIVE_UP_MS (analysis.ts), so a tarball npm lost for good ends unavailable as before.
 */
export function isRetryableTarballStatus(status: number): boolean {
  return isTransientStatus(status) || status === 404;
}

export type UpstreamAdvisories = { kind: "ok"; advisories: Record<string, unknown[]> } | { kind: "unavailable" };

export type UpstreamAuditProxy = { kind: "ok"; body: string; contentType: string } | { kind: "unavailable" };

/** npm serves packuments from registry.npmjs.org and tarballs from the same host. */
const NPM_ORIGIN = "https://registry.npmjs.org";
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_HOPS = 5;

/**
 * The parsed packument without apm's scores; scores are attached per request from the store. `etag`: npm's ETag for
 * it, when npm sent one and answered directly, which a kept row of its choices is kept for (kept-choices.ts).
 * `fetchedAt`: when npm sent it (wall-clock ms; a shared copy's own time), which a choice made of it is as old as.
 * `readAt`: when npm's packument it was read from was read whole from npm, by the registry's clock: this isolate's
 * read, or the one a shared copy carries (READ_AT_HEADER); minus infinity when that is not known. Only a whole read
 * from npm sets it; the install copy's whole-read deadline counts from it (installCopy).
 */
export type CachedPackage = Omit<UpstreamPackage, "versions"> & { versions: Omit<VersionRecord, "score">[]; fetchedAt: number; readAt: number };

type CachedProbe = { kind: "found"; pkg: CachedPackage } | { kind: "absent" };

/** The package as npm lists it, without apm's scores: what a route needs that reads only versions and checksums. */
export type UpstreamListing = CachedProbe | { kind: "unknown" };

/**
 * The package apm caches, read from the packument readPackument kept: each version npm lists with a valid document,
 * in publish order. Null when the packument is not one.
 */
export function cachedPackage(name: string, body: KeptPackument, serveCost: ServeCost, etag: string | null, fetchedAt: number = Number.NEGATIVE_INFINITY, readAt: number = Number.NEGATIVE_INFINITY): CachedPackage | null {
  const parsed = UpPackument.safeParse(body);

  if (!parsed.success) return null;
  const raw = parsed.data;
  const tarballs = new Map<string, string>();
  const versions: Omit<VersionRecord, "score" | "seq">[] = [];

  for (const [v, rawDoc] of Object.entries(raw.versions)) {
    const one = UpVersion.safeParse(rawDoc);

    if (!one.success) continue;
    const doc = one.data;
    tarballs.set(v, doc.dist.tarball);
    const manifest: Record<string, unknown> = { ...doc };
    delete manifest.dist;
    const shasum = doc.dist.shasum ?? "";
    const integrity = doc.dist.integrity ?? "";
    const digest = digestOf({ integrity, shasum });
    versions.push({
      package: name,
      version: v,
      manifest,
      shasum,
      integrity,
      size: 0,
      tarball_key: digest ? upstreamBlobKey(digest) : "",
      published_at: Date.parse(raw.time[v] ?? "") || 0,
      published_by: doc._npmUser?.name ?? NO_RECORDED_PUBLISHER,
      deprecated: typeof doc.deprecated === "string" && doc.deprecated !== "" ? doc.deprecated : null,
      status: "active",
      status_reason: null,
      status_at: null,
      status_by: null,
    });
  }

  // npm has no insert order: an upstream version's seq is its place in publish order. Each carries npm's record of the
  // name (its versions' publish times), which the score reads (core settleEstablishedName)
  const history = nameHistoryOf(versions.map((v) => v.published_at));
  const ordered = versions.toSorted((a, b) => a.published_at - b.published_at).map((v, seq) => (history === null ? { ...v, seq } : { ...v, seq, history }));

  return {
    name,
    distTags: raw["dist-tags"],
    description: raw.description ?? "",
    readme: raw.readme ?? "",
    maintainers: (raw.maintainers ?? []).map((m) => m.name),
    versions: ordered,
    tarballs,
    serveCost,
    etag,
    fetchedAt,
    readAt,
  };
}

/**
 * A kept row's records as a cached package (kept-choices.ts): only the versions its choices took, with what a choice
 * and a summary read of them, so a reader can be handed them as it is handed a package npm sent.
 */
export function keptPackage(name: string, row: KeptChoicesRow): CachedPackage {
  return { name, distTags: row.kept.distTags, description: "", readme: "", maintainers: [], versions: Object.values(row.kept.records), tarballs: new Map(), serveCost: { versionDocs: 0, maxPieceChars: 0 }, etag: row.etag, fetchedAt: Number.NEGATIVE_INFINITY, readAt: Number.NEGATIVE_INFINITY };
}

/**
 * A cached package with its analyses: an analysis counts only for the exact bytes it read, by the current scorer; a
 * version it decided it can never score says why.
 */
export function scoredPackage(pkg: CachedPackage, analyses: UpstreamAnalyses): Probe {
  return { kind: "found", pkg: { ...pkg, versions: pkg.versions.map((v) => scoredVersion(v, analyses)) } };
}

/**
 * Which versions' analyses a reader of a package reads, by version: whole, or trimmed (without PAGE_TRIMMED's members)
 * for one that works out only a score and a grade from it. A version it does not name reads as not scored.
 */
export type Wanted = (pkg: { readonly distTags: Record<string, string>; readonly versions: readonly Omit<VersionRecord, "score">[] }) => ReadonlyMap<string, "whole" | "trimmed">;

/** The keys of the versions of `name` that `want` names. */
function wantedKeys(name: string, versions: readonly Omit<VersionRecord, "score">[], want: ReadonlyMap<string, "whole" | "trimmed">): AnalysisKey[] {
  return versions.flatMap((v) => {
    const form = want.get(v.version);
    const d = digestOf(v);

    return form === undefined ? [] : [{ package: name, version: v.version, digest: d ? digestLabel(d) : null, trimmed: form === "trimmed" }];
  });
}

const NO_ANALYSES: UpstreamAnalyses = { scores: new Map(), unscorable: new Map() };

/**
 * The most a read of analyses reserves before it is sent (Lease.takeUpTo), and the least worth sending it for: what
 * does not fit is omitted, and its package answered as not checked. Twenty next-like dependencies, trimmed, hold 1.3
 * MiB; a reservation is taken from the pool only for as long as the statement runs (Sol on fb84083: the lease's
 * headroom was sent as the allowance without being reserved, so a reply could pass the pool before it was charged).
 */
const ANALYSES_READ_ALLOWANCE = 16 * 1024 * 1024;
const ANALYSES_READ_MIN = 64 * 1024;

/** The analyses of the versions of `name` that `want` names, in one statement (none when it names none). */
export const wantedAnalyses = (store: StoreApi, name: string, versions: readonly Omit<VersionRecord, "score">[], want: ReadonlyMap<string, "whole" | "trimmed">): Effect.Effect<UpstreamAnalyses, StoreError> =>
  Effect.map(store.upstreamAnalysesFor(wantedKeys(name, versions, want)), (got) => got.get(name) ?? NO_ANALYSES);

/**
 * wantedAnalyses within `lease`: sent only while they fit its headroom (Store.upstreamAnalysesWithin), and what they
 * hold once read taken from it, to stay taken while the lease holds the package. null, with nothing taken, when they
 * do not fit: the caller answers "over-budget", never a package with no score.
 */
const wantedWithin = (store: StoreApi, name: string, versions: readonly Omit<VersionRecord, "score">[], want: ReadonlyMap<string, "whole" | "trimmed">, lease: Lease): Effect.Effect<UpstreamAnalyses | null, StoreError> =>
  Effect.gen(function* () {
    const keys = wantedKeys(name, versions, want);

    if (keys.length === 0) return NO_ANALYSES;
    const allowance = lease.takeUpTo(ANALYSES_READ_ALLOWANCE, ANALYSES_READ_MIN);
    const read = yield* store.upstreamAnalysesWithin({ keys, allowance, weights: KEPT_TEXT_WEIGHTS }).pipe(Effect.onError(() => Effect.sync(() => lease.give(allowance))));

    // settled to what the reply holds: given back, and what is kept taken again at once
    lease.give(allowance);

    if (read.omitted.has(name) || !lease.take((read.sizes.get(name) ?? []).reduce((n, s) => n + parsedWeight(s), 0))) return null;

    return read.analyses.get(name) ?? NO_ANALYSES;
  });

/** One version of scoredPackage: its stored analysis for its exact bytes, or why it can never be scored. */
function scoredVersion(v: Omit<VersionRecord, "score">, { scores, unscorable }: UpstreamAnalyses): VersionRecord {
  const d = digestOf(v);
  const score = d ? (scores.get(`${v.version} ${digestLabel(d)}`) ?? null) : null;
  const why = score === null ? unscorable.get(v.version) : undefined;

  return why ? { ...v, score, unscorable: why } : { ...v, score };
}

/** How long an upstream answer is trusted before it is fetched again. */
export const DEFAULT_TTL_MS = 60_000;

/** Packuments probeMany asks npm for at once (the resolve walk's batches); the isolate cache answers the rest. */
const PROBE_CONCURRENCY = 6;
const MAX_ENTRIES = 500;

/**
 * The most package metadata the isolate cache keeps, as weight (packageWeight): an upper bound on its heap, taken from
 * the isolate's memory pool (memory.ts, CACHE_WEIGHT). next weighs 26 MiB cached (14 MiB of heap in workerd). Oldest
 * go first, and the pool takes back entries only the cache holds when a read needs the room.
 */
export const PROBE_CACHE_WEIGHT = CACHE_WEIGHT;

/**
 * What a cached package holds for each version beside the packument it was read from (cachedPackage: the version's
 * record, its tarball's URL and blob key), as weight. Measured in workerd: at most 284 bytes (react).
 */
export const RECORD_WEIGHT = 384;

/** What a request's copy of a cached package with its scores holds for each version (scoredPackage; measured: 108 bytes). */
export const SCORED_WEIGHT = 160;

/**
 * What reading a packument into a cached package holds for a moment for each version beyond its record: the schema's
 * copy of `versions` and the records before they are put in publish order (measured, with the shallow copy of each
 * version document the reader counts in versionDocs: 1,130 bytes a version of next beside its packument).
 */
const MOMENT_WEIGHT = RECORD_WEIGHT + 64;

/** What a package read from `read` weighs once cached: the packument and each version's record. */
export const packageWeight = (read: { readonly weight: number; readonly versionCount: number }): number => read.weight + read.versionCount * RECORD_WEIGHT;

/** What reading `read` into a cached package holds for a moment beside packageWeight: given back once it is read. */
export const packageMoment = (read: { readonly versionCount: number; readonly versionDocs: number }): number => read.versionDocs + read.versionCount * MOMENT_WEIGHT;

/**
 * Answers from the public registry, kept for a minute per Worker isolate. Only public data lives here, never
 * anything about a request or a person, so sharing it between requests is safe. Promises are never shared:
 * a Worker may not finish I/O that another request started.
 *
 * With a lease (the pool's cache lease, memory.ts), an entry's memory is a Block the cache holds beside whoever else
 * does: the cache keeps no more than its lease's limit (oldest go first), and when the pool needs room it takes back
 * entries only the cache holds, oldest first. Evicting one a request still holds frees nothing until that request ends.
 */
export class IsolateCache<V> {
  private readonly entries = new Map<string, { at: number; value: V; block: Block | null }>();
  private readonly ttlMs: number;
  private readonly lease: Lease | null;

  constructor(ttlMs: number, lease: Lease | null = null) {
    this.ttlMs = ttlMs;
    this.lease = lease;
    lease?.pool.onPressure((need) => this.reclaim(need));
  }
  get(key: string, now: number): V | undefined {
    return this.entry(key, now)?.value;
  }
  /** The value under `key` and the block it was kept with, while it is fresh. */
  entry(key: string, now: number): { readonly value: V; readonly block: Block | null } | undefined {
    const hit = this.entries.get(key);

    if (!hit) return undefined;

    if (now - hit.at >= this.ttlMs) {
      this.delete(key);

      return undefined;
    }

    return hit;
  }
  /**
   * Keeps `value` under `key`; with a lease, the cache holds `block` too, and older entries leave to make room for it.
   * False when it was not kept: heavier than the cache may hold.
   */
  set(key: string, value: V, now: number, block: Block | null = null): boolean {
    this.delete(key);
    const lease = this.lease;
    const held = block !== null && lease !== null ? block : null;

    if (held !== null && lease !== null) {
      if (held.weight > lease.limit) return false;

      while (lease.taken + held.weight > lease.limit) if (!this.evictOldest()) break;

      if (!lease.hold(held)) return false;
    }

    this.entries.set(key, { at: now, value, block: held });

    while (this.entries.size > MAX_ENTRIES) if (!this.evictOldest()) break;

    return true;
  }
  delete(key: string): void {
    const gone = this.entries.get(key);

    if (!gone) return;
    this.entries.delete(key);

    if (gone.block) this.lease?.drop(gone.block);
  }
  /** Weight the cache holds, its share of blocks others hold too included. */
  get weight(): number {
    return this.lease?.taken ?? 0;
  }
  private evictOldest(): boolean {
    const oldest = this.entries.keys().next();

    if (oldest.done) return false;
    this.delete(oldest.value);

    return true;
  }
  /** The pool needs `need` more: entries only the cache holds leave, oldest first, until that much is freed. */
  private reclaim(need: number): void {
    const lease = this.lease;

    if (!lease) return;
    let freed = 0;

    for (const [key, e] of this.entries) {
      if (freed >= need) return;

      if (e.block && lease.soleHolder(e.block)) {
        freed += e.block.weight;
        this.delete(key);
      }
    }
  }
}

type Caches = {
  searches: IsolateCache<Extract<UpstreamSearch, { kind: "ok" }>>;
  scopes: IsolateCache<"found" | "absent">;
  /** Version documents by "<name>@<version>": what versionOf answered, found or absent. */
  versions: IsolateCache<Exclude<UpstreamVersion, { kind: "unknown" }>>;
  /**
   * Packages npm just failed a small read for (a version document, or a packument's conditional read: an error status,
   * a body apm cannot read, a timeout), kept for NPM_FAILURE_MS: neither is asked for again meanwhile, so each read
   * goes straight to the packument as it did before summaries were kept, instead of waiting on npm once more first.
   */
  failures: IsolateCache<true>;
  /**
   * npm's ETag of each package whose install copy npm said is current (a 304), kept for the TTL from then: within it,
   * this isolate serves that copy without asking npm again.
   */
  validated: IsolateCache<string>;
};

/**
 * How long a failed version document or conditional packument read is remembered (at most the upstream TTL): a short
 * outage costs each package one failed request per isolate in this window, not one on every read.
 */
export const NPM_FAILURE_MS = 30_000;

/**
 * The longest a version document may take, and a packument's conditional read may take to start answering. Both are
 * a few KiB or no body: npm answered a version document in 0.15 s warm and 1.1 s from a cold edge when checked, so 2 s
 * leaves room for that, and a stalled npm adds at most 2 s to one read per package per NPM_FAILURE_MS (the rest go
 * straight to the packument).
 */
export const NPM_SMALL_READ_TIMEOUT_MS = 2_000;

const isolateCaches = new Map<string, Caches>();

function cachesFor(baseUrl: string, ttlMs: number): Caches {
  const key = `${ttlMs} ${baseUrl}`;
  const known = isolateCaches.get(key);

  if (known) return known;
  const made: Caches = { searches: new IsolateCache(ttlMs), scopes: new IsolateCache(ttlMs), versions: new IsolateCache(ttlMs), failures: new IsolateCache(Math.min(ttlMs, NPM_FAILURE_MS)), validated: new IsolateCache(ttlMs) };
  isolateCaches.set(key, made);

  return made;
}

/** The packument cache of each pool (the isolate's, or a test's), by upstream and TTL: its entries are the pool's blocks. */
const probeCaches = new WeakMap<MemoryPool, Map<string, IsolateCache<CachedProbe>>>();

function probeCacheFor(pool: MemoryPool, baseUrl: string, ttlMs: number): IsolateCache<CachedProbe> {
  const byKey = probeCaches.get(pool) ?? new Map<string, IsolateCache<CachedProbe>>();
  probeCaches.set(pool, byKey);
  const key = `${ttlMs} ${baseUrl}`;
  const known = byKey.get(key);

  if (known) return known;
  const made = new IsolateCache<CachedProbe>(ttlMs, pool.cache());
  byKey.set(key, made);

  return made;
}

/**
 * npm packuments shared by every isolate in a data center through the Workers Cache API, below the isolate cache. A
 * cold isolate then reads a packument another one fetched a moment ago instead of asking npm again. Only npm's own
 * 200 answer is kept, as the text npm sent, and parsed on every read exactly as a fresh one is. The Cache API works
 * on custom domains (production); on workers.dev its calls do nothing, and under Miniflare it works as in production.
 * Each copy carries when npm sent it, and both layers count one TTL from then, so a copy read near the end of its TTL
 * is not trusted for a whole new one. A TTL under a second (the tests that move an upstream between requests) turns it off.
 */
const SHARED_MIN_TTL_MS = 1_000;

/** When npm sent a shared packument (ms since the epoch): its TTL counts from then, in every isolate that reads it. */
export const FETCHED_AT_HEADER = "x-apm-fetched-at";

/** When npm's packument a shared copy holds was read whole from npm, by the registry's clock (CachedPackage.readAt). */
export const READ_AT_HEADER = "x-apm-read-at";

/** npm's ETag for a shared packument, so a copy read from the data center's cache can be revalidated as npm's own. */
const ETAG_HEADER = "x-apm-npm-etag";

/**
 * The install packument apm served for a package only npm has (the abbreviated document npm, pnpm and bun install
 * from, outside ~safe) is a function of npm's packument and of the versions apm reviewers confirmed malicious, and of
 * nothing else: it carries no score, and an npm package has no apm revoke or yank. So the served text is kept in the
 * data center's cache under the package and the registry URL its tarball links name, with npm's ETag and the confirmed
 * set's stamp (installStamp) beside it, and answers a request whose stamp, read from the database by that request, is
 * the same, while npm's packument is: within the TTL from when npm sent it, or once npm answers a conditional read of
 * that ETag with a 304. A block or an unblock changes the stamp, so the very next request makes a new copy; a new npm
 * version changes the ETag. A copy answers for at most KEPT_CHOICES_MAX_AGE_MS from the whole read it was made of,
 * however many 304s came since: then npm's packument is read whole again, and what a whole read runs (the AI review's
 * look at new versions, upstreamFetched) runs, retried if it failed before. INSTALL_COPY_FORMAT names the copy's shape, so one written by another build is never read.
 */
const INSTALL_COPY_FORMAT = "install-v1";
const INSTALL_STAMP_HEADER = "x-apm-install-stamp";
const INSTALL_FORMAT_HEADER = "x-apm-install-format";
/**
 * When npm's packument the copy was made of was read whole from npm, by the registry's clock (CachedPackage.readAt;
 * the TTL counts on the wall's, FETCHED_AT_HEADER, and tests move only the registry's): its age is checked against
 * KEPT_CHOICES_MAX_AGE_MS.
 */

const INSTALL_READ_AT_HEADER = "x-apm-install-read-at";
/** How long the data center keeps an install copy; it answers only while it is validated as above. */

const INSTALL_COPY_MAX_AGE_S = 24 * 60 * 60;

/**
 * The forms of npm's packument ETag this isolate has logged: strong, weak (`W/`) or none. kept-choices.ts keeps a row
 * only for a strong one, and which form a Worker's fetch receives from npm in production has not been observed, so
 * the first answer of each form in an isolate is logged (event "npm-etag-form"), a few lines an isolate at most.
 */
const etagFormsSeen = new Set<string>();

function noteEtagForm(etag: string | null): void {
  const form = etag === null || etag === "" ? "none" : etag.startsWith("W/") ? "weak" : "strong";

  if (etagFormsSeen.has(form)) return;
  etagFormsSeen.add(form);
  console.log(JSON.stringify({ level: "info", event: "npm-etag-form", form }));
}

/** How far a whole read's time may be ahead of the registry's clock and still count: two isolates' clocks may differ. */
const READ_AT_SKEW_MS = 60_000;

/**
 * Whether a whole read of npm's packument at `readAt` counts at `now` for a caller that needs one since `since`: after
 * `since`, and not later than `now` (and READ_AT_SKEW_MS). A time from tomorrow, or none, never counts.
 */
function wholeReadCounts(readAt: number, since: number, now: number): boolean {
  return readAt > since && readAt <= now + READ_AT_SKEW_MS;
}

/**
 * The packages this isolate is reading whole from npm for a caller that needs a whole read (listedOrSame with
 * `wholeSince`), by upstream and name, with when that read began (wall clock): a second such request for one of them
 * waits for that read to land in the isolate cache instead of reading npm again. Per isolate only: two isolates, or two
 * data centers, may each read once. A mark older than SINGLE_FLIGHT_STALE_MS is no read under way: a leader whose
 * request ended without its cleanup running (the platform dropped it) must not make every later request wait.
 */
const refreshing = new Map<string, Flight>();

/**
 * One whole read under way: when it began, and whether the one extra read a waiter may make once its wait ran out
 * (SINGLE_FLIGHT_WAIT_MS) was taken. Every other waiter whose wait runs out while this read is out is answered "unknown"
 * (a 503 with Retry-After the client retries) instead of reading npm: a stuck leader costs npm two reads, not one per
 * request that came meanwhile.
 */
type Flight = { readonly began: number; extraTaken: boolean };

/**
 * How long a request waits for another's whole read before its wait runs out (then one waiter reads npm and the rest
 * are told to retry: Flight), and how often it looks. A whole read
 * usually lands in well under a second (bench: npm p90 160 ms); one still out after SINGLE_FLIGHT_WAIT_MS is slow or
 * stuck, and waiting longer on it is a stall shared between requests (the bench's 10.1 s install document on 8ea60e1).
 */
const SINGLE_FLIGHT_WAIT_MS = 3_000;
const SINGLE_FLIGHT_POLL_MS = 25;

/** A whole read is over by then (npm's 10 s, the copy's lookup and first bytes): a mark this old is dropped. */
const SINGLE_FLIGHT_STALE_MS = 15_000;

/** The whole read of `flight` under way in this isolate at `now`, or null; a stale mark is dropped. */
function underWay(flight: string, now: number): Flight | null {
  const mark = refreshing.get(flight);

  if (mark === undefined) return null;

  if (now - mark.began < SINGLE_FLIGHT_STALE_MS && now >= mark.began) return mark;
  refreshing.delete(flight);

  return null;
}

/** A read time from a header (ms since the epoch on the registry's clock), or minus infinity when it is missing or not a number. */
function readTime(header: string | null): number {
  const n = header === null || header.trim() === "" ? Number.NaN : Number(header);

  return Number.isFinite(n) ? n : Number.NEGATIVE_INFINITY;
}

/** The Cache API key of the install copy of `name` from `upstream`, whose tarball links name `served`. */
const installKey = (input: { upstream: string; served: string; name: string }): Request =>
  new Request(`https://upstream-cache.apmjs.internal/${INSTALL_COPY_FORMAT}/${encodeURIComponent(input.upstream)}/${encodeURIComponent(input.served)}/${encodeURIComponent(input.name)}`);

/**
 * npm's ETag for a packument, as the copy keeps and revalidates it, or null when npm sent none. npm's edge sends the
 * hash of the document as a strong tag and weakens it (`W/"<hash>"`) when it compresses the answer, which it always
 * does for a Worker's fetch; it answers If-None-Match with either form, by that hash. So the weak form is used as
 * npm sends it: it changes whenever npm's packument does, which is all the copy needs it for.
 */
const npmEtag = (etag: string | null): string | null => (etag !== null && etag !== "" ? etag : null);

/**
 * The stamp of a set of confirmed reviews (version and digest), as installRead reads them, and of the OSSF feed's
 * advisories for the name (`listed`, osv.ts advisoryLines): the SHA-256 of their sorted lines, so any change to either
 * changes it. With no advisories it is the stamp of the confirmed set alone, as before the feed was read here.
 */
export async function installStamp(rows: readonly { version: string; digest: string }[], listed: readonly string[] = []): Promise<string> {
  const lines = [...rows.map((r) => `${r.version} ${r.digest}`), ...listed].toSorted().join("\n");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(lines)));

  return [...hash].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * What installCopy came to: the kept copy's text, still current ("copy"), or no copy that may answer, and the package
 * as npm lists it now, read under the request's lease ("read").
 */
/** Makes the install packument as a streamed answer (http.ts, streamedJson) with these headers and options. */
export type InstallWriter = (headers: Readonly<Record<string, string>>, options: StreamOptions) => Response;

export type InstallCopy = { kind: "copy"; body: ReadableStream<Uint8Array> } | { kind: "read"; listing: UpstreamListing | { kind: "over-budget" } };

/** What npm says of one version now, from its version document: its tarball's URL and the checksums npm publishes for it ("" when absent). */
export type UpstreamVersion = { kind: "found"; tarball: string; integrity: string; shasum: string } | { kind: "absent" } | { kind: "unknown" };

/** A version document is a few KiB; one past this is not read. */
const MAX_VERSION_DOC_BYTES = 1024 * 1024;

const VersionDist = z.object({ version: z.string(), dist: z.object({ tarball: z.string().optional(), integrity: z.string().optional(), shasum: z.string().optional() }).loose() }).loose();

/** The data center's cache. Call it only inside a Worker request: Bun (the unit tests) has no `caches`. */
const workerCache = (): Cache => caches.default;

/**
 * The Cache API key of a packument as `profile` keeps it: the registry's own reads (TRIMMED) and the devDependencies
 * the full packument adds back are kept apart. This host is never fetched; it only names the entry.
 */
export const packumentKey = (url: string, profile: KeepProfile = TRIMMED): Request =>
  new Request(`https://upstream-cache.apmjs.internal/${profile === DEV_DEPENDENCIES ? "v2-dev" : "v2"}/${encodeURIComponent(url)}`);

/**
 * What asking for a packument came to. "ok": what readPackument kept, and what it weighs (`read`), taken from the
 * lease it was read under; `fresh` when npm sent it now, so the data center's cache may be given a copy (shareCopy)
 * once the caller has made room for converting it. "status": npm answered something other than a 200 with a body.
 * "refused": npm answered, but readPackument refused it (too large, not JSON), so it is an answer apm cannot use.
 * "over-budget": the lease had no room for it. "not-modified": npm's 304 for the ETag it was asked with.
 */
type PackumentAnswer =
  | { kind: "ok"; body: KeptPackument; fetchedAt: number; readAt: number; read: Extract<PackumentRead, { kind: "ok" }>; fresh: boolean; etag: string | null; conditional: boolean }
  | { kind: "not-modified"; fetchedAt: number }
  | { kind: "status"; status: number; fetchedAt: number }
  | { kind: "refused"; fetchedAt: number }
  | { kind: "over-budget" };

function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}


export type UpstreamApi = {
  readonly baseUrl: string;
  readonly search: (text: string, size: number) => Effect.Effect<UpstreamSearch>;
  /** Whether `@scope` has packages upstream. */
  readonly scopeExists: (scope: string) => Effect.Effect<"found" | "absent" | "unknown">;
  /**
   * The package with the analyses of the versions `wanted` names, each whole or trimmed, read under `lease`
   * (memory.ts): what it holds stays taken from the lease until the lease closes. Every other version reads as not
   * scored. The analyses are read within the lease (Store.upstreamAnalysesWithin) and charged to it; a package whose
   * packument or analyses do not fit is "unknown" here. No reader asks for a package's whole history: on 216a4c7 a
   * probe with no `wanted` read every stored analysis as one value (next: 61 analyses, 16 MB), charged to nothing.
   */
  readonly probeFor: (name: string, wanted: Wanted, lease: Lease) => Effect.Effect<Probe, StoreError>;
  /** probeFor, with "over-budget" kept apart from "unknown" (a walk, a scan: one child lease per package). */
  readonly probeWithinFor: (name: string, wanted: Wanted, lease: Lease) => Effect.Effect<ListedProbe, StoreError>;
  /** Like probe, with no scores, so it reads nothing from the database: the existence check and the review's version lookup. */
  readonly listing: (name: string, lease: Lease) => Effect.Effect<UpstreamListing>;
  /**
   * The package as npm lists it, unless its packument is still the one `etag` names: then "not-modified" (npm's 304,
   * no body read). Otherwise as `listing` reads it, from the isolate cache or from npm's answer to that same request,
   * so checking a kept summary or a kept row and the read it leads to are one request (fetchPackument). A package
   * that did not fit `lease` is "over-budget"; with a null `etag` this is listing.
   */
  readonly listingIfChanged: (name: string, lease: Lease, etag: string | null) => Effect.Effect<UpstreamListing | { kind: "over-budget" } | { kind: "not-modified" }>;
  /**
   * The install packument kept for `name` (INSTALL_COPY_FORMAT) when it was made for `served` and for the stamp
   * `stampOf` makes of what `read` read, and npm's packument is still the one it was made from; otherwise the package
   * as `listingIfChanged` reads it, under `lease` (with the copy's ETag when there is one, so a 304 needs no read and a
   * 200 is the new packument). `read` (the database's statement) runs while the copy is looked up and checked with
   * npm, which needs no stamp; nothing is answered from the copy until the stamps match. A null stamp (the name is
   * published here) answers no copy and reads nothing more. A whole read of npm's packument with no copy to check
   * waits for `read`, as before.
   */
  readonly installCopy: <A, E>(input: { name: string; served: string; lease: Lease; read: Effect.Effect<A, E>; stampOf: (read: A) => string | null }) => Effect.Effect<{ read: A; copy: InstallCopy | null }, E>;
  /**
   * Keeps the install packument made from `pkg` for `served` and `stamp`, after the response: `write` makes it as a
   * streamed answer with the headers and stream options it is given. `onDone` runs once the write settles or is stopped
   * (SHARE_TIMEOUT_MS), and at once when nothing is written (no data center cache, or npm sent no ETag); it may run
   * twice, so it must do its work once. The caller holds what the answer refers to until then. `ready` is the
   * database's guard (db-health.ts, Guard.ready), checked once more just before the write: a copy is never written
   * once this request has taken the database as unavailable, since only a request that read the confirmed set from it
   * may make one.
   */
  readonly keepInstallCopy: (input: { name: string; served: string; stamp: string; pkg: CachedPackage; write: InstallWriter; ready: Effect.Effect<void, StoreError>; onDone: () => void }) => Effect.Effect<void>;
  /** One version's document (a few KiB): whether npm still lists the version, and its checksums. Kept for the TTL. */
  readonly versionOf: (name: string, version: string) => Effect.Effect<UpstreamVersion>;
  /**
   * probe for several names: their packuments (from cache or npm, a few at once) and one read of their analyses. Every
   * packument kept counts against `lease`, cached ones included, and a name past it is "over-budget".
   */
  readonly probeMany: (names: readonly string[], lease: Lease) => Effect.Effect<Map<string, BudgetedProbe>, StoreError>;
  /**
   * probeMany for a caller that needs only part of each package (the resolve walk, its root, a scan): `keep` is handed
   * each package with its analyses as soon as it is read, and `lease` to reserve what it keeps before it builds it
   * (walk-catalog.ts, keptSummary); it returns null, with nothing taken, when that does not fit. Only what it returns
   * stays taken from `lease`. A package
   * the isolate cache has stays the cache's: it is never held by `lease`, and is pinned while it is kept so the pool
   * cannot take it back meanwhile. One read from npm is held under a child of `lease` only while it is converted and
   * kept, then left to the isolate cache (which keeps it if it fits, beside older entries). Names
   * that did not fit beside the others read at the same time are read again one at a time. `keep` must return
   * nothing that refers to the package, or that memory would be held with nothing counting it.
   */
  readonly summaries: <S>(names: readonly string[], lease: Lease, keep: (pkg: UpstreamPackage, reserve: Reserve) => Summary<S> | null) => Effect.Effect<Map<string, Summarized<S>>, StoreError>;
  /**
   * summaries for a reader that makes named choices of each package's versions (kept-choices.ts): `keep` is handed
   * only the versions each choice took. What it chose is kept with npm's ETag, and answered from there while npm says
   * the packument has not changed (304), without reading it. `deadline` (Date.now() milliseconds): a package with no
   * answer by then is "out-of-time", its read stopped (its stream cancelled, its lease given back); the packages
   * answered before it keep their choices as usual. Each package's choices are made of it as it is read and held cut
   * down (summaryVersion), their dist-tags charged with them; once every package is read, the analyses of only the
   * versions they took are read, whole or trimmed as `analyses` says, in one statement bounded by the lease's headroom
   * (Store.upstreamAnalysesWithin), and each package is kept with its analyses charged to `lease`. A package one of
   * whose analyses did not fit is kept without them and answered "unread", never as a package with no score.
   */
  readonly chosen: <S>(input: { names: readonly string[]; lease: Lease; choices: (name: string) => readonly Choice[]; keep: (c: Chosen, reserve: Reserve) => Summary<S> | null; analyses: "whole" | "trimmed"; deadline?: number }) => Effect.Effect<Map<string, ChosenAnswer<S>>, StoreError>;
  /**
   * Each version's devDependencies, read apart from the packument the registry keeps (DEV_DEPENDENCIES): only the full
   * packument apm serves adds them back. Null when npm could not be asked, the read was refused, or it did not fit
   * `lease` (the request's, beside the packument it holds); what it weighs stays taken from `lease`.
   */
  readonly devDependencies: (name: string, lease: Lease) => Effect.Effect<DevDependencyRead | null>;
  /**
   * The package when upstream has it, with no scores; null when it is absent, upstream cannot be asked, or it does not
   * fit `lease`.
   */
  readonly get: (name: string, lease: Lease) => Effect.Effect<UpstreamPackage | null, StoreError>;
  /**
   * The tarball of a version the upstream lists right now, verified against its published checksum. Cached in
   * the blob store by that checksum and verified again on every read, so a removed version or tampered bytes
   * are never served.
   */
  readonly tarball: (pkg: UpstreamPackage, version: string) => Effect.Effect<UpstreamTarball, BlobError>;
  /**
   * The tarball for a client: like `tarball` up to MAX_UPSTREAM_TARBALL_BYTES, and past it a stream of the upstream's
   * answer, checked against the published checksum on the way (verifiedStream). Never "too-large".
   */
  readonly serve: (pkg: UpstreamPackage, version: string) => Effect.Effect<ServedTarball, BlobError>;
  /**
   * GETs a tarball URL for a client (fast-tarball.ts), from the upstream's origin (or npm's) only, every redirect hop
   * checked: the 200 answer, its body not read yet. The caller either passes it on (passTarball) or cancels it; an
   * interrupted open cancels its answer itself.
   */
  readonly openTarballUrl: (url: string) => Effect.Effect<OpenedUpstream>;
  /**
   * The tarball of a version the upstream lists right now, opened as a stream for an analysis of one too large to
   * hold. Not checked here: the reader checks it (OpenedTarball).
   */
  readonly openTarball: (pkg: UpstreamPackage, version: string) => Effect.Effect<OpenedTarball, BlobError>;
  /** Forwards an advisory bulk request. A failure is "unavailable", never an empty (clean) answer. */
  readonly advisories: (body: unknown) => Effect.Effect<UpstreamAdvisories>;
  readonly audits?: (endpoint: "audits" | "audits/quick", body: string) => Effect.Effect<UpstreamAuditProxy>;
};

/** Each version's devDependencies (DEV_DEPENDENCIES), and the longest version document of that read as JSON. */
export type DevDependencyRead = { readonly byVersion: ReadonlyMap<string, unknown>; readonly maxPieceChars: number };

/**
 * How long a copy written to the data center's cache may take. Past it the write is stopped (its stream errors, so no
 * partial copy is kept) and what it held is given back.
 */
const SHARE_TIMEOUT_MS = 20_000;

/**
 * How long a background put to the data center's cache is kept in the request's waitUntil: the write's own stream stops
 * at SHARE_TIMEOUT_MS, and a put that still has not settled a little after that is let go (the runtime would cancel it
 * at 30 s anyway). What the write holds is given back when its stream stops or the put settles, whichever is first.
 */
const SHARE_WAIT_MS = SHARE_TIMEOUT_MS + 5_000;

/** npm's whole packument, from the request to its last byte. */
const NPM_READ_TIMEOUT_MS = 10_000;

/**
 * A cached copy's body once its first bytes came (deadline.ts, firstChunkWithin), or null. Interrupted while it waits
 * (the request ended), the body it comes to is cancelled once it is known, so nothing holds the copy's stream.
 */
const primedCopy = (source: ReadableStream<Uint8Array>, operation: string): Effect.Effect<ReadableStream<Uint8Array> | null> =>
  Effect.callback<ReadableStream<Uint8Array> | null>((resume) => {
    const pending = firstChunkWithin({ source, firstMs: CACHE_FIRST_BYTE_MS, idleMs: CACHE_IDLE_MS, operation });

    pending.then((body) => resume(Effect.succeed(body)));

    return Effect.promise(() => pending.then((body) => body?.cancel().catch(() => undefined)));
  });

/** `work` as a waiter keeps it: settled at the latest `ms` on, a later one logged as a stall. Never rejects. */
const waitWithin = (work: Promise<unknown>, ms: number, operation: string): Promise<void> =>
  within(work, ms).then((got) => {
    if (got.kind === "late") logStall(operation, ms);
  });

/** A background put to the data center's cache as a request's waitUntil keeps it: SHARE_WAIT_MS at most. */
const waitBounded = (put: Promise<unknown>, operation: string): Promise<void> => waitWithin(put, SHARE_WAIT_MS, operation);

/** A blob store failure that is R2 not answering within its deadline (blobs.ts). */
const isLate = (e: BlobError): boolean => e.cause instanceof DeadlinePassed;

/**
 * A read of the blob store's copy of an npm tarball, where any failure is a miss: R2 past its deadline, as before, and
 * also R2 answering with an error of its own. The copy is only a cache of npm's bytes, and what npm sends instead is
 * checked against the same digest, so a miss costs a download from npm and nothing else. When only a late read was a
 * miss, an R2 outage that answered with errors (10001, 2026-11-22) made every download of an npm package a 500.
 */
const cacheRead = <A>(read: Effect.Effect<Option.Option<A>, BlobError>): Effect.Effect<Option.Option<A>> =>
  read.pipe(
    Effect.catchTag("BlobError", (e) =>
      Effect.sync(() => {
        if (!isLate(e)) console.warn(JSON.stringify({ level: "warn", event: "upstream-blob-read", error: "read-failed", operation: e.operation }));

        return Option.none<A>();
      }),
    ),
  );

/**
 * Like Effect.tryPromise, but an interruption is joined: it aborts the signal `run` was given and waits for the
 * promise to settle before the interrupted fiber ends. A read (readPackument) stopped this way has canceled its stream
 * and given its charge back by then, so the scope that releases its lease runs after nothing refers to the read any
 * more. Effect.tryPromise aborts the signal but does not wait, and a lease released then is closed under a read that
 * is still running (review of 747a032, finding 1).
 */
const joinedPromise = <A>(run: (signal: AbortSignal) => Promise<A>): Effect.Effect<A, unknown> =>
  Effect.callback<A, unknown>((resume, signal) => {
    let pending: Promise<A>;

    try {
      pending = run(signal);
    } catch (e) {
      resume(Effect.fail(e));

      return;
    }

    pending.then(
      (a) => resume(Effect.succeed(a)),
      (cause) => resume(Effect.fail(cause)),
    );

    // run when the fiber is interrupted, after `signal` has aborted: the fiber ends once the promise has settled
    return Effect.promise(() => pending.then(
      () => undefined,
      () => undefined,
    ));
  });

export class Upstream extends Context.Service<Upstream, UpstreamApi>()("@apm/registry/Upstream") {
  /**
   * The proxy of `baseUrl` (ending with "/"). `background` finishes work after the response (the shared packument
   * cache's writes); without it those writes are skipped.
   */
  static layer(baseUrl: string, ttlMs: number = DEFAULT_TTL_MS, background: ((work: Promise<void>) => void) | null = null, puts: PendingPuts = upstreamPuts): Layer.Layer<Upstream, never, Store | Blobs> {
    return Layer.effect(
      Upstream,
      Effect.gen(function* () {
        const store = yield* Store;
        const blobs = yield* Blobs;
        const timing = yield* timingOrNull;
        const caches = cachesFor(baseUrl, ttlMs);
        // `background` is set only inside a Worker request, where `caches` always exists
        const sharing = ttlMs >= SHARED_MIN_TTL_MS && background !== null;
        /** The only origins tarballs are fetched from, on every redirect hop. */
        const origins: ReadonlySet<string> = new Set([new URL(baseUrl).origin, NPM_ORIGIN]);

        /**
         * GET from the upstream's own origin (or npm's) only; each redirect hop is checked before it is followed. The 200
         * answer, its body not read yet. TARBALL_TIMEOUT_MS runs from the request until `release` is called: a download
         * calls it once the body is read, a stream as soon as the answer has come, since a client may take longer.
         */
        const open = async (raw: string): Promise<{ kind: "ok"; res: Response; release: () => void } | Extract<UpstreamTarball, { kind: "unavailable" }>> => {
          let current: URL;

          try {
            current = new URL(raw);
          } catch {
            return { kind: "unavailable", reason: "the upstream lists a malformed tarball URL", retryable: false };
          }

          for (let hop = 0; hop <= MAX_HOPS; hop++) {
            if (!origins.has(current.origin)) return { kind: "unavailable", reason: `refusing to fetch a tarball from ${current.origin}, which is not the upstream registry`, retryable: false };
            const deadline = new AbortController();
            const timer = setTimeout(() => deadline.abort(new Error("the tarball download timed out")), TARBALL_TIMEOUT_MS);
            const release = (): void => clearTimeout(timer);
            let res: Response;

            try {
              res = await fetch(current, { redirect: "manual", signal: deadline.signal });
            } catch {
              release();

              return { kind: "unavailable", reason: "the tarball download failed", retryable: true };
            }

            if (REDIRECTS.has(res.status)) {
              await res.body?.cancel();
              release();
              const location = res.headers.get("location");

              if (!location) return { kind: "unavailable", reason: "a redirect without a location", retryable: false };

              try {
                current = new URL(location, current);
              } catch {
                return { kind: "unavailable", reason: "a redirect to a malformed URL", retryable: false };
              }

              continue;
            }

            if (res.status !== 200) {
              await res.body?.cancel();
              release();

              return { kind: "unavailable", reason: `the upstream answered ${res.status}`, retryable: isRetryableTarballStatus(res.status) };
            }

            return { kind: "ok", res, release };
          }

          return { kind: "unavailable", reason: "too many redirects", retryable: false };
        };

        /** The whole body of an open answer, within MAX_UPSTREAM_TARBALL_BYTES; null when it is larger. */
        const gather = async (opened: { res: Response; release: () => void }): Promise<Uint8Array | null> => {
          try {
            return await readCapped(opened.res, MAX_UPSTREAM_TARBALL_BYTES);
          } finally {
            opened.release();
          }
        };

        /** A tarball's bytes, for analysis: never more than MAX_UPSTREAM_TARBALL_BYTES of them. */
        const download = async (raw: string): Promise<{ kind: "ok"; bytes: Uint8Array } | Extract<UpstreamTarball, { kind: "unavailable" | "too-large" }>> => {
          const opened = await open(raw);

          if (opened.kind !== "ok") return opened;
          const declared = declaredLength(opened.res);

          if (declared !== null && declared > MAX_UPSTREAM_TARBALL_BYTES) {
            await opened.res.body?.cancel();
            opened.release();

            return { kind: "too-large", bytes: declared };
          }

          const bytes = await gather(opened);

          if (!bytes) return { kind: "too-large", bytes: null };

          return { kind: "ok", bytes };
        };

        /** Where a listed version's tarball is, and the checksum it must match; "absent" or "unavailable" when apm has neither. */
        const locate = (pkg: UpstreamPackage, version: string): { kind: "found"; url: string; digest: Digest } | Extract<UpstreamTarball, { kind: "absent" | "unavailable" }> => {
          const url = pkg.tarballs.get(version);
          const rec = pkg.versions.find((v) => v.version === version);

          if (!url || !rec) return { kind: "absent" };
          const digest = digestOf(rec);

          if (!digest) return { kind: "unavailable", reason: "the upstream publishes no checksum for this version", retryable: false };

          return { kind: "found", url, digest };
        };

        /** The verified copy in the blob store, if there is one; a copy that fails its checksum is removed. */
        const cachedCopy = (digest: Digest) =>
          Effect.gen(function* () {
            const key = upstreamBlobKey(digest);
            // R2 past its deadline (blobs.ts) or failing is a miss: npm is asked, as for a copy never kept
            const cached = yield* cacheRead(blobs.bytes(key));

            if (Option.isNone(cached)) return null;

            if (matches(cached.value, digest)) return cached.value;
            // a disposable cache's delete (blobs.ts, "cache"): given up on at its deadline or on R2 failure, never under the blob lock
            yield* Effect.catchTag(blobs.remove(key, "cache"), "BlobError", (e) =>
              Effect.sync(() => {
                if (!isLate(e)) console.warn(JSON.stringify({ level: "warn", event: "upstream-blob-remove", error: "remove-failed", operation: e.operation }));
              }),
            );

            return null;
          });

        /**
         * Keeps verified bytes in the blob store, a cache of npm's: in a request, after its answer (waitUntil), within
         * R2_PUT_MS; without one (the queue's analysis), waited for within R2_PUT_MS. A put that fails or runs out of time
         * is logged and costs only a later download from npm. The isolate's ledger (pending-puts.ts) starts one put per
         * tarball and skips caching once its puts or bytes are full, counting each put until R2 settles it.
         */
        const keepBlob = (digest: Digest, bytes: Uint8Array): Effect.Effect<void> =>
          Effect.suspend(() => {
            const started = puts.start({
              key: upstreamBlobKey(digest),
              bytes: bytes.byteLength,
              put: () =>
                Effect.runPromiseExit(blobs.put(upstreamBlobKey(digest), bytes)).then((exit) => {
                  if (Exit.isFailure(exit)) console.error(JSON.stringify({ level: "error", event: "upstream-blob-put", error: "put-failed" }));
                }),
            });

            if (started.kind !== "started") {
              if (started.kind === "full") console.warn(JSON.stringify({ level: "warn", event: "upstream-blob-put", skipped: "full", ...puts.load }));

              return Effect.void;
            }

            const bounded = waitWithin(started.settled, R2_PUT_MS, "upstream-blob-put");

            if (background !== null) return Effect.sync(() => background(bounded));

            return Effect.promise(() => bounded);
          });

        /** Bytes that passed their checksum are kept in the blob store; others are "unavailable". */
        const verified = (bytes: Uint8Array, digest: Digest) =>
          Effect.gen(function* () {
            if (!matches(bytes, digest)) return { kind: "unavailable", reason: "the upstream tarball failed its integrity check", retryable: true } as const;
            yield* keepBlob(digest, bytes);

            return { kind: "ok", bytes, digest } as const;
          });

        const now = Effect.sync(() => Date.now());
        // kept choices are aged by the registry's clock (tests move it), the isolate caches by the wall's
        const clock = yield* Effect.serviceOption(Clock);
        const keptNow = Option.isSome(clock) ? clock.value.now : now;

        const fetchJson = (url: string, timeoutMs: number, init: RequestInit = {}) =>
          Effect.tryPromise({
            try: async (): Promise<{ status: number; body: unknown }> => {
              const res = await fetch(url, { ...init, headers: { accept: "application/json", ...init.headers }, signal: AbortSignal.timeout(timeoutMs) });

              if (res.status !== 200) {
                await res.body?.cancel();

                return { status: res.status, body: null };
              }

              const body: unknown = await res.json();

              return { status: res.status, body };
            },
            catch: (cause) => cause,
          });

        const fetchSearch = (text: string, size: number): Effect.Effect<UpstreamSearch> =>
          fetchJson(`${baseUrl}-/v1/search?text=${encodeURIComponent(text)}&size=${size}`, 4_000).pipe(
            Effect.map(({ status, body }): UpstreamSearch => {
              if (status !== 200) return { kind: "unavailable" };
              const parsed = UpSearch.safeParse(body);

              if (!parsed.success) return { kind: "unavailable" };
              const objects: UpSearchObject[] = [];

              for (const raw of parsed.data.objects) {
                const one = UpSearchObject.safeParse(raw);

                if (one.success) objects.push(one.data);
              }

              return { kind: "ok", objects, total: parsed.data.total ?? objects.length };
            }),
            Effect.orElseSucceed((): UpstreamSearch => ({ kind: "unavailable" })),
          );

        /** A packument read as an answer. One it refused is logged; one past the request's lease is not an error. */
        const answerOf = (input: { url: string; read: PackumentRead; fetchedAt: number; readAt: number; fresh: boolean; etag: string | null; conditional?: boolean }): PackumentAnswer => {
          const { url, read, fetchedAt, readAt, fresh, etag } = input;

          if (read.kind === "ok") return { kind: "ok", body: read.body, fetchedAt, readAt, read, fresh, etag, conditional: input.conditional === true };

          if (read.kind === "too-large" && read.over === "budget") return { kind: "over-budget" };
          const detail = read.kind === "too-large" ? { over: read.over, bytes: read.bytes, limit: read.limit } : { reason: read.reason };

          console.error(JSON.stringify({ level: "error", event: "upstream-packument", error: read.kind === "too-large" ? "packument-too-large" : "packument-invalid", url, ...detail }));

          return { kind: "refused", fetchedAt };
        };

        /**
         * npm's packument as `profile` keeps it, from the shared cache when another isolate fetched it within the TTL.
         * `fetchedAt` is when npm sent it: `now` for a fresh fetch, the copy's own time for a shared one. The body is
         * streamed through readPackument, never held whole, and what it keeps is taken from `lease`. No copy is shared
         * here: the caller starts one (shareCopy) once converting the read has fit.
         *
         * With `etag` (a kept row's or a kept summary's), npm is first asked whether the packument changed: one GET with
         * If-None-Match, the one validation both resolve's kept choices and package pages' kept summaries use. It is a
         * small read as package pages' are: skipped while `name` has a failure mark (NPM_FAILURE_MS), and given
         * NPM_SMALL_READ_TIMEOUT_MS for npm's answer to start; a failure marks `name` and the packument is read whole as
         * if no ETag had been given. Its 304 is "not-modified" (timed as npm-head: no body was read); a 200 is the
         * packument, read from that same answer; it follows no redirect, and a redirect is a whole read of the
         * document it leads to (re-check of 3366a36, finding 4). A read that answered through a redirect keeps no ETag.
         */
        const fetchPackument = (input: { name: string; url: string; now: number; readNow: number; profile: KeepProfile; lease: Lease; etag?: string | null; wholeSince?: number | null }): Effect.Effect<PackumentAnswer, unknown> =>
          // an interrupted read (a sibling of a parallel lookup failed, the request ended) cancels its stream and gives
          // its charge back before the fiber ends, so the lease is never released under it
          joinedPromise(async (interrupted): Promise<PackumentAnswer> => {
            const { name, url, now, profile, lease } = input;
            const etag = input.etag ?? null;
            const signal = AbortSignal.any([interrupted, AbortSignal.timeout(NPM_READ_TIMEOUT_MS)]);

            if (etag !== null && caches.failures.get(name, now) === undefined) {
              const askStart = performance.now();
              // the deadline is for npm's answer to start; a 200's body then reads under the packument's own
              const started = new AbortController();
              const timer = setTimeout(() => started.abort(new Error("npm did not answer the conditional read in time")), NPM_SMALL_READ_TIMEOUT_MS);
              let asked: Response | null = null;

              try {
                asked = await fetch(url, { headers: { accept: "application/json", "if-none-match": etag }, signal: AbortSignal.any([signal, started.signal]), redirect: "manual" });
              } catch {
                asked = null;
              } finally {
                clearTimeout(timer);
              }

              if (asked?.status === 304) {
                await asked.body?.cancel();
                timing?.add("npm-head", performance.now() - askStart);

                return { kind: "not-modified", fetchedAt: now };
              }

              if (asked?.status === 200 && asked.body) {
                // npm failing this read in any way (a body apm cannot read, one cut off or too slow) marks the package as
                // a failed small read does; a refusal for the request's budget, or the caller stopping it, does not
                // (combined review of 67d8658, finding 3)
                const fail = (): void => {
                  if (!interrupted.aborted) caches.failures.set(name, true, now);
                };

                let read: PackumentRead;

                try {
                  read = await readPackument(asked.body, { profile, lease, signal });
                } catch (e) {
                  fail();
                  throw e;
                } finally {
                  timing?.add("npm", performance.now() - askStart);
                }

                if (read.kind !== "ok" && !(read.kind === "too-large" && read.over === "budget")) fail();

                noteEtagForm(asked.headers.get("etag"));

                return answerOf({ url, read, fetchedAt: now, readAt: input.readNow, fresh: true, etag: asked.headers.get("etag"), conditional: true });
              }

              if (asked?.status === 404) {
                await asked.body?.cancel();
                timing?.add("npm-head", performance.now() - askStart);

                return { kind: "status", status: 404, fetchedAt: now };
              }

              await asked?.body?.cancel();
              timing?.add("npm-head", performance.now() - askStart);

              // anything but a redirect is npm failing a small read: marked, so the next reads go straight to the whole
              // packument; a redirect is no failure, just a document that is read whole
              if (!interrupted.aborted && (asked === null || !REDIRECTS.has(asked.status))) caches.failures.set(name, true, now);
            }

            const key = packumentKey(url, profile);
            const cacheStart = performance.now();
            // the data center's copy is looked up within CACHE_MATCH_MS and used only if its first bytes come within
            // CACHE_FIRST_BYTE_MS; past either, or a copy that stalls or fails while it is read, npm is asked
            const lookup = sharing ? await matchWithin({ cache: workerCache(), key, operation: "packument-copy" }) : null;
            const hit = lookup?.kind === "hit" ? lookup.res : undefined;
            // a copy with no time (written before copies carried one) or past its TTL is not used, nor, when the caller
            // needs a whole read of npm's packument since `wholeSince`, one whose read is older or not known
            const sentAt = Number(hit?.headers.get(FETCHED_AT_HEADER) ?? Number.NaN);
            const sharedReadAt = readTime(hit?.headers.get(READ_AT_HEADER) ?? null);
            const wholeSince = input.wholeSince ?? null;

            if (hit?.body && Number.isFinite(sentAt) && now - sentAt >= 0 && now - sentAt < ttlMs && (wholeSince === null || wholeReadCounts(sharedReadAt, wholeSince, input.readNow))) {
              const body = await firstChunkWithin({ source: hit.body, firstMs: CACHE_FIRST_BYTE_MS, idleMs: CACHE_IDLE_MS, operation: "packument-copy-body" });

              if (body !== null) {
                try {
                  const read = await readPackument(body, { profile, lease, signal: interrupted });
                  timing?.add("npm-cache", performance.now() - cacheStart);

                  return answerOf({ url, read, fetchedAt: sentAt, readAt: sharedReadAt, fresh: false, etag: hit.headers.get(ETAG_HEADER) });
                } catch (e) {
                  // the caller stopped the read; anything else (the copy stalled or broke) is npm's to answer
                  if (interrupted.aborted) throw e;
                }
              }
            } else await hit?.body?.cancel();

            const npmStart = performance.now();
            // npm's whole read has its own 10 s from here, whatever the copy's lookup took
            const npmSignal = AbortSignal.any([interrupted, AbortSignal.timeout(NPM_READ_TIMEOUT_MS)]);
            const res = await fetch(url, { headers: { accept: "application/json" }, signal: npmSignal });

            if (res.status !== 200 || !res.body) {
              await res.body?.cancel();
              timing?.add("npm", performance.now() - npmStart);

              return { kind: "status", status: res.status === 200 ? 502 : res.status, fetchedAt: now };
            }

            const read = await readPackument(res.body, { profile, lease, signal: npmSignal });
            timing?.add("npm", performance.now() - npmStart);

            if (!res.redirected) noteEtagForm(res.headers.get("etag"));

            // a document that answered through a redirect keeps no ETag: a row or a summary is kept only for one that
            // answered directly (re-check of 3366a36, finding 4)
            return answerOf({ url, read, fetchedAt: now, readAt: input.readNow, fresh: true, etag: res.redirected ? null : res.headers.get("etag") });
          });

        /**
         * Gives the data center's cache a copy of a packument npm just sent, written a version at a time as it is put,
         * so it is never held whole as one string. The write is background work with a lease of its own: it holds
         * `block` (the memory the copy is written from) and what serializing it takes (streamWeight) until the put
         * settles or is stopped (SHARE_TIMEOUT_MS, or its lease's deadline). Nothing is written when that does not
         * fit (review of 6862fc7, finding 3).
         */
        const shareCopy = (input: { url: string; profile: KeepProfile; fetchedAt: number; readAt: number; body: KeptPackument; maxPieceChars: number; block: Block; pool: MemoryPool; etag: string | null }): void => {
          if (!sharing || background === null) return;
          const work = input.pool.backgroundLease();

          if (!work.hold(input.block) || !work.take(streamWeight(input.maxPieceChars))) {
            work.release();

            return;
          }

          const done = (): void => work.release();
          const base = { "content-type": "application/json", "cache-control": `public, max-age=${Math.floor(ttlMs / 1000)}`, [FETCHED_AT_HEADER]: String(input.fetchedAt), [READ_AT_HEADER]: String(input.readAt) };
          const headers = input.etag === null ? base : { ...base, [ETAG_HEADER]: input.etag };
          // stopped at SHARE_TIMEOUT_MS, or at the lease's deadline: the stream then drops the package, and only that
          // lets the lease go before the put settles
          const signal = AbortSignal.any([work.signal, AbortSignal.timeout(SHARE_TIMEOUT_MS)]);
          const copy = streamedJson(input.body, "versions", headers, { signal, onDone: () => (signal.aborted ? done() : undefined) });

          const put = workerCache()
            .put(packumentKey(input.url, input.profile), copy)
            .catch(() => undefined)
            .finally(done);

          background(waitBounded(put, "packument-copy-put"));
        };

        /** An answer that is not a packument: absent when npm said 404, unknown otherwise. */
        const packageOf = (answer: Extract<PackumentAnswer, { kind: "status" | "refused" }>): CachedProbe | { kind: "unknown" } =>
          answer.kind === "status" && answer.status === 404 ? { kind: "absent" } : { kind: "unknown" };

        /**
         * The review's look at a package npm just sent runs after the response: it gets a lease of its own that holds
         * what it is given, released when it is done (worker.ts). It is given only what it reads (reviewSummary), so its
         * lease does not keep the whole package for as long as it runs: the package is pinned while that is cut from
         * it, then left to the request and the isolate cache. Not looked at when that does not fit; the next fetch of
         * the package looks again.
         */
        const fetched = (pkg: CachedPackage, block: Block, pool: MemoryPool) =>
          Effect.gen(function* () {
            const hooks = yield* Effect.serviceOption(ReleaseHooks);

            if (Option.isNone(hooks)) return;
            const held = pool.backgroundLease();
            // reserved from `held` as it is built, so the pool counts it while it is built (review of 2fbf383, finding 3)
            const looked = held.hold(block) ? reviewSummary(pkg, held) : null;
            held.drop(block);

            if (looked === null) {
              held.release();

              return;
            }

            yield* hooks.value.upstreamFetched(looked.summary, held);
          });

        /**
         * The packument as npm lists it, from the isolate cache or npm, without its analyses. What this request now
         * holds is taken from `lease`: a cached package's block (held, not copied) and its scored copy (SCORED_WEIGHT),
         * or a fresh read, the moment converting it takes (packageMoment), and its scored copy. A fresh package becomes
         * a block the lease holds, which the isolate cache and a shared-cache write may hold too.
         */
        const listedOrSame = (name: string, lease: Lease, etag: string | null, wholeSince: number | null = null): Effect.Effect<UpstreamListing | { kind: "over-budget" } | { kind: "not-modified" }> =>
          Effect.gen(function* () {
            const probes = probeCacheFor(lease.pool, baseUrl, ttlMs);
            const flight = `${baseUrl} ${name}`;
            let waited = 0;

            for (;;) {
              const t = yield* now;
              const readNow = yield* keptNow;
              // with `wholeSince`, a package this isolate holds is used only if npm's packument was read whole since then
              const entry = probes.entry(name, t);
              const cached = entry !== undefined && wholeSince !== null && entry.value.kind === "found" && !wholeReadCounts(entry.value.pkg.readAt, wholeSince, readNow) ? undefined : entry;

              if (cached !== undefined) {
                if (cached.value.kind !== "found") return cached.value;
                const scored = cached.value.pkg.versions.length * SCORED_WEIGHT;

                if ((cached.block !== null && !lease.hold(cached.block)) || !lease.take(scored)) return { kind: "over-budget" as const };

                return cached.value;
              }

              // a whole read of this package is already under way in this isolate: wait for it to publish its result
              // in this isolate's cache, then use that, rather than read npm's packument once more (no promise is
              // shared between requests: each waiter looks again on its own timer)
              const out = wholeSince === null ? null : underWay(flight, t);

              if (out !== null) {
                if (waited < SINGLE_FLIGHT_WAIT_MS) {
                  yield* Effect.sleep(Duration.millis(SINGLE_FLIGHT_POLL_MS));
                  waited += SINGLE_FLIGHT_POLL_MS;
                  continue;
                }

                logStall("single-flight", SINGLE_FLIGHT_WAIT_MS);
                timing?.add("flight-wait", waited);

                // the leader is slow or stuck: one waiter reads npm itself, every later one is told to retry (a 503
                // with Retry-After), so requests that pile up behind a stuck read never each read npm
                if (out.extraTaken) return { kind: "unknown" as const };
                out.extraTaken = true;

                return yield* npmListing({ name, lease, etag, wholeSince, t, readNow, probes });
              }

              if (waited > 0) timing?.add("flight-wait", waited);

              if (wholeSince === null) return yield* npmListing({ name, lease, etag, wholeSince, t, readNow, probes });
              // this read leads: its result is in the isolate's cache before the mark goes (npmListing's probes.set)
              const mark: Flight = { began: t, extraTaken: false };

              refreshing.set(flight, mark);

              // only its own mark: a stale one it replaced may still end later, and must not clear this read's
              return yield* npmListing({ name, lease, etag, wholeSince, t, readNow, probes }).pipe(
                Effect.ensuring(Effect.sync(() => (refreshing.get(flight) === mark ? refreshing.delete(flight) : undefined))),
              );
            }
          });

        /** listedOrSame's read of npm's packument (or a shared copy), for a package the isolate cache does not answer. */
        const npmListing = (input: { name: string; lease: Lease; etag: string | null; wholeSince: number | null; t: number; readNow: number; probes: IsolateCache<CachedProbe> }): Effect.Effect<UpstreamListing | { kind: "over-budget" } | { kind: "not-modified" }> =>
          Effect.gen(function* () {
            const { name, lease, etag, wholeSince, t, readNow, probes } = input;

            // nothing more fits: npm is not asked at all
            if (lease.exhausted) return { kind: "over-budget" as const };
            const url = `${baseUrl}${encodeName(name)}`;

            const answer = yield* fetchPackument({ name, url, now: t, readNow, profile: TRIMMED, lease, etag, wholeSince }).pipe(Effect.orElseSucceed((): PackumentAnswer => ({ kind: "status", status: 0, fetchedAt: t })));

            if (answer.kind === "over-budget") return answer;

            if (answer.kind === "not-modified") return { kind: "not-modified" as const };

            if (answer.kind !== "ok") {
              const gone = packageOf(answer);

              if (gone.kind === "absent") probes.set(name, gone, answer.fetchedAt);

              return gone;
            }

            const { read } = answer;
            const held = packageWeight(read) - read.weight + read.versionCount * SCORED_WEIGHT;
            const moment = packageMoment(read);

            // converting it must fit before anything is built from it, a shared copy included
            if (!lease.take(held + moment)) {
              lease.give(read.weight);

              return { kind: "over-budget" as const };
            }

            const pkg = cachedPackage(name, answer.body, { versionDocs: read.versionDocs, maxPieceChars: read.maxPieceChars }, answer.etag, answer.fetchedAt, answer.readAt);
            lease.give(moment);

            if (!pkg) {
              // nothing of it is held
              lease.give(read.weight + held);

              // a conditional read's 200 that is not a packument is npm failing a small read: marked as its other
              // failures are (re-check of 51fc813); a read refused for room, above, is not
              if (answer.conditional) caches.failures.set(name, true, t);

              return { kind: "unknown" as const };
            }

            const block = lease.seal(packageWeight(read));

            if (answer.fresh) shareCopy({ url, profile: TRIMMED, fetchedAt: answer.fetchedAt, readAt: answer.readAt, body: answer.body, maxPieceChars: read.maxPieceChars, block, pool: lease.pool, etag: answer.etag });
            const fresh: CachedProbe = { kind: "found", pkg };
            // the TTL counts from when npm answered, which for a shared copy is before this request; a big packument
            // takes room from older ones (PROBE_CACHE_WEIGHT)
            probes.set(name, fresh, answer.fetchedAt, block);
            yield* fetched(pkg, block, lease.pool);

            return fresh;
          });

        /** listedOrSame with no ETag, so never "not-modified". */
        const listed = (name: string, lease: Lease): Effect.Effect<UpstreamListing | { kind: "over-budget" }> =>
          Effect.map(listedOrSame(name, lease, null), (l) => (l.kind === "not-modified" ? { kind: "unknown" as const } : l));

        /** The packument as npm lists it, from the isolate cache or npm, without its analyses. */
        const listing = (name: string, lease: Lease): Effect.Effect<UpstreamListing> =>
          // a package that did not fit the lease could not be read: the caller asks again later
          Effect.map(listed(name, lease), (l) => (l.kind === "over-budget" ? { kind: "unknown" as const } : l));

        const probeWithinFor = (name: string, wanted: Wanted, lease: Lease): Effect.Effect<ListedProbe, StoreError> =>
          Effect.gen(function* () {
            const l = yield* listed(name, lease);

            if (l.kind !== "found") return l;
            const analyses = yield* wantedWithin(store, name, l.pkg.versions, wanted(l.pkg), lease);

            // the listing is kept when only its analyses did not fit, so what needs no score is still checked of it
            return analyses === null ? { kind: "unread" as const, pkg: { ...l.pkg, versions: l.pkg.versions.map((v) => scoredVersion(v, NO_ANALYSES)) } } : scoredPackage(l.pkg, analyses);
          });

        const probeFor = (name: string, wanted: Wanted, lease: Lease): Effect.Effect<Probe, StoreError> =>
          Effect.map(probeWithinFor(name, wanted, lease), (p) => (p.kind === "over-budget" || p.kind === "unread" ? { kind: "unknown" as const } : p));

        const probeMany = (names: readonly string[], lease: Lease): Effect.Effect<Map<string, BudgetedProbe>, StoreError> =>
          Effect.gen(function* () {
            const wanted = [...new Set(names)];
            // a few at once: the reads in flight share the lease, so together they keep no more than it allows
            const got = yield* Effect.forEach(wanted, (name) => Effect.map(listed(name, lease), (l) => [name, l] as const), { concurrency: PROBE_CONCURRENCY });
            const found = got.flatMap(([name, l]) => (l.kind === "found" ? [name] : []));
            const scores = yield* store.upstreamAnalysesOf(found);
            const none: UpstreamAnalyses = { scores: new Map(), unscorable: new Map() };

            return new Map(got.map(([name, l]) => [name, l.kind === "found" ? scoredPackage(l.pkg, scores.get(name) ?? none) : l]));
          });

        const summaries = <S>(names: readonly string[], lease: Lease, keep: (pkg: UpstreamPackage, reserve: Reserve) => Summary<S> | null): Effect.Effect<Map<string, Summarized<S>>, StoreError> =>
          Effect.gen(function* () {
            const wanted = [...new Set(names)];
            // read before the packuments, so each package is kept the moment it is read: a name npm has no package for
            // costs an empty row
            const analyses = yield* store.upstreamAnalysesOf(wanted);
            const none: UpstreamAnalyses = { scores: new Map(), unscorable: new Map() };

            /**
             * What `keep` returns for `pkg`, reserved from `lease` by keep as it builds it, beside the scored copy keep
             * is handed: that copy is charged while keep runs unless the read already charged it (`copyCharged`: listed
             * takes it with the package). Both are alive at once, so both are charged at once (review of 2fbf383,
             * finding 3).
             */
            const kept = (name: string, pkg: CachedPackage, copyCharged: boolean): Summarized<S> => {
              const copy = copyCharged ? 0 : pkg.versions.length * SCORED_WEIGHT;

              if (!lease.take(copy)) return { kind: "over-budget" };
              const scored = scoredPackage(pkg, analyses.get(name) ?? none);

              if (scored.kind !== "found") {
                lease.give(copy);

                return { kind: "unknown" };
              }

              const before = lease.taken;
              const made = keep(scored.pkg, lease);
              lease.give(copy);

              if (made === null) return { kind: "over-budget" };
              // a keep that did not reserve all it kept has the rest taken here, so nothing it keeps goes uncounted
              const short = made.weight - (lease.taken + copy - before);

              if (short > 0 && !lease.take(short)) {
                lease.give(made.weight - short);

                return { kind: "over-budget" };
              }

              return { kind: "found", summary: made.summary };
            };

            const one = (name: string): Effect.Effect<Summarized<S>> =>
              Effect.gen(function* () {
                const cached = probeCacheFor(lease.pool, baseUrl, ttlMs).entry(name, yield* now);

                if (cached !== undefined) {
                  if (cached.value.kind !== "found") return cached.value;
                  // pinned while it is kept, so the pool cannot take the cache's block back meanwhile, by a lease with
                  // no limit of its own: the block is already in the pool, so pinning it takes nothing from the
                  // request, whose lease counts only what it keeps
                  const pin = lease.pool.backgroundLease();

                  if (cached.block !== null) pin.hold(cached.block);

                  try {
                    return kept(name, cached.value.pkg, false);
                  } finally {
                    pin.release();
                  }
                }

                // read under a child, which holds the package (and the cache beside it) only until it is kept
                const read = lease.child();

                return yield* Effect.map(listed(name, read), (l): Summarized<S> => (l.kind === "found" ? kept(name, l.pkg, true) : l)).pipe(Effect.ensuring(Effect.sync(() => read.release())));
              });

            const first = yield* Effect.forEach(wanted, (name) => Effect.map(one(name), (s) => [name, s] as const), { concurrency: PROBE_CONCURRENCY });
            const out = new Map<string, Summarized<S>>(first);

            // a name that did not fit beside the reads in flight with it may fit alone, beside only what was kept
            for (const [name, s] of first) if (s.kind === "over-budget") out.set(name, yield* one(name));

            return out;
          });

        /**
         * summaries for a reader that makes named choices of each package's versions (Choice): each package's choices
         * are made of the packument when it is read, and kept (upstream_choices, migration 0021) with npm's strong ETag
         * for it, under the document it was asked for at (this upstream's URL for the package, answered directly). The
         * next read sends that ETag; npm's 304 means the packument is the same, so the same choices hold, and they are
         * answered from the kept row without reading the packument. A package the isolate cache has is chosen from as
         * before. Any other answer is what a read without a row comes to (an outage stays unknown, and never touches
         * the row); a 200 rewrites the row. A row is used only when every choice asked for is in it and younger than
         * KEPT_CHOICES_MAX_AGE_MS (choiceHolds), its age counted from the fetch of the packument it was made of.
         *
         * Keeping is strictly second (re-check of 3366a36, finding 1): the rows read and the rows planned are held on
         * a side lease of the pool (KeptSide), never `lease`, taken only from room the pool has free and given up
         * first under pressure; a row given up while npm was asked means a whole read. Once every package of the batch
         * has its answer, the planned rows are written one at a time, each under a short reservation of `lease` given
         * back before the next (keepPlans). A write that fails is logged and the answer stands.
         */
        const chosen = <S>(input: { names: readonly string[]; lease: Lease; choices: (name: string) => readonly Choice[]; keep: (c: Chosen, reserve: Reserve) => Summary<S> | null; analyses: "whole" | "trimmed"; deadline?: number }): Effect.Effect<Map<string, ChosenAnswer<S>>, StoreError> =>
          Effect.gen(function* () {
            const { lease, choices, keep } = input;
            const wanted = [...new Set(input.names)];
            const t = yield* keptNow;
            const wall = yield* now;
            const documentOf = (name: string): string => `${baseUrl}${encodeName(name)}`;
            const side = KeptSide.open(lease.pool);
            // the side is closed when the batch ends, unless its plans were handed to the writer, which closes it once
            // they are written
            let handedOff = false;

            const batch = Effect.gen(function* () {
              const read = yield* keptRowsWithin({ store, documents: wanted.map(documentOf), side, at: t });
              /** Each name's row, held on the side until the batch ends, or until the pool needs the room. */
              const rows = new Map<string, { row: HeldRow; holding: ReturnType<KeptSide["hold"]> }>();

              for (const name of wanted) {
                const r = read.get(documentOf(name));

                if (r === undefined) continue;

                // a row is used only for a strong validator (finding 3)
                if (!isStrongEtag(r.etag)) {
                  side.give(r.weight);
                  continue;
                }

                rows.set(name, { row: r, holding: side.hold(r.weight, () => rows.delete(name)) });
              }

              // the rows now live only in `rows`, so one the pool takes back is no longer referenced (combined review of
              // 67d8658, finding 1)
              read.clear();

              /** Whether every choice asked of `name` holds in `row` now. */
              const holds = (name: string, row: KeptChoicesRow): boolean => choices(name).every((c) => choiceHolds(row.kept, c.key, t));

              /**
               * The versions each of `name`'s choices took (a map of them by choice key, or null when one is missing), cut
               * down as a row keeps them (summaryVersion) and reserved from `lease`, so the packument they came from can
               * be let go before their analyses are read. `plan`: the row to plan once they are kept, if any. The
               * dist-tags are held by reference until the package is kept, after the packument, the cache's block or the
               * row they came from is let go, so they are reserved with the versions, as the summary's head reserves
               * them (keptHead): a package with tens of thousands of tags otherwise held them uncharged across the
               * analyses' read.
               */
              const pickedOf = (name: string, distTags: Record<string, string>, taken: ReadonlyMap<string, readonly Omit<VersionRecord, "score">[]> | null, plan: Picked["plan"]): Picking => {
                if (taken === null) return { kind: "unknown" };
                const head = keptHead(name, distTags, lease);

                if (head === null) return { kind: "over-budget" };
                const versions = new Map<string, VersionRecord[]>();
                let weight = head.weight;

                for (const [key, vs] of taken) {
                  const cut: VersionRecord[] = [];

                  for (const v of vs) {
                    const one = keptVersion({ ...v, score: null }, lease);

                    if (one === null) {
                      lease.give(weight);

                      return { kind: "over-budget" };
                    }

                    weight += one.weight;
                    cut.push(one.summary);
                  }

                  versions.set(key, cut);
                }

                return { kind: "picked", picked: { name, distTags, versions, weight, plan } };
              };

              /**
               * From a whole package: its choices made of it, with the row to plan once they are kept (one string:
               * keptPlan) when npm gave it a strong ETag and the row is missing, for another packument, or lacks one of
               * these choices or holds it past its age. Each choice is as old as the fetch of `pkg`'s packument
               * (finding 2).
               */
              const fromPackage = (name: string, pkg: CachedPackage): Picking => {
                const held = rows.get(name);
                const etag = pkg.etag;
                const plan = isStrongEtag(etag) && (held === undefined || held.row.etag !== etag || !holds(name, held.row)) ? { etag, at: t - Math.max(0, wall - pkg.fetchedAt) } : null;

                return pickedOf(name, pkg.distTags, new Map(choices(name).map((c) => [c.key, c.choose(pkg)] as const)), plan);
              };

              /** From a kept row npm said still holds: each choice's versions, from the row's records. */
              const fromRow = (name: string, entry: { row: HeldRow; holding: ReturnType<KeptSide["hold"]> }): Picking => {
                const { row } = entry;
                entry.holding.inUse = true;

                try {
                  const byVersion = new Map(Object.values(row.kept.records).map((v) => [v.version, v] as const));
                  const taken = new Map<string, readonly Omit<VersionRecord, "score">[]>();

                  for (const c of choices(name)) {
                    const list = row.kept.lists[c.key]?.versions ?? [];
                    const records = list.flatMap((v) => byVersion.get(v) ?? []);

                    if (records.length !== list.length) return pickedOf(name, row.kept.distTags, null, null);
                    taken.set(c.key, records);
                  }

                  return pickedOf(name, row.kept.distTags, taken, null);
                } finally {
                  entry.holding.inUse = false;
                }
              };

              /** One read of `name` from npm (with `etag`, a conditional one), picked from while what it read is held. */
              const readOnce = (name: string, etag: string | null): Effect.Effect<Picking | "row-gone"> =>
                Effect.suspend(() => {
                  const readLease = lease.child();

                  return Effect.map(listedOrSame(name, readLease, etag), (l): Picking | "row-gone" => {
                    if (l.kind === "not-modified") {
                      const entry = rows.get(name);

                      return entry === undefined ? "row-gone" : fromRow(name, entry);
                    }

                    return l.kind === "found" ? fromPackage(name, l.pkg) : l;
                  }).pipe(Effect.ensuring(Effect.sync(() => readLease.release())));
                });

              const one = (name: string): Effect.Effect<Picking> =>
                Effect.gen(function* () {
                  const cached = probeCacheFor(lease.pool, baseUrl, ttlMs).entry(name, yield* now);

                  if (cached !== undefined) {
                    if (cached.value.kind !== "found") return cached.value;
                    const pin = lease.pool.backgroundLease();

                    if (cached.block !== null) pin.hold(cached.block);

                    try {
                      return fromPackage(name, cached.value.pkg);
                    } finally {
                      pin.release();
                    }
                  }

                  const entry = rows.get(name);
                  const got = yield* readOnce(name, entry !== undefined && holds(name, entry.row) ? entry.row.etag : null);

                  // the row was given up to the pool while npm was asked: the packument is read whole
                  if (got !== "row-gone") return got;
                  const again = yield* readOnce(name, null);

                  return again === "row-gone" ? { kind: "unknown" as const } : again;
                });

              /**
               * one, stopped at the batch's deadline: interrupting it cancels its read (joinedPromise) and gives back
               * its lease. A package picked from before then is kept.
               */
              const inTime = (name: string): Effect.Effect<Picking> => {
                const deadline = input.deadline;

                if (deadline === undefined) return one(name);

                return Effect.suspend(() => {
                  const left = deadline - Date.now();

                  if (left <= 0) return Effect.succeed({ kind: "out-of-time" as const });

                  return Effect.map(Effect.timeoutOption(one(name), Duration.millis(left)), (o): Picking => Option.getOrElse(o, () => ({ kind: "out-of-time" as const })));
                });
              };

              const first = yield* Effect.forEach(wanted, (name) => Effect.map(inTime(name), (p) => [name, p] as const), { concurrency: PROBE_CONCURRENCY });
              const picks = new Map<string, Picking>(first);

              // a package that did not fit beside the others is read again alone: only the others' picks are in its way
              for (const [name, p] of first) if (p.kind === "over-budget") picks.set(name, yield* inTime(name));

              // every package is picked from: no row is needed any more
              for (const entry of rows.values()) side.letGo(entry.holding);
              rows.clear();
              const picked = [...picks.values()].flatMap((p) => (p.kind === "picked" ? [p.picked] : []));

              // the analyses of exactly the versions picked, in one statement: what is read grows with the versions the
              // choices took, never with a package's history (next: 61 analyses, 16 MB, for the one version a range picks).
              // A version with no checksum is asked for too: its outcome (unavailable) is read by version
              const keys = picked.flatMap((p) =>
                [...p.versions.values()].flat().map((v) => {
                  const d = digestOf(v);

                  return { package: p.name, version: v.version, digest: d ? digestLabel(d) : null, trimmed: input.analyses === "trimmed" };
                }),
              );

              // the statement sends only the analyses that fit the lease's headroom, smallest first, so the reply is
              // bounded before it is sent; on 216a4c7 it was held, parsed and kept with the tree charged to nothing
              const pickedWeight = picked.reduce((n, p) => n + p.weight, 0);

              picked.length = 0;
              first.length = 0;
              const allowance = lease.takeUpTo(ANALYSES_READ_ALLOWANCE, ANALYSES_READ_MIN);
              const got = yield* store.upstreamAnalysesWithin({ keys, allowance, weights: KEPT_TEXT_WEIGHTS }).pipe(Effect.onError(() => Effect.sync(() => lease.give(pickedWeight + allowance))));

              // settled to what the reply holds: given back, and what each package keeps taken again at once
              lease.give(allowance);
              /** What each package's analyses hold once read, taken from `lease` while its answer holds them. */
              const held = new Map<string, number>();
              /**
               * Packages whose analyses were not all read, or did not fit once read: kept without any of them, and
               * answered "unread", so a reader still knows which versions it picked (and checks what needs no score)
               * but never takes one for a version with no score.
               */
              const unread = new Set(got.omitted);

              for (const [name, sizes] of got.sizes) {
                const weight = sizes.reduce((n, s) => n + parsedWeight(s), 0);

                if (!unread.has(name) && lease.take(weight)) held.set(name, weight);
                else unread.add(name);
              }

              for (const name of unread) got.analyses.delete(name);

              const plans: PlanHandle[] = [];

              /** keep, handed the versions picked of `p` scored, with their scored copies charged while it runs. */
              const kept = (p: Picked): Summarized<S> => {
                const a = got.analyses.get(p.name) ?? NO_ANALYSES;
                const copy = [...p.versions.values()].reduce((n, vs) => n + vs.length, 0) * SCORED_WEIGHT;

                if (!lease.take(copy)) return { kind: "over-budget" };
                const versions = new Map([...p.versions].map(([key, vs]) => [key, vs.map((v) => scoredVersion(v, a))] as const));
                const before = lease.taken;
                const made = keep({ name: p.name, distTags: p.distTags, versions }, lease);
                lease.give(copy);

                if (made === null) return { kind: "over-budget" };
                const short = made.weight - (lease.taken + copy - before);

                if (short > 0 && !lease.take(short)) {
                  lease.give(made.weight - short);

                  return { kind: "over-budget" };
                }

                if (p.plan !== null) {
                  const plan = keptPlan({ document: documentOf(p.name), etag: p.plan.etag, distTags: p.distTags, versions, reserve: side, at: p.plan.at });

                  if (plan !== null) plans.push(side.holdPlan(plan));
                }

                return { kind: "found", summary: made.summary };
              };

              const again: Picked[] = [];

              /**
               * kept, handed `p`'s picks: their charge is given back as keep starts, since keep reserves all it keeps of
               * them itself, as it did of a whole package, and taken again when it did not fit, for one more try alone.
               * Its caller lets go of `p` as it settles it, so past keep nothing refers to what was given back (Sol on
               * fb84083: the picks stayed reachable from the batch while later packages and plans were kept).
               */
              const settled = (p: Picked, last: boolean): ChosenAnswer<S> => {
                lease.give(p.weight);
                const answer = kept(p);

                if (answer.kind === "over-budget" && !last && lease.take(p.weight)) {
                  again.push(p);

                  return answer;
                }

                // a package not kept lets go of its analyses with its answer: nothing refers to them past here
                if (answer.kind !== "found") {
                  got.analyses.delete(p.name);
                  lease.give(held.get(p.name) ?? 0);
                  held.delete(p.name);

                  return answer;
                }

                return unread.has(p.name) ? { kind: "unread", summary: answer.summary } : answer;
              };

              const out = new Map<string, ChosenAnswer<S>>();

              // each pick is let go of as it is settled, so what its charge was given back for is referred to no more
              for (const [name, p] of picks) {
                picks.delete(name);
                out.set(name, p.kind === "picked" ? settled(p.picked, false) : p);
              }

              // a package whose answer did not fit beside the others is kept again alone, once every other is
              for (let p = again.shift(); p !== undefined; p = again.shift()) out.set(p.name, settled(p, true));

              if (plans.length === 0) return out;
              const writer = yield* Effect.serviceOption(ChoicesWriter);

              // the planned rows are written after the response, on a connection and a lease of their own, the side
              // holding them until then (combined review of 67d8658, finding 4); without a writer (no Worker request),
              // now, each under a short reservation of `lease`
              if (Option.isSome(writer)) {
                handedOff = true;
                yield* writer.value.later(
                  Effect.gen(function* () {
                    yield* keepPlans({ store: yield* Store, plans, at: t, lease: yield* RequestMemory });
                  }).pipe(Effect.ensuring(Effect.sync(() => side.close()))),
                );
              } else yield* keepPlans({ store, plans, at: t, lease });

              return out;
            });

            return yield* batch.pipe(
              Effect.ensuring(
                Effect.sync(() => {
                  if (!handedOff) side.close();
                }),
              ),
            );
          });

        /**
         * Each version's devDependencies as npm lists them, read apart (DEV_DEPENDENCIES) and never kept in the isolate.
         * Converting them is charged (packageMoment) before it is done, and stays charged with the read while the
         * request holds the answer.
         */
        const devDependencies = (name: string, lease: Lease): Effect.Effect<DevDependencyRead | null> =>
          Effect.gen(function* () {
            const t = yield* now;
            const url = `${baseUrl}${encodeName(name)}`;
            const answer = yield* fetchPackument({ name, url, now: t, readNow: yield* keptNow, profile: DEV_DEPENDENCIES, lease }).pipe(Effect.orElseSucceed(() => null));

            if (answer?.kind !== "ok") return null;
            const { read } = answer;
            const moment = packageMoment(read);

            if (!lease.take(moment)) {
              lease.give(read.weight);

              return null;
            }

            const parsed = DevDependencies.safeParse(answer.body);

            if (!parsed.success) {
              lease.give(read.weight + moment);

              return null;
            }

            const byVersion = new Map<string, unknown>();

            for (const [version, doc] of Object.entries(parsed.data.versions)) {
              const one = DevDocument.safeParse(doc);

              if (one.success && one.data.devDependencies !== undefined) byVersion.set(version, one.data.devDependencies);
            }

            if (answer.fresh) {
              const block = lease.seal(read.weight + moment);
              shareCopy({ url, profile: DEV_DEPENDENCIES, fetchedAt: answer.fetchedAt, readAt: answer.readAt, body: answer.body, maxPieceChars: read.maxPieceChars, block, pool: lease.pool, etag: answer.etag });
            }

            return { byVersion, maxPieceChars: read.maxPieceChars };
          });

        const installCopy = <A, E>(input: { name: string; served: string; lease: Lease; read: Effect.Effect<A, E>; stampOf: (read: A) => string | null }): Effect.Effect<{ read: A; copy: InstallCopy | null }, E> =>
          Effect.gen(function* () {
            const { name, lease } = input;
            const t = yield* now;
            // npm's packument must have been read whole since `since`, by the registry's clock (tests move it): the
            // copy, and any packument this path builds a copy from (the isolate's, a shared copy), counts from that
            // read, whatever the upstream TTL. Past it the packument is read whole from npm, which runs what a whole
            // read runs (`fetched`: the AI review's look at new versions, retried there when it failed). A 304 never
            // makes anything younger, nor does making a copy again from what was read before
            const at = yield* keptNow;
            const since = at - KEPT_CHOICES_MAX_AGE_MS;
            // the copy's body while this holds it unanswered: cancelled on every way out that does not hand it on
            let held: ReadableStream<Uint8Array> | null = null;

            const drop = Effect.promise(async () => {
              const body = held;

              held = null;
              await body?.cancel().catch(() => undefined);
            });

            // the copy and whether npm's packument is still the one it was made from, found while the database is read
            // (it does not need the stamp); a whole read, which runs the AI review's hook, waits for the database
            const look = Effect.gen(function* () {
              const copyStart = performance.now();
              // the lookup within CACHE_MATCH_MS, and the copy used only if its first bytes come within
              // CACHE_FIRST_BYTE_MS (then CACHE_IDLE_MS between chunks): past either it is no copy, and the document is
              // made from npm's packument as for a miss
              const lookup = sharing ? yield* Effect.promise(() => matchWithin({ cache: workerCache(), key: installKey({ upstream: baseUrl, served: input.served, name }), operation: "install-copy" })) : null;
              const hit = lookup?.kind === "hit" ? lookup.res : undefined;
              held = hit?.body ?? null;
              const etag = npmEtag(hit?.headers.get(ETAG_HEADER) ?? null);
              const sentAt = Number(hit?.headers.get(FETCHED_AT_HEADER) ?? Number.NaN);
              const readAt = readTime(hit?.headers.get(INSTALL_READ_AT_HEADER) ?? null);
              const stamp = hit?.headers.get(INSTALL_STAMP_HEADER) ?? null;
              const usable = hit !== undefined && etag !== null && stamp !== null && wholeReadCounts(readAt, since, at) && hit.headers.get(INSTALL_FORMAT_HEADER) === INSTALL_COPY_FORMAT;
              const source = held;

              // the copy's first bytes, taken now: a copy whose body does not start is no copy
              if (usable && source !== null) held = yield* primedCopy(source, "install-copy-body");

              if (sharing) timing?.add("install-copy", performance.now() - copyStart);

              if (!usable || held === null || etag === null || stamp === null) {
                yield* drop;

                return { kind: "none" } as const;
              }

              // npm sent it within the TTL, or said it is current within the TTL: no need to ask
              if ((Number.isFinite(sentAt) && t - sentAt >= 0 && t - sentAt < ttlMs) || caches.validated.get(name, t) === etag) return { kind: "copy", stamp } as const;
              const l = yield* listedOrSame(name, lease, etag, since);

              if (l.kind === "not-modified" || (l.kind === "found" && l.pkg.etag === etag)) {
                caches.validated.set(name, etag, t);

                return { kind: "copy", stamp } as const;
              }

              yield* drop;

              return { kind: "read", listing: l } as const;
            });

            const [read, found] = yield* Effect.all([input.read, look], { concurrency: "unbounded" }).pipe(Effect.onError(() => drop));
            const stamp = input.stampOf(read);

            if (stamp === null) {
              yield* drop;

              return { read, copy: null };
            }

            if (found.kind === "copy" && found.stamp === stamp && held !== null) {
              const body: ReadableStream<Uint8Array> = held;

              held = null;

              return { read, copy: { kind: "copy", body } };
            }

            yield* drop;

            if (found.kind === "read") return { read, copy: { kind: "read", listing: found.listing } };
            const listing = yield* listedOrSame(name, lease, null, since).pipe(Effect.map((l) => (l.kind === "not-modified" ? { kind: "unknown" as const } : l)));

            return { read, copy: { kind: "read", listing } };
          });

        const keepInstallCopy = (input: { name: string; served: string; stamp: string; pkg: CachedPackage; write: InstallWriter; ready: Effect.Effect<void, StoreError>; onDone: () => void }): Effect.Effect<void> =>
          Effect.gen(function* () {
            const etag = npmEtag(input.pkg.etag);
            // the time of the whole read the package was made of, carried as it is: never made younger here
            const readAt = input.pkg.readAt;

            if (!sharing || background === null || etag === null || !Number.isFinite(readAt) || Exit.isFailure(yield* Effect.exit(input.ready))) {
              input.onDone();

              return;
            }

            const signal = AbortSignal.timeout(SHARE_TIMEOUT_MS);

            const headers = {
              "content-type": "application/vnd.npm.install-v1+json; charset=utf-8",
              "cache-control": `public, max-age=${INSTALL_COPY_MAX_AGE_S}`,
              [FETCHED_AT_HEADER]: String(input.pkg.fetchedAt),
              [INSTALL_READ_AT_HEADER]: String(readAt),
              [ETAG_HEADER]: etag,
              [INSTALL_STAMP_HEADER]: input.stamp,
              [INSTALL_FORMAT_HEADER]: INSTALL_COPY_FORMAT,
            };
            // stopped at SHARE_TIMEOUT_MS: the stream then drops the body, and its holder may let go before the put settles

            const copy = input.write(headers, { signal, onDone: () => (signal.aborted ? input.onDone() : undefined) });

            const put = workerCache()
              .put(installKey({ upstream: baseUrl, served: input.served, name: input.name }), copy)
              .catch(() => undefined)
              .finally(input.onDone);

            background(waitBounded(put, "install-copy-put"));
          });

        const api: UpstreamApi = {
          baseUrl,
          search: (text, size) =>
            Effect.gen(function* () {
              const key = `${size}\u0000${text}`;
              const t = yield* now;
              const hit = caches.searches.get(key, t);

              if (hit) return hit;
              const result = yield* fetchSearch(text, size);

              // Failures are not cached, so the next keystroke retries.
              if (result.kind === "ok") caches.searches.set(key, result, t);

              return result;
            }),
          scopeExists: (scope) =>
            Effect.gen(function* () {
              const t = yield* now;
              const hit = caches.scopes.get(scope, t);

              if (hit) return hit;

              // npm answers /-/org/<scope>/package for user and org scopes alike: 200 with a map of packages, or 404.
              const answer = yield* fetchJson(`${baseUrl}-/org/${encodeURIComponent(scope)}/package`, 5_000).pipe(
                Effect.map(({ status, body }): "found" | "absent" | "unknown" => {
                  if (status === 404) return "absent";

                  if (status !== 200) return "unknown";
                  const map = z.record(z.string(), z.unknown()).safeParse(body);

                  return map.success ? (Object.keys(map.data).length > 0 ? "found" : "absent") : "unknown";
                }),
                Effect.orElseSucceed(() => "unknown" as const),
              );

              if (answer !== "unknown") caches.scopes.set(scope, answer, t);

              return answer;
            }),
          probeFor,
          probeWithinFor,
          listing,
          listingIfChanged: listedOrSame,
          installCopy,
          keepInstallCopy,
          versionOf: (name, version) =>
            Effect.gen(function* () {
              const key = `${name}@${version}`;
              const t = yield* now;
              const hit = caches.versions.get(key, t);

              if (hit !== undefined) return hit;

              // npm just failed a small read for this package: not asked again, the caller reads the packument
              if (caches.failures.get(name, t) !== undefined) return { kind: "unknown" } satisfies UpstreamVersion;

              const got = yield* Effect.promise(async (): Promise<UpstreamVersion> => {
                const start = performance.now();

                try {
                  const res = await fetch(`${baseUrl}${encodeName(name)}/${encodeURIComponent(version)}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(NPM_SMALL_READ_TIMEOUT_MS) });

                  if (res.status !== 200) {
                    await res.body?.cancel();

                    return res.status === 404 ? { kind: "absent" } : { kind: "unknown" };
                  }

                  const bytes = await readCapped(res, MAX_VERSION_DOC_BYTES);
                  const doc = bytes === null ? null : VersionDist.safeParse(JSON.parse(new TextDecoder().decode(bytes)));

                  if (!doc?.success) return { kind: "unknown" };

                  // npm answers a range or a dist-tag here with the version it resolves to: only the exact one is this version
                  if (doc.data.version !== version) return { kind: "absent" };
                  const { dist } = doc.data;

                  return { kind: "found", tarball: dist.tarball ?? "", integrity: dist.integrity ?? "", shasum: dist.shasum ?? "" };
                } catch {
                  return { kind: "unknown" };
                } finally {
                  timing?.add("npm-version", performance.now() - start);
                }
              });

              if (got.kind === "unknown") caches.failures.set(name, true, t);
              else caches.versions.set(key, got, t);

              return got;
            }),
          probeMany,
          summaries,
          chosen,
          devDependencies,
          get: (name, lease) => Effect.map(probeFor(name, () => new Map(), lease), (p) => (p.kind === "found" ? p.pkg : null)),
          tarball: (pkg, version) =>
            Effect.gen(function* () {
              const at = locate(pkg, version);

              if (at.kind !== "found") return at;
              const cached = yield* cachedCopy(at.digest);

              if (cached) return { kind: "ok", bytes: cached, digest: at.digest } as const;
              const got = yield* Effect.promise(() => download(at.url));

              if (got.kind !== "ok") return got;

              return yield* verified(got.bytes, at.digest);
            }),
          serve: (pkg, version) =>
            Effect.gen(function* () {
              const at = locate(pkg, version);

              if (at.kind !== "found") return at;
              const cached = yield* cachedCopy(at.digest);

              if (cached) return { kind: "ok", bytes: cached, digest: at.digest } as const;
              const opened = yield* Effect.promise(() => open(at.url));

              if (opened.kind !== "ok") return opened;
              const declared = declaredLength(opened.res);

              // small enough to analyze: held, checked and cached as the analysis would, so its bytes are fetched once
              if (declared === null || declared <= MAX_UPSTREAM_TARBALL_BYTES) {
                const bytes = yield* Effect.promise(() => gather(opened));

                if (bytes) return yield* verified(bytes, at.digest);
                // no length declared and more than the cap sent: asked again, to stream from the start
                const again = yield* Effect.promise(() => open(at.url));

                if (again.kind !== "ok") return again;
                again.release();

                return streamed(again.res, at.digest, declaredLength(again.res));
              }

              opened.release();

              return streamed(opened.res, at.digest, declared);
            }),
          openTarballUrl: (url) =>
            Effect.callback<OpenedUpstream>((resume) => {
              const start = performance.now();

              const pending = open(url).then((opened): OpenedUpstream => {
                timing?.add("npm-open", performance.now() - start);

                if (opened.kind !== "ok") return opened;
                // a stream's deadline ends once the answer has come: a client may take longer to read it
                opened.release();

                return { kind: "open", res: opened.res };
              });

              pending.then((opened) => resume(Effect.succeed(opened)));

              // interrupted (a check failed while it was opening): its answer is cancelled once it comes, and the fiber
              // ends after that, so no opened answer is left unread
              return Effect.promise(() => pending.then((opened) => (opened.kind === "open" ? opened.res.body?.cancel() : undefined)));
            }),
          openTarball: (pkg, version) =>
            Effect.gen(function* () {
              const at = locate(pkg, version);

              if (at.kind !== "found") return at;
              // R2 past its deadline or failing is a miss here too: npm's answer is opened instead
              const cached = yield* cacheRead(blobs.stream(upstreamBlobKey(at.digest)));

              if (Option.isSome(cached)) return { kind: "stream", body: cached.value.body, length: cached.value.size, digest: at.digest } as const;
              const opened = yield* Effect.promise(() => open(at.url));

              if (opened.kind !== "ok") return opened;
              // the reader keeps its own deadlines: tens of megabytes may take longer than a download's 30 s
              opened.release();

              return { kind: "stream", body: opened.res.body ?? new ReadableStream<Uint8Array>({ start: (c) => c.close() }), length: declaredLength(opened.res), digest: at.digest } as const;
            }),
          advisories: (body) =>
            fetchJson(`${baseUrl}-/npm/v1/security/advisories/bulk`, 10_000, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(body),
            }).pipe(
              Effect.map(({ status, body: answer }): UpstreamAdvisories => {
                if (status !== 200) return { kind: "unavailable" };
                const parsed = z.record(z.string(), z.array(z.unknown())).safeParse(answer);

                return parsed.success ? { kind: "ok", advisories: parsed.data } : { kind: "unavailable" };
              }),
              Effect.orElseSucceed((): UpstreamAdvisories => ({ kind: "unavailable" })),
            ),
          audits: (endpoint, body) =>
            Effect.tryPromise(async (): Promise<UpstreamAuditProxy> => {
              const res = await fetch(`${baseUrl}-/npm/v1/security/${endpoint}`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body,
                signal: AbortSignal.timeout(10_000),
              });

              if (res.status !== 200) {
                await res.body?.cancel();

                return { kind: "unavailable" };
              }

              const text = await res.text();

              return { kind: "ok", body: text, contentType: res.headers.get("content-type") ?? "application/json" };
            }).pipe(Effect.orElseSucceed((): UpstreamAuditProxy => ({ kind: "unavailable" }))),
        };

        return Upstream.of(api);
      }),
    );
  }
}
