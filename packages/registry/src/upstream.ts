// Read-only proxy of a public registry (registry.npmjs.org in production). Packuments are fetched on demand
// and rewritten so tarballs flow through apm, where they are verified, cached in R2 and scored.
import { Context, Effect, Layer, Option } from "effect";
import { z } from "zod";
import { Blobs } from "./blobs.ts";
import { digestLabel, digestOf, type Digest } from "./digest.ts";
import { Store, type UpstreamAnalyses, type VersionRecord } from "./db.ts";
import type { BlobError, StoreError } from "./errors.ts";
import { ReleaseHooks } from "./hooks.ts";
import { readCapped, streamedJson, streamWeight } from "./http.ts";
import { CACHE_WEIGHT, type Block, type Lease, type MemoryPool } from "./memory.ts";
import { DEV_DEPENDENCIES, readPackument, TRIMMED, type KeepProfile, type KeptPackument, type PackumentRead } from "./packument-read.ts";
import { timingOrNull } from "./timing.ts";
import { reviewSummary, type Summary } from "./walk-catalog.ts";
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
    time: z.record(z.string(), z.string()).default({}),
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
};

/** "unknown" means the upstream could not be asked; it is never treated as "absent". */
export type Probe = { kind: "found"; pkg: UpstreamPackage } | { kind: "absent" } | { kind: "unknown" };

/**
 * A probe made under a request's lease (memory.ts): "over-budget" when the request already holds as much package
 * metadata as it may, or the isolate does, so this one was not read (or not kept). Not the same as "unknown": npm may
 * well have answered.
 */
export type BudgetedProbe = Probe | { kind: "over-budget" };

/** A summaries answer for one name: BudgetedProbe, with what the caller kept in place of the package. */
export type Summarized<S> = { kind: "found"; summary: S } | { kind: "absent" } | { kind: "unknown" } | { kind: "over-budget" };

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
 * The largest upstream tarball apm downloads. A Worker has 128 MB of memory, and analysis inflates the
 * tarball next to it; larger packages are reported as unavailable to score, never as clean.
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

/** Upstream answers that may succeed when asked again. */
function isTransientStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

export type UpstreamAdvisories = { kind: "ok"; advisories: Record<string, unknown[]> } | { kind: "unavailable" };

/** npm serves packuments from registry.npmjs.org and tarballs from the same host. */
const NPM_ORIGIN = "https://registry.npmjs.org";
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_HOPS = 5;

/** The parsed packument without apm's scores; scores are attached per request from the store. */
export type CachedPackage = Omit<UpstreamPackage, "versions"> & { versions: Omit<VersionRecord, "score">[] };

type CachedProbe = { kind: "found"; pkg: CachedPackage } | { kind: "absent" };

/** The package as npm lists it, without apm's scores: what a route needs that reads only versions and checksums. */
export type UpstreamListing = CachedProbe | { kind: "unknown" };

/**
 * The package apm caches, read from the packument readPackument kept: each version npm lists with a valid document,
 * in publish order. Null when the packument is not one.
 */
export function cachedPackage(name: string, body: KeptPackument, serveCost: ServeCost): CachedPackage | null {
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
      published_by: doc._npmUser?.name ?? "upstream",
      deprecated: typeof doc.deprecated === "string" && doc.deprecated !== "" ? doc.deprecated : null,
      status: "active",
      status_reason: null,
      status_at: null,
      status_by: null,
    });
  }

  // npm has no insert order: an upstream version's seq is its place in publish order
  const ordered = versions.toSorted((a, b) => a.published_at - b.published_at).map((v, seq) => ({ ...v, seq }));

  return {
    name,
    distTags: raw["dist-tags"],
    description: raw.description ?? "",
    readme: raw.readme ?? "",
    maintainers: (raw.maintainers ?? []).map((m) => m.name),
    versions: ordered,
    tarballs,
    serveCost,
  };
}

/**
 * A cached package with its analyses: an analysis counts only for the exact bytes it read, by the current scorer; a
 * version it decided it can never score says why.
 */
export function scoredPackage(pkg: CachedPackage, { scores, unscorable }: UpstreamAnalyses): Probe {
  return {
    kind: "found",
    pkg: {
      ...pkg,
      versions: pkg.versions.map((v) => {
        const d = digestOf(v);
        const score = d ? (scores.get(`${v.version} ${digestLabel(d)}`) ?? null) : null;
        const why = score === null ? unscorable.get(v.version) : undefined;

        return why ? { ...v, score, unscorable: why } : { ...v, score };
      }),
    },
  };
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
};

const isolateCaches = new Map<string, Caches>();

function cachesFor(baseUrl: string, ttlMs: number): Caches {
  const key = `${ttlMs} ${baseUrl}`;
  const known = isolateCaches.get(key);

  if (known) return known;
  const made: Caches = { searches: new IsolateCache(ttlMs), scopes: new IsolateCache(ttlMs) };
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
 * "over-budget": the lease had no room for it.
 */
type PackumentAnswer =
  | { kind: "ok"; body: KeptPackument; fetchedAt: number; read: Extract<PackumentRead, { kind: "ok" }>; fresh: boolean }
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
   * The package with its analyses, read under `lease` (memory.ts): what it holds stays taken from the lease until the
   * lease closes. Every read of a packument takes a lease; a package that does not fit is "unknown" here.
   */
  readonly probe: (name: string, lease: Lease) => Effect.Effect<Probe, StoreError>;
  /** probe, with "over-budget" kept apart from "unknown" (a walk, a scan: one child lease per package). */
  readonly probeWithin: (name: string, lease: Lease) => Effect.Effect<BudgetedProbe, StoreError>;
  /** Like probe, with no scores, so it reads nothing from the database: the existence check and the review's version lookup. */
  readonly listing: (name: string, lease: Lease) => Effect.Effect<UpstreamListing>;
  /**
   * probe for several names: their packuments (from cache or npm, a few at once) and one read of their analyses. Every
   * packument kept counts against `lease`, cached ones included, and a name past it is "over-budget".
   */
  readonly probeMany: (names: readonly string[], lease: Lease) => Effect.Effect<Map<string, BudgetedProbe>, StoreError>;
  /**
   * probeMany for a caller that needs only part of each package (the resolve walk, its root, a scan): `keep` is handed
   * each package with its analyses as soon as it is read, and only what it returns stays taken from `lease`. A package
   * the isolate cache has stays the cache's: it is never held by `lease`, and is pinned while it is kept so the pool
   * cannot take it back meanwhile. One read from npm is held under a child of `lease` only while it is converted and
   * kept, then left to the isolate cache (which keeps it if it fits, beside older entries). Names
   * that did not fit beside the others read at the same time are read again one at a time. `keep` must return
   * nothing that refers to the package, or that memory would be held with nothing counting it.
   */
  readonly summaries: <S>(names: readonly string[], lease: Lease, keep: (pkg: UpstreamPackage) => Summary<S>) => Effect.Effect<Map<string, Summarized<S>>, StoreError>;
  /**
   * Each version's devDependencies, read apart from the packument the registry keeps (DEV_DEPENDENCIES): only the full
   * packument apm serves adds them back. Null when npm could not be asked, the read was refused, or it did not fit
   * `lease` (the request's, beside the packument it holds); what it weighs stays taken from `lease`.
   */
  readonly devDependencies: (name: string, lease: Lease) => Effect.Effect<DevDependencyRead | null>;
  /** The package when upstream has it; null when it is absent, upstream cannot be asked, or it does not fit `lease`. */
  readonly get: (name: string, lease: Lease) => Effect.Effect<UpstreamPackage | null, StoreError>;
  /**
   * The tarball of a version the upstream lists right now, verified against its published checksum. Cached in
   * the blob store by that checksum and verified again on every read, so a removed version or tampered bytes
   * are never served.
   */
  readonly tarball: (pkg: UpstreamPackage, version: string) => Effect.Effect<UpstreamTarball, BlobError>;
  /** Forwards an advisory bulk request. A failure is "unavailable", never an empty (clean) answer. */
  readonly advisories: (body: unknown) => Effect.Effect<UpstreamAdvisories>;
};

/** Each version's devDependencies (DEV_DEPENDENCIES), and the longest version document of that read as JSON. */
export type DevDependencyRead = { readonly byVersion: ReadonlyMap<string, unknown>; readonly maxPieceChars: number };

/**
 * How long a copy written to the data center's cache may take. Past it the write is stopped (its stream errors, so no
 * partial copy is kept) and what it held is given back.
 */
const SHARE_TIMEOUT_MS = 20_000;

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
  static layer(baseUrl: string, ttlMs: number = DEFAULT_TTL_MS, background: ((work: Promise<void>) => void) | null = null): Layer.Layer<Upstream, never, Store | Blobs> {
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

        /** GET from the upstream's own origin (or npm's) only; each redirect hop is checked before it is followed. */
        const download = async (raw: string): Promise<{ kind: "ok"; bytes: Uint8Array } | Extract<UpstreamTarball, { kind: "unavailable" | "too-large" }>> => {
          let current: URL;

          try {
            current = new URL(raw);
          } catch {
            return { kind: "unavailable", reason: "the upstream lists a malformed tarball URL", retryable: false };
          }

          for (let hop = 0; hop <= MAX_HOPS; hop++) {
            if (!origins.has(current.origin)) return { kind: "unavailable", reason: `refusing to fetch a tarball from ${current.origin}, which is not the upstream registry`, retryable: false };
            let res: Response;

            try {
              res = await fetch(current, { redirect: "manual", signal: AbortSignal.timeout(30_000) });
            } catch {
              return { kind: "unavailable", reason: "the tarball download failed", retryable: true };
            }

            if (REDIRECTS.has(res.status)) {
              await res.body?.cancel();
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

              return { kind: "unavailable", reason: `the upstream answered ${res.status}`, retryable: isTransientStatus(res.status) };
            }

            const declared = Number(res.headers.get("content-length") ?? 0);

            if (declared > MAX_UPSTREAM_TARBALL_BYTES) {
              await res.body?.cancel();

              return { kind: "too-large", bytes: declared };
            }

            const bytes = await readCapped(res, MAX_UPSTREAM_TARBALL_BYTES);

            if (!bytes) return { kind: "too-large", bytes: null };

            return { kind: "ok", bytes };
          }

          return { kind: "unavailable", reason: "too many redirects", retryable: false };
        };

        const now = Effect.sync(() => Date.now());

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
        const answerOf = (url: string, read: PackumentRead, fetchedAt: number, fresh: boolean): PackumentAnswer => {
          if (read.kind === "ok") return { kind: "ok", body: read.body, fetchedAt, read, fresh };

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
         */
        const fetchPackument = (input: { url: string; now: number; profile: KeepProfile; lease: Lease }): Effect.Effect<PackumentAnswer, unknown> =>
          // an interrupted read (a sibling of a parallel lookup failed, the request ended) cancels its stream and gives
          // its charge back before the fiber ends, so the lease is never released under it
          joinedPromise(async (interrupted): Promise<PackumentAnswer> => {
            const { url, now, profile, lease } = input;
            const key = packumentKey(url, profile);
            const shared = sharing ? workerCache() : null;
            const cacheStart = performance.now();
            const hit = shared ? await shared.match(key).catch(() => undefined) : undefined;
            // a copy with no time (written before copies carried one) or past its TTL is not used
            const sentAt = Number(hit?.headers.get(FETCHED_AT_HEADER) ?? Number.NaN);

            if (hit?.body && Number.isFinite(sentAt) && now - sentAt >= 0 && now - sentAt < ttlMs) {
              const read = await readPackument(hit.body, { profile, lease, signal: interrupted });
              timing?.add("npm-cache", performance.now() - cacheStart);

              return answerOf(url, read, sentAt, false);
            }

            await hit?.body?.cancel();
            const npmStart = performance.now();
            const signal = AbortSignal.any([interrupted, AbortSignal.timeout(10_000)]);
            const res = await fetch(url, { headers: { accept: "application/json" }, signal });

            if (res.status !== 200 || !res.body) {
              await res.body?.cancel();
              timing?.add("npm", performance.now() - npmStart);

              return { kind: "status", status: res.status === 200 ? 502 : res.status, fetchedAt: now };
            }

            const read = await readPackument(res.body, { profile, lease, signal });
            timing?.add("npm", performance.now() - npmStart);

            return answerOf(url, read, now, true);
          });

        /**
         * Gives the data center's cache a copy of a packument npm just sent, written a version at a time as it is put,
         * so it is never held whole as one string. The write is background work with a lease of its own: it holds
         * `block` (the memory the copy is written from) and what serializing it takes (streamWeight) until the put
         * settles or is stopped (SHARE_TIMEOUT_MS, or its lease's deadline). Nothing is written when that does not
         * fit (review of 6862fc7, finding 3).
         */
        const shareCopy = (input: { url: string; profile: KeepProfile; fetchedAt: number; body: KeptPackument; maxPieceChars: number; block: Block; pool: MemoryPool }): void => {
          if (!sharing || background === null) return;
          const work = input.pool.backgroundLease();

          if (!work.hold(input.block) || !work.take(streamWeight(input.maxPieceChars))) {
            work.release();

            return;
          }

          const done = (): void => work.release();
          const headers = { "content-type": "application/json", "cache-control": `public, max-age=${Math.floor(ttlMs / 1000)}`, [FETCHED_AT_HEADER]: String(input.fetchedAt) };
          // stopped at SHARE_TIMEOUT_MS, or at the lease's deadline: the stream then drops the package, and only that
          // lets the lease go before the put settles
          const signal = AbortSignal.any([work.signal, AbortSignal.timeout(SHARE_TIMEOUT_MS)]);
          const copy = streamedJson(input.body, "versions", headers, { signal, onDone: () => (signal.aborted ? done() : undefined) });

          background(
            workerCache()
              .put(packumentKey(input.url, input.profile), copy)
              .catch(() => undefined)
              .finally(done),
          );
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
            const looked = held.hold(block) ? reviewSummary(pkg) : null;
            held.drop(block);

            if (looked === null || !held.take(looked.weight)) {
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
        const listed = (name: string, lease: Lease): Effect.Effect<UpstreamListing | { kind: "over-budget" }> =>
          Effect.gen(function* () {
            const t = yield* now;
            const probes = probeCacheFor(lease.pool, baseUrl, ttlMs);
            const cached = probes.entry(name, t);

            if (cached !== undefined) {
              if (cached.value.kind !== "found") return cached.value;
              const scored = cached.value.pkg.versions.length * SCORED_WEIGHT;

              if ((cached.block !== null && !lease.hold(cached.block)) || !lease.take(scored)) return { kind: "over-budget" as const };

              return cached.value;
            }

            // nothing more fits: npm is not asked at all
            if (lease.exhausted) return { kind: "over-budget" as const };
            const url = `${baseUrl}${encodeName(name)}`;

            const answer = yield* fetchPackument({ url, now: t, profile: TRIMMED, lease }).pipe(Effect.orElseSucceed((): PackumentAnswer => ({ kind: "status", status: 0, fetchedAt: t })));

            if (answer.kind === "over-budget") return answer;

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

            const pkg = cachedPackage(name, answer.body, { versionDocs: read.versionDocs, maxPieceChars: read.maxPieceChars });
            lease.give(moment);

            if (!pkg) {
              // nothing of it is held
              lease.give(read.weight + held);

              return { kind: "unknown" as const };
            }

            const block = lease.seal(packageWeight(read));

            if (answer.fresh) shareCopy({ url, profile: TRIMMED, fetchedAt: answer.fetchedAt, body: answer.body, maxPieceChars: read.maxPieceChars, block, pool: lease.pool });
            const fresh: CachedProbe = { kind: "found", pkg };
            // the TTL counts from when npm answered, which for a shared copy is before this request; a big packument
            // takes room from older ones (PROBE_CACHE_WEIGHT)
            probes.set(name, fresh, answer.fetchedAt, block);
            yield* fetched(pkg, block, lease.pool);

            return fresh;
          });

        /** The packument as npm lists it, from the isolate cache or npm, without its analyses. */
        const listing = (name: string, lease: Lease): Effect.Effect<UpstreamListing> =>
          // a package that did not fit the lease could not be read: the caller asks again later
          Effect.map(listed(name, lease), (l) => (l.kind === "over-budget" ? { kind: "unknown" as const } : l));

        const probeWithin = (name: string, lease: Lease): Effect.Effect<BudgetedProbe, StoreError> =>
          Effect.gen(function* () {
            const l = yield* listed(name, lease);

            if (l.kind !== "found") return l;

            return scoredPackage(l.pkg, yield* store.upstreamAnalyses(name));
          });

        const probe = (name: string, lease: Lease): Effect.Effect<Probe, StoreError> =>
          Effect.map(probeWithin(name, lease), (p) => (p.kind === "over-budget" ? { kind: "unknown" as const } : p));

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

        const summaries = <S>(names: readonly string[], lease: Lease, keep: (pkg: UpstreamPackage) => Summary<S>): Effect.Effect<Map<string, Summarized<S>>, StoreError> =>
          Effect.gen(function* () {
            const wanted = [...new Set(names)];
            // read before the packuments, so each package is kept the moment it is read: a name npm has no package for
            // costs an empty row
            const analyses = yield* store.upstreamAnalysesOf(wanted);
            const none: UpstreamAnalyses = { scores: new Map(), unscorable: new Map() };

            /**
             * What `keep` returns for `pkg`, its weight taken from `lease`. The scored copy keep is handed is charged
             * while it runs unless the read already charged it (`copyCharged`: listed takes it with the package).
             */
            const kept = (name: string, pkg: CachedPackage, copyCharged: boolean): Summarized<S> => {
              const copy = copyCharged ? 0 : pkg.versions.length * SCORED_WEIGHT;

              if (!lease.take(copy)) return { kind: "over-budget" };
              const scored = scoredPackage(pkg, analyses.get(name) ?? none);
              const made = scored.kind === "found" ? keep(scored.pkg) : null;
              lease.give(copy);

              if (made === null) return { kind: "unknown" };

              return lease.take(made.weight) ? { kind: "found", summary: made.summary } : { kind: "over-budget" };
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
         * Each version's devDependencies as npm lists them, read apart (DEV_DEPENDENCIES) and never kept in the isolate.
         * Converting them is charged (packageMoment) before it is done, and stays charged with the read while the
         * request holds the answer.
         */
        const devDependencies = (name: string, lease: Lease): Effect.Effect<DevDependencyRead | null> =>
          Effect.gen(function* () {
            const t = yield* now;
            const url = `${baseUrl}${encodeName(name)}`;
            const answer = yield* fetchPackument({ url, now: t, profile: DEV_DEPENDENCIES, lease }).pipe(Effect.orElseSucceed(() => null));

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
              shareCopy({ url, profile: DEV_DEPENDENCIES, fetchedAt: answer.fetchedAt, body: answer.body, maxPieceChars: read.maxPieceChars, block, pool: lease.pool });
            }

            return { byVersion, maxPieceChars: read.maxPieceChars };
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
          probe,
          probeWithin,
          listing,
          probeMany,
          summaries,
          devDependencies,
          get: (name, lease) => Effect.map(probe(name, lease), (p) => (p.kind === "found" ? p.pkg : null)),
          tarball: (pkg, version) =>
            Effect.gen(function* () {
              const url = pkg.tarballs.get(version);
              const rec = pkg.versions.find((v) => v.version === version);

              if (!url || !rec) return { kind: "absent" } as const;
              const digest = digestOf(rec);

              if (!digest) return { kind: "unavailable", reason: "the upstream publishes no checksum for this version", retryable: false } as const;
              const key = upstreamBlobKey(digest);
              const cached = yield* blobs.bytes(key);

              if (Option.isSome(cached)) {
                if (matches(cached.value, digest)) return { kind: "ok", bytes: cached.value, digest } as const;
                yield* blobs.remove(key);
              }

              const got = yield* Effect.promise(() => download(url));

              if (got.kind !== "ok") return got;

              if (!matches(got.bytes, digest)) return { kind: "unavailable", reason: "the upstream tarball failed its integrity check", retryable: true } as const;
              yield* blobs.put(key, got.bytes);

              return { kind: "ok", bytes: got.bytes, digest } as const;
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
        };

        return Upstream.of(api);
      }),
    );
  }
}
