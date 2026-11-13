// Read-only proxy of a public registry (registry.npmjs.org in production). Packuments are fetched on demand
// and rewritten so tarballs flow through apm, where they are verified, cached in R2 and scored.
import { Context, Effect, Layer, Option } from "effect";
import { z } from "zod";
import { Blobs } from "./blobs.ts";
import { digestLabel, digestOf, type Digest } from "./digest.ts";
import { Store, type UpstreamAnalyses, type VersionRecord } from "./db.ts";
import type { BlobError, StoreError } from "./errors.ts";
import { notify } from "./hooks.ts";
import { readCapped } from "./http.ts";
import { streamedJson } from "./http.ts";
import { DEV_DEPENDENCIES, KeptBudget, MAX_PACKUMENT_WEIGHT, readPackument, TRIMMED, type KeepProfile, type KeptPackument, type PackumentRead } from "./packument-read.ts";
import { timingOrNull } from "./timing.ts";
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

export type UpstreamPackage = {
  name: string;
  distTags: Record<string, string>;
  description: string;
  readme: string;
  maintainers: string[];
  versions: VersionRecord[];
  /** original tarball URL per version */
  tarballs: Map<string, string>;
};

/** "unknown" means the upstream could not be asked; it is never treated as "absent". */
export type Probe = { kind: "found"; pkg: UpstreamPackage } | { kind: "absent" } | { kind: "unknown" };

/**
 * A probe made under a request's KeptBudget: "over-budget" when the request already holds as much package metadata
 * as it may, so this one was not read (or not kept). Not the same as "unknown": npm may well have answered.
 */
export type BudgetedProbe = Probe | { kind: "over-budget" };

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
export function cachedPackage(name: string, body: KeptPackument): CachedPackage | null {
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
 * The most package metadata the isolate keeps, as weight (packageWeight): an upper bound on its heap, which an isolate
 * has 128 MB of for every request it runs. next weighs 26 MiB cached (14 MiB of heap in workerd). Oldest go first.
 */
export const PROBE_CACHE_WEIGHT = 32 * 1024 * 1024;

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
 */
export class IsolateCache<V> {
  private readonly entries = new Map<string, { at: number; value: V; weight: number }>();
  private weight = 0;
  private readonly ttlMs: number;
  /** The most total weight kept; an entry heavier than this is not kept at all. */
  private readonly budget: number;

  constructor(ttlMs: number, budget = Number.POSITIVE_INFINITY) {
    this.ttlMs = ttlMs;
    this.budget = budget;
  }
  get(key: string, now: number): V | undefined {
    return this.entry(key, now)?.value;
  }
  /** The value under `key` and the weight it was kept with, while it is fresh. */
  entry(key: string, now: number): { readonly value: V; readonly weight: number } | undefined {
    const hit = this.entries.get(key);

    if (!hit) return undefined;

    if (now - hit.at >= this.ttlMs) {
      this.delete(key);

      return undefined;
    }

    return hit;
  }
  /** Keeps `value` under `key`; `weight` counts toward the budget, and older entries leave to make room. */
  set(key: string, value: V, now: number, weight = 0): void {
    this.delete(key);

    if (weight > this.budget) return;
    this.entries.set(key, { at: now, value, weight });
    this.weight += weight;

    while (this.entries.size > MAX_ENTRIES || this.weight > this.budget) {
      const oldest = this.entries.keys().next();

      if (oldest.done) break;
      this.delete(oldest.value);
    }
  }
  delete(key: string): void {
    const gone = this.entries.get(key);

    if (!gone) return;
    this.weight -= gone.weight;
    this.entries.delete(key);
  }
}

type Caches = {
  probes: IsolateCache<CachedProbe>;
  searches: IsolateCache<Extract<UpstreamSearch, { kind: "ok" }>>;
  scopes: IsolateCache<"found" | "absent">;
};

const isolateCaches = new Map<string, Caches>();

function cachesFor(baseUrl: string, ttlMs: number): Caches {
  const key = `${ttlMs} ${baseUrl}`;
  const known = isolateCaches.get(key);

  if (known) return known;
  const made: Caches = { probes: new IsolateCache(ttlMs, PROBE_CACHE_WEIGHT), searches: new IsolateCache(ttlMs), scopes: new IsolateCache(ttlMs) };
  isolateCaches.set(key, made);

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
 * budget it was read under. "status": npm answered something other than a 200 with a body. "refused": npm answered,
 * but readPackument refused it (too large, not JSON), so it is an answer apm cannot use. "over-budget": the request's
 * KeptBudget had no room for it.
 */
type PackumentAnswer =
  | { kind: "ok"; body: KeptPackument; fetchedAt: number; read: Extract<PackumentRead, { kind: "ok" }> }
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
  readonly probe: (name: string) => Effect.Effect<Probe, StoreError>;
  /** probe under a request's budget for the package metadata it holds (scan: one lease per package). */
  readonly probeWithin: (name: string, budget: KeptBudget) => Effect.Effect<BudgetedProbe, StoreError>;
  /** Like probe, with no scores, so it reads nothing from the database: the existence check and the review's version lookup. */
  readonly listing: (name: string) => Effect.Effect<UpstreamListing>;
  /**
   * probe for several names: their packuments (from cache or npm, a few at once) and one read of their analyses. With
   * a budget, every packument kept counts against it, cached ones included, and a name past it is "over-budget".
   */
  readonly probeMany: (names: readonly string[], budget?: KeptBudget) => Effect.Effect<Map<string, BudgetedProbe>, StoreError>;
  /**
   * Each version's devDependencies, read apart from the packument the registry keeps (DEV_DEPENDENCIES): only the full
   * packument apm serves adds them back. Null when npm could not be asked, the read was refused, or it did not fit
   * `budget` (the request's, beside the packument it holds); what it weighs stays taken from `budget`.
   */
  readonly devDependencies: (name: string, budget?: KeptBudget) => Effect.Effect<ReadonlyMap<string, unknown> | null>;
  /** The package when upstream has it; null when it is absent or upstream cannot be asked. */
  readonly get: (name: string) => Effect.Effect<UpstreamPackage | null, StoreError>;
  /**
   * The tarball of a version the upstream lists right now, verified against its published checksum. Cached in
   * the blob store by that checksum and verified again on every read, so a removed version or tampered bytes
   * are never served.
   */
  readonly tarball: (pkg: UpstreamPackage, version: string) => Effect.Effect<UpstreamTarball, BlobError>;
  /** Forwards an advisory bulk request. A failure is "unavailable", never an empty (clean) answer. */
  readonly advisories: (body: unknown) => Effect.Effect<UpstreamAdvisories>;
};

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

        // `background` is set only inside a Worker request, where `caches` always exists
        const sharing = ttlMs >= SHARED_MIN_TTL_MS && background !== null;

        /** A packument read as an answer. One it refused is logged; one past the request's budget is not an error. */
        const answerOf = (url: string, read: PackumentRead, fetchedAt: number): PackumentAnswer => {
          if (read.kind === "ok") return { kind: "ok", body: read.body, fetchedAt, read };

          if (read.kind === "too-large" && read.over === "budget") return { kind: "over-budget" };
          const detail = read.kind === "too-large" ? { over: read.over, bytes: read.bytes, limit: read.limit } : { reason: read.reason };

          console.error(JSON.stringify({ level: "error", event: "upstream-packument", error: read.kind === "too-large" ? "packument-too-large" : "packument-invalid", url, ...detail }));

          return { kind: "refused", fetchedAt };
        };

        /**
         * npm's packument as `profile` keeps it, from the shared cache when another isolate fetched it within the TTL.
         * `fetchedAt` is when npm sent it: `now` for a fresh fetch, the copy's own time for a shared one. The body is
         * streamed through readPackument, never held whole, and only what it keeps is shared: vite's 39 MB packument
         * is 2.8 MB kept. What it keeps is taken from `budget`, when there is one.
         */
        const fetchPackument = (input: { url: string; now: number; profile: KeepProfile; budget: KeptBudget | null }): Effect.Effect<PackumentAnswer, unknown> =>
          Effect.tryPromise({
            try: async (): Promise<PackumentAnswer> => {
              const { url, now, profile, budget } = input;
              const key = packumentKey(url, profile);
              const shared = sharing ? workerCache() : null;
              const cacheStart = performance.now();
              const hit = shared ? await shared.match(key).catch(() => undefined) : undefined;
              // a copy with no time (written before copies carried one) or past its TTL is not used
              const sentAt = Number(hit?.headers.get(FETCHED_AT_HEADER) ?? Number.NaN);

              if (hit?.body && Number.isFinite(sentAt) && now - sentAt >= 0 && now - sentAt < ttlMs) {
                const read = await readPackument(hit.body, { profile, budget });
                timing?.add("npm-cache", performance.now() - cacheStart);

                return answerOf(url, read, sentAt);
              }

              await hit?.body?.cancel();
              const npmStart = performance.now();
              const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000) });

              if (res.status !== 200 || !res.body) {
                await res.body?.cancel();
                timing?.add("npm", performance.now() - npmStart);

                return { kind: "status", status: res.status === 200 ? 502 : res.status, fetchedAt: now };
              }

              const read = await readPackument(res.body, { profile, budget });
              timing?.add("npm", performance.now() - npmStart);

              if (shared && background && read.kind === "ok") {
                const headers = { "content-type": "application/json", "cache-control": `public, max-age=${Math.floor(ttlMs / 1000)}`, [FETCHED_AT_HEADER]: String(now) };
                // written a version at a time, as it is put, so the copy is never held whole as one string
                background(shared.put(key, streamedJson(read.body, "versions", headers)).catch(() => undefined));
              }

              return answerOf(url, read, now);
            },
            catch: (cause) => cause,
          });

        /** An answer that is not a packument: absent when npm said 404, unknown otherwise. */
        const packageOf = (answer: Extract<PackumentAnswer, { kind: "status" | "refused" }>): CachedProbe | { kind: "unknown" } =>
          answer.kind === "status" && answer.status === 404 ? { kind: "absent" } : { kind: "unknown" };

        /**
         * The packument as npm lists it, from the isolate cache or npm, without its analyses. With a budget, what this
         * request now holds is taken from it: a package's weight (packageWeight) and its scored copy (SCORED_WEIGHT),
         * for a cached one and a fresh one alike. Without one, a fresh read is held to MAX_PACKUMENT_WEIGHT on its own.
         */
        const listed = (name: string, budget: KeptBudget | null): Effect.Effect<UpstreamListing | { kind: "over-budget" }> =>
          Effect.gen(function* () {
            const t = yield* now;
            const cached = caches.probes.entry(name, t);

            if (cached !== undefined) {
              const held = cached.weight + (cached.value.kind === "found" ? cached.value.pkg.versions.length * SCORED_WEIGHT : 0);

              return budget && !budget.take(held) ? { kind: "over-budget" as const } : cached.value;
            }

            // nothing more fits: npm is not asked at all
            if (budget?.exhausted) return { kind: "over-budget" as const };
            const within = budget ?? new KeptBudget(MAX_PACKUMENT_WEIGHT);

            const answer = yield* fetchPackument({ url: `${baseUrl}${encodeName(name)}`, now: t, profile: TRIMMED, budget: within }).pipe(
              Effect.orElseSucceed((): PackumentAnswer => ({ kind: "status", status: 0, fetchedAt: t })),
            );

            if (answer.kind === "over-budget") return budget ? answer : { kind: "unknown" as const };
            let fresh: CachedProbe | { kind: "unknown" };
            let weight = 0;

            if (answer.kind === "ok") {
              const { read } = answer;
              const held = packageWeight(read) - read.weight + read.versionCount * SCORED_WEIGHT;
              const moment = packageMoment(read);

              if (!within.take(held + moment)) {
                within.give(read.weight);

                if (budget) return { kind: "over-budget" as const };
                console.error(JSON.stringify({ level: "error", event: "upstream-packument", error: "packument-too-large", url: `${baseUrl}${encodeName(name)}`, over: "weight", bytes: within.taken + held + moment, limit: within.limit }));

                return { kind: "unknown" as const };
              }

              const pkg = cachedPackage(name, answer.body);
              within.give(moment);
              fresh = pkg ? { kind: "found", pkg } : { kind: "unknown" };
              weight = packageWeight(read);

              // nothing of it is held
              if (!pkg) within.give(read.weight + held);
            } else fresh = packageOf(answer);

            if (fresh.kind === "unknown") return fresh;

            // the TTL counts from when npm answered, which for a shared copy is before this request; a big packument
            // takes room from older ones (PROBE_CACHE_WEIGHT)
            caches.probes.set(name, fresh, answer.fetchedAt, weight);

            if (fresh.kind === "found") yield* notify((h) => h.upstreamFetched, { ...fresh.pkg, versions: fresh.pkg.versions.map((v) => ({ ...v, score: null })) });

            return fresh;
          });

        /** The packument as npm lists it, from the isolate cache or npm, without its analyses. */
        const listing = (name: string): Effect.Effect<UpstreamListing> =>
          // with no budget there is nothing to be over
          Effect.map(listed(name, null), (l) => (l.kind === "over-budget" ? { kind: "unknown" as const } : l));

        const probe = (name: string): Effect.Effect<Probe, StoreError> =>
          Effect.gen(function* () {
            const listed = yield* listing(name);

            if (listed.kind !== "found") return listed;

            return scoredPackage(listed.pkg, yield* store.upstreamAnalyses(name));
          });

        const probeWithin = (name: string, budget: KeptBudget): Effect.Effect<BudgetedProbe, StoreError> =>
          Effect.gen(function* () {
            const l = yield* listed(name, budget);

            if (l.kind !== "found") return l;

            return scoredPackage(l.pkg, yield* store.upstreamAnalyses(name));
          });

        const probeMany = (names: readonly string[], budget?: KeptBudget): Effect.Effect<Map<string, BudgetedProbe>, StoreError> =>
          Effect.gen(function* () {
            const wanted = [...new Set(names)];
            // a few at once: the reads in flight share the budget, so together they keep no more than it allows
            const got = yield* Effect.forEach(wanted, (name) => Effect.map(listed(name, budget ?? null), (l) => [name, l] as const), { concurrency: PROBE_CONCURRENCY });
            const found = got.flatMap(([name, l]) => (l.kind === "found" ? [name] : []));
            const scores = yield* store.upstreamAnalysesOf(found);
            const none: UpstreamAnalyses = { scores: new Map(), unscorable: new Map() };

            return new Map(got.map(([name, l]) => [name, l.kind === "found" ? scoredPackage(l.pkg, scores.get(name) ?? none) : l]));
          });

        /** Each version's devDependencies as npm lists them, read apart (DEV_DEPENDENCIES) and never kept in the isolate. */
        const devDependencies = (name: string, budget?: KeptBudget): Effect.Effect<ReadonlyMap<string, unknown> | null> =>
          Effect.gen(function* () {
            const t = yield* now;
            const within = budget ?? new KeptBudget(MAX_PACKUMENT_WEIGHT);
            const answer = yield* fetchPackument({ url: `${baseUrl}${encodeName(name)}`, now: t, profile: DEV_DEPENDENCIES, budget: within }).pipe(Effect.orElseSucceed(() => null));

            if (answer?.kind !== "ok") return null;
            const parsed = DevDependencies.safeParse(answer.body);

            if (!parsed.success) {
              within.give(answer.read.weight);

              return null;
            }

            const out = new Map<string, unknown>();

            for (const [version, doc] of Object.entries(parsed.data.versions)) {
              const one = DevDocument.safeParse(doc);

              if (one.success && one.data.devDependencies !== undefined) out.set(version, one.data.devDependencies);
            }

            return out;
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
          devDependencies,
          get: (name) => Effect.map(probe(name), (p) => (p.kind === "found" ? p.pkg : null)),
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
