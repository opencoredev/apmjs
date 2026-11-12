// Read-only proxy of a public registry (registry.npmjs.org in production). Packuments are fetched on demand
// and rewritten so tarballs flow through apm, where they are verified, cached in R2 and scored.
import { Context, Effect, Layer, Option } from "effect";
import { z } from "zod";
import { Blobs } from "./blobs.ts";
import { Store, type VersionRecord } from "./db.ts";
import type { BlobError, StoreError } from "./errors.ts";
import { notify } from "./hooks.ts";
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
export type Digest = { algo: "sha512" | "sha1"; hex: string };

export function digestOf(v: { integrity: string; shasum: string }): Digest | null {
  if (v.integrity.startsWith("sha512-")) {
    const raw = Buffer.from(v.integrity.slice("sha512-".length), "base64");

    if (raw.length === 64) return { algo: "sha512", hex: raw.toString("hex") };
  }

  if (/^[0-9a-f]{40}$/i.test(v.shasum)) return { algo: "sha1", hex: v.shasum.toLowerCase() };

  return null;
}

/** "sha512-<hex>": names a tarball's bytes; stored analyses are keyed by it. */
export function digestLabel(d: Digest): string {
  return `${d.algo}-${d.hex}`;
}

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

/** "absent": the upstream does not list that version (now). "unavailable": it does, but apm could not get verified bytes. */
export type UpstreamTarball = { kind: "ok"; bytes: Uint8Array; digest: Digest } | { kind: "absent" } | { kind: "unavailable"; reason: string };

export type UpstreamAdvisories = { kind: "ok"; advisories: Record<string, unknown[]> } | { kind: "unavailable" };

/** npm serves packuments from registry.npmjs.org and tarballs from the same host. */
const NPM_ORIGIN = "https://registry.npmjs.org";
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_HOPS = 5;

/** The response body, or null once it passes `max` bytes (the rest is not read). */
async function readCapped(res: Response, max: number): Promise<Uint8Array | null> {
  if (!res.body) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = res.body.getReader();

  for (;;) {
    const { done, value } = await reader.read();

    if (done) break;
    total += value.length;

    if (total > max) {
      await reader.cancel();

      return null;
    }

    chunks.push(value);
  }

  return Buffer.concat(chunks);
}

/** The parsed packument without apm's scores; scores are attached per request from the store. */
type CachedPackage = Omit<UpstreamPackage, "versions"> & { versions: Omit<VersionRecord, "score">[] };

type CachedProbe = { kind: "found"; pkg: CachedPackage } | { kind: "absent" };

/** How long an upstream answer is trusted before it is fetched again. */
export const DEFAULT_TTL_MS = 60_000;
const MAX_ENTRIES = 500;

/**
 * Answers from the public registry, kept for a minute per Worker isolate. Only public data lives here, never
 * anything about a request or a person, so sharing it between requests is safe. Promises are never shared:
 * a Worker may not finish I/O that another request started.
 */
class IsolateCache<V> {
  private readonly entries = new Map<string, { at: number; value: V }>();
  constructor(private readonly ttlMs: number) {}
  get(key: string, now: number): V | undefined {
    const hit = this.entries.get(key);

    if (!hit) return undefined;

    if (now - hit.at >= this.ttlMs) {
      this.entries.delete(key);

      return undefined;
    }

    return hit.value;
  }
  set(key: string, value: V, now: number): void {
    this.entries.delete(key);
    this.entries.set(key, { at: now, value });

    if (this.entries.size > MAX_ENTRIES) {
      const oldest = this.entries.keys().next();

      if (!oldest.done) this.entries.delete(oldest.value);
    }
  }
  delete(key: string): void {
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
  const made: Caches = { probes: new IsolateCache(ttlMs), searches: new IsolateCache(ttlMs), scopes: new IsolateCache(ttlMs) };
  isolateCaches.set(key, made);

  return made;
}

function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}


export type UpstreamApi = {
  readonly baseUrl: string;
  readonly search: (text: string, size: number) => Effect.Effect<UpstreamSearch>;
  /** Whether `@scope` has packages upstream. */
  readonly scopeExists: (scope: string) => Effect.Effect<"found" | "absent" | "unknown">;
  readonly probe: (name: string) => Effect.Effect<Probe, StoreError>;
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
  /** The proxy of `baseUrl` (ending with "/"). */
  static layer(baseUrl: string, ttlMs: number = DEFAULT_TTL_MS): Layer.Layer<Upstream, never, Store | Blobs> {
    return Layer.effect(
      Upstream,
      Effect.gen(function* () {
        const store = yield* Store;
        const blobs = yield* Blobs;
        const caches = cachesFor(baseUrl, ttlMs);
        /** The only origins tarballs are fetched from, on every redirect hop. */
        const origins: ReadonlySet<string> = new Set([new URL(baseUrl).origin, NPM_ORIGIN]);

        /** GET from the upstream's own origin (or npm's) only; each redirect hop is checked before it is followed. */
        const download = async (raw: string): Promise<{ kind: "ok"; bytes: Uint8Array } | { kind: "unavailable"; reason: string }> => {
          let current: URL;

          try {
            current = new URL(raw);
          } catch {
            return { kind: "unavailable", reason: "the upstream lists a malformed tarball URL" };
          }

          for (let hop = 0; hop <= MAX_HOPS; hop++) {
            if (!origins.has(current.origin)) return { kind: "unavailable", reason: `refusing to fetch a tarball from ${current.origin}, which is not the upstream registry` };
            let res: Response;

            try {
              res = await fetch(current, { redirect: "manual", signal: AbortSignal.timeout(30_000) });
            } catch {
              return { kind: "unavailable", reason: "the tarball download failed" };
            }

            if (REDIRECTS.has(res.status)) {
              await res.body?.cancel();
              const location = res.headers.get("location");

              if (!location) return { kind: "unavailable", reason: "a redirect without a location" };

              try {
                current = new URL(location, current);
              } catch {
                return { kind: "unavailable", reason: "a redirect to a malformed URL" };
              }

              continue;
            }

            if (res.status !== 200) {
              await res.body?.cancel();

              return { kind: "unavailable", reason: `the upstream answered ${res.status}` };
            }

            const declared = Number(res.headers.get("content-length") ?? 0);

            if (declared > MAX_UPSTREAM_TARBALL_BYTES) {
              await res.body?.cancel();

              return { kind: "unavailable", reason: "the tarball is too large" };
            }

            const bytes = await readCapped(res, MAX_UPSTREAM_TARBALL_BYTES);

            if (!bytes) return { kind: "unavailable", reason: "the tarball is too large" };

            return { kind: "ok", bytes };
          }

          return { kind: "unavailable", reason: "too many redirects" };
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

        const fetchPackage = (name: string): Effect.Effect<CachedProbe | { kind: "unknown" }> =>
          fetchJson(`${baseUrl}${encodeName(name)}`, 10_000).pipe(
            Effect.map(({ status, body }): CachedProbe | { kind: "unknown" } => {
              if (status === 404) return { kind: "absent" };

              if (status !== 200) return { kind: "unknown" };
              const parsed = UpPackument.safeParse(body);

              if (!parsed.success) return { kind: "unknown" };
              const raw = parsed.data;
              const tarballs = new Map<string, string>();
              const versions: Omit<VersionRecord, "score">[] = [];

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

              versions.sort((a, b) => a.published_at - b.published_at);

              return {
                kind: "found",
                pkg: {
                  name,
                  distTags: raw["dist-tags"],
                  description: raw.description ?? "",
                  readme: raw.readme ?? "",
                  maintainers: (raw.maintainers ?? []).map((m) => m.name),
                  versions,
                  tarballs,
                },
              };
            }),
            Effect.orElseSucceed(() => ({ kind: "unknown" as const })),
          );

        const probe = (name: string): Effect.Effect<Probe, StoreError> =>
          Effect.gen(function* () {
            const t = yield* now;
            let cached = caches.probes.get(name, t);

            if (cached === undefined) {
              const fresh = yield* fetchPackage(name);

              if (fresh.kind === "unknown") return fresh;
              caches.probes.set(name, fresh, t);
              cached = fresh;

              if (fresh.kind === "found") yield* notify((h) => h.upstreamFetched, { ...fresh.pkg, versions: fresh.pkg.versions.map((v) => ({ ...v, score: null })) });
            }

            if (cached.kind === "absent") return cached;
            const scores = yield* store.upstreamAnalyses(name);
            const pkg = cached.pkg;

            return {
              kind: "found",
              // an analysis counts only for the exact bytes it read, by the current scorer
              pkg: {
                ...pkg,
                versions: pkg.versions.map((v) => {
                  const d = digestOf(v);

                  return { ...v, score: d ? (scores.get(`${v.version} ${digestLabel(d)}`) ?? null) : null };
                }),
              },
            } satisfies Probe;
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
          get: (name) => Effect.map(probe(name), (p) => (p.kind === "found" ? p.pkg : null)),
          tarball: (pkg, version) =>
            Effect.gen(function* () {
              const url = pkg.tarballs.get(version);
              const rec = pkg.versions.find((v) => v.version === version);

              if (!url || !rec) return { kind: "absent" } as const;
              const digest = digestOf(rec);

              if (!digest) return { kind: "unavailable", reason: "the upstream publishes no checksum for this version" } as const;
              const key = upstreamBlobKey(digest);
              const cached = yield* blobs.bytes(key);

              if (Option.isSome(cached)) {
                if (matches(cached.value, digest)) return { kind: "ok", bytes: cached.value, digest } as const;
                yield* blobs.remove(key);
              }

              const got = yield* Effect.promise(() => download(url));

              if (got.kind !== "ok") return got;

              if (!matches(got.bytes, digest)) return { kind: "unavailable", reason: "the upstream tarball failed its integrity check" } as const;
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
