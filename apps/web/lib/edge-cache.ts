// A short cache for public registry answers, so a page view does not wait on the registry for data it read a moment
// ago. Two layers:
//  1. This isolate's memory, shared through globalThis: proxy.ts and the page are bundled apart by OpenNext but run
//     in the same isolate, so the package the proxy looked up is the one the page renders.
//  2. The Workers Cache API (caches.default), shared by every isolate in a data center. It works on custom domains
//     (production); on workers.dev and under `next dev` its calls are no-ops or missing, and layer 1 still holds.
// Only answers that are the same for everyone go in here: callers never pass a cookie or a token with a cached read.
// An entry is fresh for `freshMs`, then served for up to `staleMs` more while one background refresh replaces it.
// No "server-only": the unit tests import it.
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { z } from "zod";

export type CachePolicy = { readonly freshMs: number; readonly staleMs: number };

/** A cached body and how old it is. `stale` means past `freshMs`: serve it, and refresh it in the background. */
export type CacheHit = { text: string; stale: boolean };

type Entry = { text: string; at: number; until: number };

/** Layer 1's bounds: a Worker has 128 MB, and one big file view must not push everything else out. */
const MEMORY_BYTES = 24 * 1024 * 1024;
const MEMORY_ENTRY_BYTES = 2 * 1024 * 1024;
const MEMORY_ENTRIES = 1_000;

type Memory = { entries: Map<string, Entry>; bytes: number };

declare global {
  /** Layer 1, on globalThis so every bundle in the isolate (proxy.ts, the pages) shares it. Only this file uses it. */
  var apmEdgeCache: Memory | undefined;
}

function memory(): Memory {
  globalThis.apmEdgeCache ??= { entries: new Map(), bytes: 0 };

  return globalThis.apmEdgeCache;
}

/** UTF-16 length is close enough to a byte budget for JSON text. */
const sizeOf = (text: string): number => text.length;

function forget(m: Memory, key: string): void {
  const old = m.entries.get(key);

  if (!old) return;
  m.entries.delete(key);
  m.bytes -= sizeOf(old.text);
}

function remember(key: string, entry: Entry): void {
  const m = memory();
  forget(m, key);

  if (sizeOf(entry.text) > MEMORY_ENTRY_BYTES) return;
  m.entries.set(key, entry);
  m.bytes += sizeOf(entry.text);

  // a Map iterates in insertion order and a hit re-inserts, so the first key is the least recently used
  for (const oldest of m.entries.keys()) {
    if (m.bytes <= MEMORY_BYTES && m.entries.size <= MEMORY_ENTRIES) break;
    forget(m, oldest);
  }
}

/** The Cache API key for a cache key. Any URL works as a key; this host is never fetched. */
const cacheRequest = (key: string): Request => new Request(`https://edge-cache.apmjs.internal/v1/${encodeURIComponent(key)}`);

const STORED_AT = "x-apm-stored-at";

/** What a Worker's `caches` has that a browser's does not: the data center's default cache. */
const WorkerCaches = z.object({ default: z.custom<Cache>((v) => v instanceof Cache) });

/** caches.default when this runs in a Worker; undefined under `next dev` (no `caches`) and in tests. */
function sharedCache(): Cache | undefined {
  const parsed = WorkerCaches.safeParse(globalThis.caches);

  return parsed.success ? parsed.data.default : undefined;
}

/** Hands work to the runtime to finish after the response, or lets it run on its own outside a Worker. */
export function inBackground(work: Promise<unknown>): void {
  const settled = work.then(
    () => undefined,
    () => undefined,
  );

  try {
    getCloudflareContext().ctx.waitUntil(settled);
  } catch {
    // not in a Worker request (next dev, tests): the promise runs to the end by itself
    void settled;
  }
}

function hitOf(entry: Entry, policy: CachePolicy, now: number): CacheHit | null {
  const age = now - entry.at;

  if (age < 0 || age >= policy.freshMs + policy.staleMs) return null;

  return { text: entry.text, stale: age >= policy.freshMs };
}

/** The cached body for `key`, fresh or stale; null when there is none worth serving. */
export async function lookup(key: string, policy: CachePolicy, now = Date.now()): Promise<CacheHit | null> {
  const m = memory();
  const local = m.entries.get(key);

  if (local) {
    const hit = hitOf(local, policy, now);

    if (hit) {
      // keep it at the young end of the LRU order
      m.entries.delete(key);
      m.entries.set(key, local);

      return hit;
    }

    forget(m, key);
  }

  const shared = sharedCache();

  if (!shared) return null;

  try {
    const res = await shared.match(cacheRequest(key));

    if (!res) return null;
    const at = Number(res.headers.get(STORED_AT));
    const text = await res.text();

    if (!Number.isFinite(at)) return null;
    const entry: Entry = { text, at, until: at + policy.freshMs + policy.staleMs };
    const hit = hitOf(entry, policy, now);

    if (hit) remember(key, entry);

    return hit;
  } catch {
    return null;
  }
}

/** Keeps `text` under `key` in both layers. The Cache API write finishes after the response. */
export function store(key: string, text: string, policy: CachePolicy, now = Date.now()): void {
  const entry: Entry = { text, at: now, until: now + policy.freshMs + policy.staleMs };
  remember(key, entry);
  const shared = sharedCache();

  if (!shared) return;
  const seconds = Math.max(1, Math.ceil((policy.freshMs + policy.staleMs) / 1000));
  const res = new Response(text, { headers: { "content-type": "application/json", "cache-control": `public, max-age=${seconds}`, [STORED_AT]: String(now) } });

  inBackground(shared.put(cacheRequest(key), res));
}

/** Drops `key` from both layers: the registry now answers something else (a revoked version's 410, a 404). */
export function evict(key: string): void {
  forget(memory(), key);
  const shared = sharedCache();

  if (shared) inBackground(shared.delete(cacheRequest(key)));
}

/** How long each kind of public answer is kept. */
export const POLICIES = {
  /** A package's versions, statuses and latest score. A yank or revoke shows within about 10 seconds of the next view. */
  package: { freshMs: 10_000, staleMs: 60_000 },
  /** That a package exists, for proxy.ts's 404 check. Packages are never deleted, so a yes holds. */
  exists: { freshMs: 10 * 60_000, staleMs: 24 * 60 * 60_000 },
  /** The public AI review: the review card polls for the live state. */
  review: { freshMs: 5_000, staleMs: 30_000 },
  events: { freshMs: 10_000, staleMs: 60_000 },
  /** An older version's full score report: it changes only when evidence is dismissed or restored. */
  versionScore: { freshMs: 60_000, staleMs: 10 * 60_000 },
  /** Files, excerpts and readmes of one version: the bytes of a published version never change. */
  versionFile: { freshMs: 10 * 60_000, staleMs: 24 * 60 * 60_000 },
  search: { freshMs: 60_000, staleMs: 5 * 60_000 },
} as const satisfies Record<string, CachePolicy>;
