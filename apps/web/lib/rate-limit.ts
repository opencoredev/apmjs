// In-memory limits for the public search route. One process only: after the Cloudflare port these
// are replaced by Cloudflare's rate limiting rules and its cache, which hold across instances.

export type Take = { ok: true } | { ok: false; retryAfterSeconds: number };

export type TokenBucket = { take: (key: string, now?: number) => Take };

type Bucket = { tokens: number; at: number };

/**
 * A token bucket per key: `capacity` requests at once, refilled at `refillPerSecond`. At most `maxKeys`
 * buckets are kept; the least recently used one is dropped first, so memory stays bounded.
 */
export function createTokenBucket(opts: { capacity: number; refillPerSecond: number; maxKeys: number }): TokenBucket {
  const buckets = new Map<string, Bucket>();

  return {
    take(key, now = Date.now()) {
      const prev = buckets.get(key);
      const tokens = prev ? Math.min(opts.capacity, prev.tokens + ((now - prev.at) / 1000) * opts.refillPerSecond) : opts.capacity;

      buckets.delete(key);

      if (buckets.size >= opts.maxKeys) {
        const oldest = buckets.keys().next();

        if (!oldest.done) buckets.delete(oldest.value);
      }

      if (tokens < 1) {
        buckets.set(key, { tokens, at: now });

        return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((1 - tokens) / opts.refillPerSecond)) };
      }

      buckets.set(key, { tokens: tokens - 1, at: now });

      return { ok: true };
    },
  };
}

export type SharedCache<T> = { get: (key: string, load: () => Promise<T | null>, now?: number) => Promise<T | null> };

type Entry<T> = { value: T; expires: number };

/**
 * A short cache shared by every visitor: an answer is reused for `ttlMs`, and concurrent requests for
 * the same key wait on one load. Failed loads (null) are not stored, nor answers `keep` refuses (by
 * default every answer is kept). At most `maxEntries` are kept.
 */
export function createSharedCache<T>(opts: { ttlMs: number; maxEntries: number; keep?: (value: T) => boolean }): SharedCache<T> {
  const keep = opts.keep ?? (() => true);
  const entries = new Map<string, Entry<T>>();
  const loading = new Map<string, Promise<T | null>>();

  return {
    async get(key, load, now = Date.now()) {
      const hit = entries.get(key);

      if (hit && hit.expires > now) return hit.value;

      if (hit) entries.delete(key);
      const pending = loading.get(key);

      if (pending) return pending;

      const promise = load().then((value) => {
        if (value !== null && keep(value)) {
          if (entries.size >= opts.maxEntries) {
            const oldest = entries.keys().next();

            if (!oldest.done) entries.delete(oldest.value);
          }

          entries.set(key, { value, expires: now + opts.ttlMs });
        }

        return value;
      });

      loading.set(key, promise);

      try {
        return await promise;
      } finally {
        loading.delete(key);
      }
    },
  };
}
