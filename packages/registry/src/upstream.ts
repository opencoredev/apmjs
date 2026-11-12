// Read-only proxy of a public registry (registry.npmjs.org in production). Packuments are
// fetched on demand and rewritten so tarballs flow through apm, where they are verified and scored.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import { MAX_UNPACKED_BYTES } from "@apm/core";
import type { VersionRecord } from "./db.ts";
import type { Ctx } from "./server.ts";

const Dist = z.object({ tarball: z.string(), shasum: z.string().optional(), integrity: z.string().optional() }).loose();
// Real packuments carry `deprecated: false` and other odd shapes on old versions (react does),
// so the field is read loosely and one malformed version is skipped, not fatal to the package.
const UpVersion = z.object({ name: z.string(), version: z.string(), dist: Dist, deprecated: z.unknown().optional(), _npmUser: z.object({ name: z.string() }).loose().optional() }).loose();
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
export type UpPackument = z.infer<typeof UpPackument>;

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

function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

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

/** "sha512-<hex>": names a tarball's bytes; stored analyses and cache files are keyed by it. */
export function digestLabel(d: Digest): string {
  return `${d.algo}-${d.hex}`;
}

/** The response body, or null once it passes `max` bytes (the rest is not read). */
async function readCapped(res: Response, max: number): Promise<Uint8Array | null> {
  if (!res.body) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of res.body) {
    total += chunk.length;
    // leaving the loop early cancels the stream
    if (total > max) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function matches(bytes: Uint8Array, d: Digest): boolean {
  return createHash(d.algo).update(bytes).digest("hex") === d.hex;
}

/** "absent": the upstream does not list that version (now). "unavailable": it does, but apm could not get verified bytes. */
export type UpstreamTarball = { kind: "ok"; bytes: Uint8Array; digest: Digest } | { kind: "absent" } | { kind: "unavailable"; reason: string };
export type UpstreamAdvisories = { kind: "ok"; advisories: Record<string, unknown[]> } | { kind: "unavailable" };

/** npm serves packuments from registry.npmjs.org and tarballs from the same host. */
const NPM_ORIGIN = "https://registry.npmjs.org";
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_HOPS = 5;

const SEARCH_CACHE_MAX = 500;

export class Upstream {
  private cache = new Map<string, { at: number; probe: Probe }>();
  private inflight = new Map<string, Promise<Probe>>();
  private searchCache = new Map<string, { at: number; result: Extract<UpstreamSearch, { kind: "ok" }> }>();
  private searchInflight = new Map<string, Promise<UpstreamSearch>>();
  private scopeCache = new Map<string, { at: number; answer: "found" | "absent" }>();
  /** Runs when a packument is fetched (not on cache hits). Index wires the AI review's enqueue policy here. */
  onPackage: ((pkg: UpstreamPackage) => void) | null = null;
  /** The only origins tarballs are fetched from, on every redirect hop. */
  private readonly origins: ReadonlySet<string>;
  constructor(
    readonly baseUrl: string,
    private readonly ttlMs = 60_000,
  ) {
    this.origins = new Set([new URL(baseUrl).origin, NPM_ORIGIN]);
  }

  /** The upstream's own search, cached for the TTL. Failures are not cached so the next keystroke retries. */
  async search(text: string, size: number): Promise<UpstreamSearch> {
    const key = `${size}\u0000${text}`;
    const hit = this.searchCache.get(key);
    if (hit && Date.now() - hit.at < this.ttlMs) return hit.result;
    const running = this.searchInflight.get(key);
    if (running) return running;
    const p = this.fetchSearch(text, size).finally(() => this.searchInflight.delete(key));
    this.searchInflight.set(key, p);
    const result = await p;
    if (result.kind === "ok") {
      this.searchCache.delete(key);
      this.searchCache.set(key, { at: Date.now(), result });
      // Map keeps insertion order, so the first key is the oldest entry.
      if (this.searchCache.size > SEARCH_CACHE_MAX) {
        const oldest = this.searchCache.keys().next();
        if (!oldest.done) this.searchCache.delete(oldest.value);
      }
    }
    return result;
  }

  private async fetchSearch(text: string, size: number): Promise<UpstreamSearch> {
    const url = `${this.baseUrl}-/v1/search?text=${encodeURIComponent(text)}&size=${size}`;
    try {
      const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(4_000) });
      if (res.status !== 200) return { kind: "unavailable" };
      const parsed = UpSearch.safeParse(await res.json());
      if (!parsed.success) return { kind: "unavailable" };
      const objects: UpSearchObject[] = [];
      for (const raw of parsed.data.objects) {
        const one = UpSearchObject.safeParse(raw);
        if (one.success) objects.push(one.data);
      }
      return { kind: "ok", objects, total: parsed.data.total ?? objects.length };
    } catch {
      return { kind: "unavailable" };
    }
  }

  /**
   * Whether `@scope` has packages upstream. npm answers /-/org/<scope>/package for user and org scopes
   * alike: 200 with a map of packages, or 404 "Scope not found".
   */
  async scopeExists(scope: string): Promise<"found" | "absent" | "unknown"> {
    const hit = this.scopeCache.get(scope);
    if (hit && Date.now() - hit.at < this.ttlMs) return hit.answer;
    let answer: "found" | "absent" | "unknown";
    try {
      const res = await fetch(`${this.baseUrl}-/org/${encodeURIComponent(scope)}/package`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(5_000) });
      if (res.status === 404) answer = "absent";
      else if (res.status !== 200) answer = "unknown";
      else {
        const body = z.record(z.string(), z.unknown()).safeParse(await res.json());
        answer = body.success ? (Object.keys(body.data).length > 0 ? "found" : "absent") : "unknown";
      }
    } catch {
      answer = "unknown";
    }
    if (answer !== "unknown") this.scopeCache.set(scope, { at: Date.now(), answer });
    return answer;
  }

  /** The package when upstream has it; null when it is absent or upstream cannot be asked. */
  async get(ctx: Ctx, name: string): Promise<UpstreamPackage | null> {
    const p = await this.probe(ctx, name);
    return p.kind === "found" ? p.pkg : null;
  }

  async probe(ctx: Ctx, name: string): Promise<Probe> {
    const hit = this.cache.get(name);
    if (hit && Date.now() - hit.at < this.ttlMs) return hit.probe;
    const running = this.inflight.get(name);
    if (running) return running;
    const p = this.fetchPackage(ctx, name).finally(() => this.inflight.delete(name));
    this.inflight.set(name, p);
    const probe = await p;
    if (probe.kind !== "unknown") this.cache.set(name, { at: Date.now(), probe });

    if (probe.kind === "found") this.onPackage?.(probe.pkg);
    return probe;
  }

  private async fetchPackage(ctx: Ctx, name: string): Promise<Probe> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${encodeName(name)}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000) });
    } catch {
      return { kind: "unknown" };
    }
    if (res.status === 404) return { kind: "absent" };
    if (res.status !== 200) return { kind: "unknown" };
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      return { kind: "unknown" };
    }
    const parsed = UpPackument.safeParse(json);
    if (!parsed.success) return { kind: "unknown" };
    const raw = parsed.data;
    const tarballs = new Map<string, string>();
    const versions: VersionRecord[] = [];
    for (const [v, rawDoc] of Object.entries(raw.versions)) {
      const one = UpVersion.safeParse(rawDoc);
      if (!one.success) continue;
      const doc = one.data;
      tarballs.set(v, doc.dist.tarball);
      const manifest: Record<string, unknown> = { ...doc };
      delete manifest.dist;
      const digest = digestOf({ integrity: doc.dist.integrity ?? "", shasum: doc.dist.shasum ?? "" });
      versions.push({
        package: name,
        version: v,
        manifest,
        shasum: doc.dist.shasum ?? "",
        integrity: doc.dist.integrity ?? "",
        size: 0,
        published_at: Date.parse(raw.time[v] ?? "") || 0,
        published_by: doc._npmUser?.name ?? "upstream",
        deprecated: typeof doc.deprecated === "string" && doc.deprecated !== "" ? doc.deprecated : null,
        status: "active",
        status_reason: null,
        status_at: null,
        status_by: null,
        // an analysis counts only for the exact bytes it read, by the current scorer
        score: digest ? ctx.store.getUpstreamAnalysis(name, v, digestLabel(digest)) : null,
      });
    }
    versions.sort((a, b) => a.published_at - b.published_at);
    const pkg: UpstreamPackage = {
      name,
      distTags: raw["dist-tags"],
      description: raw.description ?? "",
      readme: raw.readme ?? "",
      maintainers: (raw.maintainers ?? []).map((m) => m.name),
      versions,
      tarballs,
    };
    return { kind: "found", pkg };
  }

  /**
   * The tarball of a version the upstream lists right now, verified against its published checksum.
   * Cached content-addressed by that checksum and verified again on every read, so a removed version
   * or a tampered cache file is never served.
   */
  async tarball(ctx: Ctx, pkg: UpstreamPackage, version: string): Promise<UpstreamTarball> {
    const url = pkg.tarballs.get(version);
    const rec = pkg.versions.find((v) => v.version === version);
    if (!url || !rec) return { kind: "absent" };
    const digest = digestOf(rec);
    if (!digest) return { kind: "unavailable", reason: "the upstream publishes no checksum for this version" };
    const file = join(ctx.store.tarballDir, "_upstream", "blobs", digest.hex.slice(0, 2), `${digestLabel(digest)}.tgz`);
    if (existsSync(file)) {
      const cached = new Uint8Array(readFileSync(file));
      if (matches(cached, digest)) return { kind: "ok", bytes: cached, digest };
      rmSync(file, { force: true });
    }
    const got = await this.download(url);
    if (got.kind !== "ok") return got;
    if (!matches(got.bytes, digest)) return { kind: "unavailable", reason: "the upstream tarball failed its integrity check" };
    mkdirSync(dirname(file), { recursive: true });
    const tmp = `${file}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(tmp, got.bytes);
    renameSync(tmp, file);
    return { kind: "ok", bytes: got.bytes, digest };
  }

  /** GET from the upstream's own origin (or npm's) only; each redirect hop is checked before it is followed. */
  private async download(raw: string): Promise<{ kind: "ok"; bytes: Uint8Array } | { kind: "unavailable"; reason: string }> {
    let current: URL;
    try {
      current = new URL(raw);
    } catch {
      return { kind: "unavailable", reason: "the upstream lists a malformed tarball URL" };
    }
    for (let hop = 0; hop <= MAX_HOPS; hop++) {
      if (!this.origins.has(current.origin)) return { kind: "unavailable", reason: `refusing to fetch a tarball from ${current.origin}, which is not the upstream registry` };
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
      if (declared > MAX_UNPACKED_BYTES) {
        await res.body?.cancel();
        return { kind: "unavailable", reason: "the tarball is too large" };
      }
      const bytes = await readCapped(res, MAX_UNPACKED_BYTES);
      if (!bytes) return { kind: "unavailable", reason: "the tarball is too large" };
      return { kind: "ok", bytes };
    }
    return { kind: "unavailable", reason: "too many redirects" };
  }

  /** Forwards an advisory bulk request. A failure is "unavailable", never an empty (clean) answer. */
  async advisories(body: unknown): Promise<UpstreamAdvisories> {
    try {
      const res = await fetch(`${this.baseUrl}-/npm/v1/security/advisories/bulk`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
      if (res.status !== 200) return { kind: "unavailable" };
      const parsed = z.record(z.string(), z.array(z.unknown())).safeParse(await res.json());
      return parsed.success ? { kind: "ok", advisories: parsed.data } : { kind: "unavailable" };
    } catch {
      return { kind: "unavailable" };
    }
  }

  forget(name: string): void {
    this.cache.delete(name);
  }
}
