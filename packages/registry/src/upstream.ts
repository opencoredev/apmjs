// Read-only proxy of a public registry (registry.npmjs.org in production). Packuments are
// fetched on demand and rewritten so tarballs flow through apm, where they are verified and scored.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import type { VersionRecord } from "./db.ts";
import type { Ctx } from "./server.ts";

const Dist = z.object({ tarball: z.string(), shasum: z.string().optional(), integrity: z.string().optional() }).loose();
const UpVersion = z.object({ name: z.string(), version: z.string(), dist: Dist, deprecated: z.string().optional(), _npmUser: z.object({ name: z.string() }).loose().optional() }).loose();
const UpPackument = z
  .object({
    name: z.string(),
    "dist-tags": z.record(z.string(), z.string()).default({}),
    versions: z.record(z.string(), UpVersion).default({}),
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

export class Upstream {
  private cache = new Map<string, { at: number; pkg: UpstreamPackage | null }>();
  private inflight = new Map<string, Promise<UpstreamPackage | null>>();
  constructor(
    readonly baseUrl: string,
    private readonly ttlMs = 60_000,
  ) {}

  async get(ctx: Ctx, name: string): Promise<UpstreamPackage | null> {
    const hit = this.cache.get(name);
    if (hit && Date.now() - hit.at < this.ttlMs) return hit.pkg;
    const running = this.inflight.get(name);
    if (running) return running;
    const p = this.fetchPackage(ctx, name).finally(() => this.inflight.delete(name));
    this.inflight.set(name, p);
    const pkg = await p;
    this.cache.set(name, { at: Date.now(), pkg });
    return pkg;
  }

  private async fetchPackage(ctx: Ctx, name: string): Promise<UpstreamPackage | null> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${encodeName(name)}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000) });
    } catch {
      return null;
    }
    if (res.status !== 200) return null;
    const parsed = UpPackument.safeParse(await res.json());
    if (!parsed.success) return null;
    const raw = parsed.data;
    const tarballs = new Map<string, string>();
    const versions: VersionRecord[] = [];
    for (const [v, doc] of Object.entries(raw.versions)) {
      tarballs.set(v, doc.dist.tarball);
      const manifest: Record<string, unknown> = { ...doc };
      delete manifest.dist;
      versions.push({
        package: name,
        version: v,
        manifest,
        shasum: doc.dist.shasum ?? "",
        integrity: doc.dist.integrity ?? "",
        size: 0,
        published_at: Date.parse(raw.time[v] ?? "") || 0,
        published_by: doc._npmUser?.name ?? "upstream",
        deprecated: doc.deprecated ?? null,
        status: "active",
        status_reason: null,
        status_at: null,
        status_by: null,
        score: ctx.store.getUpstreamAnalysis(name, v),
      });
    }
    versions.sort((a, b) => a.published_at - b.published_at);
    return {
      name,
      distTags: raw["dist-tags"],
      description: raw.description ?? "",
      readme: raw.readme ?? "",
      maintainers: (raw.maintainers ?? []).map((m) => m.name),
      versions,
      tarballs,
    };
  }

  /** Fetches (or reads from disk) and verifies the tarball against the upstream integrity. */
  async tarball(ctx: Ctx, pkg: UpstreamPackage, version: string): Promise<Uint8Array | null> {
    const file = join(ctx.store.tarballDir, "_upstream", ...pkg.name.split("/"), `${version}.tgz`);
    if (existsSync(file)) return new Uint8Array(readFileSync(file));
    const url = pkg.tarballs.get(version);
    const rec = pkg.versions.find((v) => v.version === version);
    if (!url || !rec) return null;
    let res: Response;
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    } catch {
      return null;
    }
    if (res.status !== 200) return null;
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (rec.integrity.startsWith("sha512-")) {
      const got = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
      if (got !== rec.integrity) return null;
    } else if (rec.shasum) {
      if (createHash("sha1").update(bytes).digest("hex") !== rec.shasum) return null;
    }
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, bytes);
    return bytes;
  }

  /** Forwards an advisory bulk request; empty on any failure. */
  async advisories(body: unknown): Promise<Record<string, unknown[]>> {
    try {
      const res = await fetch(`${this.baseUrl}-/npm/v1/security/advisories/bulk`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
      if (res.status !== 200) return {};
      const parsed = z.record(z.string(), z.array(z.unknown())).safeParse(await res.json());
      return parsed.success ? parsed.data : {};
    } catch {
      return {};
    }
  }

  forget(name: string): void {
    this.cache.delete(name);
  }
}
