// HTTP routing for the npm wire protocol plus the apm extensions under /-/apm/v1.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { z } from "zod";
import type { Store, VersionRecord, PackageRecord } from "./db.ts";

export type Ctx = { store: Store; now: () => number; baseUrl: () => string };
export type Auth = { kind: "anon" } | { kind: "user"; user: string; tokenHash: string };

// ---------- responses ----------
export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
export function fail(status: number, error: string, extra: Record<string, unknown> = {}): Response {
  return json({ error, ...extra }, status);
}

// ---------- names ----------
const NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
export function isValidName(name: string): boolean {
  return name.length > 0 && name.length <= 214 && NAME_RE.test(name);
}
function tarballBase(name: string): string {
  const i = name.lastIndexOf("/");
  return i >= 0 ? name.slice(i + 1) : name;
}
export function tarballUrl(base: string, name: string, version: string): string {
  return `${base}${name}/-/${tarballBase(name)}-${version}.tgz`;
}

/** Splits a request path into a package name and the remaining segments. */
export function splitPath(pathname: string): { name: string; rest: string[] } | null {
  const raw = pathname.split("/").filter((s) => s.length > 0);
  const segs = raw.map((s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
  const first = segs[0];
  if (first === undefined) return null;
  if (first.startsWith("@")) {
    if (first.includes("/")) return { name: first, rest: segs.slice(1) };
    const second = segs[1];
    if (second === undefined) return null;
    return { name: `${first}/${second}`, rest: segs.slice(2) };
  }
  return { name: first, rest: segs.slice(1) };
}

// ---------- auth ----------
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
export function newToken(): string {
  return `apm_${randomBytes(24).toString("base64url")}`;
}
function authOf(req: Request, ctx: Ctx): Auth {
  const h = req.headers.get("authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m?.[1]) return { kind: "anon" };
  const tokenHash = hashToken(m[1].trim());
  const tok = ctx.store.getToken(tokenHash);
  if (!tok || tok.revoked_at !== null) return { kind: "anon" };
  if (tok.expires_at !== null && tok.expires_at < ctx.now()) return { kind: "anon" };
  return { kind: "user", user: tok.user, tokenHash };
}
export function issueToken(ctx: Ctx, user: string, label: string, ttlMs: number | null = null): string {
  const token = newToken();
  const at = ctx.now();
  ctx.store.insertToken({ token_hash: hashToken(token), user, label, scope: "publish", created_at: at, expires_at: ttlMs === null ? null : at + ttlMs, revoked_at: null });
  return token;
}

// ---------- packuments ----------
const ABBREV_FIELDS = [
  "name",
  "version",
  "dependencies",
  "optionalDependencies",
  "devDependencies",
  "bundleDependencies",
  "bundledDependencies",
  "peerDependencies",
  "peerDependenciesMeta",
  "bin",
  "directories",
  "engines",
  "os",
  "cpu",
  "libc",
  "_hasShrinkwrap",
  "hasInstallScript",
  "deprecated",
  "funding",
  "acceptDependencies",
] as const;

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export function servedVersions(versions: VersionRecord[]): VersionRecord[] {
  return versions.filter((v) => v.status === "active");
}

export type PackumentView = { keep: (v: VersionRecord) => boolean };

/** Highest stable version, or highest prerelease when there is no stable one. */
export function highest(versions: string[]): string | undefined {
  const sorted = [...versions].sort((a, b) => Bun.semver.order(b, a));
  return sorted.find((v) => !v.includes("-")) ?? sorted[0];
}

/** Keeps tags that point at kept versions; moves latest to the highest kept version. */
export function retag(tags: Record<string, string>, kept: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [t, v] of Object.entries(tags)) if (kept.includes(v)) out[t] = v;
  if (!out.latest) {
    const h = highest(kept);
    if (h) out.latest = h;
  }
  return out;
}

export function versionDoc(ctx: Ctx, pkg: PackageRecord, v: VersionRecord, ext: Extensions = {}): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    ...v.manifest,
    name: pkg.name,
    version: v.version,
    _id: `${pkg.name}@${v.version}`,
    dist: {
      tarball: tarballUrl(ctx.baseUrl(), pkg.name, v.version),
      shasum: v.shasum,
      integrity: v.integrity,
      unpackedSize: v.size,
    },
    _npmUser: { name: v.published_by },
  };
  const scripts = v.manifest.scripts;
  if (typeof scripts === "object" && scripts !== null && ["preinstall", "install", "postinstall"].some((k) => k in scripts)) doc.hasInstallScript = true;
  if (v.deprecated) doc.deprecated = v.deprecated;
  else delete doc.deprecated;
  if (ext.compactScore) {
    const c = ext.compactScore(v);
    if (c !== null) doc._apmScore = c;
  }
  return doc;
}

export function packument(ctx: Ctx, pkg: PackageRecord, abbreviated: boolean, ext: Extensions = {}, view?: PackumentView): Record<string, unknown> {
  const all = ctx.store.listVersions(pkg.name);
  const served = servedVersions(all);
  const live = view ? served.filter(view.keep) : served;
  const versions: Record<string, unknown> = {};
  const time: Record<string, string> = { created: iso(pkg.created_at), modified: iso(pkg.modified_at) };
  for (const v of live) {
    const full = versionDoc(ctx, pkg, v, ext);
    if (abbreviated) {
      const slim: Record<string, unknown> = {};
      for (const k of ABBREV_FIELDS) if (k in full) slim[k] = full[k];
      slim.dist = full.dist;
      versions[v.version] = slim;
    } else {
      versions[v.version] = full;
    }
    time[v.version] = iso(v.published_at);
  }
  const distTags = view ? retag(pkg.distTags, live.map((v) => v.version)) : { ...pkg.distTags };
  if (abbreviated) {
    return { name: pkg.name, modified: iso(pkg.modified_at), "dist-tags": distTags, versions };
  }
  return {
    _id: pkg.name,
    name: pkg.name,
    description: pkg.description,
    "dist-tags": distTags,
    versions,
    time,
    maintainers: ctx.store.owners(pkg.name).map((name) => ({ name })),
    readme: pkg.readme,
    keywords: pkg.keywords,
  };
}

// ---------- tarball files ----------
export function tarballPath(ctx: Ctx, name: string, version: string): string {
  return join(ctx.store.tarballDir, ...name.split("/"), `${tarballBase(name)}-${version}.tgz`);
}

// ---------- publish ----------
const Attachment = z.object({ data: z.string(), length: z.number().optional(), content_type: z.string().optional() });
const PublishBody = z.object({
  name: z.string(),
  versions: z.record(z.string(), z.record(z.string(), z.unknown())).default({}),
  "dist-tags": z.record(z.string(), z.string()).default({}),
  _attachments: z.record(z.string(), Attachment).optional(),
  readme: z.string().optional(),
  description: z.string().optional(),
});
type PublishBody = z.infer<typeof PublishBody>;

export type PublishHook = (input: {
  ctx: Ctx;
  name: string;
  version: string;
  manifest: Record<string, unknown>;
  tarball: Uint8Array;
  user: string;
  existing: PackageRecord | null;
}) => Promise<PublishVerdict>;
export type PublishVerdict = { ok: true; manifest: Record<string, unknown>; score: unknown } | { ok: false; status: number; error: string; detail?: unknown };

export type Extensions = {
  onPublish?: PublishHook;
  compactScore?: (v: VersionRecord) => unknown;
  /** Filter for the `~safe` registry view. */
  safeView?: (ctx: Ctx) => PackumentView;
  searchScore?: (v: VersionRecord) => unknown;
  routes?: (req: Request, url: URL, ctx: Ctx, auth: Auth) => Promise<Response | null> | Response | null;
};

function canPublishName(ctx: Ctx, name: string, user: string): { ok: true } | { ok: false; status: number; error: string } {
  const pkg = ctx.store.getPackage(name);
  if (pkg) {
    return ctx.store.owners(name).includes(user) ? { ok: true } : { ok: false, status: 403, error: `You do not have permission to publish "${name}". Owners: ${ctx.store.owners(name).join(", ")}` };
  }
  if (name.startsWith("@")) {
    const scope = name.slice(1, name.indexOf("/"));
    if (scope !== user) return { ok: false, status: 403, error: `Scope @${scope} belongs to another user or org.` };
  }
  return { ok: true };
}

async function handlePublish(req: Request, ctx: Ctx, name: string, auth: Auth, ext: Extensions): Promise<Response> {
  if (auth.kind !== "user") return fail(401, "You must be logged in to publish packages.");
  let body: PublishBody;
  try {
    body = PublishBody.parse(await req.json());
  } catch (e) {
    return fail(400, `Invalid publish body: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (body.name !== name) return fail(400, `Body name ${body.name} does not match URL ${name}`);
  if (!isValidName(name)) return fail(400, `Invalid package name "${name}"`);
  const perm = canPublishName(ctx, name, auth.user);
  if (!perm.ok) return fail(perm.status, perm.error);

  if (!body._attachments || Object.keys(body._attachments).length === 0) {
    return handleMetadataUpdate(ctx, name, body, auth.user);
  }

  const entries = Object.entries(body.versions);
  if (entries.length !== 1) return fail(400, "Publish exactly one version at a time.");
  const [version, manifest] = entries[0] ?? ["", {}];
  if (!Bun.semver.satisfies(version, "*") && !/^\d+\.\d+\.\d+/.test(version)) return fail(400, `Invalid version ${version}`);
  const attachment = Object.values(body._attachments)[0];
  if (!attachment) return fail(400, "Missing tarball");
  const tarball = new Uint8Array(Buffer.from(attachment.data, "base64"));
  if (tarball.length === 0) return fail(400, "Empty tarball");

  const existing = ctx.store.getPackage(name);
  if (existing && ctx.store.getVersion(name, version)) {
    return fail(409, `Cannot publish over existing version ${name}@${version}. Versions are immutable; bump the version.`);
  }
  const shasum = createHash("sha1").update(tarball).digest("hex");
  const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;

  let score: unknown = null;
  let storedManifest: Record<string, unknown> = manifest;
  if (ext.onPublish) {
    const verdict = await ext.onPublish({ ctx, name, version, manifest, tarball, user: auth.user, existing });
    if (!verdict.ok) return fail(verdict.status, verdict.error, verdict.detail === undefined ? {} : { detail: verdict.detail });
    score = verdict.score;
    storedManifest = verdict.manifest;
  }

  const at = ctx.now();
  const path = tarballPath(ctx, name, version);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, tarball);
  const cleanManifest: Record<string, unknown> = { ...storedManifest };
  for (const k of ["_id", "dist", "_npmUser", "_attachments", "readme", "_resolved", "_integrity", "_from"]) delete cleanManifest[k];
  const requestedTag = Object.keys(body["dist-tags"])[0] ?? "latest";

  ctx.store.tx(() => {
    if (!existing) ctx.store.createPackage(name, at, auth.user);
    ctx.store.insertVersion({
      package: name,
      version,
      manifest: cleanManifest,
      shasum,
      integrity,
      size: tarball.length,
      published_at: at,
      published_by: auth.user,
      score,
    });
    const pkg = ctx.store.getPackage(name);
    const tags = { ...(pkg?.distTags ?? {}) };
    const isPrerelease = version.includes("-");
    const currentLatest = tags.latest;
    // a prerelease never takes `latest` once a stable release exists; it goes to `next`
    const tag = requestedTag === "latest" && isPrerelease && currentLatest ? "next" : requestedTag;
    if (tag === "latest" && currentLatest && Bun.semver.order(version, currentLatest) < 0) {
      // publishing an older line (a 1.x backport) never moves latest backwards
    } else {
      tags[tag] = version;
    }
    ctx.store.setDistTags(name, tags, at);
    const description = typeof manifest.description === "string" ? manifest.description : undefined;
    const keywords = Array.isArray(manifest.keywords) ? manifest.keywords.filter((k): k is string => typeof k === "string") : undefined;
    const readme = body.readme ?? (typeof manifest.readme === "string" ? manifest.readme : undefined);
    ctx.store.updatePackageMeta(name, {
      modifiedAt: at,
      ...(description !== undefined ? { description } : {}),
      ...(keywords !== undefined ? { keywords } : {}),
      ...(readme !== undefined ? { readme } : {}),
    });
    ctx.store.addEvent({ package: name, kind: "publish", actor: auth.user, at, detail: { version, tag: requestedTag } });
  });
  return json({ ok: true, id: name, rev: `${at}`, success: true, score }, 201);
}

function handleMetadataUpdate(ctx: Ctx, name: string, body: PublishBody, user: string): Response {
  const pkg = ctx.store.getPackage(name);
  if (!pkg) return fail(404, "Not found");
  const at = ctx.now();
  ctx.store.tx(() => {
    for (const [version, manifest] of Object.entries(body.versions)) {
      const v = ctx.store.getVersion(name, version);
      if (!v) continue;
      const dep = manifest.deprecated;
      const next = typeof dep === "string" && dep.length > 0 ? dep : null;
      if (next !== v.deprecated) {
        ctx.store.setDeprecated(name, version, next);
        ctx.store.addEvent({ package: name, kind: next ? "deprecate" : "undeprecate", actor: user, at, detail: { version, message: next } });
      }
    }
    ctx.store.updatePackageMeta(name, { modifiedAt: at });
  });
  return json({ ok: true });
}

// ---------- dist-tags ----------
async function handleDistTags(req: Request, ctx: Ctx, name: string, tag: string | undefined, auth: Auth): Promise<Response> {
  const pkg = ctx.store.getPackage(name);
  if (!pkg) return fail(404, "Not found");
  if (req.method === "GET") return json(pkg.distTags);
  if (auth.kind !== "user") return fail(401, "Login required");
  if (!ctx.store.owners(name).includes(auth.user)) return fail(403, "Not an owner");
  if (!tag) return fail(400, "Tag required");
  const tags = { ...pkg.distTags };
  if (req.method === "PUT" || req.method === "POST") {
    const raw: unknown = await req.json();
    const version = z.string().parse(raw);
    const v = ctx.store.getVersion(name, version);
    if (!v || v.status !== "active") return fail(404, `Version ${version} not found or not active`);
    tags[tag] = version;
  } else if (req.method === "DELETE") {
    if (tag === "latest") return fail(400, "Cannot delete latest");
    delete tags[tag];
  } else {
    return fail(405, "Method not allowed");
  }
  const at = ctx.now();
  ctx.store.setDistTags(name, tags, at);
  ctx.store.addEvent({ package: name, kind: "dist-tag", actor: auth.user, at, detail: { tag, version: tags[tag] ?? null } });
  return json({ ok: true, ...tags });
}

// ---------- users ----------
const UserBody = z.object({ name: z.string().min(1), password: z.string().min(1), email: z.string().optional() });
const USER_RE = /^[a-z0-9][a-z0-9-]{0,38}$/;

async function handleAddUser(req: Request, ctx: Ctx, rawName: string): Promise<Response> {
  let body: z.infer<typeof UserBody>;
  try {
    body = UserBody.parse(await req.json());
  } catch {
    return fail(400, "name and password required");
  }
  const name = rawName.replace(/^org\.couchdb\.user:/, "");
  if (body.name !== name) return fail(400, "name mismatch");
  if (!USER_RE.test(name)) return fail(400, "Usernames are lowercase letters, digits and dashes.");
  const existing = ctx.store.getUser(name);
  if (existing) {
    const ok = await Bun.password.verify(body.password, existing.password_hash);
    if (!ok) return fail(401, "Incorrect username or password.");
    return json({ ok: true, id: `org.couchdb.user:${name}`, token: issueToken(ctx, name, "cli login") }, 201);
  }
  if (body.password.length < 8) return fail(400, "Password must be at least 8 characters.");
  ctx.store.createUser({ name, password_hash: await Bun.password.hash(body.password), email: body.email ?? "", created_at: ctx.now() });
  return json({ ok: true, id: `org.couchdb.user:${name}`, token: issueToken(ctx, name, "cli login") }, 201);
}

// ---------- search ----------
export type SearchHit = { pkg: PackageRecord; latest: VersionRecord | null; rank: number };

export function searchPackages(ctx: Ctx, text: string): SearchHit[] {
  const q = text.trim().toLowerCase();
  const terms = q.split(/\s+/).filter(Boolean);
  const hits: SearchHit[] = [];
  for (const name of ctx.store.listPackageNames()) {
    const pkg = ctx.store.getPackage(name);
    if (!pkg) continue;
    const hay = `${name} ${pkg.description} ${pkg.keywords.join(" ")}`.toLowerCase();
    let rank = 0;
    if (terms.length === 0) rank = 1;
    for (const t of terms) {
      if (name === t) rank += 100;
      else if (name.startsWith(t)) rank += 40;
      else if (name.includes(t)) rank += 25;
      else if (pkg.keywords.some((k) => k.toLowerCase() === t)) rank += 15;
      else if (hay.includes(t)) rank += 5;
    }
    if (rank === 0) continue;
    const live = servedVersions(ctx.store.listVersions(name));
    const latestVersion = pkg.distTags.latest;
    const latest = live.find((v) => v.version === latestVersion) ?? live[live.length - 1] ?? null;
    if (!latest) continue;
    hits.push({ pkg, latest, rank });
  }
  hits.sort((a, b) => b.rank - a.rank || a.pkg.name.localeCompare(b.pkg.name));
  return hits;
}

/** Paging of a /-/v1/search request, clamped the way npm's registry clamps it. */
export function searchPaging(url: URL): { text: string; size: number; from: number } {
  return {
    text: url.searchParams.get("text") ?? "",
    size: Math.min(250, Math.max(1, Number(url.searchParams.get("size") ?? 20) || 20)),
    from: Math.max(0, Number(url.searchParams.get("from") ?? 0) || 0),
  };
}

/** Search objects in npm's wire shape for packages published here, best match first. */
export function localSearchObjects(ctx: Ctx, ext: Extensions, text: string) {
  return searchPackages(ctx, text).map((h) => ({
    source: "local" as const,
    package: {
      name: h.pkg.name,
      scope: h.pkg.name.startsWith("@") ? h.pkg.name.slice(1, h.pkg.name.indexOf("/")) : "unscoped",
      version: h.latest?.version ?? "",
      description: h.pkg.description,
      keywords: h.pkg.keywords,
      date: iso(h.latest?.published_at ?? h.pkg.modified_at),
      links: { npm: `${ctx.baseUrl()}package/${h.pkg.name}` },
      publisher: { username: h.latest?.published_by ?? "" },
      maintainers: ctx.store.owners(h.pkg.name).map((username) => ({ username })),
    },
    score: { final: h.rank / 100, detail: { quality: 1, popularity: 1, maintenance: 1 } },
    searchScore: h.rank,
    apmScore: h.latest && ext.searchScore ? ext.searchScore(h.latest) : null,
  }));
}
export type LocalSearchObject = ReturnType<typeof localSearchObjects>[number];

function handleSearch(url: URL, ctx: Ctx, ext: Extensions): Response {
  const { text, size, from } = searchPaging(url);
  const all = localSearchObjects(ctx, ext, text);
  return json({ objects: all.slice(from, from + size), total: all.length, time: new Date(ctx.now()).toUTCString(), upstreamFailed: false });
}

// ---------- router ----------
export function createHandler(ctx: Ctx, ext: Extensions = {}): (req: Request) => Promise<Response> {
  return async (req: Request): Promise<Response> => {
    try {
      return await route(req, ctx, ext);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      process.stderr.write(`apm registry error: ${req.method} ${req.url}: ${msg}\n`);
      return fail(500, "Internal error");
    }
  };
}

async function route(req: Request, ctx: Ctx, ext: Extensions): Promise<Response> {
  const url = new URL(req.url);
  let path = url.pathname;
  const auth = authOf(req, ctx);
  let view: PackumentView | undefined;
  if (path === "/~safe" || path.startsWith("/~safe/")) {
    path = path.slice("/~safe".length) || "/";
    url.pathname = path;
    if (ext.safeView) view = ext.safeView(ctx);
  }

  if (ext.routes) {
    const r = await ext.routes(req, url, ctx, auth);
    if (r) return r;
  }

  if (path === "/-/ping") return json({});
  if (path === "/-/whoami") return auth.kind === "user" ? json({ username: auth.user }) : fail(401, "Not logged in");
  if (path.startsWith("/-/user/") && req.method === "PUT") {
    return handleAddUser(req, ctx, decodeURIComponent(path.slice("/-/user/".length)));
  }
  if (path.startsWith("/-/user/token/") && req.method === "DELETE") {
    if (auth.kind === "user") ctx.store.db.query("UPDATE tokens SET revoked_at = ? WHERE token_hash = ?").run(ctx.now(), auth.tokenHash);
    return json({ ok: true });
  }
  if (path === "/-/v1/search") return handleSearch(url, ctx, ext);
  if (path.startsWith("/-/package/")) {
    const sp = splitPath(path.slice("/-/package".length));
    if (!sp) return fail(404, "Not found");
    if (sp.rest[0] !== "dist-tags") return fail(404, "Not found");
    return handleDistTags(req, ctx, sp.name, sp.rest[1], auth);
  }
  if (path.startsWith("/-/")) return fail(404, "Not found");

  const sp = splitPath(path);
  if (!sp) return json({ name: "apm registry", ok: true });
  const { name, rest } = sp;

  if (req.method === "PUT" && rest.length === 0) return handlePublish(req, ctx, name, auth, ext);
  if (req.method === "PUT" && rest[0] === "-rev") return handlePublish(req, ctx, name, auth, ext);

  if (req.method !== "GET" && req.method !== "HEAD") return fail(405, "Method not allowed");

  const pkg = ctx.store.getPackage(name);
  // tarball
  if (rest[0] === "-" && rest[1]) {
    const file = rest[1];
    const m = /^(.*)-(\d+\.\d+\.\d+.*)\.tgz$/.exec(file);
    if (!pkg || !m?.[2]) return fail(404, "Not found");
    const v = ctx.store.getVersion(name, m[2]);
    if (!v) return fail(404, "Not found");
    if (v.status === "revoked") {
      return fail(410, `${name}@${v.version} was revoked: ${v.status_reason ?? "no reason given"}`, { revoked: true });
    }
    const p = tarballPath(ctx, name, v.version);
    if (!existsSync(p)) return fail(404, "Tarball missing");
    return new Response(readFileSync(p), { headers: { "content-type": "application/octet-stream" } });
  }
  if (!pkg) return fail(404, "Not found");
  if (rest.length === 0) {
    const accept = req.headers.get("accept") ?? "";
    const abbreviated = accept.includes("application/vnd.npm.install-v1+json");
    const body = packument(ctx, pkg, abbreviated, ext, view);
    const text = JSON.stringify(body);
    const etag = `"${createHash("sha1").update(text).digest("base64url")}"`;
    // Version state can change at any time (yank, revoke), so clients must revalidate every time.
    const headers = {
      "content-type": abbreviated ? "application/vnd.npm.install-v1+json; charset=utf-8" : "application/json",
      "cache-control": "no-cache",
      etag,
      "last-modified": new Date(pkg.modified_at).toUTCString(),
    };
    if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers });
    return new Response(text, { status: 200, headers });
  }
  // GET /:name/:versionOrTag
  const spec = rest[0] ?? "";
  const resolved = pkg.distTags[spec] ?? spec;
  const v = ctx.store.getVersion(name, resolved);
  if (!v || v.status === "revoked") return fail(404, "Version not found");
  return json(versionDoc(ctx, pkg, v, ext));
}
