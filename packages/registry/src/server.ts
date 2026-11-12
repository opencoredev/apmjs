// HTTP routing for the npm wire protocol plus the apm extensions under /-/apm/v1.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, linkSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname, resolve, sep } from "node:path";
import { z } from "zod";
import { editDistance, isValidTagName, isValidVersion } from "@apm/core";
import type { LiveAction } from "./actions.ts";
import type { StagedLoad, Store, VersionRecord, PackageRecord } from "./db.ts";
import { checkPassword, LOCKED_MESSAGE } from "./passwords.ts";

export type NamePolicy = "scoped" | "open";
export type Refusal = { status: number; error: string };
/** Who may publish what, and how. Built in index.ts from the auth setup and the upstream. */
export type Access = {
  /** npm's password adduser and password re-auth. Off in production. */
  legacyAuth: boolean;
  namePolicy: NamePolicy;
  /** The website: approval links and the device page live here. Ends with "/". */
  webUrl: () => string;
  /** Why `user` may not publish a first version of `name`, or null. */
  newNameRefusal: (input: { name: string; user: string }) => Promise<Refusal | null>;
  /** Why `user` may not stage a publish (no passkey or 2FA), or null. */
  stageRefusal: (user: string) => Refusal | null;
  /**
   * Why `user` may not do `action` with this proof, or null. A password counts only in legacy mode; a TOTP code
   * counts once; with neither, a website confirmation of exactly this command counts once.
   */
  secondFactor: (input: { user: string; password?: string | undefined; otp?: string | undefined; action: LiveAction }) => Promise<Refusal | null>;
  /** Why this token may not change live state (`action`), or null. Staging tokens need a fresh second factor for it. */
  liveChangeRefusal: (input: { user: string; scope: TokenScope; action: LiveAction; otp?: string | undefined }) => Promise<Refusal | null>;
};
export type Ctx = {
  store: Store;
  now: () => number;
  baseUrl: () => string;
  access: Access;
  /** Runs after a version goes live (direct publish or approval). Index wires the AI review queue here. */
  afterCommit?: (v: { name: string; version: string; firstPublish: boolean }) => void;
};
/** "publish" tokens go live at once (legacy logins, test tokens, later CI trusted publishing); "stage" tokens need approval. */
export type TokenScope = "publish" | "stage";

/**
 * What each kind of token may do. A staging token (apm login, the website's device flow) uploads versions that wait
 * for a person, and changes live state (dist-tags, deprecate, yank, unyank) only with a fresh second factor.
 */
export const TOKEN_CAPABILITIES: Record<TokenScope, { publish: "live" | "staged"; liveChanges: "token" | "second-factor" }> = {
  publish: { publish: "live", liveChanges: "token" },
  stage: { publish: "staged", liveChanges: "second-factor" },
};
/** What a token row's scope means today. "legacy" tokens came from password logins: direct publish only while legacy auth is on. */
export function effectiveScope(stored: string, legacyAuth: boolean): TokenScope {
  if (stored === "stage") return "stage";
  if (stored === "legacy") return legacyAuth ? "publish" : "stage";
  return "publish";
}
export type Auth = { kind: "anon" } | { kind: "user"; user: string; tokenHash: string; scope: TokenScope };

/** A staged version waits this long for approval. */
export const STAGE_TTL_MS = 24 * 60 * 60 * 1000;

/** Versions one account may have waiting for approval at once, and their total size. */
export const MAX_STAGED_PER_USER = 20;
export const MAX_STAGED_BYTES_PER_USER = 256 * 1024 * 1024;

/** Versions of one package that may wait for approval at once. */
export const MAX_STAGED_PER_PACKAGE = 5;

/** The most readme and manifest text one version may store (npm's own readme cap is far lower in practice). */
export const MAX_README_BYTES = 1024 * 1024;
export const MAX_MANIFEST_BYTES = 1024 * 1024;

// ---------- responses ----------
export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
export function fail(status: number, error: string, extra: Record<string, unknown> = {}): Response {
  return json({ error, ...extra }, status);
}

// Answers that belong to whoever asked: the account, sessions, staged versions, tokens, step-ups and login.
const PER_USER_PATHS = ["/api/auth/", "/-/whoami", "/-/user/", "/-/npm/v1/", "/-/apm/v1/account", "/-/apm/v1/staged", "/-/apm/v1/verify", "/-/apm/v1/login/", "/-/apm/v1/review"];

/**
 * Marks per-user answers `Cache-Control: private, no-store` and `Vary: Authorization, Cookie`, so no shared
 * cache keeps one: every answer on a per-user path, and any other /-/ answer to a request that carried
 * credentials. Packuments and tarballs are the same for everyone and keep their own caching.
 */
export function withPrivacyHeaders(req: Request, res: Response): Response {
  const path = new URL(req.url).pathname;
  const credentialed = req.headers.has("authorization") || req.headers.has("cookie");

  if (!PER_USER_PATHS.some((p) => path.startsWith(p)) && !(credentialed && path.startsWith("/-/"))) return res;
  // some answers (redirects) have immutable headers, so the answer is rebuilt around a copy
  const headers = new Headers(res.headers);
  const vary = new Set((headers.get("vary") ?? "").split(",").map((v) => v.trim()).filter((v) => v !== ""));

  vary.add("Authorization");
  vary.add("Cookie");
  headers.set("cache-control", "private, no-store");
  headers.set("vary", [...vary].join(", "));

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
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
  return { kind: "user", user: tok.user, tokenHash, scope: effectiveScope(tok.scope, ctx.access.legacyAuth) };
}
export function issueToken(ctx: Ctx, input: { user: string; label: string; scope: TokenScope | "legacy"; ttlMs?: number }): string {
  const token = newToken();
  const at = ctx.now();
  ctx.store.insertToken({
    token_hash: hashToken(token),
    user: input.user,
    label: input.label,
    scope: input.scope,
    created_at: at,
    expires_at: input.ttlMs === undefined ? null : at + input.ttlMs,
    revoked_at: null,
  });
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

/** A filtered registry view (`~safe`): which versions it serves, why it hides the others, and the URL prefix it lives under. */
export type PackumentView = { keep: (v: VersionRecord) => boolean; why: (v: VersionRecord) => string | null; prefix: string };

/** The version a dist-tag points to. Own keys only: `toString` or `__proto__` is never a tag. */
export function tagTarget(tags: Record<string, string>, tag: string): string | undefined {
  return Object.hasOwn(tags, tag) ? tags[tag] : undefined;
}

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

export function versionDoc(ctx: Ctx, pkg: PackageRecord, v: VersionRecord, ext: Extensions = {}, view?: PackumentView): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    ...v.manifest,
    name: pkg.name,
    version: v.version,
    _id: `${pkg.name}@${v.version}`,
    dist: {
      // a view's tarballs stay inside the view, so a lockfile written from it keeps being checked
      tarball: tarballUrl(`${ctx.baseUrl()}${view?.prefix ?? ""}`, pkg.name, v.version),
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
    const full = versionDoc(ctx, pkg, v, ext, view);
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
// Published tarballs are blobs named by their sha512, so no name or version ever becomes part of a
// path. Every path is still checked to stay inside its root.

/** `segments` joined under `root`; throws when the result would leave it. */
export function inside(root: string, ...segments: string[]): string {
  const base = resolve(root);
  const p = resolve(base, ...segments);
  if (p === base || !p.startsWith(base + sep)) throw new Error(`storage path escapes ${base}`);
  return p;
}

export function integrityOf(bytes: Uint8Array): string {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

/** The blob file for a "sha512-<base64>" integrity, or null when it is not one. */
export function blobPath(ctx: Ctx, integrity: string): string | null {
  if (!integrity.startsWith("sha512-")) return null;
  const raw = Buffer.from(integrity.slice("sha512-".length), "base64");
  if (raw.length !== 64 || `sha512-${raw.toString("base64")}` !== integrity) return null;
  const hex = raw.toString("hex");
  return inside(ctx.store.tarballDir, "blobs", hex.slice(0, 2), `${hex}.tgz`);
}

/** Where versions published before blobs were kept. Read only, as a fallback. */
function legacyTarballPath(ctx: Ctx, name: string, version: string): string | null {
  try {
    return inside(ctx.store.tarballDir, ...name.split("/"), `${tarballBase(name)}-${version}.tgz`);
  } catch {
    return null;
  }
}

/** The bytes of a published version, or null when the file is missing. */
export function readVersionTarball(ctx: Ctx, v: VersionRecord): Uint8Array | null {
  for (const p of [blobPath(ctx, v.integrity), legacyTarballPath(ctx, v.package, v.version)]) {
    if (p && existsSync(p)) return new Uint8Array(readFileSync(p));
  }
  return null;
}

const STAGED_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
/** Staged tarballs sit outside the served tree until approval. */
export function stagedTarballPath(ctx: Ctx, id: string): string {
  if (!STAGED_ID_RE.test(id)) throw new Error("malformed staged id");
  return inside(join(ctx.store.tarballDir, "..", "staged"), `${id}.tgz`);
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
export type PublishVerdict = { ok: true; manifest: Record<string, unknown>; score: unknown; warnings: string[] } | { ok: false; status: number; error: string; detail?: unknown };

export type Extensions = {
  onPublish?: PublishHook;
  compactScore?: (v: VersionRecord) => unknown;
  /** Filter for the `~safe` registry view. */
  safeView?: (ctx: Ctx) => PackumentView;
  searchScore?: (v: VersionRecord) => unknown;
  routes?: (req: Request, url: URL, ctx: Ctx, auth: Auth) => Promise<Response | null> | Response | null;
};

/** Why `user` may not publish to `name` (owners for existing packages, the name policy for new ones), or null. */
export async function publishRefusal(ctx: Ctx, name: string, user: string): Promise<Refusal | null> {
  const pkg = ctx.store.getPackage(name);
  if (pkg) {
    return ctx.store.owners(name).includes(user) ? null : { status: 403, error: `You do not have permission to publish "${name}". Owners: ${ctx.store.owners(name).join(", ")}` };
  }
  return ctx.access.newNameRefusal({ name, user });
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
  const perm = await publishRefusal(ctx, name, auth.user);
  if (perm) return fail(perm.status, perm.error);

  if (!body._attachments || Object.keys(body._attachments).length === 0) {
    // the versions and messages that would change are what a second factor authorizes; no change needs none
    const [first, ...rest] = deprecationChanges(ctx, name, body);

    if (first) {
      const denied = await ctx.access.liveChangeRefusal({ user: auth.user, scope: auth.scope, action: { kind: "deprecate", name, changes: [first, ...rest] }, otp: npmOtp(req) });

      if (denied) return otpFail(denied);
    }

    return handleMetadataUpdate(ctx, name, body, auth.user);
  }

  const entries = Object.entries(body.versions);
  if (entries.length !== 1) return fail(400, "Publish exactly one version at a time.");
  const tags = Object.keys(body["dist-tags"]);

  if (tags.length > 1) return fail(400, "Publish with one dist-tag at a time.");
  const bad = tags.find((t) => !isValidTagName(t));

  if (bad !== undefined) return fail(400, tagNameError(bad));
  const [version, manifest] = entries[0] ?? ["", {}];
  if (!isValidVersion(version)) return fail(400, `Invalid version "${version}": apm accepts strict semver only (1.2.3, 1.2.3-beta.1).`);
  const attachment = Object.values(body._attachments)[0];
  if (!attachment) return fail(400, "Missing tarball");
  const tarball = new Uint8Array(Buffer.from(attachment.data, "base64"));
  if (tarball.length === 0) return fail(400, "Empty tarball");

  const existing = ctx.store.getPackage(name);
  if (existing && ctx.store.getVersion(name, version)) {
    return fail(409, `Cannot publish over existing version ${name}@${version}. Versions are immutable; bump the version.`);
  }

  const readme = body.readme ?? (typeof manifest.readme === "string" ? manifest.readme : null);

  if (readme !== null && Buffer.byteLength(readme, "utf8") > MAX_README_BYTES) return fail(413, `The readme is over ${MAX_README_BYTES / (1024 * 1024)} MB. Shorten it or link to longer docs.`);

  if (Buffer.byteLength(JSON.stringify(manifest), "utf8") > MAX_MANIFEST_BYTES) return fail(413, `package.json is over ${MAX_MANIFEST_BYTES / (1024 * 1024)} MB.`);

  const staged = TOKEN_CAPABILITIES[auth.scope].publish === "staged";

  if (staged) {
    const pending = ctx.store.pendingStaged(name, version);
    if (pending && pending.expires_at > ctx.now()) {
      return fail(409, `${name}@${version} is already waiting for approval: ${approvalUrl(ctx, pending.id)}`);
    }
    const noFactor = ctx.access.stageRefusal(auth.user);
    if (noFactor) return fail(noFactor.status, noFactor.error);
    const over = stageQuotaRefusal(ctx, { user: auth.user, name, size: tarball.length });

    if (over) return fail(429, over);
  }

  let score: unknown = null;
  let storedManifest: Record<string, unknown> = manifest;
  let warnings: string[] = [];
  if (ext.onPublish) {
    const verdict = await ext.onPublish({ ctx, name, version, manifest, tarball, user: auth.user, existing });
    if (!verdict.ok) return fail(verdict.status, verdict.error, verdict.detail === undefined ? {} : { detail: verdict.detail });
    score = verdict.score;
    storedManifest = verdict.manifest;
    warnings = verdict.warnings;
  }

  const cleanManifest: Record<string, unknown> = { ...storedManifest };
  for (const k of ["_id", "dist", "_npmUser", "_attachments", "readme", "_resolved", "_integrity", "_from"]) delete cleanManifest[k];
  const tag = Object.keys(body["dist-tags"])[0] ?? "latest";
  const shasum = createHash("sha1").update(tarball).digest("hex");
  const integrity = integrityOf(tarball);
  // header-safe: a tar path may hold control characters
  const warningText = warnings.length > 0 ? `Warning: ${warnings.join(" ")}`.replace(/[\x00-\x1f\x7f]/g, " ") : null;

  if (staged) {
    const at = ctx.now();
    const id = randomBytes(12).toString("base64url");
    const path = stagedTarballPath(ctx, id);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, tarball);

    // the checks above ran before the analysis awaited; these run again atomically with the insert
    const stored = ctx.store.insertStagedWithin(
      { id, package: name, version, manifest: cleanManifest, shasum, integrity, size: tarball.length, tag, readme, score, staged_by: auth.user, staged_at: at, expires_at: at + STAGE_TTL_MS },
      { perUser: MAX_STAGED_PER_USER, perPackage: MAX_STAGED_PER_PACKAGE, bytesPerUser: MAX_STAGED_BYTES_PER_USER },
    );

    if (stored.kind !== "staged") {
      rmSync(path, { force: true });

      return stored.kind === "duplicate" ? fail(409, `${name}@${version} is already waiting for approval: ${approvalUrl(ctx, stored.id)}`) : fail(429, quotaMessage(ctx, { name, quota: stored.quota, load: stored.load }));
    }
    const link = approvalUrl(ctx, id);
    const expiresAt = new Date(at + STAGE_TTL_MS).toISOString();
    // bun prints this header as "note: ...", npm as "npm notice ...": that is how the link reaches a person.
    const notice = `${name}@${version} is uploaded but NOT live. A person must approve it within 24h: ${link}${warningText ? ` ${warningText}` : ""}`;
    return json({ ok: true, success: true, staged: true, id, approvalUrl: link, expiresAt, message: notice, warnings }, 202, { "npm-notice": notice });
  }

  const done = commitVersion(ctx, { name, version, manifest: cleanManifest, tarball, shasum, integrity, tag, readme, score, publisher: auth.user, detail: {} });
  if (done.kind === "refused") return fail(done.status, done.error);
  return json({ ok: true, id: name, rev: `${ctx.now()}`, success: true, score, warnings }, 201, warningText ? { "npm-notice": warningText } : {});
}

/** Why one more staged upload of `size` tarball bytes would go over a quota, or null. A fast check before the analysis. */
function stageQuotaRefusal(ctx: Ctx, input: { user: string; name: string; size: number }): string | null {
  const load = ctx.store.pendingStagedLoad({ user: input.user, name: input.name, now: ctx.now() });

  if (load.byPackage >= MAX_STAGED_PER_PACKAGE) return quotaMessage(ctx, { name: input.name, quota: "package", load });

  if (load.byUser >= MAX_STAGED_PER_USER) return quotaMessage(ctx, { name: input.name, quota: "user", load });

  if (load.bytesByUser + input.size > MAX_STAGED_BYTES_PER_USER) return quotaMessage(ctx, { name: input.name, quota: "bytes", load });

  return null;
}

function quotaMessage(ctx: Ctx, input: { name: string; quota: "package" | "user" | "bytes"; load: StagedLoad }): string {
  const where = `Approve or reject them at ${ctx.access.webUrl()}publish, or wait for them to expire (24h).`;

  switch (input.quota) {
    case "package":
      return `${input.name} already has ${input.load.byPackage} versions waiting for approval, the most one package may have. ${where}`;
    case "user":
      return `You already have ${input.load.byUser} versions waiting for approval, the most one account may have. ${where}`;
    case "bytes":
      return `Your versions waiting for approval would take more than ${MAX_STAGED_BYTES_PER_USER / (1024 * 1024)} MB. ${where}`;
    default: {
      const _exhaustive: never = input.quota;

      return _exhaustive;
    }
  }
}

export function approvalUrl(ctx: Ctx, id: string): string {
  return `${ctx.access.webUrl()}approve/${id}`;
}

export type CommitResult = { kind: "committed" } | { kind: "refused"; status: 403 | 409; error: string };

class CommitRefusal extends Error {
  constructor(
    readonly status: 403 | 409,
    message: string,
  ) {
    super(message);
  }
}

function hasCode(e: unknown): e is { code: unknown } {
  return typeof e === "object" && e !== null && "code" in e;
}

/** Puts the bytes at their blob path. Never replaces an existing blob; says whether this call created it. */
function placeBlob(path: string, bytes: Uint8Array): boolean {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(tmp, bytes);
  try {
    linkSync(tmp, path);
    return true;
  } catch (e) {
    if (hasCode(e) && e.code === "EEXIST") return false;
    throw e;
  } finally {
    rmSync(tmp, { force: true });
  }
}

/**
 * Makes a version live: blob in place, version row, dist-tags, package metadata and the publish event.
 * The version insert is the one decision: inside a single transaction it checks the version is new and
 * the publisher still owns the package (the primary key backs this up). A losing publish gets 409 and
 * its blob is removed unless another version uses the same bytes.
 */
export function commitVersion(
  ctx: Ctx,
  v: {
    name: string;
    version: string;
    manifest: Record<string, unknown>;
    tarball: Uint8Array | { stagedPath: string };
    shasum: string;
    integrity: string;
    tag: string;
    readme: string | null;
    score: unknown;
    publisher: string;
    detail: Record<string, unknown>;
  },
): CommitResult {
  const at = ctx.now();
  const bytes = v.tarball instanceof Uint8Array ? v.tarball : new Uint8Array(readFileSync(v.tarball.stagedPath));
  if (integrityOf(bytes) !== v.integrity) throw new Error(`${v.name}@${v.version}: tarball bytes do not match their integrity`);
  const path = blobPath(ctx, v.integrity);
  if (!path) throw new Error(`${v.name}@${v.version}: malformed integrity`);
  const created = placeBlob(path, bytes);
  const size = bytes.length;
  let firstPublish = false;

  try {
    ctx.store.tx(() => {
      if (ctx.store.getVersion(v.name, v.version)) {
        throw new CommitRefusal(409, `Cannot publish over existing version ${v.name}@${v.version}. Versions are immutable; bump the version.`);
      }
      if (!ctx.store.getPackage(v.name)) {
        ctx.store.createPackage(v.name, at, v.publisher);
        firstPublish = true;
      } else if (!ctx.store.owners(v.name).includes(v.publisher)) {
        throw new CommitRefusal(403, `You do not have permission to publish "${v.name}". Owners: ${ctx.store.owners(v.name).join(", ")}`);
      }
      commitRows(ctx, v, { at, size });
    });
  } catch (e) {
    if (created && !ctx.store.integrityInUse(v.integrity)) rmSync(path, { force: true });
    if (e instanceof CommitRefusal) return { kind: "refused", status: e.status, error: e.message };
    if (hasCode(e) && typeof e.code === "string" && e.code.startsWith("SQLITE_CONSTRAINT")) {
      return { kind: "refused", status: 409, error: `Cannot publish over existing version ${v.name}@${v.version}. Versions are immutable; bump the version.` };
    }
    throw e;
  }
  if (!(v.tarball instanceof Uint8Array)) rmSync(v.tarball.stagedPath, { force: true });
  ctx.afterCommit?.({ name: v.name, version: v.version, firstPublish });
  return { kind: "committed" };
}

type CommitInput = Parameters<typeof commitVersion>[1];

/** The rows of a publish. Runs inside commitVersion's transaction. */
function commitRows(ctx: Ctx, v: CommitInput, m: { at: number; size: number }): void {
  const { at, size } = m;
  ctx.store.insertVersion({
    package: v.name,
    version: v.version,
    manifest: v.manifest,
    shasum: v.shasum,
    integrity: v.integrity,
    size,
    published_at: at,
    published_by: v.publisher,
    score: v.score,
  });
  const pkg = ctx.store.getPackage(v.name);
  const tags = { ...(pkg?.distTags ?? {}) };
  const isPrerelease = v.version.includes("-");
  const currentLatest = tags.latest;
  // a prerelease never takes `latest` once a stable release exists; it goes to `next`
  const tag = v.tag === "latest" && isPrerelease && currentLatest ? "next" : v.tag;
  if (tag === "latest" && currentLatest && Bun.semver.order(v.version, currentLatest) < 0) {
    // publishing an older line (a 1.x backport) never moves latest backwards
  } else {
    tags[tag] = v.version;
  }
  ctx.store.setDistTags(v.name, tags, at);
  const description = typeof v.manifest.description === "string" ? v.manifest.description : undefined;
  const keywords = Array.isArray(v.manifest.keywords) ? v.manifest.keywords.filter((k): k is string => typeof k === "string") : undefined;
  ctx.store.updatePackageMeta(v.name, {
    modifiedAt: at,
    ...(description !== undefined ? { description } : {}),
    ...(keywords !== undefined ? { keywords } : {}),
    ...(v.readme !== null ? { readme: v.readme } : {}),
  });
  ctx.store.addEvent({ package: v.name, kind: "publish", actor: v.publisher, at, detail: { version: v.version, tag: v.tag, ...v.detail } });
}

/** The deprecation message a metadata PUT sets on a version: a non-empty string, or null to take it off. */
function deprecationOf(manifest: { readonly deprecated?: unknown }): string | null {
  const dep = z.string().min(1).safeParse(manifest.deprecated);

  return dep.success ? dep.data : null;
}

/** What a metadata PUT (npm deprecate) would change: each existing version whose message differs. */
function deprecationChanges(ctx: Ctx, name: string, body: PublishBody): { version: string; message: string | null }[] {
  return Object.entries(body.versions).flatMap(([version, manifest]) => {
    const v = ctx.store.getVersion(name, version);
    const next = deprecationOf(manifest);

    return v && next !== v.deprecated ? [{ version, message: next }] : [];
  });
}

/** A publish-shaped PUT without a tarball: npm deprecate. Answers with the versions it changed; a missing version changes nothing. */
function handleMetadataUpdate(ctx: Ctx, name: string, body: PublishBody, user: string): Response {
  const pkg = ctx.store.getPackage(name);
  if (!pkg) return fail(404, "Not found");
  const asked = Object.entries(body.versions);

  if (asked.length === 0) return fail(400, "Nothing to update: the request names no versions. Publishing needs a tarball in _attachments.");
  const missing = asked.map(([version]) => version).filter((version) => !ctx.store.getVersion(name, version));

  if (missing.length > 0) return fail(404, `${name} has no version ${missing.join(", ")}. Nothing was changed.`, { missing });
  const at = ctx.now();
  const updated: string[] = [];
  ctx.store.tx(() => {
    for (const [version, manifest] of asked) {
      const v = ctx.store.getVersion(name, version);
      if (!v) continue;
      const next = deprecationOf(manifest);
      if (next !== v.deprecated) {
        ctx.store.setDeprecated(name, version, next);
        ctx.store.addEvent({ package: name, kind: next ? "deprecate" : "undeprecate", actor: user, at, detail: { version, message: next } });
        updated.push(version);
      }
    }

    if (updated.length > 0) ctx.store.updatePackageMeta(name, { modifiedAt: at });
  });

  return json({ ok: true, updated });
}

/** The one-time code npm sends with `--otp` (and after asking, when a 401 says `www-authenticate: OTP`). */
function npmOtp(req: Request): string | undefined {
  return req.headers.get("npm-otp") ?? undefined;
}

/** A refusal npm answers by asking for a one-time code. */
function otpFail(r: Refusal): Response {
  return json({ error: r.error }, r.status, r.status === 401 ? { "www-authenticate": "OTP" } : {});
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
    if (!isValidTagName(tag)) return fail(400, tagNameError(tag));
    let raw: unknown;

    try {
      raw = await req.json();
    } catch {
      return fail(400, 'The body must be a JSON string naming a version, like "1.2.3".');
    }

    const parsed = z.string().safeParse(raw);

    if (!parsed.success) return fail(400, 'The body must be a JSON string naming a version, like "1.2.3".');
    const version = parsed.data;
    if (!isValidVersion(version)) return fail(400, `Invalid version "${version}"`);
    const v = ctx.store.getVersion(name, version);
    if (!v || v.status !== "active") return fail(404, `Version ${version} not found or not active`);
    const denied = await ctx.access.liveChangeRefusal({ user: auth.user, scope: auth.scope, action: { kind: "dist-tag", name, tag, version }, otp: npmOtp(req) });

    if (denied) return otpFail(denied);
    tags[tag] = version;
  } else if (req.method === "DELETE") {
    if (tag === "latest") return fail(400, "Cannot delete latest");

    if (tagTarget(tags, tag) === undefined) return fail(404, `No dist-tag ${tag} on ${name}.`);
    const denied = await ctx.access.liveChangeRefusal({ user: auth.user, scope: auth.scope, action: { kind: "dist-tag", name, tag, version: null }, otp: npmOtp(req) });

    if (denied) return otpFail(denied);
    delete tags[tag];
  } else {
    return fail(405, "Method not allowed");
  }
  const at = ctx.now();
  ctx.store.setDistTags(name, tags, at);
  ctx.store.addEvent({ package: name, kind: "dist-tag", actor: auth.user, at, detail: { tag, version: tags[tag] ?? null } });
  return json({ ok: true, ...tags });
}

function tagNameError(tag: string): string {
  return `Invalid dist-tag "${tag.slice(0, 64)}": a tag starts with a letter, uses letters, digits, ".", "-" and "_", and must not read as a version or range (1.2.3, v1, ^1).`;
}

// ---------- users ----------
const UserBody = z.object({ name: z.string().min(1), password: z.string().min(1), email: z.string().optional() });
const USER_RE = /^[a-z0-9][a-z0-9-]{0,38}$/;

async function handleAddUser(req: Request, ctx: Ctx, rawName: string): Promise<Response> {
  if (!ctx.access.legacyAuth) {
    return fail(403, "Password accounts are off on this registry. Run `apm login`: it opens your browser to sign in with GitHub, and the token works with npm and bun too.");
  }
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
    const check = await checkPassword({ store: ctx.store, user: name, password: body.password, hash: existing.password_hash, now: ctx.now() });

    if (check === "locked") return fail(429, LOCKED_MESSAGE);

    if (check === "bad") return fail(401, "Incorrect username or password.");
    return json({ ok: true, id: `org.couchdb.user:${name}`, token: issueToken(ctx, { user: name, label: "cli login", scope: "legacy" }) }, 201);
  }
  if (body.password.length < 8) return fail(400, "Password must be at least 8 characters.");
  ctx.store.createUser({ name, password_hash: await Bun.password.hash(body.password), email: body.email ?? "", created_at: ctx.now() });
  return json({ ok: true, id: `org.couchdb.user:${name}`, token: issueToken(ctx, { user: name, label: "cli login", scope: "legacy" }) }, 201);
}

// ---------- npm owner and unpublish ----------
// npm owner add/rm reads GET /-/user/org.couchdb.user:<name>, then PUTs the packument's maintainers to
// /<pkg>/-rev/<rev>. apm applies that as an owner change behind the same second factor as apm's own owner
// route: npm sends it as --otp. npm unpublish PUTs or DELETEs under -rev too; apm never deletes versions.

export const UNPUBLISH_REFUSED =
  'apm never deletes a published version, so lockfiles and mirrors cannot be pointed at different bytes later. To hide a version from new installs run `apm yank <pkg>@<version>`; to pull a malicious version from everyone run `apm revoke <pkg>@<version> --reason "..."`.';

function handleUserLookup(ctx: Ctx, rawName: string): Response {
  const name = rawName.replace(/^org\.couchdb\.user:/, "");
  const u = ctx.store.getUser(name);

  if (!u) return fail(404, `No user ${name}.`);

  return json({ _id: `org.couchdb.user:${name}`, name });
}

const RevBody = z.object({ maintainers: z.array(z.object({ name: z.string() }).loose()).optional(), versions: z.unknown().optional() }).loose();

async function handleRevPut(req: Request, ctx: Ctx, name: string, auth: Auth): Promise<Response> {
  if (auth.kind !== "user") return fail(401, "Log in first (apm login).");

  if (!ctx.store.getPackage(name)) return fail(404, "Not found");
  let raw: unknown;

  try {
    raw = await req.json();
  } catch {
    return fail(400, "Invalid JSON body");
  }

  const body = RevBody.safeParse(raw);

  if (!body.success) return fail(400, "Invalid body: expected { maintainers: [{ name }] }");

  // npm unpublish of one version sends the packument minus that version
  if (body.data.versions !== undefined) return fail(405, UNPUBLISH_REFUSED);
  const wanted = body.data.maintainers;

  if (!wanted) return fail(400, "Nothing to change: apm takes owner changes ({ maintainers }) on this route.");
  const owners = ctx.store.owners(name);

  if (!owners.includes(auth.user)) return fail(403, `Only owners of ${name} can change its owners. Owners: ${owners.join(", ")}`);
  const names = [...new Set(wanted.map((m) => m.name))];
  const add = names.filter((n) => !owners.includes(n));
  const remove = owners.filter((n) => !names.includes(n));

  if (add.length === 0 && remove.length === 0) return json({ ok: true, owners });
  // one change per request, so one code (or one website confirmation) covers exactly one command
  if (add.length + remove.length !== 1) return fail(400, "Change one owner at a time (npm owner add or npm owner rm).");
  const added = add[0];
  const removed = remove[0];
  const action = added !== undefined ? { kind: "owner-add" as const, name, user: added } : { kind: "owner-remove" as const, name, user: removed ?? "" };

  if (added !== undefined && !ctx.store.getUser(added)) return fail(404, `No user ${added}.`);

  if (removed !== undefined && owners.length === 1) return fail(409, `${removed} is the last owner of ${name}. Add another owner first.`);
  const refused = await ctx.access.secondFactor({ user: auth.user, otp: npmOtp(req), action });

  if (refused) return otpFail(refused);
  const at = ctx.now();

  if (added !== undefined) ctx.store.addOwner(name, added);
  else if (removed !== undefined) ctx.store.removeOwner(name, removed);
  ctx.store.addEvent({ package: name, kind: action.kind, actor: auth.user, at, detail: { user: action.user, via: "npm owner" } });

  return json({ ok: true, owners: ctx.store.owners(name) });
}

// ---------- search ----------
export type SearchHit = { pkg: PackageRecord; latest: VersionRecord | null; rank: number };

function bareName(name: string): string {
  return name.startsWith("@") ? name.slice(name.indexOf("/") + 1) : name;
}

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
      // A misspelled name still finds the package: one edit away for short names, two for long ones.
      else if (t.length >= 4 && editDistance(bareName(name), bareName(t)) <= (t.length >= 8 ? 2 : 1)) rank += 10;
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

  if (path.startsWith("/-/user/org.couchdb.user:") && req.method === "PUT") {
    return handleAddUser(req, ctx, decodeURIComponent(path.slice("/-/user/".length)));
  }

  if (path.startsWith("/-/user/org.couchdb.user:") && (req.method === "GET" || req.method === "HEAD")) {
    return handleUserLookup(ctx, decodeURIComponent(path.slice("/-/user/".length)));
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

  if (req.method === "PUT" && rest[0] === "-rev") return handleRevPut(req, ctx, name, auth);

  // npm unpublish: DELETE /<pkg>/-rev/<rev> for the package, DELETE <tarball>/-rev/<rev> for one version
  if (req.method === "DELETE" && rest.includes("-rev")) return fail(405, UNPUBLISH_REFUSED);

  if (req.method !== "GET" && req.method !== "HEAD") return fail(405, "Method not allowed");

  const pkg = ctx.store.getPackage(name);
  // tarball
  if (rest[0] === "-" && rest[1]) {
    const file = rest[1];
    const m = /^(.*)-(\d+\.\d+\.\d+.*)\.tgz$/.exec(file);
    if (!pkg || !m?.[2] || !isValidVersion(m[2])) return fail(404, "Not found");
    const v = ctx.store.getVersion(name, m[2]);
    if (!v) return fail(404, "Not found");
    if (v.status === "revoked") {
      return fail(410, `${name}@${v.version} was revoked: ${v.status_reason ?? "no reason given"}`, { revoked: true });
    }

    if (view && !view.keep(v)) return fail(404, `${name}@${v.version} is not in this view: ${view.why(v) ?? "blocked by its policy"}.`);
    const bytes = readVersionTarball(ctx, v);
    if (!bytes) return fail(404, "Tarball missing");
    return new Response(bytes, { headers: { "content-type": "application/octet-stream" } });
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
  // in a view, tags point at what the view serves (latest moves back to the newest kept version)
  const tags = view ? retag(pkg.distTags, servedVersions(ctx.store.listVersions(name)).filter(view.keep).map((x) => x.version)) : pkg.distTags;
  const resolved = tagTarget(tags, spec) ?? spec;

  if (!isValidVersion(resolved)) return fail(404, "Version not found");
  const v = ctx.store.getVersion(name, resolved);
  if (!v || v.status === "revoked") return fail(404, "Version not found");

  if (view && !view.keep(v)) return fail(404, `${name}@${v.version} is not in this view: ${view.why(v) ?? "blocked by its policy"}.`);

  return json(versionDoc(ctx, pkg, v, ext, view));
}
