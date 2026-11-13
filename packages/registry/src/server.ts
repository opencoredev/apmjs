// The npm wire protocol: tokens, packuments, tarballs, publish, dist-tags, adduser and search.
// apm's own routes live in apm.ts and account.ts; router.ts puts them together.
import { createHash } from "node:crypto";
import { Effect, Option } from "effect";
import { z } from "zod";
import { isValidTagName, isValidVersion, servableManifest } from "@apm/core";
import { hashPassword } from "better-auth/crypto";
import { liveChangeRefusal, publishRefusal, secondFactor, stageRefusal, TOKEN_CAPABILITIES, type AccessServices, type Refusal as AccessRefusal, type TokenScope } from "./access.ts";
import type { Analysis } from "./analysis.ts";
import { Blobs } from "./blobs.ts";
import { Clock } from "./clock.ts";
import { confirmedText, confirmedVersions } from "./confirmed.ts";
import { RegistryConfig, type NamePolicy } from "./config.ts";
import { Store, type PackageRecord, type StagedLoad, type StoredScope, type VersionRecord } from "./db.ts";
import { refuse, type BlobError, type HttpFailure, type InfraError, type StoreError } from "./errors.ts";
import { randomId, sha1Hex, sha256Hex, sha512, tarballKey } from "./hash.ts";
import { notify } from "./hooks.ts";
import { checkPassword, LOCKED_MESSAGE } from "./passwords.ts";
import { fail, json, MAX_PUBLISH_BODY_BYTES, parseBody } from "./http.ts";
import { atTime } from "./lifecycle.ts";
import { order } from "./semver.ts";
import { searchPackages } from "./search.ts";
import { isWithheld, packageTextShown, readmeShown } from "./withheld.ts";

export type { NamePolicy };

export type Refusal = { status: number; error: string };

export type { TokenScope } from "./access.ts";

/** What a token row's scope means today. "legacy" tokens came from password logins: direct publish only while legacy auth is on. */
export function effectiveScope(stored: StoredScope, legacyAuth: boolean): TokenScope {
  if (stored === "stage") return "stage";

  if (stored === "legacy") return legacyAuth ? "publish" : "stage";

  return "publish";
}

export type Caller = { kind: "anon" } | { kind: "user"; user: string; tokenHash: string; scope: TokenScope };

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

// ---------- tokens ----------
export function hashToken(token: string): string {
  return sha256Hex(token);
}

export function newToken(): string {
  return `apm_${randomId(24)}`;
}

export const callerOf = (req: Request): Effect.Effect<Caller, StoreError, Store | Clock | RegistryConfig> =>
  Effect.gen(function* () {
    const h = req.headers.get("authorization") ?? "";
    const m = /^Bearer\s+(.+)$/i.exec(h);

    if (!m?.[1]) return { kind: "anon" } as const;
    const tokenHash = hashToken(m[1].trim());
    const store = yield* Store;
    const tok = yield* store.getToken(tokenHash);

    if (!tok || tok.revoked_at !== null) return { kind: "anon" } as const;
    const now = yield* (yield* Clock).now;

    if (tok.expires_at !== null && tok.expires_at < now) return { kind: "anon" } as const;
    const config = yield* RegistryConfig;

    return { kind: "user", user: tok.user, tokenHash, scope: effectiveScope(tok.scope, config.legacyAuth) } as const;
  });

export const issueToken = (input: { user: string; label: string; scope: StoredScope; ttlMs?: number }): Effect.Effect<string, StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const token = newToken();
    const at = yield* (yield* Clock).now;
    yield* (yield* Store).insertToken({
      token_hash: hashToken(token),
      user: input.user,
      label: input.label,
      scope: input.scope,
      created_at: at,
      expires_at: input.ttlMs === undefined ? null : at + input.ttlMs,
      revoked_at: null,
    });

    return token;
  });

export const requireUser = (caller: Caller, message = "Log in first (apm login)."): Effect.Effect<Extract<Caller, { kind: "user" }>, HttpFailure> =>
  caller.kind === "user" ? Effect.succeed(caller) : Effect.fail(refuse(401, message));

// ---------- versions as of now ----------
/** The package's versions with each one's effective status at the registry's current time. */
export const versionsOf = (name: string): Effect.Effect<VersionRecord[], StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const now = yield* (yield* Clock).now;
    const all = yield* (yield* Store).listVersions(name);

    return all.map((v) => atTime(v, now));
  });

export const versionOf = (name: string, version: string): Effect.Effect<VersionRecord | null, StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const now = yield* (yield* Clock).now;
    const v = yield* (yield* Store).getVersion(name, version);

    return v === null ? null : atTime(v, now);
  });

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

export function iso(ms: number): string {
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
  const sorted = [...versions].sort((a, b) => order(b, a));

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

/** The score summary packuments and search hits carry on each version. */
export type CompactScore = { score: number; grade: string; signals: string[] };

/** Hooks apm.ts supplies: the publish guard, score summaries and the ~safe filter. */
export type Extensions = {
  onPublish?: PublishHook;
  compactScore?: (v: VersionRecord, now: number) => CompactScore | null;
  /** Filter for the `~safe` registry view. */
  safeView?: (now: number) => PackumentView;
  searchScore?: (v: VersionRecord, now: number) => CompactScore | null;
};

export function versionDoc(base: string, pkg: PackageRecord, v: VersionRecord, now: number, ext: Extensions = {}): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    ...servableManifest(v.manifest),
    name: pkg.name,
    version: v.version,
    _id: `${pkg.name}@${v.version}`,
    dist: {
      tarball: tarballUrl(base, pkg.name, v.version),
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
    const c = ext.compactScore(v, now);

    if (c !== null) doc._apmScore = c;
  }

  return doc;
}

export const packument = (pkg: PackageRecord, abbreviated: boolean, ext: Extensions = {}, view?: PackumentView) =>
  Effect.gen(function* () {
    // a view's tarballs stay inside the view, so a lockfile written from it keeps being checked
    const base = `${(yield* RegistryConfig).baseUrl}${view?.prefix ?? ""}`;
    const now = yield* (yield* Clock).now;
    const all = yield* versionsOf(pkg.name);
    // a version an apm reviewer confirmed malicious is not offered, in any view (confirmed.ts)
    const confirmed = yield* confirmedVersions(pkg.name, all);
    const served = servedVersions(all).filter((v) => !confirmed.has(v.version));
    const live = view ? served.filter(view.keep) : served;
    const versions: Record<string, unknown> = {};
    const time: Record<string, string> = { created: iso(pkg.created_at), modified: iso(pkg.modified_at) };

    for (const v of live) {
      const full = versionDoc(base, pkg, v, now, ext);

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

    const distTags = view || confirmed.size > 0 ? retag(pkg.distTags, live.map((v) => v.version)) : { ...pkg.distTags };

    if (abbreviated) {
      return { name: pkg.name, modified: iso(pkg.modified_at), "dist-tags": distTags, versions };
    }

    const owners = yield* (yield* Store).owners(pkg.name);
    const text = packageTextShown(pkg, all);

    return {
      _id: pkg.name,
      name: pkg.name,
      description: text.description,
      "dist-tags": distTags,
      versions,
      time,
      maintainers: owners.map((name) => ({ name })),
      readme: readmeShown(pkg, all).text,
      keywords: text.keywords,
    };
  });

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

export type PublishVerdict =
  | { ok: true; manifest: Record<string, unknown>; score: unknown; warnings: readonly string[] }
  | { ok: false; status: number; error: string; detail?: unknown };

export type PublishHook = (input: {
  name: string;
  version: string;
  manifest: Record<string, unknown>;
  tarball: Uint8Array;
  user: string;
  existing: PackageRecord | null;
}) => Effect.Effect<PublishVerdict, InfraError, PublishServices>;

/** Every service a publish may touch, the guard included. */
export type PublishServices = Blobs | AccessServices | Analysis;

export const approvalUrl = (id: string): Effect.Effect<string, never, RegistryConfig> => Effect.map(RegistryConfig, (c) => `${c.webUrl}approve/${id}`);

const handlePublish = (req: Request, name: string, caller: Caller, ext: Extensions) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const clock = yield* Clock;
    const user = yield* requireUser(caller, "You must be logged in to publish packages.");

    const body = yield* parseBody(req, PublishBody, MAX_PUBLISH_BODY_BYTES).pipe(
      Effect.mapError((f) => refuse(f.status, f.error.replace("Invalid request body", "Invalid publish body"))),
    );

    if (body.name !== name) return fail(400, `Body name ${body.name} does not match URL ${name}`);

    if (!isValidName(name)) return fail(400, `Invalid package name "${name}"`);
    const perm = yield* publishRefusal(name, user.user);

    if (perm) return fail(perm.status, perm.error);

    if (!body._attachments || Object.keys(body._attachments).length === 0) {
      // the versions and messages that would change are what a second factor authorizes; no change needs none
      const [first, ...rest] = yield* deprecationChanges(name, body);

      if (first) {
        const denied = yield* liveChangeRefusal({ user: user.user, scope: user.scope, action: { kind: "deprecate", name, changes: [first, ...rest] }, otp: npmOtp(req) });

        if (denied) return otpFail(denied);
      }

      return yield* handleMetadataUpdate(name, body, user.user);
    }

    const entries = Object.entries(body.versions);

    if (entries.length !== 1) return fail(400, "Publish exactly one version at a time.");
    const tagNames = Object.keys(body["dist-tags"]);

    if (tagNames.length > 1) return fail(400, "Publish with one dist-tag at a time.");
    const badTag = tagNames.find((t) => !isValidTagName(t));

    if (badTag !== undefined) return fail(400, tagNameError(badTag));
    const [version, manifest] = entries[0] ?? ["", {}];

    if (!isValidVersion(version)) return fail(400, `Invalid version "${version}": apm accepts strict semver only (1.2.3, 1.2.3-beta.1).`);
    const attachment = Object.values(body._attachments)[0];

    if (!attachment) return fail(400, "Missing tarball");
    const tarball = new Uint8Array(Buffer.from(attachment.data, "base64"));

    if (tarball.length === 0) return fail(400, "Empty tarball");

    const existing = yield* store.getPackage(name);

    if (existing && (yield* store.getVersion(name, version))) {
      return fail(409, `Cannot publish over existing version ${name}@${version}. Versions are immutable; bump the version.`);
    }

    const readme = body.readme ?? (typeof manifest.readme === "string" ? manifest.readme : null);

    if (readme !== null && utf8Bytes(readme) > MAX_README_BYTES) return fail(413, `The readme is over ${MAX_README_BYTES / (1024 * 1024)} MB. Shorten it or link to longer docs.`);

    if (utf8Bytes(JSON.stringify(manifest)) > MAX_MANIFEST_BYTES) return fail(413, `package.json is over ${MAX_MANIFEST_BYTES / (1024 * 1024)} MB.`);

    const staged = TOKEN_CAPABILITIES[user.scope].publish === "staged";

    if (staged) {
      const pending = yield* store.pendingStaged(name, version, yield* clock.now);

      if (pending) return fail(409, `${name}@${version} is already waiting for approval: ${yield* approvalUrl(pending.id)}`);
      const noFactor = yield* stageRefusal(user.user);

      if (noFactor) return fail(noFactor.status, noFactor.error);
      const over = yield* stageQuotaRefusal({ user: user.user, name, size: tarball.length });

      if (over) return fail(429, over);
    }

    let score: unknown = null;
    let storedManifest: Record<string, unknown> = manifest;
    let warnings: readonly string[] = [];

    if (ext.onPublish) {
      const verdict = yield* ext.onPublish({ name, version, manifest, tarball, user: user.user, existing });

      if (!verdict.ok) return fail(verdict.status, verdict.error, verdict.detail === undefined ? {} : { detail: verdict.detail });
      score = verdict.score;
      storedManifest = verdict.manifest;
      warnings = verdict.warnings;
    }

    // header-safe: a tar path may hold control characters
    const warningText = warnings.length > 0 ? `Warning: ${warnings.join(" ")}`.replace(/[\x00-\x1f\x7f]/g, " ") : null;

    const cleanManifest: Record<string, unknown> = { ...storedManifest };

    for (const k of ["_id", "dist", "_npmUser", "_attachments", "readme", "_resolved", "_integrity", "_from"]) delete cleanManifest[k];

    // the cap above read the request's manifest; this one reads the manifest apm stores and serves (the tarball's)
    if (utf8Bytes(JSON.stringify(cleanManifest)) > MAX_MANIFEST_BYTES) return fail(413, `package.json is over ${MAX_MANIFEST_BYTES / (1024 * 1024)} MB.`);
    const tag = Object.keys(body["dist-tags"])[0] ?? "latest";
    const shasum = sha1Hex(tarball);
    const digest = sha512(tarball);
    const key = tarballKey(digest.hex);

    if (staged) {
      const at = yield* clock.now;
      const id = randomId(12);

      // the blob is written and its staged row inserted under the blob's shared lock (see Store.lockBlob); the
      // checks above ran before the analysis, and these run again atomically with the insert
      const stored = yield* store.tx(
        Effect.gen(function* () {
          yield* store.lockBlob(key, "shared");
          yield* (yield* Blobs).put(key, tarball);

          return yield* store.insertStagedWithin(
            {
              id,
              package: name,
              version,
              manifest: cleanManifest,
              shasum,
              integrity: digest.integrity,
              size: tarball.length,
              tarball_key: key,
              tag,
              readme,
              score,
              staged_by: user.user,
              staged_at: at,
              expires_at: at + STAGE_TTL_MS,
            },
            { perUser: MAX_STAGED_PER_USER, perPackage: MAX_STAGED_PER_PACKAGE, bytesPerUser: MAX_STAGED_BYTES_PER_USER },
          );
        }),
      );

      if (stored.kind !== "staged") {
        yield* dropBlobIfUnused(key);

        return stored.kind === "duplicate"
          ? fail(409, `${name}@${version} is already waiting for approval: ${yield* approvalUrl(stored.id)}`)
          : fail(429, yield* quotaMessage({ name, quota: stored.quota, load: stored.load }));
      }

      const link = yield* approvalUrl(id);
      const expiresAt = new Date(at + STAGE_TTL_MS).toISOString();
      // bun prints this header as "note: ...", npm as "npm notice ...": that is how the link reaches a person.
      const notice = `${name}@${version} is uploaded but NOT live. A person must approve it within 24h: ${link}${warningText ? ` ${warningText}` : ""}`;

      return json({ ok: true, success: true, staged: true, id, approvalUrl: link, expiresAt, message: notice, warnings }, 202, { "npm-notice": notice });
    }

    yield* commitVersion({
      name,
      version,
      manifest: cleanManifest,
      tarballKey: key,
      size: tarball.length,
      shasum,
      integrity: digest.integrity,
      tag,
      readme,
      score,
      publisher: user.user,
      detail: {},
      upload: tarball,
    }).pipe(
      // the losing publish of a race leaves no blob behind unless another version holds the same bytes
      Effect.tapError(() => dropBlobIfUnused(key)),
    );

    return json({ ok: true, id: name, rev: `${yield* clock.now}`, success: true, score, warnings }, 201, warningText ? { "npm-notice": warningText } : {});
  });

/** Why one more staged upload of `size` tarball bytes would go over a quota, or null. A fast check before the analysis. */
const stageQuotaRefusal = (input: { user: string; name: string; size: number }) =>
  Effect.gen(function* () {
    const load = yield* (yield* Store).pendingStagedLoad({ user: input.user, name: input.name, now: yield* (yield* Clock).now });

    if (load.byPackage >= MAX_STAGED_PER_PACKAGE) return yield* quotaMessage({ name: input.name, quota: "package", load });

    if (load.byUser >= MAX_STAGED_PER_USER) return yield* quotaMessage({ name: input.name, quota: "user", load });

    if (load.bytesByUser + input.size > MAX_STAGED_BYTES_PER_USER) return yield* quotaMessage({ name: input.name, quota: "bytes", load });

    return null;
  });

const quotaMessage = (input: { name: string; quota: "package" | "user" | "bytes"; load: StagedLoad }): Effect.Effect<string, never, RegistryConfig> =>
  Effect.map(RegistryConfig, (config) => {
    const where = `Approve or reject them at ${config.webUrl}publish, or wait for them to expire (24h).`;

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
  });

function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * Takes the package's row lock, then checks that `user` still owns it. Call inside a transaction, before any
 * change: an ownership check made before the lock may be stale by the time the lock is granted.
 */
export const lockOwned = (name: string, user: string): Effect.Effect<PackageRecord, HttpFailure | StoreError, Store> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const pkg = yield* store.lockPackage(name);

    if (!pkg) return yield* Effect.fail(refuse(404, `No package named ${name} on this registry.`));
    const owners = yield* store.owners(name);

    if (!owners.includes(user)) return yield* Effect.fail(refuse(403, `Only owners of ${name} can do this. Owners: ${owners.join(", ")}`));

    return pkg;
  });

/** Whether stored tarball bytes are the ones the version was published with: its sha512 integrity, or the sha1 shasum when that is all it has. */
function matchesPublished(bytes: Uint8Array, v: Pick<VersionRecord, "integrity" | "shasum">): boolean {
  if (v.integrity.startsWith("sha512-")) return sha512(bytes).integrity === v.integrity;

  return sha1Hex(bytes) === v.shasum;
}

/**
 * Drops a tarball from the blob store once nothing points at it any more. The check and the delete hold the
 * blob's lock exclusively, so an upload of the same bytes waits, or is waited for and then counted.
 */
export const dropBlobIfUnused = (key: string): Effect.Effect<void, StoreError | BlobError, Store | Blobs> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const blobs = yield* Blobs;

    yield* store.tx(
      Effect.gen(function* () {
        yield* store.lockBlob(key, "exclusive");

        if (yield* store.blobReferenced(key)) return;
        yield* blobs.remove(key);
      }),
    );
  });

/**
 * Makes a version live: version row, dist-tags, package metadata and the publish event, in one transaction
 * that holds the package row. With `upload`, the tarball is written to the blob store in that transaction,
 * under the blob's shared lock; without it, it is already there (an approved staged upload, whose row holds it).
 */
export const commitVersion = (v: {
  name: string;
  version: string;
  manifest: Record<string, unknown>;
  tarballKey: string;
  size: number;
  shasum: string;
  integrity: string;
  tag: string;
  readme: string | null;
  score: unknown;
  publisher: string;
  detail: Record<string, unknown>;
  upload?: Uint8Array;
}): Effect.Effect<void, HttpFailure | StoreError | BlobError, Store | Clock | Blobs> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const blobs = yield* Blobs;
    const at = yield* (yield* Clock).now;

    const firstPublish = yield* store.tx(
      Effect.gen(function* () {
        if (v.upload !== undefined) {
          yield* store.lockBlob(v.tarballKey, "shared");
          yield* blobs.put(v.tarballKey, v.upload);
        }

        const created = yield* store.createPackage(v.name, at, v.publisher);
        const pkg = yield* store.lockPackage(v.name);

        if (!pkg) return yield* Effect.fail(refuse(500, "Internal error"));

        if (!created) {
          const owners = yield* store.owners(v.name);

          if (!owners.includes(v.publisher)) return yield* Effect.fail(refuse(403, `You do not have permission to publish "${v.name}". Owners: ${owners.join(", ")}`));
        }

        const inserted = yield* store.insertVersion({
          package: v.name,
          version: v.version,
          manifest: v.manifest,
          shasum: v.shasum,
          integrity: v.integrity,
          size: v.size,
          tarball_key: v.tarballKey,
          published_at: at,
          published_by: v.publisher,
          score: v.score,
        });

        if (!inserted) return yield* Effect.fail(refuse(409, `Cannot publish over existing version ${v.name}@${v.version}. Versions are immutable; bump the version.`));
        const tags = { ...pkg.distTags };
        const isPrerelease = v.version.includes("-");
        const currentLatest = tags.latest;
        // a prerelease never takes `latest` once a stable release exists; it goes to `next`
        const tag = v.tag === "latest" && isPrerelease && currentLatest ? "next" : v.tag;
        // publishing an older line (a 1.x backport) never moves latest backwards
        const backport = tag === "latest" && currentLatest !== undefined && order(v.version, currentLatest) < 0;

        if (!backport) tags[tag] = v.version;
        yield* store.setDistTags(v.name, tags, at);
        const description = typeof v.manifest.description === "string" ? v.manifest.description : undefined;
        const keywords = Array.isArray(v.manifest.keywords) ? v.manifest.keywords.filter((k): k is string => typeof k === "string") : undefined;
        yield* store.updatePackageMeta(v.name, {
          modifiedAt: at,
          ...(description !== undefined ? { description } : {}),
          ...(keywords !== undefined ? { keywords } : {}),
          // the readme's owner is recorded with it, so revoking that version hides it (withheld.ts)
          ...(v.readme !== null ? { readme: { text: v.readme, version: v.version } } : {}),
        });
        yield* store.addEvent({ package: v.name, kind: "publish", actor: v.publisher, at, detail: { version: v.version, tag: v.tag, ...v.detail } });

        return created;
      }),
    );

    yield* notify((h) => h.afterCommit, { name: v.name, version: v.version, firstPublish });
  });

/** The deprecation message a metadata PUT sets on a version: a non-empty string, or null to take it off. */
function deprecationOf(manifest: { readonly deprecated?: unknown }): string | null {
  const dep = z.string().min(1).safeParse(manifest.deprecated);

  return dep.success ? dep.data : null;
}

/** What a metadata PUT (npm deprecate) would change: each existing version whose message differs. */
const deprecationChanges = (name: string, body: PublishBody) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const changes: { version: string; message: string | null }[] = [];

    for (const [version, manifest] of Object.entries(body.versions)) {
      const v = yield* store.getVersion(name, version);
      const next = deprecationOf(manifest);

      if (v && next !== v.deprecated) changes.push({ version, message: next });
    }

    return changes;
  });

const handleMetadataUpdate = (name: string, body: PublishBody, user: string) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const pkg = yield* store.getPackage(name);

    if (!pkg) return fail(404, "Not found");
    const asked = Object.entries(body.versions);

    if (asked.length === 0) return fail(400, "Nothing to update: the request names no versions. Publishing needs a tarball in _attachments.");
    const missing: string[] = [];

    for (const [version] of asked) if (!(yield* store.getVersion(name, version))) missing.push(version);

    if (missing.length > 0) return fail(404, `${name} has no version ${missing.join(", ")}. Nothing was changed.`, { missing });
    const at = yield* (yield* Clock).now;

    const updated = yield* store.tx(
      Effect.gen(function* () {
        yield* lockOwned(name, user);
        const changed: string[] = [];

        for (const [version, manifest] of asked) {
          const v = yield* store.getVersion(name, version);

          if (!v) continue;
          const next = deprecationOf(manifest);

          if (next !== v.deprecated) {
            yield* store.setDeprecated(name, version, next);
            yield* store.addEvent({ package: name, kind: next ? "deprecate" : "undeprecate", actor: user, at, detail: { version, message: next } });
            changed.push(version);
          }
        }

        if (changed.length > 0) yield* store.updatePackageMeta(name, { modifiedAt: at });

        return changed;
      }),
    );

    return json({ ok: true, updated });
  });

/** The one-time code npm sends with `--otp` (and after asking, when a 401 says `www-authenticate: OTP`). */
function npmOtp(req: Request): string | undefined {
  return req.headers.get("npm-otp") ?? undefined;
}

/** A refusal npm answers by asking for a one-time code. */
function otpFail(r: AccessRefusal): Response {
  return json({ error: r.error }, r.status, r.status === 401 ? { "www-authenticate": "OTP" } : {});
}

// ---------- dist-tags ----------
const handleDistTags = (req: Request, name: string, tag: string | undefined, caller: Caller) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const pkg = yield* store.getPackage(name);

    if (!pkg) return fail(404, "Not found");

    if (req.method === "GET") return json(pkg.distTags);

    if (caller.kind !== "user") return fail(401, "Login required");

    if (!(yield* store.owners(name)).includes(caller.user)) return fail(403, "Not an owner");

    if (!tag) return fail(400, "Tag required");
    let change: { kind: "set"; version: string } | { kind: "delete" };

    if (req.method === "PUT" || req.method === "POST") {
      if (!isValidTagName(tag)) return fail(400, tagNameError(tag));
      const bodyError = 'The body must be a JSON string naming a version, like "1.2.3".';
      const raw = yield* Effect.tryPromise({ try: (): Promise<unknown> => req.json(), catch: () => refuse(400, bodyError) });
      const parsed = z.string().safeParse(raw);

      if (!parsed.success) return fail(400, bodyError);
      const version = parsed.data;

      if (!isValidVersion(version)) return fail(400, `Invalid version "${version}"`);
      const v = yield* versionOf(name, version);

      if (!v || v.status !== "active") return fail(404, `Version ${version} not found or not active`);
      const denied = yield* liveChangeRefusal({ user: caller.user, scope: caller.scope, action: { kind: "dist-tag", name, tag, version }, otp: npmOtp(req) });

      if (denied) return otpFail(denied);
      change = { kind: "set", version };
    } else if (req.method === "DELETE") {
      if (tag === "latest") return fail(400, "Cannot delete latest");

      if (tagTarget(pkg.distTags, tag) === undefined) return fail(404, `No dist-tag ${tag} on ${name}.`);
      const denied = yield* liveChangeRefusal({ user: caller.user, scope: caller.scope, action: { kind: "dist-tag", name, tag, version: null }, otp: npmOtp(req) });

      if (denied) return otpFail(denied);
      change = { kind: "delete" };
    } else {
      return fail(405, "Method not allowed");
    }

    const at = yield* (yield* Clock).now;
    const user = caller.user;

    // the tags are re-read under the lock, so a concurrent change to another tag is kept
    const tags = yield* store.tx(
      Effect.gen(function* () {
        const locked = yield* lockOwned(name, user);
        const next = { ...locked.distTags };

        if (change.kind === "set") next[tag] = change.version;
        else delete next[tag];
        yield* store.setDistTags(name, next, at);
        yield* store.addEvent({ package: name, kind: "dist-tag", actor: user, at, detail: { tag, version: next[tag] ?? null } });

        return next;
      }),
    );

    return json({ ok: true, ...tags });
  });

function tagNameError(tag: string): string {
  return `Invalid dist-tag "${tag.slice(0, 64)}": a tag starts with a letter, uses letters, digits, ".", "-" and "_", and must not read as a version or range (1.2.3, v1, ^1).`;
}

// ---------- users ----------
const UserBody = z.object({ name: z.string().min(1), password: z.string().min(1), email: z.string().optional() });
const USER_RE = /^[a-z0-9][a-z0-9-]{0,38}$/;

const handleAddUser = (req: Request, rawName: string) =>
  Effect.gen(function* () {
    const config = yield* RegistryConfig;
    const store = yield* Store;

    if (!config.legacyAuth) {
      return fail(403, "Password accounts are off on this registry. Run `apm login`: it opens your browser to sign in with GitHub, and the token works with npm and bun too.");
    }

    const body = yield* parseBody(req, UserBody).pipe(Effect.mapError(() => refuse(400, "name and password required")));
    const name = rawName.replace(/^org\.couchdb\.user:/, "");

    if (body.name !== name) return fail(400, "name mismatch");

    if (!USER_RE.test(name)) return fail(400, "Usernames are lowercase letters, digits and dashes.");
    const existing = yield* store.getUser(name);

    if (existing) {
      const check = yield* checkPassword({ user: name, password: body.password, hash: existing.password_hash, now: yield* (yield* Clock).now });

      if (check === "locked") return fail(429, LOCKED_MESSAGE);

      if (check === "bad") return fail(401, "Incorrect username or password.");

      return json({ ok: true, id: `org.couchdb.user:${name}`, token: yield* issueToken({ user: name, label: "cli login", scope: "legacy" }) }, 201);
    }

    if (body.password.length < 8) return fail(400, "Password must be at least 8 characters.");
    const hash = yield* Effect.promise(() => hashPassword(body.password));
    const created = yield* store.createUser({ name, password_hash: hash, email: body.email ?? "", created_at: yield* (yield* Clock).now });

    if (!created) return fail(409, "That name was just taken.");

    return json({ ok: true, id: `org.couchdb.user:${name}`, token: yield* issueToken({ user: name, label: "cli login", scope: "legacy" }) }, 201);
  });

// ---------- npm owner and unpublish ----------
// npm owner add/rm reads GET /-/user/org.couchdb.user:<name>, then PUTs the packument's maintainers to
// /<pkg>/-rev/<rev>. apm applies that as an owner change behind the same second factor as apm's own owner
// route: npm sends it as --otp. npm unpublish PUTs or DELETEs under -rev too; apm never deletes versions.

export const UNPUBLISH_REFUSED =
  'apm never deletes a published version, so lockfiles and mirrors cannot be pointed at different bytes later. To hide a version from new installs run `apm yank <pkg>@<version>`; to pull a malicious version from everyone run `apm revoke <pkg>@<version> --reason "..."`.';

const handleUserLookup = (rawName: string) =>
  Effect.gen(function* () {
    const name = rawName.replace(/^org\.couchdb\.user:/, "");

    if (!(yield* (yield* Store).getUser(name))) return fail(404, `No user ${name}.`);

    return json({ _id: `org.couchdb.user:${name}`, name });
  });

const RevBody = z.object({ maintainers: z.array(z.object({ name: z.string() }).loose()).optional(), versions: z.unknown().optional() }).loose();

function otpRequired(error: string): Response {
  return json({ error }, 401, { "www-authenticate": "OTP" });
}

const handleRevPut = (req: Request, name: string, caller: Caller) =>
  Effect.gen(function* () {
    if (caller.kind !== "user") return fail(401, "Log in first (apm login).");
    const store = yield* Store;

    if (!(yield* store.getPackage(name))) return fail(404, "Not found");
    const body = yield* parseBody(req, RevBody).pipe(Effect.mapError(() => refuse(400, "Invalid body: expected { maintainers: [{ name }] }")));

    // npm unpublish of one version sends the packument minus that version
    if (body.versions !== undefined) return fail(405, UNPUBLISH_REFUSED);
    const wanted = body.maintainers;

    if (!wanted) return fail(400, "Nothing to change: apm takes owner changes ({ maintainers }) on this route.");
    const owners = yield* store.owners(name);

    if (!owners.includes(caller.user)) return fail(403, `Only owners of ${name} can change its owners. Owners: ${owners.join(", ")}`);
    const names = [...new Set(wanted.map((m) => m.name))];
    const add = names.filter((n) => !owners.includes(n));
    const remove = owners.filter((n) => !names.includes(n));

    if (add.length === 0 && remove.length === 0) return json({ ok: true, owners });

    for (const n of add) if (!(yield* store.getUser(n))) return fail(404, `No user ${n}.`);

    if (remove.length >= owners.length + add.length) return fail(409, `${name} would have no owners. Add another owner first.`);
    const otp = req.headers.get("npm-otp")?.trim();

    if (!otp) return otpRequired("Changing owners needs a code from your authenticator app: run it again with --otp=<code>.");
    const first = add[0];
    const action = first !== undefined ? ({ kind: "owner-add", name, user: first } as const) : ({ kind: "owner-remove", name, user: remove[0] ?? "" } as const);
    const refused = yield* secondFactor({ user: caller.user, otp, action });

    if (refused) return refused.status === 401 ? otpRequired(refused.error) : fail(refused.status, refused.error);
    const at = yield* (yield* Clock).now;
    yield* store.tx(
      Effect.gen(function* () {
        yield* lockOwned(name, caller.user);

        for (const u of add) {
          yield* store.addOwner(name, u);
          yield* store.addEvent({ package: name, kind: "owner-add", actor: caller.user, at, detail: { user: u, via: "npm owner" } });
        }

        for (const u of remove) {
          const removed = yield* store.removeOwner(name, u);

          if (removed === "last-owner") return yield* Effect.fail(refuse(409, `${name} would have no owners. Add another owner first.`));
          yield* store.addEvent({ package: name, kind: "owner-remove", actor: caller.user, at, detail: { user: u, via: "npm owner" } });
        }
      }),
    );

    return json({ ok: true, owners: yield* store.owners(name) });
  });

// ---------- search ----------
/** Paging of a /-/v1/search request, clamped the way npm's registry clamps it. */
export function searchPaging(url: URL): { text: string; size: number; from: number } {
  return {
    text: url.searchParams.get("text") ?? "",
    size: Math.min(250, Math.max(1, Number(url.searchParams.get("size") ?? 20) || 20)),
    from: Math.max(0, Number(url.searchParams.get("from") ?? 0) || 0),
  };
}

/** Search objects in npm's wire shape for packages published here, best match first. */
export const localSearchObjects = (text: string, scoreOf: ((v: VersionRecord, now: number) => CompactScore | null) | undefined) =>
  Effect.gen(function* () {
    const base = (yield* RegistryConfig).baseUrl;
    const now = yield* (yield* Clock).now;
    const hits = yield* searchPackages(text);

    return hits.map((h) => ({
      source: "local" as const,
      package: {
        name: h.pkg.name,
        scope: h.pkg.name.startsWith("@") ? h.pkg.name.slice(1, h.pkg.name.indexOf("/")) : "unscoped",
        version: h.latest.version,
        description: h.pkg.description,
        keywords: h.pkg.keywords,
        date: iso(h.latest.published_at),
        links: { npm: `${base}package/${h.pkg.name}` },
        publisher: { username: h.latest.published_by },
        maintainers: h.owners.map((username) => ({ username })),
      },
      score: { final: h.rank / 100, detail: { quality: 1, popularity: 1, maintenance: 1 } },
      searchScore: h.rank,
      apmScore: scoreOf ? scoreOf(h.latest, now) : null,
    }));
  });

const handleSearch = (url: URL, ext: Extensions) =>
  Effect.gen(function* () {
    const { text, size, from } = searchPaging(url);
    const all = yield* localSearchObjects(text, ext.searchScore);
    const now = yield* (yield* Clock).now;

    return json({ objects: all.slice(from, from + size), total: all.length, time: new Date(now).toUTCString(), upstreamFailed: false });
  });

// ---------- the protocol routes ----------
/** Answers the npm protocol for local packages; null when the path is not one of these routes. */
export const protocolRoute = (req: Request, url: URL, path: string, caller: Caller, ext: Extensions, view: PackumentView | undefined) =>
  Effect.gen(function* () {
    const store = yield* Store;

    if (path === "/-/ping") return json({});

    if (path === "/-/whoami") return caller.kind === "user" ? json({ username: caller.user }) : fail(401, "Not logged in");

    if (path.startsWith("/-/user/token/") && req.method === "DELETE") {
      if (caller.kind === "user") yield* store.revokeToken(caller.tokenHash, yield* (yield* Clock).now);

      return json({ ok: true });
    }

    if (path.startsWith("/-/user/org.couchdb.user:") && req.method === "PUT") return yield* handleAddUser(req, decodeURIComponent(path.slice("/-/user/".length)));

    if (path.startsWith("/-/user/org.couchdb.user:") && (req.method === "GET" || req.method === "HEAD")) {
      return yield* handleUserLookup(decodeURIComponent(path.slice("/-/user/".length)));
    }

    if (path === "/-/v1/search") return yield* handleSearch(url, ext);

    if (path.startsWith("/-/package/")) {
      const sp = splitPath(path.slice("/-/package".length));

      if (!sp) return fail(404, "Not found");

      if (sp.rest[0] !== "dist-tags") return fail(404, "Not found");

      return yield* handleDistTags(req, sp.name, sp.rest[1], caller);
    }

    if (path.startsWith("/-/")) return fail(404, "Not found");

    const sp = splitPath(path);

    if (!sp) return json({ name: "apm registry", ok: true });
    const { name, rest } = sp;

    if (req.method === "PUT" && rest.length === 0) return yield* handlePublish(req, name, caller, ext);

    if (req.method === "PUT" && rest[0] === "-rev") return yield* handleRevPut(req, name, caller);

    // npm unpublish: DELETE /<pkg>/-rev/<rev> for the package, DELETE <tarball>/-rev/<rev> for one version
    if (req.method === "DELETE" && rest.includes("-rev")) return fail(405, UNPUBLISH_REFUSED);

    if (req.method !== "GET" && req.method !== "HEAD") return fail(405, "Method not allowed");

    const pkg = yield* store.getPackage(name);

    // tarball
    if (rest[0] === "-" && rest[1]) {
      const m = /^(.*)-(\d+\.\d+\.\d+.*)\.tgz$/.exec(rest[1]);

      if (!pkg || !m?.[2] || !isValidVersion(m[2])) return fail(404, "Not found");
      const v = yield* versionOf(name, m[2]);

      if (!v) return fail(404, "Not found");

      if (v.status === "revoked") {
        const reason = v.status_reason ?? "no reason given";

        // npm prints only `error`, so the owner's reason is in it too; revokeReason holds it alone for other clients
        return fail(410, `${name}@${v.version} was revoked by its owner: ${reason}`, { revoked: true, revokeReason: reason });
      }

      // confirmed malicious by an apm reviewer: gone like a revoked version, for existing lockfiles too (confirmed.ts)
      if ((yield* confirmedVersions(name, [v])).has(v.version)) return fail(410, confirmedText(name, v.version), { confirmed: true });

      if (view && !view.keep(v)) return fail(404, `${name}@${v.version} is not in this view: ${view.why(v) ?? "blocked by its policy"}.`);
      const blobs = yield* Blobs;

      if (req.method === "HEAD") {
        const head = yield* blobs.stream(v.tarball_key);

        if (Option.isNone(head)) return fail(404, "Tarball missing");
        yield* Effect.promise(() => head.value.body.cancel());

        return new Response(null, { headers: { "content-type": "application/octet-stream", "content-length": String(head.value.size) } });
      }

      // the bytes are checked against the checksum the packument publishes before any of them are sent
      const bytes = yield* blobs.bytes(v.tarball_key);

      if (Option.isNone(bytes)) return fail(404, "Tarball missing");

      if (!matchesPublished(bytes.value, v)) {
        yield* Effect.logError("stored tarball failed its integrity check").pipe(Effect.annotateLogs({ name, version: v.version, key: v.tarball_key }));

        return fail(500, `The stored tarball of ${name}@${v.version} does not match its published checksum, so it is not served.`);
      }

      return new Response(bytes.value, { headers: { "content-type": "application/octet-stream", "content-length": String(bytes.value.length) } });
    }

    if (!pkg) return fail(404, "Not found");

    if (rest.length === 0) {
      const accept = req.headers.get("accept") ?? "";
      const abbreviated = accept.includes("application/vnd.npm.install-v1+json");
      const body = yield* packument(pkg, abbreviated, ext, view);
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
    const every = yield* versionsOf(name);
    const confirmed = yield* confirmedVersions(name, every);
    const offered = servedVersions(every).filter((x) => !confirmed.has(x.version));
    const tags = view ? retag(pkg.distTags, offered.filter(view.keep).map((x) => x.version)) : confirmed.size > 0 ? retag(pkg.distTags, offered.map((x) => x.version)) : pkg.distTags;
    const resolved = tagTarget(tags, spec) ?? spec;

    if (!isValidVersion(resolved)) return fail(404, "Version not found");
    const v = yield* versionOf(name, resolved);

    // a revoke-pending version's manifest (its scripts, its dependency specs) is withheld like a revoked one's; only
    // its tarball stays, for existing lockfiles. One confirmed malicious is withheld the same way (confirmed.ts).
    if (!v || isWithheld(v.status) || confirmed.has(v.version)) return fail(404, "Version not found");

    if (view && !view.keep(v)) return fail(404, `${name}@${v.version} is not in this view: ${view.why(v) ?? "blocked by its policy"}.`);
    const base = `${(yield* RegistryConfig).baseUrl}${view?.prefix ?? ""}`;

    return json(versionDoc(base, pkg, v, yield* (yield* Clock).now, ext));
  });
