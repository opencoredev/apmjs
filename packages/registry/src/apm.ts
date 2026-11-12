// apm extensions on top of the npm protocol: publish guards, scoring, version states,
// incident response, name search, the ~safe view, server-side resolve, the scan API and
// the upstream proxy.
import { z } from "zod";
import {
  analyze,
  ArchiveError,
  dependencySpecs,
  describeDependency,
  describeSkip,
  finalize,
  findSecrets,
  gunzipCapped,
  httpStatusOf,
  isRegistryDependency,
  parseAnalysis,
  readTarball,
  uncheckableReason,
  signalChanges,
  typoConflicts,
  editDistance,
  isValidPackageName,
  dependencyNames,
  missingEntries,
  COOLDOWN_MS,
  SCORE_FLOOR,
  POPULAR_NAMES,
  ambiguousPaths,
  type DependencyRisk,
  type RegistryDependency,
  type ScoreReport,
  type TarEntry,
} from "@apm/core";
import { canonicalSince, type LiveAction } from "./actions.ts";
import type { VersionRecord } from "./db.ts";
import { fail, json, splitPath, highest, servedVersions, tagTarget, tarballUrl, searchPaging, localSearchObjects, type Auth, type Ctx, type Extensions, type PublishHook, type PackumentView } from "./server.ts";
import { digestLabel, type Upstream, type UpstreamPackage } from "./upstream.ts";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** A revoke of an old or depended-on version waits this long before it becomes final. */
export const PENDING_MS = DAY;
/** Revokes of versions younger than this with no dependents take effect at once. */
const FRESH_MS = 72 * HOUR;
/** Incident response can reach back at most this far. */
const INCIDENT_WINDOW_MS = 30 * DAY;

type Env = { ctx: Ctx; upstream: Upstream | null };

// ---------- scoring helpers ----------
export function reportFor(ctx: Ctx, v: VersionRecord, opts: { ignoreRecent?: boolean } = {}): ScoreReport | null {
  const analysis = parseAnalysis(v.score);
  if (!analysis) return null;
  return finalize(analysis, {
    publishedAt: opts.ignoreRecent ? Number.NEGATIVE_INFINITY : v.published_at,
    now: ctx.now(),
    deprecated: v.deprecated,
    status: v.status,
    statusReason: v.status_reason,
  });
}

function compact(r: ScoreReport): { score: number; grade: string; signals: string[] } {
  return { score: r.score, grade: r.grade, signals: r.signals.map((s) => s.id) };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ---------- catalog: local or upstream ----------
type Source =
  | { kind: "local"; name: string; distTags: Record<string, string>; versions: VersionRecord[] }
  | { kind: "upstream"; name: string; distTags: Record<string, string>; versions: VersionRecord[]; pkg: UpstreamPackage };

async function lookup(env: Env, name: string): Promise<Source | null> {
  const pkg = env.ctx.store.getPackage(name);
  if (pkg) return { kind: "local", name, distTags: pkg.distTags, versions: env.ctx.store.listVersions(name) };
  if (!env.upstream) return null;
  const up = await env.upstream.get(env.ctx, name);
  if (!up) return null;
  return { kind: "upstream", name, distTags: up.distTags, versions: up.versions, pkg: up };
}

/** Like lookup, but keeps "upstream could not be asked" apart from "nobody has it". */
async function lookupOrUnknown(env: Env, name: string): Promise<Source | null | "unknown"> {
  const pkg = env.ctx.store.getPackage(name);
  if (pkg) return { kind: "local", name, distTags: pkg.distTags, versions: env.ctx.store.listVersions(name) };
  if (!env.upstream) return null;
  const probe = await env.upstream.probe(env.ctx, name);
  if (probe.kind === "unknown") return "unknown";
  if (probe.kind === "absent") return null;
  const up = probe.pkg;
  return { kind: "upstream", name, distTags: up.distTags, versions: up.versions, pkg: up };
}

/** Makes sure an upstream version has a stored analysis; returns the version with it. */
async function ensureAnalyzed(env: Env, src: Source, v: VersionRecord): Promise<VersionRecord> {
  if (src.kind === "local" || parseAnalysis(v.score) || !env.upstream) return v;
  const got = await env.upstream.tarball(env.ctx, src.pkg, v.version);
  if (got.kind !== "ok") return v;
  let files: TarEntry[];
  try {
    files = readTarball(got.bytes);
  } catch {
    return v;
  }
  const pj = files.find((f) => f.path === "package.json");
  let manifest: Record<string, unknown> = v.manifest;
  if (pj) {
    try {
      const parsed: unknown = JSON.parse(new TextDecoder().decode(pj.data));
      if (isRecord(parsed)) manifest = parsed;
    } catch {
      // keep the packument manifest
    }
  }
  const earlier = src.versions.filter((x) => x.published_at < v.published_at);
  const previousPublishers = [...new Set(earlier.map((x) => x.published_by))];
  const analysis = analyze({ name: src.name, manifest, files, publisher: v.published_by, previousPublishers });
  env.ctx.store.setUpstreamAnalysis({ name: src.name, version: v.version, digest: digestLabel(got.digest), analysis, at: env.ctx.now() });
  v.score = analysis;
  return v;
}

// ---------- publish guard ----------
const INSTALL_KEYS = ["preinstall", "install", "postinstall"] as const;

function scriptsOf(m: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isRecord(m.scripts)) return out;
  for (const k of INSTALL_KEYS) {
    const v = m.scripts[k];
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

function sameDeps(a: unknown, b: unknown): boolean {
  const ra = isRecord(a) ? a : {};
  const rb = isRecord(b) ? b : {};
  const ka = Object.keys(ra).sort();
  const kb = Object.keys(rb).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && ra[k] === rb[k]);
}

/** Manifest confusion: the request body must not hide what the tarball's package.json says. */
export function manifestMismatch(body: Record<string, unknown>, tar: Record<string, unknown>): string[] {
  const problems: string[] = [];
  const bs = scriptsOf(body);
  const ts = scriptsOf(tar);
  for (const k of INSTALL_KEYS) {
    if (ts[k] !== undefined && bs[k] !== ts[k]) problems.push(`scripts.${k} (tarball: "${ts[k]}", request: ${bs[k] === undefined ? "missing" : `"${bs[k]}"`})`);
    if (ts[k] === undefined && bs[k] !== undefined) problems.push(`scripts.${k} is in the request but not in the tarball`);
  }
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies"] as const) {
    if (field in body && !sameDeps(body[field], tar[field])) problems.push(`${field} differ between request and tarball`);
  }
  if (body.name !== undefined && body.name !== tar.name) problems.push("name");
  if (body.version !== undefined && body.version !== tar.version) problems.push("version");
  return problems;
}

type Picked = { kind: "found"; src: Source; v: VersionRecord } | { kind: "missing"; reason: string };

/** The newest version a registry dependency (plain or npm: alias) would install, among those `keep` allows. */
async function pickDependency(env: Env, dep: RegistryDependency, keep: (v: VersionRecord) => boolean): Promise<Picked> {
  const src = await lookupOrUnknown(env, dep.name);
  if (src === "unknown") return { kind: "missing", reason: "the upstream registry could not be asked" };
  if (src === null) return { kind: "missing", reason: "not on this registry or upstream" };
  let inRange: VersionRecord[];
  switch (dep.kind) {
    case "tag": {
      const tagged = tagTarget(src.distTags, dep.tag);
      inRange = tagged ? src.versions.filter((v) => v.version === tagged) : [];
      break;
    }
    case "registry":
      inRange = src.versions.filter((v) => Bun.semver.satisfies(v.version, dep.range));
      break;
    default: {
      const _exhaustive: never = dep;
      return _exhaustive;
    }
  }
  const best = inRange.filter(keep).sort((a, b) => Bun.semver.order(b.version, a.version))[0];
  return best ? { kind: "found", src, v: best } : { kind: "missing", reason: `no installable version matches ${describeDependency(dep)}` };
}

/** Each checked dependency may mean an upstream download and analysis, so publish checks a bounded number. */
const MAX_PUBLISH_DEPS = 50;

/** Dependencies of a manifest whose best matching version scores below the floor, and those apm could not check. */
async function checkDependencies(env: Env, manifest: Record<string, unknown>): Promise<{ risky: DependencyRisk[]; unchecked: string[] }> {
  const risky: DependencyRisk[] = [];
  const unchecked: string[] = [];
  const specs = dependencySpecs(manifest);
  for (const dep of specs.slice(0, MAX_PUBLISH_DEPS)) {
    if (!isRegistryDependency(dep)) {
      unchecked.push(`${describeDependency(dep)}: ${uncheckableReason(dep)}`);
      continue;
    }
    const picked = await pickDependency(env, dep, (v) => v.status !== "revoked");
    if (picked.kind !== "found") {
      unchecked.push(`${describeDependency(dep)}: ${picked.reason}`);
      continue;
    }
    const analyzed = await ensureAnalyzed(env, picked.src, picked.v);
    const r = reportFor(env.ctx, analyzed, { ignoreRecent: true });
    if (!r) unchecked.push(`${dep.name}@${picked.v.version}: could not be analyzed`);
    else if (r.score < SCORE_FLOOR) risky.push({ name: dep.name, version: picked.v.version, score: r.score });
  }
  if (specs.length > MAX_PUBLISH_DEPS) unchecked.push(`${specs.length - MAX_PUBLISH_DEPS} more dependencies: apm checks the first ${MAX_PUBLISH_DEPS} at publish`);
  return { risky, unchecked };
}

function makeOnPublish(env: Env): PublishHook {
  return async ({ ctx, name, version, manifest, tarball, user, existing }) => {
    let files: TarEntry[];
    try {
      files = readTarball(tarball);
    } catch (e) {
      if (e instanceof ArchiveError) return { ok: false, status: httpStatusOf(e), error: `Refusing to read the tarball: ${e.message}.` };
      return { ok: false, status: 400, error: "The tarball is not a valid gzip'd tar." };
    }
    const ambiguous = ambiguousPaths(files);
    if (ambiguous.length > 0) {
      return { ok: false, status: 422, error: `Refusing to publish: the tarball has duplicate or escaping paths (${ambiguous.slice(0, 5).join(", ")}). Different tools would extract different files from it.` };
    }
    const pj = files.find((f) => f.path === "package.json");
    if (!pj) return { ok: false, status: 400, error: "The tarball has no package.json." };
    let tarManifest: unknown;
    try {
      tarManifest = JSON.parse(new TextDecoder().decode(pj.data));
    } catch {
      return { ok: false, status: 400, error: "The tarball's package.json is not valid JSON." };
    }
    if (!isRecord(tarManifest)) return { ok: false, status: 400, error: "The tarball's package.json is not an object." };
    if (tarManifest.name !== name || tarManifest.version !== version) {
      return { ok: false, status: 422, error: `Manifest mismatch: tarball says ${String(tarManifest.name)}@${String(tarManifest.version)}, request says ${name}@${version}.` };
    }
    const mismatch = manifestMismatch(manifest, tarManifest);
    if (mismatch.length > 0) {
      return { ok: false, status: 422, error: `Manifest mismatch: the publish request does not match the tarball's package.json: ${mismatch.join("; ")}. apm serves metadata from the tarball, so this publish was refused.` };
    }

    const secrets = findSecrets(files);
    if (secrets.findings.length > 0) {
      return {
        ok: false,
        status: 422,
        error: `Refusing to publish: ${secrets.findings.map((s) => s.detail).join("; ")}. Remove the file or add a "files" allowlist to package.json, then publish again. Rotate any key that was ever committed.`,
        detail: secrets.findings,
      };
    }
    const warnings = secrets.skipped.map((s) => `${describeSkip(s)} was not scanned for secrets; check it yourself.`);

    const missing = missingEntries(tarManifest, files);
    if (missing.length > 0) {
      return {
        ok: false,
        status: 422,
        error: `Refusing to publish: ${missing.map((m) => `"${m.field}" points to ${m.path}, which is not in the tarball`).join("; ")}. Did you forget to build, or is it excluded by "files"?`,
      };
    }

    if (!existing) {
      if (POPULAR_NAMES.includes(name)) {
        return { ok: false, status: 403, error: `"${name}" is a reserved name (a widely used public package). Publish under your scope (@${user}/${name}) instead.` };
      }
      if (env.upstream) {
        const probe = await env.upstream.probe(ctx, name);
        if (probe.kind === "found") {
          return { ok: false, status: 403, error: `"${name}" already exists on the public registry. apm shares one namespace with it, so you cannot publish over it here. Publish under your scope (@${user}/${name}) instead.` };
        }
        // scoped names too: during an outage nobody can tell whose @scope/name this is on npm
        if (probe.kind === "unknown") {
          return { ok: false, status: 503, error: `Cannot check whether "${name}" exists on the public registry right now, so a first publish of this name is refused. Try again shortly.` };
        }
      }
      const conflicts = typoConflicts(name);
      if (conflicts.length > 0) {
        const instead = name.startsWith("@") ? "Pick a more distinct name." : `Pick a more distinct name or publish under your scope (@${user}/${name}).`;
        return {
          ok: false,
          status: 422,
          error: `Refusing to publish "${name}": ${conflicts.map((c) => c.reason).join("; ")}. Names this close are how typosquatting works. ${instead}`,
          detail: conflicts,
        };
      }
    }

    const previous = existing ? ctx.store.listVersions(name) : [];
    const previousPublishers = [...new Set(previous.map((v) => v.published_by))];
    const last = previous[previous.length - 1];
    const prevDeps = last ? new Set(dependencyNames(last.manifest)) : null;
    const addedDependencies = prevDeps ? dependencyNames(tarManifest).filter((d) => !prevDeps.has(d)) : [];
    const deps = await checkDependencies(env, tarManifest);
    const analysis = analyze({ name, manifest: tarManifest, files, publisher: user, previousPublishers, riskyDependencies: deps.risky, addedDependencies, uncheckedDependencies: deps.unchecked });
    const served: Record<string, unknown> = { ...tarManifest };
    if (typeof manifest.readme === "string") served.readme = manifest.readme;
    return { ok: true, manifest: served, score: analysis, warnings };
  };
}

/** Existing local packages one edit away: shown as a warning in name search, never blocking. */
function registryNeighbours(ctx: Ctx, name: string): { name: string; distance: number; reason: string }[] {
  if (name.startsWith("@") || name.length < 5) return [];
  return ctx.store
    .listPackageNames()
    .filter((n) => !n.startsWith("@") && n !== name && n.length >= 5 && editDistance(n, name) === 1)
    .slice(0, 5)
    .map((n) => ({ name: n, distance: 1, reason: `one edit away from "${n}" on this registry` }));
}

// ---------- version state changes ----------
function moveTagsOff(ctx: Ctx, name: string, version: string): void {
  const pkg = ctx.store.getPackage(name);
  if (!pkg) return;
  const live = servedVersions(ctx.store.listVersions(name)).map((v) => v.version).filter((v) => v !== version);
  const tags: Record<string, string> = {};
  for (const [t, v] of Object.entries(pkg.distTags)) if (v !== version) tags[t] = v;
  if (!tags.latest) {
    const h = highest(live);
    if (h) tags.latest = h;
  }
  ctx.store.setDistTags(name, tags, ctx.now());
}

/** Revokes now when the version is fresh and nothing depends on it; otherwise starts a pending revoke. */
function revokeVersion(ctx: Ctx, v: VersionRecord, actor: string, reason: string, opts: { forceFinal?: boolean } = {}): "revoked" | "revoke-pending" {
  const at = ctx.now();
  // A fresh version revoked with the owner's password is the malware case: final at once, even if
  // other packages depend on it (they are the victims). Older versions that builds rely on get 24h.
  const fresh = at - v.published_at <= FRESH_MS;
  const dependents = ctx.store.dependentsOf(v.package);
  const final = opts.forceFinal === true || fresh;
  const status = final ? "revoked" : "revoke-pending";
  ctx.store.setStatus(v.package, v.version, { status, reason, at, by: actor });
  ctx.store.deleteAdvisoriesFor(v.package, v.version);
  ctx.store.addAdvisory({
    package: v.package,
    versions: [v.version],
    severity: "critical",
    title: `${v.package}@${v.version} was revoked by its maintainer: ${reason}`,
    detail: reason,
    created_at: at,
    created_by: actor,
  });
  moveTagsOff(ctx, v.package, v.version);
  ctx.store.addEvent({
    package: v.package,
    kind: final ? "revoke" : "revoke-pending",
    actor,
    at,
    detail: { version: v.version, reason, ...(final ? {} : { finalAt: new Date(at + PENDING_MS).toISOString(), dependents }) },
  });
  return status;
}

const Password = z.string().min(1).optional();
const Otp = z.string().min(1).optional();
const StateBody = z.object({ name: z.string(), version: z.string(), reason: z.string().optional(), password: Password, otp: Otp });
const IncidentBody = z.object({ since: z.string(), reason: z.string().optional(), password: Password, otp: Otp, dryRun: z.boolean().optional() });
const OwnerBody = z.object({ name: z.string(), user: z.string(), password: Password, otp: Otp });

/** JSON bodies of the apm and audit APIs, before and after gzip. Thousands of packages fit in a fraction of it. */
export const MAX_JSON_BODY_BYTES = 5 * 1024 * 1024;

/** Reads a JSON body, gzip'd or not, within MAX_JSON_BODY_BYTES. Throws ArchiveError "too-large" past it. */
async function readJson(req: Request): Promise<unknown> {
  const tooLarge = (): ArchiveError => new ArchiveError("too-large", `request body over ${MAX_JSON_BODY_BYTES / (1024 * 1024)} MB`);
  if (Number(req.headers.get("content-length") ?? 0) > MAX_JSON_BODY_BYTES) throw tooLarge();
  const enc = req.headers.get("content-encoding") ?? "";
  const buf = new Uint8Array(await req.arrayBuffer());
  if (buf.length > MAX_JSON_BODY_BYTES) throw tooLarge();
  const raw = enc.includes("gzip") || (buf[0] === 0x1f && buf[1] === 0x8b) ? gunzipCapped(buf, MAX_JSON_BODY_BYTES) : buf;
  return JSON.parse(new TextDecoder().decode(raw));
}

function bodyError(e: unknown): Response {
  if (e instanceof ArchiveError) return fail(httpStatusOf(e), `Request body refused: ${e.message}`);
  return fail(400, `Invalid request body: ${e instanceof Error ? e.message : String(e)}`);
}

type Parsed<T> = { ok: true; value: T } | { ok: false; res: Response };
async function parseBody<T>(req: Request, schema: z.ZodType<T>): Promise<Parsed<T>> {
  try {
    return { ok: true, value: schema.parse(await readJson(req)) };
  } catch (e) {
    return { ok: false, res: bodyError(e) };
  }
}

/** Destructive actions need a fresh second factor for this exact action on top of the bearer token (a password only in legacy mode). */
async function reauth(ctx: Ctx, auth: Auth, proof: { password?: string | undefined; otp?: string | undefined }, action: LiveAction): Promise<Response | { user: string }> {
  if (auth.kind !== "user") return fail(401, "Log in first (apm login).");
  const refused = await ctx.access.secondFactor({ user: auth.user, password: proof.password, otp: proof.otp, action });
  if (refused) return fail(refused.status, refused.error);
  return { user: auth.user };
}

function requireOwner(ctx: Ctx, user: string, name: string): Response | null {
  if (!ctx.store.getPackage(name)) return fail(404, `No package named ${name} on this registry.`);
  if (!ctx.store.owners(name).includes(user)) return fail(403, `Only owners of ${name} can do this. Owners: ${ctx.store.owners(name).join(", ")}`);
  return null;
}

async function handleState(req: Request, ctx: Ctx, auth: Auth, action: "yank" | "unyank" | "revoke" | "restore"): Promise<Response> {
  const parsed = await parseBody(req, StateBody);
  if (!parsed.ok) return parsed.res;
  const { name, version, reason, password, otp } = parsed.value;
  let user: string;
  const live: LiveAction = { kind: action, name, version };
  if (action === "revoke" || action === "restore") {
    const who = await reauth(ctx, auth, { password, otp }, live);
    if (who instanceof Response) return who;
    user = who.user;
  } else {
    if (auth.kind !== "user") return fail(401, "Log in first (apm login).");
    // yank and unyank change what installs: a staging token needs a fresh second factor for them
    const ownerFirst = requireOwner(ctx, auth.user, name);

    if (ownerFirst) return ownerFirst;
    const refused = await ctx.access.liveChangeRefusal({ user: auth.user, scope: auth.scope, action: live, otp });

    if (refused) return fail(refused.status, refused.error);
    user = auth.user;
  }
  const denied = requireOwner(ctx, user, name);
  if (denied) return denied;
  const v = ctx.store.getVersion(name, version);
  if (!v) return fail(404, `No version ${name}@${version}.`);
  const at = ctx.now();

  if (action === "revoke") {
    if (v.status === "revoked") return json({ ok: true, name, version, status: "revoked", already: true });
    if (v.status === "revoke-pending") {
      if (v.status_by === user) return json({ ok: true, name, version, status: "revoke-pending", finalAt: new Date((v.status_at ?? at) + PENDING_MS).toISOString() });
      // a second owner confirms: final at once
      ctx.store.setStatus(name, version, { status: "revoked", reason: v.status_reason, at, by: user });
      ctx.store.addEvent({ package: name, kind: "revoke", actor: user, at, detail: { version, reason: v.status_reason, confirms: v.status_by } });
      return json({ ok: true, name, version, status: "revoked" });
    }
    if (!reason) return fail(400, "A reason is required to revoke; it is shown to everyone who has this version installed.");
    const status = revokeVersion(ctx, v, user, reason);
    return json({
      ok: true,
      name,
      version,
      status,
      ...(status === "revoke-pending"
        ? { finalAt: new Date(at + PENDING_MS).toISOString(), note: "Hidden from new installs now. Existing lockfiles keep working until it becomes final, or until another owner confirms." }
        : {}),
    });
  }
  if (action === "restore") {
    if (v.status !== "revoked" && v.status !== "revoke-pending") return fail(409, `${name}@${version} is ${v.status}, not revoked.`);
    ctx.store.setStatus(name, version, { status: "yanked", reason: reason ?? "restored after revoke", at, by: user });
    ctx.store.deleteAdvisoriesFor(name, version);
    ctx.store.addEvent({ package: name, kind: "restore", actor: user, at, detail: { version, reason: reason ?? null, from: v.status } });
    return json({ ok: true, name, version, status: "yanked" });
  }
  if (action === "yank") {
    if (v.status === "revoked" || v.status === "revoke-pending") return fail(409, "This version is revoked, which is stronger than a yank.");
    if (v.status === "yanked") return json({ ok: true, name, version, status: "yanked", already: true });
    ctx.store.setStatus(name, version, { status: "yanked", reason: reason ?? null, at, by: user });
    moveTagsOff(ctx, name, version);
    ctx.store.addEvent({ package: name, kind: "yank", actor: user, at, detail: { version, reason: reason ?? null } });
    return json({ ok: true, name, version, status: "yanked" });
  }
  if (v.status !== "yanked") return fail(409, `${name}@${version} is ${v.status}, not yanked.`);
  ctx.store.setStatus(name, version, { status: "active", reason: null, at, by: user });
  const pkg = ctx.store.getPackage(name);
  if (pkg) {
    const tags = { ...pkg.distTags };
    const latest = tags.latest;
    if (!version.includes("-") && (!latest || Bun.semver.order(version, latest) > 0)) tags.latest = version;
    ctx.store.setDistTags(name, tags, at);
  }
  ctx.store.addEvent({ package: name, kind: "unyank", actor: user, at, detail: { version } });
  return json({ ok: true, name, version, status: "active" });
}

async function handleIncident(req: Request, ctx: Ctx, auth: Auth): Promise<Response> {
  const parsed = await parseBody(req, IncidentBody);
  if (!parsed.ok) return parsed.res;
  // `since` is exclusive: pass the time of the last publish you trust.
  const since = Date.parse(parsed.value.since);
  if (Number.isNaN(since)) return fail(400, "since must be an ISO timestamp");
  if (ctx.now() - since > INCIDENT_WINDOW_MS) return fail(400, "Incident response reaches back at most 30 days. Revoke older versions one by one (apm revoke).");
  // the range and whether it is a preview are part of what the second factor authorizes
  const command: LiveAction = { kind: "incident", since: canonicalSince(parsed.value.since), dryRun: parsed.value.dryRun === true };
  const who = await reauth(ctx, auth, { password: parsed.value.password, otp: parsed.value.otp }, command);
  if (who instanceof Response) return who;
  const reason = parsed.value.reason ?? "account compromised";
  const user = who.user;
  const targets: VersionRecord[] = [];
  for (const name of ctx.store.listPackageNames()) {
    // only packages the account still owns: a former owner's old publishes are the current owners' call
    if (!ctx.store.owners(name).includes(user)) continue;

    for (const v of ctx.store.listVersions(name)) {
      if (v.published_by === user && v.published_at > since && v.status !== "revoked") targets.push(v);
    }
  }
  const ids = targets.map((v) => `${v.package}@${v.version}`);
  if (parsed.value.dryRun) {
    return json({ ok: true, dryRun: true, user, since: new Date(since).toISOString(), revoked: ids, tokensRevoked: ctx.store.listTokens(user).filter((t) => t.revoked_at === null).length });
  }
  const statuses: Record<string, string> = {};
  ctx.store.tx(() => {
    for (const v of targets) statuses[`${v.package}@${v.version}`] = revokeVersion(ctx, v, user, `incident: ${reason}`);
  });
  const tokensRevoked = ctx.store.revokeTokensOf(user, ctx.now());
  return json({ ok: true, user, since: new Date(since).toISOString(), revoked: ids, statuses, tokensRevoked, next: ctx.access.legacyAuth
      ? "Every token is revoked. Change your password, log in again with apm login, then read each package's event log."
      : "Every token is revoked. Check your GitHub account's security, run apm login again, then read each package's event log." });
}

async function handleOwners(req: Request, ctx: Ctx, auth: Auth): Promise<Response> {
  const parsed = await parseBody(req, OwnerBody);
  if (!parsed.ok) return parsed.res;
  const remove = req.method === "DELETE";
  const ownerAction: LiveAction = { kind: remove ? "owner-remove" : "owner-add", name: parsed.value.name, user: parsed.value.user };
  const who = await reauth(ctx, auth, { password: parsed.value.password, otp: parsed.value.otp }, ownerAction);
  if (who instanceof Response) return who;
  const denied = requireOwner(ctx, who.user, parsed.value.name);
  if (denied) return denied;
  if (!ctx.store.getUser(parsed.value.user)) return fail(404, `No user ${parsed.value.user}.`);
  if (remove) {
    const removed = ctx.store.removeOwner(parsed.value.name, parsed.value.user);
    switch (removed) {
      case "removed":
        break;
      case "not-owner":
        return fail(404, `${parsed.value.user} is not an owner of ${parsed.value.name}.`);
      case "last-owner":
        return fail(409, `${parsed.value.user} is the last owner of ${parsed.value.name}. Add another owner first: a package with no owners can never be published, yanked or revoked again.`);
      default: {
        const _exhaustive: never = removed;
        return _exhaustive;
      }
    }
  } else ctx.store.addOwner(parsed.value.name, parsed.value.user);
  ctx.store.addEvent({ package: parsed.value.name, kind: remove ? "owner-remove" : "owner-add", actor: who.user, at: ctx.now(), detail: { user: parsed.value.user } });
  return json({ ok: true, owners: ctx.store.owners(parsed.value.name) });
}

// ---------- read APIs ----------
function previousOf(src: Source, v: VersionRecord): VersionRecord | null {
  const all = src.versions.filter((x) => x.version !== v.version && x.published_at <= v.published_at && x.status !== "revoked");
  return all[all.length - 1] ?? null;
}

async function scoreResponse(env: Env, src: Source, v0: VersionRecord): Promise<Response> {
  const v = await ensureAnalyzed(env, src, v0);
  const report = reportFor(env.ctx, v);
  if (!report) return fail(404, "No score for this version (the tarball could not be read).");
  const prev0 = previousOf(src, v);
  const prev = prev0 ? await ensureAnalyzed(env, src, prev0) : null;
  const prevReport = prev ? reportFor(env.ctx, prev, { ignoreRecent: true }) : null;
  return json({
    name: v.package,
    version: v.version,
    source: src.kind,
    status: v.status,
    publishedAt: new Date(v.published_at).toISOString(),
    publishedBy: v.published_by,
    ...report,
    previous: prev && prevReport ? { version: prev.version, score: prevReport.score, grade: prevReport.grade } : null,
    changes: prev && prevReport ? signalChanges(prevReport.signals, report.signals) : [],
  });
}

async function packageResponse(env: Env, name: string): Promise<Response> {
  const src = await lookup(env, name);
  if (!src) return fail(404, "Not found");
  const ctx = env.ctx;
  const local = src.kind === "local" ? ctx.store.getPackage(name) : null;
  const latest0 = src.versions.find((v) => v.version === src.distTags.latest) ?? null;
  const latest = latest0 ? await ensureAnalyzed(env, src, latest0) : null;
  const latestReport = latest ? reportFor(ctx, latest) : null;
  return json({
    name,
    source: src.kind,
    description: local?.description ?? (src.kind === "upstream" ? src.pkg.description : ""),
    keywords: local?.keywords ?? [],
    readme: local?.readme ?? (src.kind === "upstream" ? src.pkg.readme : ""),
    distTags: src.distTags,
    maintainers: src.kind === "local" ? ctx.store.owners(name) : src.pkg.maintainers,
    createdAt: local ? new Date(local.created_at).toISOString() : null,
    modifiedAt: local ? new Date(local.modified_at).toISOString() : null,
    latest: latest?.version ?? null,
    facts: latestReport?.facts ?? null,
    score: latestReport ? { score: latestReport.score, grade: latestReport.grade, signals: latestReport.signals, notChecked: latestReport.notChecked } : null,
    versions: [...src.versions]
      .sort((a, b) => Bun.semver.order(b.version, a.version))
      .slice(0, 200)
      .map((v) => {
        const r = reportFor(ctx, v);
        return {
          version: v.version,
          publishedAt: new Date(v.published_at).toISOString(),
          publishedBy: v.published_by,
          status: v.status,
          statusReason: v.status_reason,
          deprecated: v.deprecated,
          score: r?.score ?? null,
          grade: r?.grade ?? null,
        };
      }),
  });
}

function eventsResponse(ctx: Ctx, name: string): Response {
  if (!ctx.store.getPackage(name)) return fail(404, "Not found");
  return json({
    name,
    events: ctx.store.eventsFor(name).map((e) => ({ kind: e.kind, actor: e.actor, at: new Date(e.at).toISOString(), detail: e.detail })),
  });
}

/** The name check answers in parts so a UI can fill each slot as soon as its part is ready. */
export const NAME_PARTS = ["exact", "lookalike", "alternatives"] as const;
export type NamePart = (typeof NAME_PARTS)[number];
export function isNamePart(s: string | null): s is NamePart {
  return NAME_PARTS.some((p) => p === s);
}

async function exactPart(env: Env, query: string, valid: boolean): Promise<Record<string, unknown>> {
  const ctx = env.ctx;
  const found = valid ? await lookupOrUnknown(env, query) : null;
  // When npm can't be asked, the name is neither taken nor available: say so instead of "available".
  const unknown = found === "unknown";
  const src = found === "unknown" ? null : found;
  const conflicts = valid && !src ? typoConflicts(query) : [];
  const latestRaw = src ? (src.versions.find((v) => v.version === src.distTags.latest) ?? null) : null;
  const latest0 = src && latestRaw ? await ensureAnalyzed(env, src, latestRaw) : null;
  const latestReport = latest0 ? reportFor(ctx, latest0) : null;
  return {
    taken: src !== null,
    source: src?.kind ?? null,
    unknown,
    available: valid && !unknown && src === null && conflicts.length === 0,
    owners: src ? (src.kind === "local" ? ctx.store.owners(query) : src.pkg.maintainers) : [],
    latest: latest0 ? { version: latest0.version, score: latestReport?.score ?? null, grade: latestReport?.grade ?? null } : null,
    description: src ? (src.kind === "local" ? (ctx.store.getPackage(query)?.description ?? "") : src.pkg.description) : null,
    conflicts,
  };
}

function lookalikePart(ctx: Ctx, query: string, valid: boolean): Record<string, unknown> {
  return {
    // popular names this one could be mistaken for, whether or not it is taken (install-side typo warning)
    lookalikes: valid ? typoConflicts(query) : [],
    similar: valid ? registryNeighbours(ctx, query) : [],
  };
}

async function alternativesPart(env: Env, query: string, user: string | null): Promise<Record<string, unknown>> {
  const bare = query.startsWith("@") ? query.slice(query.indexOf("/") + 1) : query;
  const candidates = [...(user ? [`@${user}/${bare}`] : []), `${bare}-js`, `${bare}js`, `use-${bare}`, `${bare}-kit`, `${bare}-core`].filter((c) => c !== query);
  const suggestions = await Promise.all(
    candidates
      .filter((c) => isValidPackageName(c))
      .map(async (c) => {
        const hit = await lookupOrUnknown(env, c);
        const taken = hit !== null && hit !== "unknown";
        const cc = taken ? [] : typoConflicts(c);
        return { name: c, available: hit === null && cc.length === 0, taken, unknown: hit === "unknown" };
      }),
  );
  return { suggestions };
}

export async function nameReport(env: Env, q: string, user: string | null, part: NamePart | null = null): Promise<Record<string, unknown>> {
  const query = q.trim().toLowerCase();
  const valid = isValidPackageName(query);
  const head = { query, valid };
  if (part !== null) {
    switch (part) {
      case "exact":
        return { ...head, ...(await exactPart(env, query, valid)) };
      case "lookalike":
        return { ...head, ...lookalikePart(env.ctx, query, valid) };
      case "alternatives":
        return { ...head, ...(await alternativesPart(env, query, user)) };
      default: {
        const _exhaustive: never = part;
        return _exhaustive;
      }
    }
  }
  const [exact, alternatives] = await Promise.all([exactPart(env, query, valid), alternativesPart(env, query, user)]);
  return { ...head, ...lookalikePart(env.ctx, query, valid), ...exact, ...alternatives };
}

// ---------- search: local packages merged with the upstream's search ----------
/** A score for an upstream search hit, only when that version was analyzed before. Never fetches a tarball. */
function storedUpstreamScore(ctx: Ctx, name: string, version: string, date: string | null | undefined): ReturnType<typeof compact> | null {
  const analysis = parseAnalysis(ctx.store.latestUpstreamAnalysis(name, version));
  if (!analysis) return null;
  return compact(finalize(analysis, { publishedAt: Date.parse(date ?? "") || 0, now: ctx.now(), deprecated: null, status: "active", statusReason: null }));
}

/**
 * Local hits first (they are what this registry serves under that name), then the upstream's in its own order.
 * An exact name match from either side goes to the top; a name published here hides the upstream hit.
 */
export function mergeSearch<L extends { package: { name: string } }, U extends { package: { name: string } }>(input: { text: string; local: L[]; upstream: U[] }): (L | U)[] {
  const q = input.text.trim().toLowerCase();
  const localNames = new Set(input.local.map((o) => o.package.name));
  const upstream = input.upstream.filter((o) => !localNames.has(o.package.name));
  const merged: (L | U)[] = [...input.local, ...upstream];
  const exact = merged.findIndex((o) => o.package.name === q);
  if (exact > 0) merged.unshift(...merged.splice(exact, 1));
  return merged;
}

async function searchResponse(env: Env, url: URL, scoreOf: (v: VersionRecord) => unknown): Promise<Response> {
  const ctx = env.ctx;
  const { text, size, from } = searchPaging(url);
  const local = localSearchObjects(ctx, { searchScore: scoreOf }, text);
  // npm refuses text shorter than two characters, so asking it would only look like an outage
  const up = env.upstream && text.trim().length >= 2 ? await env.upstream.search(text.trim(), Math.min(250, from + size)) : null;
  const upstream =
    up?.kind === "ok"
      ? up.objects.map((o) => ({ ...o, source: "npm" as const, apmScore: storedUpstreamScore(ctx, o.package.name, o.package.version, o.package.date) }))
      : [];
  const merged = mergeSearch({ text, local, upstream });
  const total = local.length + (up?.kind === "ok" ? Math.max(up.total, upstream.length) : 0);
  return json({ objects: merged.slice(from, from + size), total, time: new Date(ctx.now()).toUTCString(), upstreamFailed: up?.kind === "unavailable" });
}

// ---------- recent activity on this registry ----------
const RECENT_KINDS = ["publish", "yank", "unyank", "revoke", "restore"] as const;
const EventDetail = z.object({ version: z.string(), reason: z.string().nullish() }).loose();

function recentResponse(ctx: Ctx, url: URL): Response {
  const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") ?? 12) || 12));
  const seen = new Set<string>();
  const events: Record<string, unknown>[] = [];
  for (const e of ctx.store.recentEvents([...RECENT_KINDS], limit * 4)) {
    const d = EventDetail.safeParse(e.detail);
    if (!d.success) continue;
    const key = `${e.package}@${d.data.version}:${e.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const v = ctx.store.getVersion(e.package, d.data.version);
    const r = v ? reportFor(ctx, v) : null;
    events.push({
      package: e.package,
      version: d.data.version,
      kind: e.kind,
      actor: e.actor,
      at: new Date(e.at).toISOString(),
      reason: d.data.reason ?? null,
      status: v?.status ?? null,
      score: r?.score ?? null,
      grade: r?.grade ?? null,
    });
    if (events.length >= limit) break;
  }
  return json({ events });
}

// ---------- policy: ~safe view, resolve, scan ----------
export type Policy = { cooldownMs: number; floor: number };
export const DEFAULT_POLICY: Policy = { cooldownMs: COOLDOWN_MS, floor: SCORE_FLOOR };

/** Why a version fails the policy, or null when it passes. A version that was never scored fails. */
export function policyBlock(ctx: Ctx, v: VersionRecord, policy: Policy): string | null {
  if (v.status === "revoked") return `revoked: ${v.status_reason ?? "no reason given"}`;
  if (v.status === "revoke-pending") return `revocation pending: ${v.status_reason ?? "no reason given"}`;
  if (v.status === "yanked") return `yanked${v.status_reason ? `: ${v.status_reason}` : ""}`;
  const age = ctx.now() - v.published_at;
  if (age < policy.cooldownMs) return `published ${Math.floor(age / HOUR)}h ago (cooldown ${Math.round(policy.cooldownMs / HOUR)}h)`;
  const r = reportFor(ctx, v, { ignoreRecent: true });
  if (!r) return "not scored yet";
  if (r.score < policy.floor) {
    return `score ${r.score}/100 is below ${policy.floor} (${r.signals.filter((s) => s.points < 0).map((s) => s.id).join(", ")})`;
  }
  return null;
}

/** The URL prefix of the safe view: versions past the cooldown that score at or above the floor. */
export const SAFE_PREFIX = "~safe/";

function safeView(ctx: Ctx): PackumentView {
  const why = (v: VersionRecord): string | null => policyBlock(ctx, v, DEFAULT_POLICY);

  return { keep: (v) => why(v) === null, why, prefix: SAFE_PREFIX };
}

/** "24h", "90m", "2d", "0" (hours by default), or null when it is not a duration of zero or more. */
function parseDuration(s: string): number | null {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/.exec(s.trim());

  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2] ?? "h";
  const mult = unit === "ms" ? 1 : unit === "s" ? 1000 : unit === "m" ? 60_000 : unit === "h" ? HOUR : DAY;
  return n * mult;
}

type PolicyParse = { kind: "ok"; policy: Policy } | { kind: "invalid"; error: string };

/** The policy a resolve asks for. A floor or cooldown apm cannot read is an error, never "no policy". */
function parsePolicy(url: URL): PolicyParse {
  const rawFloor = url.searchParams.get("floor");
  const rawCooldown = url.searchParams.get("cooldown");
  const floor = rawFloor === null ? DEFAULT_POLICY.floor : /^\d+(?:\.\d+)?$/.test(rawFloor.trim()) ? Number(rawFloor) : Number.NaN;

  if (!Number.isFinite(floor) || floor < 0) return { kind: "invalid", error: `floor must be a number of 0 or more (got "${rawFloor ?? ""}")` };
  const cooldownMs = rawCooldown === null ? DEFAULT_POLICY.cooldownMs : parseDuration(rawCooldown);

  if (cooldownMs === null) return { kind: "invalid", error: `cooldown must be a duration of 0 or more, like 24h, 90m or 2d (got "${rawCooldown ?? ""}")` };

  return { kind: "ok", policy: { floor, cooldownMs } };
}

type TreeBlock = { name: string; version: string; reason: string; via: string[] };
/** A dependency the walk could not score: a git or URL spec, a missing package, a failed analysis or the walk's limit. */
type UncheckedDep = { dependency: string; reason: string; via: string[] };
/** `packages`: every name@version the walk checked, so the CLI can pin each scope in the tree to this registry. */
type Tree = { blocks: TreeBlock[]; unchecked: number; uncheckedDeps: UncheckedDep[]; packages: { name: string; version: string }[] };
const MAX_UNCHECKED_LISTED = 50;

/**
 * Walks the dependency tree the package manager would install (newest active version matching each
 * range, npm: aliases followed to the package they install) and returns the versions that are revoked
 * or score below the floor. Bounded: at most `maxNodes` packages and `maxAnalyses` tarball analyses.
 * Everything it could not score is counted and listed, never dropped.
 */
async function treeBlocks(env: Env, root: VersionRecord, policy: Policy, limits = { maxNodes: 300, maxAnalyses: 40 }): Promise<Tree> {
  const blocks: TreeBlock[] = [];
  const uncheckedDeps: UncheckedDep[] = [];
  const packages: Tree["packages"] = [];
  let unchecked = 0;
  const miss = (dependency: string, reason: string, via: string[]): void => {
    unchecked++;
    if (uncheckedDeps.length < MAX_UNCHECKED_LISTED) uncheckedDeps.push({ dependency, reason, via });
  };
  const seen = new Set<string>();
  let analyses = 0;
  const rootId = `${root.package}@${root.version}`;
  const queue = dependencySpecs(root.manifest).map((dep) => ({ dep, via: [rootId] }));
  for (let qi = 0; qi < queue.length; qi++) {
    const item = queue[qi];
    if (!item) break;
    if (seen.size >= limits.maxNodes) {
      const rest = queue.length - qi;
      unchecked += rest;
      uncheckedDeps.push({ dependency: `${rest} more`, reason: `the check stops after ${limits.maxNodes} packages`, via: [rootId] });
      break;
    }
    const dep = item.dep;
    if (!isRegistryDependency(dep)) {
      miss(describeDependency(dep), uncheckableReason(dep), item.via);
      continue;
    }
    // what the package manager would pick: the newest active version in range (pulled versions are hidden)
    const picked = await pickDependency(env, dep, (v) => v.status === "active");
    if (picked.kind !== "found") {
      miss(describeDependency(dep), picked.reason, item.via);
      continue;
    }
    const key = `${dep.name}@${picked.v.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    packages.push({ name: dep.name, version: picked.v.version });
    let v = picked.v;
    if (!parseAnalysis(v.score) && analyses < limits.maxAnalyses) {
      analyses++;
      v = await ensureAnalyzed(env, picked.src, v);
    }

    const age = env.ctx.now() - v.published_at;
    const r = reportFor(env.ctx, v, { ignoreRecent: true });

    // the package manager installs this version whatever its age, so a fresh one blocks the tree like a low score
    if (age < policy.cooldownMs) blocks.push({ name: dep.name, version: v.version, reason: `published ${Math.floor(age / HOUR)}h ago (cooldown ${Math.round(policy.cooldownMs / HOUR)}h)`, via: item.via });
    else if (!r) miss(key, "could not be analyzed", item.via);
    else if (r.score < policy.floor) blocks.push({ name: dep.name, version: v.version, reason: `score ${r.score}/100 (${r.signals.filter((s) => s.points < 0).map((s) => s.id).join(", ")})`, via: item.via });
    if (item.via.length < 12) for (const d of dependencySpecs(v.manifest)) queue.push({ dep: d, via: [...item.via, key] });
  }
  return { blocks, unchecked, uncheckedDeps, packages };
}

async function resolveResponse(env: Env, url: URL): Promise<Response> {
  const ctx = env.ctx;
  const name = url.searchParams.get("name") ?? "";
  const range = url.searchParams.get("range") || "latest";
  const parsedPolicy = parsePolicy(url);

  if (parsedPolicy.kind === "invalid") return fail(400, parsedPolicy.error);
  const policy = parsedPolicy.policy;
  // A lower floor (apm add --force sends 0) applies to the named package only; its dependencies are
  // always checked at the default floor or the stricter one asked for. The cooldown is the one asked for.
  const treePolicy: Policy = { floor: Math.max(policy.floor, DEFAULT_POLICY.floor), cooldownMs: policy.cooldownMs };
  const src = await lookup(env, name);
  if (!src) return fail(404, `No package named ${name}.`);
  const tagged = tagTarget(src.distTags, range);
  // A tag keeps its channel: `next` -> 2.0.0-beta.3 may fall back to 2.0.0-beta.2 or a stable release
  // below it, but a stable tag never falls back to a prerelease.
  const base = (v: string): string => v.split("-")[0] ?? v;
  const inChannel = (v: string, t: string): boolean => Bun.semver.order(v, t) <= 0 && (!v.includes("-") || (t.includes("-") && base(v) === base(t)));
  const matches = src.versions
    .filter((v) => (tagged ? inChannel(v.version, tagged) : v.version === range || Bun.semver.satisfies(v.version, range)))
    .sort((a, b) => Bun.semver.order(b.version, a.version));
  const skipped: { version: string; reason: string }[] = [];
  let analyzedCount = 0;
  for (const v0 of matches) {
    // analyze a bounded number of candidates; upstream analysis means downloading the tarball
    const v = analyzedCount < 5 ? await ensureAnalyzed(env, src, v0) : v0;
    analyzedCount++;
    const block = policyBlock(ctx, v, policy);
    if (block === null) {
      const report = reportFor(ctx, v);
      const tree: Tree = await treeBlocks(env, v, treePolicy);
      if (tree.blocks.length > 0) {
        const list = tree.blocks.map((b) => `${b.name}@${b.version} ${b.reason} via ${b.via.join(" > ")}`).join("; ");
        return json({ error: `${name}@${v.version} would install dangerous dependencies: ${list}`, name, range, version: null, skipped, newest: { version: v.version, report }, tree }, 422);
      }
      return json({ name, range, source: src.kind, version: v.version, report, skipped, tree, policy: { cooldownHours: policy.cooldownMs / HOUR, floor: policy.floor } });
    }
    skipped.push({ version: v.version, reason: block });
    if (skipped.length >= 20) break;
  }
  const newest = matches[0];
  const newestReport = newest ? reportFor(ctx, newest) : null;
  return json({ error: `No version of ${name} matching ${range} passes the policy.`, name, range, version: null, skipped, newest: newest ? { version: newest.version, report: newestReport } : null }, 422);
}

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })) });

/** Packages one scan checks: signed in, and without a token. Each may mean an upstream packument and tarball. */
export const MAX_SCAN = 2000;
export const MAX_SCAN_ANONYMOUS = 200;

/** Upstream lookups and downloads one scan runs at once. */
const SCAN_CONCURRENCY = 8;

type ScanAdvisory = { package: string; version: string; level: "fatal" | "warn"; description: string; url: string | null };

type ScanUnchecked = { package: string; version: string; reason: string };

type ScanOne = { kind: "clean" } | { kind: "advisory"; advisory: ScanAdvisory } | { kind: "unchecked"; unchecked: ScanUnchecked };

/** Runs `fn` over `items` with at most `limit` running at once; results keep the input order. */
async function pool<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  let next = 0;

  const worker = async (): Promise<void> => {
    for (let i = next++; i < items.length; i = next++) {
      const item = items[i];

      if (item !== undefined) out[i] = await fn(item);
    }
  };

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));

  return out;
}

async function scanOne(env: Env, p: { name: string; version: string }): Promise<ScanOne> {
  const ctx = env.ctx;
  const unchecked = (reason: string): ScanOne => ({ kind: "unchecked", unchecked: { package: p.name, version: p.version, reason } });
  const src = await lookupOrUnknown(env, p.name);

  if (src === "unknown") return unchecked("the upstream registry could not be asked");

  if (src === null) return unchecked("not on this registry or upstream");
  const v0 = src.versions.find((x) => x.version === p.version);

  if (!v0) return unchecked("no such version");
  const url = `${ctx.baseUrl()}package/${p.name}`;

  if (v0.status === "revoked" || v0.status === "revoke-pending") {
    return { kind: "advisory", advisory: { package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version} was revoked by its maintainer: ${v0.status_reason ?? "no reason given"}`, url } };
  }

  // a stored analysis of these exact bytes is reused; only a version never analyzed is downloaded
  const v = await ensureAnalyzed(env, src, v0);
  const r = reportFor(ctx, v, { ignoreRecent: true });

  if (!r) return unchecked("could not be analyzed");

  if (r.score >= SCORE_FLOOR) return { kind: "clean" };
  const why = r.signals.filter((s) => s.points < 0).map((s) => s.id).join(", ");

  return { kind: "advisory", advisory: { package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version} has apm score ${r.score}/100 (${why}). Review it, then allow it with apm add ${p.name} --force.`, url } };
}

async function scanResponse(req: Request, env: Env, auth: Auth): Promise<Response> {
  const parsed = await parseBody(req, ScanBody);
  if (!parsed.ok) return parsed.res;
  const signedIn = auth.kind === "user";
  const cap = signedIn ? MAX_SCAN : MAX_SCAN_ANONYMOUS;
  const seen = new Set<string>();

  const packages = parsed.value.packages.filter((p) => {
    const key = `${p.name}@${p.version}`;

    if (seen.has(key)) return false;
    seen.add(key);

    return true;
  });

  const advisories: ScanAdvisory[] = [];
  // Versions the scan could not judge. Missing from `advisories` is not the same as clean.
  const unchecked: ScanUnchecked[] = [];
  const results = await pool(packages.slice(0, cap), SCAN_CONCURRENCY, (p) => scanOne(env, p));

  for (const r of results) {
    if (r.kind === "advisory") advisories.push(r.advisory);
    else if (r.kind === "unchecked") unchecked.push(r.unchecked);
  }

  const over = signedIn
    ? `a scan checks at most ${MAX_SCAN} packages; send the rest in another request`
    : `a scan without a token checks at most ${MAX_SCAN_ANONYMOUS} packages; sign in (apm login) to check up to ${MAX_SCAN}, or send the rest in another request`;

  for (const p of packages.slice(cap)) unchecked.push({ package: p.name, version: p.version, reason: over });
  return json({ advisories, unchecked });
}

const AuditBody = z.record(z.string(), z.array(z.string()));
type Audit = { advisories: Record<string, unknown[]>; unavailable: string[] };

/** Local advisories plus the upstream's for names not published here. `unavailable` names packages whose upstream advisories could not be fetched. */
async function collectAdvisories(env: Env, query: z.infer<typeof AuditBody>): Promise<Audit> {
  const ctx = env.ctx;
  const out: Record<string, unknown[]> = {};
  const upstreamQuery: Record<string, string[]> = {};
  for (const [name, versions] of Object.entries(query)) {
    if (!ctx.store.getPackage(name)) upstreamQuery[name] = versions;
    const list = ctx.store.advisoriesFor(name).map((a) => ({
      id: a.id,
      url: `${ctx.baseUrl()}package/${name}`,
      title: a.title,
      severity: a.severity,
      vulnerable_versions: a.versions.join(" || "),
      cwe: ["CWE-506"],
      cvss: { score: 10, vectorString: null },
    }));
    if (list.length > 0) out[name] = list;
  }
  if (env.upstream && Object.keys(upstreamQuery).length > 0) {
    const up = await env.upstream.advisories(upstreamQuery);
    switch (up.kind) {
      case "ok":
        for (const [name, list] of Object.entries(up.advisories)) out[name] = [...(out[name] ?? []), ...list];
        break;
      case "unavailable":
        return { advisories: out, unavailable: Object.keys(upstreamQuery) };
      default: {
        const _exhaustive: never = up;
        return _exhaustive;
      }
    }
  }
  return { advisories: out, unavailable: [] };
}

/** npm's bulk advisory endpoint. When part of the answer could not be fetched it is a 503, never a clean {}. */
async function bulkAdvisories(req: Request, env: Env): Promise<Response> {
  const parsed = await parseBody(req, AuditBody);
  if (!parsed.ok) return parsed.res;
  const audit = await collectAdvisories(env, parsed.value);
  if (audit.unavailable.length > 0) {
    return fail(503, `The upstream advisory service did not answer for ${audit.unavailable.length} package(s), so this audit would be incomplete. Try again shortly.`);
  }
  return json(audit.advisories);
}

/** apm's audit: the same advisories, plus the packages whose advisories could not be fetched. */
async function auditResponse(req: Request, env: Env): Promise<Response> {
  const parsed = await parseBody(req, AuditBody);
  if (!parsed.ok) return parsed.res;
  return json(await collectAdvisories(env, parsed.value));
}

// ---------- upstream packuments and tarballs ----------
const ABBREV = ["name", "version", "dependencies", "optionalDependencies", "devDependencies", "bundleDependencies", "peerDependencies", "peerDependenciesMeta", "bin", "directories", "engines", "os", "cpu", "libc", "_hasShrinkwrap", "hasInstallScript", "deprecated"];

function upstreamPackument(env: Env, src: Extract<Source, { kind: "upstream" }>, abbreviated: boolean, view: PackumentView | null): Record<string, unknown> {
  const base = `${env.ctx.baseUrl()}${view?.prefix ?? ""}`;
  const kept = view ? src.versions.filter(view.keep) : src.versions;
  const versions: Record<string, unknown> = {};
  const time: Record<string, string> = {};
  for (const v of kept) {
    const doc: Record<string, unknown> = { ...v.manifest, dist: { tarball: tarballUrl(base, src.name, v.version), shasum: v.shasum, integrity: v.integrity } };
    const r = reportFor(env.ctx, v);
    if (r) doc._apmScore = compact(r);
    if (abbreviated) {
      const slim: Record<string, unknown> = {};
      for (const k of ABBREV) if (k in doc) slim[k] = doc[k];
      slim.dist = doc.dist;
      versions[v.version] = slim;
    } else {
      versions[v.version] = doc;
    }
    if (v.published_at) time[v.version] = new Date(v.published_at).toISOString();
  }
  let distTags = { ...src.distTags };
  if (view) {
    const keptIds = kept.map((v) => v.version);
    const tags: Record<string, string> = {};
    for (const [t, v] of Object.entries(distTags)) if (keptIds.includes(v)) tags[t] = v;
    if (!tags.latest) {
      const h = highest(keptIds);
      if (h) tags.latest = h;
    }
    distTags = tags;
  }
  if (abbreviated) return { name: src.name, modified: new Date(env.ctx.now()).toISOString(), "dist-tags": distTags, versions };
  return { _id: src.name, name: src.name, description: src.pkg.description, "dist-tags": distTags, versions, time, readme: src.pkg.readme, maintainers: src.pkg.maintainers.map((name) => ({ name })) };
}

async function upstreamRoute(req: Request, url: URL, env: Env, viaSafe: boolean): Promise<Response | null> {
  if (!env.upstream || (req.method !== "GET" && req.method !== "HEAD")) return null;
  const p = url.pathname;
  if (p.startsWith("/-/")) return null;
  const sp = splitPath(p);
  if (!sp || env.ctx.store.getPackage(sp.name)) return null;
  const src = await lookup(env, sp.name);
  if (!src || src.kind !== "upstream") return null;
  if (sp.rest[0] === "-" && sp.rest[1]) {
    const m = /^(.*)-(\d+\.\d+\.\d+.*)\.tgz$/.exec(sp.rest[1]);
    const version = m?.[2];
    if (!version) return fail(404, "Not found");
    const got = await env.upstream.tarball(env.ctx, src.pkg, version);
    switch (got.kind) {
      case "absent":
        return fail(404, `${src.name}@${version} is not published upstream.`);
      case "unavailable":
        return fail(502, `Upstream tarball unavailable: ${got.reason}.`);
      case "ok":
        break;
      default: {
        const _exhaustive: never = got;
        return _exhaustive;
      }
    }
    const v = src.versions.find((x) => x.version === version);
    const analyzed = v ? await ensureAnalyzed(env, src, v) : null;

    if (viaSafe) {
      const block = analyzed ? policyBlock(env.ctx, analyzed, DEFAULT_POLICY) : "not listed upstream";

      if (block !== null) return fail(404, `${src.name}@${version} is not in this view: ${block}.`);
    }
    return new Response(got.bytes, { headers: { "content-type": "application/octet-stream" } });
  }
  if (sp.rest.length > 0) return null;
  const abbreviated = (req.headers.get("accept") ?? "").includes("application/vnd.npm.install-v1+json");
  if (viaSafe) {
    // score the newest cooled versions before answering; anything left unscored stays hidden
    const now = env.ctx.now();
    const cooled = src.versions
      .filter((v) => now - v.published_at >= DEFAULT_POLICY.cooldownMs)
      .sort((a, b) => Bun.semver.order(b.version, a.version))
      .slice(0, 5);
    for (const v of cooled) await ensureAnalyzed(env, src, v);
  }
  const body = upstreamPackument(env, src, abbreviated, viaSafe ? safeView(env.ctx) : null);
  return json(body, 200, { "content-type": abbreviated ? "application/vnd.npm.install-v1+json; charset=utf-8" : "application/json", "cache-control": "no-cache" });
}

// ---------- router ----------
function makeRoutes(env: Env, scoreOf: (v: VersionRecord) => unknown): NonNullable<Extensions["routes"]> {
  return async (req, url, ctx, auth) => {
    for (const v of ctx.store.matureRevocations(ctx.now() - PENDING_MS)) {
      ctx.store.addEvent({ package: v.package, kind: "revoke", actor: "registry", at: ctx.now(), detail: { version: v.version, reason: "pending revoke became final after 24h" } });
    }
    const p = url.pathname;
    if (p === "/-/npm/v1/security/advisories/bulk" && req.method === "POST") return bulkAdvisories(req, env);
    if (p === "/-/v1/search" && env.upstream && (req.method === "GET" || req.method === "HEAD")) return searchResponse(env, url, scoreOf);
    if (!p.startsWith("/-/apm/v1/")) {
      const viaSafe = new URL(req.url).pathname.startsWith("/~safe");
      return upstreamRoute(req, url, env, viaSafe);
    }
    const rest = p.slice("/-/apm/v1/".length);
    if (req.method === "POST") {
      if (rest === "yank" || rest === "unyank" || rest === "revoke" || rest === "restore") return handleState(req, ctx, auth, rest);
      if (rest === "incident") return handleIncident(req, ctx, auth);
      if (rest === "owners") return handleOwners(req, ctx, auth);

      if (rest === "scan") return scanResponse(req, env, auth);
      if (rest === "audit") return auditResponse(req, env);
    }
    if (req.method === "DELETE" && rest === "owners") return handleOwners(req, ctx, auth);
    if (req.method !== "GET") return fail(405, "Method not allowed");
    if (rest === "names") {
      const user = url.searchParams.get("user") ?? (auth.kind === "user" ? auth.user : null);
      const part = url.searchParams.get("part");
      if (part !== null && !isNamePart(part)) return fail(400, `part must be one of ${NAME_PARTS.join(", ")}`);
      return json(await nameReport(env, url.searchParams.get("q") ?? "", user, part));
    }
    if (rest === "recent") return recentResponse(ctx, url);
    if (rest === "resolve") return resolveResponse(env, url);
    if (rest === "me") return auth.kind === "user" ? json({ username: auth.user }) : fail(401, "Not logged in");
    if (rest.startsWith("score/")) {
      const sp = splitPath(`/${rest.slice("score/".length)}`);
      if (!sp) return fail(404, "Not found");
      const src = await lookup(env, sp.name);
      if (!src) return fail(404, "Not found");
      const spec = sp.rest[0];
      const version = spec ? (tagTarget(src.distTags, spec) ?? spec) : tagTarget(src.distTags, "latest");
      const v = src.versions.find((x) => x.version === version);
      if (!v) return fail(404, "No such version");
      return scoreResponse(env, src, v);
    }
    if (rest.startsWith("packages/")) {
      const sp = splitPath(`/${rest.slice("packages/".length)}`);
      if (!sp) return fail(404, "Not found");
      if (sp.rest[0] === "events") return eventsResponse(ctx, sp.name);
      if (sp.rest.length === 0) return packageResponse(env, sp.name);
    }
    return fail(404, "Not found");
  };
}

export function apmExtensions(ctx: Ctx, upstream: Upstream | null = null): Extensions {
  const env: Env = { ctx, upstream };
  const scoreOf = (v: VersionRecord): unknown => {
    const r = reportFor(ctx, v);
    return r ? compact(r) : null;
  };
  return { onPublish: makeOnPublish(env), routes: makeRoutes(env, scoreOf), safeView, compactScore: scoreOf, searchScore: scoreOf };
}
