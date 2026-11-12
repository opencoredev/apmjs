// apm extensions on top of the npm protocol: publish guards, scoring, version states,
// incident response, name search, the ~safe view, server-side resolve, the scan API and
// the upstream proxy.
import { gunzipSync } from "node:zlib";
import { z } from "zod";
import {
  analyze,
  finalize,
  findSecrets,
  isAnalysis,
  readTarball,
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
  type ScoreReport,
  type TarEntry,
} from "@apm/core";
import type { VersionRecord } from "./db.ts";
import { fail, json, splitPath, highest, servedVersions, tarballUrl, searchPaging, localSearchObjects, type Auth, type Ctx, type Extensions, type PublishHook, type PackumentView } from "./server.ts";
import type { Upstream, UpstreamPackage } from "./upstream.ts";

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
  if (!isAnalysis(v.score)) return null;
  return finalize(v.score, {
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
  if (src.kind === "local" || isAnalysis(v.score) || !env.upstream) return v;
  const bytes = await env.upstream.tarball(env.ctx, src.pkg, v.version);
  if (!bytes) return v;
  let files: TarEntry[];
  try {
    files = readTarball(bytes);
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
  env.ctx.store.setUpstreamAnalysis(src.name, v.version, analysis);
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

/** Dependencies of a manifest whose best matching version scores below the floor. */
async function riskyDependencies(env: Env, manifest: Record<string, unknown>): Promise<DependencyRisk[]> {
  const out: DependencyRisk[] = [];
  const deps = { ...(isRecord(manifest.dependencies) ? manifest.dependencies : {}), ...(isRecord(manifest.optionalDependencies) ? manifest.optionalDependencies : {}) };
  for (const [dep, rangeRaw] of Object.entries(deps).slice(0, 25)) {
    const range = typeof rangeRaw === "string" ? rangeRaw : "*";
    const src = await lookup(env, dep);
    if (!src) continue;
    const candidates = src.versions
      .filter((v) => v.status !== "revoked" && Bun.semver.satisfies(v.version, range))
      .sort((a, b) => Bun.semver.order(b.version, a.version));
    const best = candidates[0];
    if (!best) continue;
    const analyzed = await ensureAnalyzed(env, src, best);
    const r = reportFor(env.ctx, analyzed, { ignoreRecent: true });
    if (r && r.score < SCORE_FLOOR) out.push({ name: dep, version: best.version, score: r.score });
  }
  return out;
}

function makeOnPublish(env: Env): PublishHook {
  return async ({ ctx, name, version, manifest, tarball, user, existing }) => {
    let files: TarEntry[];
    try {
      files = readTarball(tarball);
    } catch {
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
    if (secrets.length > 0) {
      return {
        ok: false,
        status: 422,
        error: `Refusing to publish: ${secrets.map((s) => s.detail).join("; ")}. Remove the file or add a "files" allowlist to package.json, then publish again. Rotate any key that was ever committed.`,
        detail: secrets,
      };
    }

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
        if (probe.kind === "unknown" && !name.startsWith("@")) {
          return { ok: false, status: 503, error: `Cannot check whether "${name}" exists on the public registry right now, so a first publish of this name is refused. Try again shortly, or publish under your scope (@${user}/${name}).` };
        }
      }
      const conflicts = typoConflicts(name);
      if (conflicts.length > 0) {
        return {
          ok: false,
          status: 422,
          error: `Refusing to publish "${name}": ${conflicts.map((c) => c.reason).join("; ")}. Names this close are how typosquatting works. Pick a more distinct name or publish under your scope (@${user}/${name}).`,
          detail: conflicts,
        };
      }
    }

    const previous = existing ? ctx.store.listVersions(name) : [];
    const previousPublishers = [...new Set(previous.map((v) => v.published_by))];
    const last = previous[previous.length - 1];
    const prevDeps = last ? new Set(dependencyNames(last.manifest)) : null;
    const addedDependencies = prevDeps ? dependencyNames(tarManifest).filter((d) => !prevDeps.has(d)) : [];
    const risky = await riskyDependencies(env, tarManifest);
    const analysis = analyze({ name, manifest: tarManifest, files, publisher: user, previousPublishers, riskyDependencies: risky, addedDependencies });
    const served: Record<string, unknown> = { ...tarManifest };
    if (typeof manifest.readme === "string") served.readme = manifest.readme;
    return { ok: true, manifest: served, score: analysis };
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
const StateBody = z.object({ name: z.string(), version: z.string(), reason: z.string().optional(), password: Password });
const IncidentBody = z.object({ since: z.string(), reason: z.string().optional(), password: Password, dryRun: z.boolean().optional() });
const OwnerBody = z.object({ name: z.string(), user: z.string(), password: Password });

async function readJson(req: Request): Promise<unknown> {
  const enc = req.headers.get("content-encoding") ?? "";
  const buf = new Uint8Array(await req.arrayBuffer());
  const raw = enc.includes("gzip") || (buf[0] === 0x1f && buf[1] === 0x8b) ? new Uint8Array(gunzipSync(buf)) : buf;
  return JSON.parse(new TextDecoder().decode(raw));
}

type Parsed<T> = { ok: true; value: T } | { ok: false; res: Response };
async function parseBody<T>(req: Request, schema: z.ZodType<T>): Promise<Parsed<T>> {
  try {
    return { ok: true, value: schema.parse(await readJson(req)) };
  } catch (e) {
    return { ok: false, res: fail(400, `Invalid request body: ${e instanceof Error ? e.message : String(e)}`) };
  }
}

/** Destructive actions need the account password on top of the bearer token. */
async function reauth(ctx: Ctx, auth: Auth, password: string | undefined): Promise<Response | { user: string }> {
  if (auth.kind !== "user") return fail(401, "Log in first (apm login).");
  if (!password) return fail(401, "This action needs your account password as well as a token (apm asks for it; agents pass --password-stdin). A stolen publish token alone cannot revoke.");
  const u = ctx.store.getUser(auth.user);
  if (!u || !(await Bun.password.verify(password, u.password_hash))) return fail(401, "Incorrect password.");
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
  const { name, version, reason, password } = parsed.value;
  let user: string;
  if (action === "revoke" || action === "restore") {
    const who = await reauth(ctx, auth, password);
    if (who instanceof Response) return who;
    user = who.user;
  } else {
    if (auth.kind !== "user") return fail(401, "Log in first (apm login).");
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
  const who = await reauth(ctx, auth, parsed.value.password);
  if (who instanceof Response) return who;
  // `since` is exclusive: pass the time of the last publish you trust.
  const since = Date.parse(parsed.value.since);
  if (Number.isNaN(since)) return fail(400, "since must be an ISO timestamp");
  if (ctx.now() - since > INCIDENT_WINDOW_MS) return fail(400, "Incident response reaches back at most 30 days. Revoke older versions one by one (apm revoke).");
  const reason = parsed.value.reason ?? "account compromised";
  const user = who.user;
  const targets: VersionRecord[] = [];
  for (const name of ctx.store.listPackageNames()) {
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
  return json({ ok: true, user, since: new Date(since).toISOString(), revoked: ids, statuses, tokensRevoked, next: "Every token is revoked. Change your password, log in again with apm login, then read each package's event log." });
}

async function handleOwners(req: Request, ctx: Ctx, auth: Auth): Promise<Response> {
  const parsed = await parseBody(req, OwnerBody);
  if (!parsed.ok) return parsed.res;
  const who = await reauth(ctx, auth, parsed.value.password);
  if (who instanceof Response) return who;
  const denied = requireOwner(ctx, who.user, parsed.value.name);
  if (denied) return denied;
  if (!ctx.store.getUser(parsed.value.user)) return fail(404, `No user ${parsed.value.user}.`);
  const remove = req.method === "DELETE";
  if (remove) ctx.store.removeOwner(parsed.value.name, parsed.value.user);
  else ctx.store.addOwner(parsed.value.name, parsed.value.user);
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
  const analysis = ctx.store.getUpstreamAnalysis(name, version);
  if (!isAnalysis(analysis)) return null;
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
  const up = env.upstream && text.trim() !== "" ? await env.upstream.search(text.trim(), Math.min(250, from + size)) : null;
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

function safeView(ctx: Ctx): PackumentView {
  return { keep: (v) => policyBlock(ctx, v, DEFAULT_POLICY) === null };
}

function parseDuration(s: string | null, fallback: number): number {
  if (!s) return fallback;
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/.exec(s.trim());
  if (!m) return fallback;
  const n = Number(m[1]);
  const unit = m[2] ?? "h";
  const mult = unit === "ms" ? 1 : unit === "s" ? 1000 : unit === "m" ? 60_000 : unit === "h" ? HOUR : DAY;
  return n * mult;
}

type TreeBlock = { name: string; version: string; reason: string; via: string[] };

/**
 * Walks the dependency tree the package manager would install (newest active version matching each
 * range) and returns the versions that are revoked or score below the floor. Bounded: at most
 * `maxNodes` packages and `maxAnalyses` tarball analyses; the rest is reported as unchecked.
 */
async function treeBlocks(env: Env, root: VersionRecord, floor: number, limits = { maxNodes: 300, maxAnalyses: 40 }): Promise<{ blocks: TreeBlock[]; unchecked: number }> {
  const blocks: TreeBlock[] = [];
  const seen = new Set<string>();
  let analyses = 0;
  let unchecked = 0;
  const queue: { name: string; range: string; via: string[] }[] = dependencyEntries(root.manifest).map(([name, range]) => ({ name, range, via: [`${root.package}@${root.version}`] }));
  while (queue.length > 0) {
    const item = queue.shift();
    if (!item) break;
    if (seen.size >= limits.maxNodes) {
      unchecked += queue.length + 1;
      break;
    }
    const src = await lookup(env, item.name);
    if (!src) continue;
    // what the package manager would pick: the newest active version in range (pulled versions are hidden)
    const pick = src.versions
      .filter((v) => v.status === "active" && Bun.semver.satisfies(v.version, item.range))
      .sort((a, b) => Bun.semver.order(b.version, a.version))[0] ?? null;
    if (!pick) continue;
    const key = `${item.name}@${pick.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let v = pick;
    if (!isAnalysis(v.score)) {
      if (analyses < limits.maxAnalyses) {
        analyses++;
        v = await ensureAnalyzed(env, src, v);
      }
    }
    const r = reportFor(env.ctx, v, { ignoreRecent: true });
    if (!r) unchecked++;
    else if (r.score < floor) blocks.push({ name: item.name, version: v.version, reason: `score ${r.score}/100 (${r.signals.filter((s) => s.points < 0).map((s) => s.id).join(", ")})`, via: item.via });
    if (item.via.length < 12) for (const [n, range] of dependencyEntries(v.manifest)) queue.push({ name: n, range, via: [...item.via, key] });
  }
  return { blocks, unchecked };
}

function dependencyEntries(manifest: Record<string, unknown>): [string, string][] {
  const out: [string, string][] = [];
  for (const k of ["dependencies", "optionalDependencies"] as const) {
    const d = manifest[k];
    if (isRecord(d)) for (const [n, r] of Object.entries(d)) if (typeof r === "string") out.push([n, r]);
  }
  return out;
}

async function resolveResponse(env: Env, url: URL): Promise<Response> {
  const ctx = env.ctx;
  const name = url.searchParams.get("name") ?? "";
  const range = url.searchParams.get("range") || "latest";
  const policy: Policy = {
    cooldownMs: parseDuration(url.searchParams.get("cooldown"), DEFAULT_POLICY.cooldownMs),
    floor: Number(url.searchParams.get("floor") ?? DEFAULT_POLICY.floor),
  };
  const src = await lookup(env, name);
  if (!src) return fail(404, `No package named ${name}.`);
  const tagged = src.distTags[range];
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
      const tree = policy.floor > 0 ? await treeBlocks(env, v, policy.floor) : { blocks: [], unchecked: 0 };
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

async function scanResponse(req: Request, env: Env): Promise<Response> {
  const ctx = env.ctx;
  const parsed = await parseBody(req, ScanBody);
  if (!parsed.ok) return parsed.res;
  const advisories: { package: string; version: string; level: "fatal" | "warn"; description: string; url: string | null }[] = [];
  for (const p of parsed.value.packages.slice(0, 2000)) {
    const src = await lookup(env, p.name);
    const v0 = src?.versions.find((x) => x.version === p.version);
    if (!src || !v0) continue;
    const url = `${ctx.baseUrl()}package/${p.name}`;
    if (v0.status === "revoked" || v0.status === "revoke-pending") {
      advisories.push({ package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version} was revoked by its maintainer: ${v0.status_reason ?? "no reason given"}`, url });
      continue;
    }
    const v = await ensureAnalyzed(env, src, v0);
    const r = reportFor(ctx, v, { ignoreRecent: true });
    if (r && r.score < SCORE_FLOOR) {
      const why = r.signals.filter((s) => s.points < 0).map((s) => s.id).join(", ");
      advisories.push({ package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version} has apm score ${r.score}/100 (${why}). Review it, then allow it with apm add ${p.name} --force.`, url });
    }
  }
  return json({ advisories });
}

async function bulkAdvisories(req: Request, env: Env): Promise<Response> {
  const ctx = env.ctx;
  let body: unknown;
  try {
    body = await readJson(req);
  } catch {
    return fail(400, "Invalid body");
  }
  const parsed = z.record(z.string(), z.array(z.string())).safeParse(body);
  if (!parsed.success) return fail(400, "Expected { name: [versions] }");
  const out: Record<string, unknown[]> = {};
  const upstreamQuery: Record<string, string[]> = {};
  for (const [name, versions] of Object.entries(parsed.data)) {
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
    for (const [name, list] of Object.entries(up)) out[name] = [...(out[name] ?? []), ...list];
  }
  return json(out);
}

// ---------- upstream packuments and tarballs ----------
const ABBREV = ["name", "version", "dependencies", "optionalDependencies", "devDependencies", "bundleDependencies", "peerDependencies", "peerDependenciesMeta", "bin", "directories", "engines", "os", "cpu", "libc", "_hasShrinkwrap", "hasInstallScript", "deprecated"];

function upstreamPackument(env: Env, src: Extract<Source, { kind: "upstream" }>, abbreviated: boolean, view: PackumentView | null): Record<string, unknown> {
  const base = env.ctx.baseUrl();
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
    const bytes = await env.upstream.tarball(env.ctx, src.pkg, version);
    if (!bytes) return fail(502, "Upstream tarball unavailable or failed its integrity check.");
    const v = src.versions.find((x) => x.version === version);
    if (v) await ensureAnalyzed(env, src, v);
    return new Response(bytes, { headers: { "content-type": "application/octet-stream" } });
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
      if (rest === "scan") return scanResponse(req, env);
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
      const version = spec ? (src.distTags[spec] ?? spec) : src.distTags.latest;
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
