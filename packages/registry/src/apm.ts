// apm extensions on top of the npm protocol: publish guards, scoring, version states,
// incident response, name search, the ~safe view, server-side resolve and the scan API.
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
  COOLDOWN_MS,
  SCORE_FLOOR,
  type ScoreReport,
  type TarEntry,
} from "@apm/core";
import type { VersionRecord } from "./db.ts";
import { fail, json, splitPath, highest, servedVersions, type Auth, type Ctx, type Extensions, type PublishHook, type PackumentView } from "./server.ts";

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

// ---------- publish guard ----------
const INSTALL_KEYS = ["preinstall", "install", "postinstall"] as const;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function stripDot(p: string): string {
  return p.replace(/^\.\//, "").replace(/^\//, "");
}

function entryPaths(manifest: Record<string, unknown>): { field: string; path: string }[] {
  const out: { field: string; path: string }[] = [];
  if (typeof manifest.main === "string") out.push({ field: "main", path: manifest.main });
  if (typeof manifest.types === "string") out.push({ field: "types", path: manifest.types });
  if (typeof manifest.typings === "string") out.push({ field: "typings", path: manifest.typings });
  if (typeof manifest.bin === "string") out.push({ field: "bin", path: manifest.bin });
  if (isRecord(manifest.bin)) for (const [k, v] of Object.entries(manifest.bin)) if (typeof v === "string") out.push({ field: `bin.${k}`, path: v });
  return out;
}

export function missingEntries(manifest: Record<string, unknown>, files: readonly { path: string }[]): { field: string; path: string }[] {
  const have = new Set(files.map((f) => f.path));
  return entryPaths(manifest).filter(({ path }) => {
    const p = stripDot(path);
    if (have.has(p)) return false;
    // node resolves "main": "lib" and "lib/index" as well
    return ![".js", ".json", ".node", "/index.js", "/index.json"].some((ext) => have.has(p + ext));
  });
}

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

/** Manifest confusion: the body must not hide what the tarball's package.json says. */
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

const onPublish: PublishHook = ({ ctx, name, version, manifest, tarball, user, existing }) => {
  let files: TarEntry[];
  try {
    files = readTarball(tarball);
  } catch {
    return { ok: false, status: 400, error: "The tarball is not a valid gzip'd tar." };
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
    const list = secrets.map((s) => s.detail).join("; ");
    return {
      ok: false,
      status: 422,
      error: `Refusing to publish: ${list}. Remove the file or add a "files" allowlist to package.json, then publish again. Rotate any key that was ever committed.`,
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
    // Blocking uses the popular-names list only; same-registry neighbours ("foo-a" next to "foo-b")
    // are normal and only shown as warnings in the name search.
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

  const previousPublishers = existing ? [...new Set(ctx.store.listVersions(name).map((v) => v.published_by))] : [];
  const analysis = analyze({ name, manifest: tarManifest, files, publisher: user, previousPublishers });
  const served: Record<string, unknown> = { ...tarManifest };
  if (typeof manifest.readme === "string") served.readme = manifest.readme;
  return { ok: true, manifest: served, score: analysis };
};

/** Existing local packages one edit away (not counting the package itself). */
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

function revokeVersion(ctx: Ctx, name: string, version: string, actor: string, reason: string): void {
  const at = ctx.now();
  ctx.store.setStatus(name, version, { status: "revoked", reason, at, by: actor });
  ctx.store.addAdvisory({
    package: name,
    versions: [version],
    severity: "critical",
    title: `${name}@${version} was revoked: ${reason}`,
    detail: reason,
    created_at: at,
    created_by: actor,
  });
  moveTagsOff(ctx, name, version);
  ctx.store.addEvent({ package: name, kind: "revoke", actor, at, detail: { version, reason } });
}

const StateBody = z.object({ name: z.string(), version: z.string(), reason: z.string().optional() });
// `since` is exclusive: pass the time of the last publish you trust.
const IncidentBody = z.object({ since: z.string(), reason: z.string().optional() });
const OwnerBody = z.object({ name: z.string(), user: z.string() });

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

function requireOwner(ctx: Ctx, auth: Auth, name: string): Response | { user: string } {
  if (auth.kind !== "user") return fail(401, "Log in first (apm login).");
  if (!ctx.store.getPackage(name)) return fail(404, `No package named ${name}.`);
  if (!ctx.store.owners(name).includes(auth.user)) return fail(403, `Only owners of ${name} can do this. Owners: ${ctx.store.owners(name).join(", ")}`);
  return { user: auth.user };
}

async function handleState(req: Request, ctx: Ctx, auth: Auth, action: "yank" | "unyank" | "revoke"): Promise<Response> {
  const parsed = await parseBody(req, StateBody);
  if (!parsed.ok) return parsed.res;
  const { name, version, reason } = parsed.value;
  const who = requireOwner(ctx, auth, name);
  if (who instanceof Response) return who;
  const v = ctx.store.getVersion(name, version);
  if (!v) return fail(404, `No version ${name}@${version}.`);
  const at = ctx.now();
  if (action === "revoke") {
    if (v.status === "revoked") return json({ ok: true, already: true });
    if (!reason) return fail(400, "A reason is required to revoke; it is shown to everyone who has this version installed.");
    revokeVersion(ctx, name, version, who.user, reason);
    return json({ ok: true, name, version, status: "revoked" });
  }
  if (action === "yank") {
    if (v.status === "revoked") return fail(409, "This version is revoked, which is stronger than a yank.");
    ctx.store.setStatus(name, version, { status: "yanked", reason: reason ?? null, at, by: who.user });
    moveTagsOff(ctx, name, version);
    ctx.store.addEvent({ package: name, kind: "yank", actor: who.user, at, detail: { version, reason: reason ?? null } });
    return json({ ok: true, name, version, status: "yanked" });
  }
  if (v.status !== "yanked") return fail(409, `${name}@${version} is ${v.status}, not yanked.`);
  ctx.store.setStatus(name, version, { status: "active", reason: null, at, by: who.user });
  const pkg = ctx.store.getPackage(name);
  if (pkg) {
    const tags = { ...pkg.distTags };
    const latest = tags.latest;
    if (!version.includes("-") && (!latest || Bun.semver.order(version, latest) > 0)) tags.latest = version;
    ctx.store.setDistTags(name, tags, at);
  }
  ctx.store.addEvent({ package: name, kind: "unyank", actor: who.user, at, detail: { version } });
  return json({ ok: true, name, version, status: "active" });
}

async function handleIncident(req: Request, ctx: Ctx, auth: Auth): Promise<Response> {
  if (auth.kind !== "user") return fail(401, "Log in first.");
  const parsed = await parseBody(req, IncidentBody);
  if (!parsed.ok) return parsed.res;
  const since = Date.parse(parsed.value.since);
  if (Number.isNaN(since)) return fail(400, "since must be an ISO timestamp");
  const reason = parsed.value.reason ?? "account compromised";
  const user = auth.user;
  const revoked: string[] = [];
  ctx.store.tx(() => {
    for (const name of ctx.store.listPackageNames()) {
      for (const v of ctx.store.listVersions(name)) {
        if (v.published_by === user && v.published_at > since && v.status !== "revoked") {
          revokeVersion(ctx, name, v.version, user, `incident: ${reason}`);
          revoked.push(`${name}@${v.version}`);
        }
      }
    }
  });
  const tokensRevoked = ctx.store.revokeTokensOf(user, ctx.now());
  return json({ ok: true, user, since: new Date(since).toISOString(), revoked, tokensRevoked, next: "Log in again with apm login, then check each package's event log." });
}

async function handleOwners(req: Request, ctx: Ctx, auth: Auth): Promise<Response> {
  const parsed = await parseBody(req, OwnerBody);
  if (!parsed.ok) return parsed.res;
  const who = requireOwner(ctx, auth, parsed.value.name);
  if (who instanceof Response) return who;
  if (!ctx.store.getUser(parsed.value.user)) return fail(404, `No user ${parsed.value.user}.`);
  const remove = req.method === "DELETE";
  if (remove) ctx.store.removeOwner(parsed.value.name, parsed.value.user);
  else ctx.store.addOwner(parsed.value.name, parsed.value.user);
  ctx.store.addEvent({ package: parsed.value.name, kind: remove ? "owner-remove" : "owner-add", actor: who.user, at: ctx.now(), detail: { user: parsed.value.user } });
  return json({ ok: true, owners: ctx.store.owners(parsed.value.name) });
}

// ---------- read APIs ----------
function previousOf(ctx: Ctx, v: VersionRecord): VersionRecord | null {
  const all = ctx.store.listVersions(v.package).filter((x) => x.version !== v.version && x.published_at <= v.published_at && x.status !== "revoked");
  return all[all.length - 1] ?? null;
}

function scoreResponse(ctx: Ctx, v: VersionRecord): Response {
  const report = reportFor(ctx, v);
  if (!report) return fail(404, "No score for this version.");
  const prev = previousOf(ctx, v);
  const prevReport = prev ? reportFor(ctx, prev, { ignoreRecent: true }) : null;
  return json({
    name: v.package,
    version: v.version,
    status: v.status,
    publishedAt: new Date(v.published_at).toISOString(),
    publishedBy: v.published_by,
    ...report,
    previous: prev && prevReport ? { version: prev.version, score: prevReport.score, grade: prevReport.grade } : null,
    changes: prev && prevReport ? signalChanges(prevReport.signals, report.signals) : [],
  });
}

function packageResponse(ctx: Ctx, name: string): Response {
  const pkg = ctx.store.getPackage(name);
  if (!pkg) return fail(404, "Not found");
  const versions = ctx.store.listVersions(name);
  const latest = versions.find((v) => v.version === pkg.distTags.latest) ?? null;
  const latestReport = latest ? reportFor(ctx, latest) : null;
  return json({
    name,
    description: pkg.description,
    keywords: pkg.keywords,
    readme: pkg.readme,
    distTags: pkg.distTags,
    maintainers: ctx.store.owners(name),
    createdAt: new Date(pkg.created_at).toISOString(),
    modifiedAt: new Date(pkg.modified_at).toISOString(),
    latest: latest?.version ?? null,
    facts: latestReport?.facts ?? null,
    score: latestReport ? { score: latestReport.score, grade: latestReport.grade, signals: latestReport.signals } : null,
    versions: [...versions]
      .sort((a, b) => Bun.semver.order(b.version, a.version))
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

export function nameReport(ctx: Ctx, q: string, user: string | null): Record<string, unknown> {
  const query = q.trim().toLowerCase();
  const valid = isValidPackageName(query);
  const existing = valid ? ctx.store.getPackage(query) : null;
  const conflicts = valid && !existing ? typoConflicts(query) : [];
  const similar = valid ? registryNeighbours(ctx, query) : [];
  const bare = query.startsWith("@") ? query.slice(query.indexOf("/") + 1) : query;
  const candidates = [
    ...(user ? [`@${user}/${bare}`] : []),
    `${bare}-js`,
    `${bare}js`,
    `use-${bare}`,
    `${bare}-kit`,
    `${bare}-core`,
  ].filter((c) => c !== query);
  const suggestions = candidates
    .filter((c) => isValidPackageName(c))
    .map((c) => {
      const taken = ctx.store.getPackage(c) !== null;
      const cc = taken ? [] : typoConflicts(c);
      return { name: c, available: !taken && cc.length === 0, taken };
    });
  const latest = existing ? ctx.store.getVersion(query, existing.distTags.latest ?? "") : null;
  const latestReport = latest ? reportFor(ctx, latest) : null;
  return {
    query,
    valid,
    taken: existing !== null,
    available: valid && existing === null && conflicts.length === 0,
    owners: existing ? ctx.store.owners(query) : [],
    latest: latest ? { version: latest.version, score: latestReport?.score ?? null, grade: latestReport?.grade ?? null } : null,
    description: existing?.description ?? null,
    conflicts,
    similar,
    suggestions,
  };
}

// ---------- policy: ~safe view, resolve, scan ----------
export type Policy = { cooldownMs: number; floor: number };
export const DEFAULT_POLICY: Policy = { cooldownMs: COOLDOWN_MS, floor: SCORE_FLOOR };

/** Why a version fails the policy, or null when it passes. */
export function policyBlock(ctx: Ctx, v: VersionRecord, policy: Policy): string | null {
  if (v.status === "revoked") return `revoked: ${v.status_reason ?? "no reason given"}`;
  if (v.status === "yanked") return `yanked${v.status_reason ? `: ${v.status_reason}` : ""}`;
  const age = ctx.now() - v.published_at;
  if (age < policy.cooldownMs) return `published ${Math.floor(age / 3_600_000)}h ago (cooldown ${Math.round(policy.cooldownMs / 3_600_000)}h)`;
  const r = reportFor(ctx, v, { ignoreRecent: true });
  if (r && r.score < policy.floor) {
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
  const mult = unit === "ms" ? 1 : unit === "s" ? 1000 : unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
  return n * mult;
}

function resolveResponse(ctx: Ctx, url: URL): Response {
  const name = url.searchParams.get("name") ?? "";
  const range = url.searchParams.get("range") || "latest";
  const policy: Policy = {
    cooldownMs: parseDuration(url.searchParams.get("cooldown"), DEFAULT_POLICY.cooldownMs),
    floor: Number(url.searchParams.get("floor") ?? DEFAULT_POLICY.floor),
  };
  const pkg = ctx.store.getPackage(name);
  if (!pkg) return fail(404, `No package named ${name}.`);
  const all = ctx.store.listVersions(name);
  const tagged = pkg.distTags[range];
  const matches = all
    .filter((v) => (tagged ? Bun.semver.order(v.version, tagged) <= 0 && !v.version.includes("-") : v.version === range || Bun.semver.satisfies(v.version, range)))
    .sort((a, b) => Bun.semver.order(b.version, a.version));
  const skipped: { version: string; reason: string }[] = [];
  for (const v of matches) {
    const block = policyBlock(ctx, v, policy);
    if (block === null) {
      const report = reportFor(ctx, v);
      return json({ name, range, version: v.version, report, skipped, policy: { cooldownHours: policy.cooldownMs / 3_600_000, floor: policy.floor } });
    }
    skipped.push({ version: v.version, reason: block });
  }
  return json({ error: `No version of ${name} matching ${range} passes the policy.`, name, range, version: null, skipped }, 422);
}

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })) });

async function scanResponse(req: Request, ctx: Ctx): Promise<Response> {
  const parsed = await parseBody(req, ScanBody);
  if (!parsed.ok) return parsed.res;
  const advisories: { package: string; version: string; level: "fatal" | "warn"; description: string; url: string | null }[] = [];
  for (const p of parsed.value.packages) {
    const v = ctx.store.getVersion(p.name, p.version);
    if (!v) continue;
    const url = `${ctx.baseUrl()}package/${p.name}`;
    if (v.status === "revoked") {
      advisories.push({ package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version} was revoked by its maintainer: ${v.status_reason ?? "no reason given"}`, url });
      continue;
    }
    const r = reportFor(ctx, v, { ignoreRecent: true });
    if (r && r.score < SCORE_FLOOR) {
      const why = r.signals.filter((s) => s.points < 0).map((s) => s.id).join(", ");
      advisories.push({ package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version} has apm score ${r.score}/100 (${why}). Review it, then allow it with apm add ${p.name} --force.`, url });
    }
  }
  return json({ advisories });
}

async function bulkAdvisories(req: Request, ctx: Ctx): Promise<Response> {
  let body: unknown;
  try {
    body = await readJson(req);
  } catch {
    return fail(400, "Invalid body");
  }
  const parsed = z.record(z.string(), z.array(z.string())).safeParse(body);
  if (!parsed.success) return fail(400, "Expected { name: [versions] }");
  const out: Record<string, unknown[]> = {};
  for (const name of Object.keys(parsed.data)) {
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
  return json(out);
}

// ---------- router ----------
async function routes(req: Request, url: URL, ctx: Ctx, auth: Auth): Promise<Response | null> {
  const p = url.pathname;
  if (p === "/-/npm/v1/security/advisories/bulk" && req.method === "POST") return bulkAdvisories(req, ctx);
  if (!p.startsWith("/-/apm/v1/")) return null;
  const rest = p.slice("/-/apm/v1/".length);
  if (req.method === "POST") {
    if (rest === "yank" || rest === "unyank" || rest === "revoke") return handleState(req, ctx, auth, rest);
    if (rest === "incident") return handleIncident(req, ctx, auth);
    if (rest === "owners") return handleOwners(req, ctx, auth);
    if (rest === "scan") return scanResponse(req, ctx);
  }
  if (req.method === "DELETE" && rest === "owners") return handleOwners(req, ctx, auth);
  if (req.method !== "GET") return fail(405, "Method not allowed");
  if (rest === "names") {
    const user = url.searchParams.get("user") ?? (auth.kind === "user" ? auth.user : null);
    return json(nameReport(ctx, url.searchParams.get("q") ?? "", user));
  }
  if (rest === "resolve") return resolveResponse(ctx, url);
  if (rest === "me") return auth.kind === "user" ? json({ username: auth.user, tokenHash: auth.tokenHash.slice(0, 8) }) : fail(401, "Not logged in");
  if (rest.startsWith("score/")) {
    const sp = splitPath(`/${rest.slice("score/".length)}`);
    if (!sp) return fail(404, "Not found");
    const spec = sp.rest[0];
    const pkg = ctx.store.getPackage(sp.name);
    if (!pkg) return fail(404, "Not found");
    const version = spec ? (pkg.distTags[spec] ?? spec) : pkg.distTags.latest;
    const v = version ? ctx.store.getVersion(sp.name, version) : null;
    if (!v) return fail(404, "No such version");
    return scoreResponse(ctx, v);
  }
  if (rest.startsWith("packages/")) {
    const sp = splitPath(`/${rest.slice("packages/".length)}`);
    if (!sp) return fail(404, "Not found");
    if (sp.rest[0] === "events") return eventsResponse(ctx, sp.name);
    if (sp.rest.length === 0) return packageResponse(ctx, sp.name);
  }
  return fail(404, "Not found");
}

export function apmExtensions(ctx: Ctx): Extensions {
  const scoreOf = (v: VersionRecord): unknown => {
    const r = reportFor(ctx, v);
    return r ? compact(r) : null;
  };
  return { onPublish, routes, safeView, compactScore: scoreOf, searchScore: scoreOf };
}

