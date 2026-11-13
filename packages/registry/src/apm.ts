// apm extensions on top of the npm protocol: publish guards, scoring, version states,
// incident response, name search, the ~safe view, server-side resolve, the scan API and
// the upstream proxy.
import { Context, Effect, Option } from "effect";
import { z } from "zod";
import {
  analyze,
  ArchiveError,
  dependencySpecs,
  describeDependency,
  describeSkip,
  finalize,
  findSecrets,
  Meter,
  MeterExhausted,
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
  type SecretScan,
  type TarEntry,
  servableManifest,
} from "@apm/core";
import { liveChangeRefusal, secondFactor } from "./access.ts";
import { canonicalSince, type LiveAction } from "./actions.ts";
import { Analysis, WORKER_MAX_UNPACKED_BYTES } from "./analysis.ts";
import { Auth } from "./auth.ts";
import { Blobs } from "./blobs.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig } from "./config.ts";
import { digestLabel, digestOf } from "./digest.ts";
import { Store, type PackageRecord, type Unscorable, type VersionRecord } from "./db.ts";
import { refuse, type HttpFailure } from "./errors.ts";
import { fail, json, parseBody } from "./http.ts";
import { atTime, DAY, FRESH_MS, PENDING_MS, transition } from "./lifecycle.ts";
import { newestFirst, order, satisfies } from "./semver.ts";
import {
  highest,
  localSearchObjects,
  lockOwned,
  MAX_MANIFEST_BYTES,
  requireUser,
  searchPaging,
  servedVersions,
  splitPath,
  tagTarget,
  tarballUrl,
  versionOf,
  versionsOf,
  type Caller,
  type CompactScore,
  type Extensions,
  type PackumentView,
  type PublishHook,
} from "./server.ts";
import { ReviewConfig, reviewStandings } from "./review.ts";
import { scoreWarning, stateWarning, UNAVAILABLE_TEXT, versionUrl, warningLines, type InstallWarning } from "./warnings.ts";
import { tooLargeText, Upstream, type Probe, type UpstreamPackage } from "./upstream.ts";
import {
  eventDetailShown,
  fileReferences,
  isWithheld,
  StoredEventDetail,
  packageTextShown,
  readmeShown,
  withheldCapability,
  withheldDismissals,
  withheldFacts,
  withheldLimitations,
  withheldSignal,
  withheldSkipped,
} from "./withheld.ts";

const HOUR = 3_600_000;

/** Incident response can reach back at most this far. */
const INCIDENT_WINDOW_MS = 30 * DAY;

const upstreamOrNull = Effect.map(Effect.serviceOption(Upstream), Option.getOrNull);
const now = Effect.flatMap(Clock, (c) => c.now);

// ---------- scoring helpers ----------
export function reportFor(v: VersionRecord, at: number, opts: { ignoreRecent?: boolean } = {}): ScoreReport | null {
  const analysis = parseAnalysis(v.score);

  if (!analysis) return null;

  return finalize(analysis, {
    publishedAt: opts.ignoreRecent ? Number.NEGATIVE_INFINITY : v.published_at,
    now: at,
    deprecated: v.deprecated,
    status: v.status,
    statusReason: v.status_reason,
  });
}

/**
 * What a page needs to name one evidence item for a reviewer's dismissal (the scorer and these bytes' digest), the
 * items already dismissed, and the signals without the evidence kept only for dismissals. A withheld version's signals
 * and dismissed items are rebuilt from allowed fields (withheld.ts), so none of its evidence lines is sent.
 */
function reviewable(v: VersionRecord, r: ScoreReport) {
  const d = digestOf(v);
  const head = { scorer: r.scorer, digest: d ? digestLabel(d) : null };

  if (isWithheld(v.status)) return { ...head, redacted: true, signals: r.signals.map(withheldSignal), dismissed: withheldDismissals(r.dismissed ?? [], scoreFileRefs(r)) };
  const signals = r.signals.map(({ more: _more, fallback: _fallback, uncounted: _uncounted, sources: _sources, ...s }) => s);

  return { ...head, redacted: false, signals, dismissed: r.dismissed ?? [] };
}

/**
 * A withheld version's file references in its score answer: one numbering for the dismissed items' files and the files
 * the score did not read, so "file 2" is one file wherever the answer says it (withheld.ts).
 */
function scoreFileRefs(r: ScoreReport) {
  return fileReferences([...(r.dismissed ?? []).map((d) => d.file), ...r.skipped.map((k) => k.path)]);
}

/**
 * The parts of a score report that do not quote the package's code: numbers, enums, paths and the not-checked list.
 * A stored not-checked entry and the license can carry manifest text (a dependency's URL, the license string), so a
 * withheld version's are rebuilt from fixed wording and structured fields, and its paths are references (withheld.ts).
 */
function sourceFreeReport(v: VersionRecord, r: ScoreReport) {
  const withheld = isWithheld(v.status);

  return {
    score: r.score,
    grade: r.grade,
    facts: withheld ? withheldFacts(r.facts) : r.facts,
    notChecked: withheld ? withheldLimitations(r.notChecked, v.manifest) : r.notChecked,
    skipped: withheld ? withheldSkipped(r.skipped, scoreFileRefs(r)) : r.skipped.map((k) => ({ path: k.path, size: k.size, reason: k.reason })),
    // a capability's evidence, variable names and declared text quote the package; a withheld version keeps only kinds
    capabilities: withheld ? r.capabilities.map(withheldCapability) : r.capabilities,
    declaration: r.declaration ? (withheld ? { kind: r.declaration.kind, notes: [] } : r.declaration) : null,
  };
}

/**
 * A score report inside another answer (resolve). A shown version's is sent whole, as the CLI reads it; a withheld
 * version's is the score answer's own allowlist, so neither its evidence nor its manifest text goes out.
 */
function embeddedReport(v: VersionRecord, r: ScoreReport | null) {
  if (!r) return null;

  return isWithheld(v.status) ? { ...sourceFreeReport(v, r), ...reviewable(v, r) } : r;
}

function compact(r: ScoreReport): CompactScore {
  return { score: r.score, grade: r.grade, signals: r.signals.map((s) => s.id) };
}

export function compactScore(v: VersionRecord, at: number): CompactScore | null {
  const r = reportFor(v, at);

  return r ? compact(r) : null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ---------- catalog: local or upstream ----------
type Source =
  | { kind: "local"; name: string; distTags: Record<string, string>; versions: VersionRecord[]; pkg: PackageRecord }
  | { kind: "upstream"; name: string; distTags: Record<string, string>; versions: VersionRecord[]; pkg: UpstreamPackage };

const localSource = (pkg: PackageRecord, versions: VersionRecord[]): Source => ({ kind: "local", name: pkg.name, distTags: pkg.distTags, versions, pkg });
const upstreamSource = (pkg: UpstreamPackage): Source => ({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: pkg.versions, pkg });

const lookup = (name: string) =>
  Effect.gen(function* () {
    const pkg = yield* (yield* Store).getPackage(name);

    if (pkg) return localSource(pkg, yield* versionsOf(name));
    const upstream = yield* upstreamOrNull;

    if (!upstream) return null;
    const up = yield* upstream.get(name);

    if (!up) return null;

    return upstreamSource(up);
  });

/** Like lookup, but keeps "upstream could not be asked" apart from "nobody has it". */
const lookupOrUnknown = (name: string) =>
  Effect.gen(function* () {
    const pkg = yield* (yield* Store).getPackage(name);

    if (pkg) return localSource(pkg, yield* versionsOf(name));
    const upstream = yield* upstreamOrNull;

    if (!upstream) return null;
    const probe = yield* upstream.probe(name);

    if (probe.kind === "unknown") return "unknown" as const;

    if (probe.kind === "absent") return null;
    const up = probe.pkg;

    return upstreamSource(up);
  });

/** Makes sure an upstream version has a stored analysis (now, or queued); returns the version with it. */
const ensureAnalyzed = (src: Source, v: VersionRecord) =>
  src.kind === "local" || parseAnalysis(v.score) ? Effect.succeed(v) : Effect.flatMap(Analysis, (a) => a.ensure(src.pkg, v));

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

/** `unavailable`: the upstream could not be asked, so whether the dependency exists, and what it is, is not known. */
type Picked = { kind: "found"; src: Source; v: VersionRecord } | { kind: "missing"; reason: string } | { kind: "unavailable"; reason: string };

const missing = (reason: string): Picked => ({ kind: "missing", reason });
const found = (src: Source, v: VersionRecord): Picked => ({ kind: "found", src, v });

/** A package's catalog as a lookup finds it: here or upstream, nowhere (null), or upstream could not be asked. */
type Lookup = Source | null | "unknown";

/** The newest version a registry dependency (plain or npm: alias) would install, among those `keep` allows. */
const pickDependency = (dep: RegistryDependency, keep: (v: VersionRecord) => boolean) => Effect.map(lookupOrUnknown(dep.name), (src) => pickFrom(src, dep, keep));

/** pickDependency on a catalog already read. */
function pickFrom(src: Lookup, dep: RegistryDependency, keep: (v: VersionRecord) => boolean): Picked {
  if (src === "unknown") return { kind: "unavailable", reason: UNAVAILABLE_TEXT };

  if (src === null) return missing("not on this registry or upstream");
  let inRange: VersionRecord[];

  switch (dep.kind) {
    case "tag": {
      const tagged = tagTarget(src.distTags, dep.tag);
      inRange = tagged ? src.versions.filter((v) => v.version === tagged) : [];
      break;
    }

    case "registry":
      inRange = src.versions.filter((v) => satisfies(v.version, dep.range));
      break;
    default: {
      const _exhaustive: never = dep;

      return _exhaustive;
    }
  }

  const best = inRange.filter(keep).sort((a, b) => newestFirst(a.version, b.version))[0];

  return best ? found(src, best) : missing(`no installable version matches ${describeDependency(dep)}`);
}

/** An upstream probe as a lookup; a name the batch has no answer for counts as "upstream could not be asked". */
function lookupOf(p: Probe | undefined): Lookup {
  if (p === undefined) return "unknown";

  switch (p.kind) {
    case "found":
      return upstreamSource(p.pkg);
    case "absent":
      return null;
    case "unknown":
      return "unknown";
    default: {
      const _exhaustive: never = p;

      return _exhaustive;
    }
  }
}

/**
 * The catalogs one request reads, each name once. `load` reads a batch of names in a fixed number of statements
 * (this registry's packages, versions and dismissals, then npm's packuments and their analyses); `get` reads a name
 * no batch has.
 */
function catalogMemo() {
  const known = new Map<string, Lookup>();

  const load = (names: readonly string[]) =>
    Effect.gen(function* () {
      const wanted = [...new Set(names)].filter((n) => !known.has(n));

      if (wanted.length === 0) return;
      const at = yield* now;
      const local = yield* (yield* Store).catalogsOf(wanted);

      for (const [name, c] of local) {
        known.set(name, localSource(c.pkg, c.versions.map((v) => atTime(v, at))));
      }

      const rest = wanted.filter((n) => !local.has(n));
      const upstream = yield* upstreamOrNull;

      if (rest.length === 0) return;

      if (!upstream) {
        for (const n of rest) known.set(n, null);

        return;
      }

      const probes = yield* upstream.probeMany(rest);

      for (const n of rest) known.set(n, lookupOf(probes.get(n)));
    });

  const get = (name: string) =>
    Effect.gen(function* () {
      if (!known.has(name)) yield* load([name]);
      const found = known.get(name);

      // null is a confirmed absence ("not on this registry or upstream"): only a name load left unread is unknown
      return found === undefined ? "unknown" : found;
    });

  return { load, get };
}

/** Each checked dependency may mean an upstream download and analysis, so publish checks a bounded number. */
const MAX_PUBLISH_DEPS = 50;

/** Dependencies of a manifest whose best matching version scores below the floor, and those apm could not check. */
const checkDependencies = (manifest: Record<string, unknown>) =>
  Effect.gen(function* () {
    const at = yield* now;
    const risky: DependencyRisk[] = [];
    const unchecked: string[] = [];
    const specs = dependencySpecs(manifest);

    for (const dep of specs.slice(0, MAX_PUBLISH_DEPS)) {
      if (!isRegistryDependency(dep)) {
        unchecked.push(`${describeDependency(dep)}: ${uncheckableReason(dep)}`);
        continue;
      }

      const picked = yield* pickDependency(dep, (v) => v.status !== "revoked");

      if (picked.kind !== "found") {
        unchecked.push(`${describeDependency(dep)}: ${picked.reason}`);
        continue;
      }

      const analyzed = yield* ensureAnalyzed(picked.src, picked.v);
      const r = reportFor(analyzed, at, { ignoreRecent: true });

      if (!r) unchecked.push(`${dep.name}@${picked.v.version}: ${notScored(picked.src, analyzed).text}`);
      else if (r.score < SCORE_FLOOR) risky.push({ name: dep.name, version: picked.v.version, score: r.score });
    }

    if (specs.length > MAX_PUBLISH_DEPS) unchecked.push(`${specs.length - MAX_PUBLISH_DEPS} more dependencies: apm checks the first ${MAX_PUBLISH_DEPS} at publish`);

    return { risky, unchecked };
  });

/** A publish whose unpack or secret scan alone spends the work meter: never the case for a tarball under the caps. */
const OVER_METER = { ok: false, status: 413, error: "Refusing to read the tarball: it is more than apm can analyze." } as const;

const onPublish: PublishHook = ({ name, version, manifest, tarball, user, existing }) =>
  Effect.gen(function* () {
    // one work meter for the unpack, the secret scan and the analysis, as for an upstream version (analysis.ts)
    const meter = new Meter();
    let files: TarEntry[];

    try {
      files = readTarball(tarball, WORKER_MAX_UNPACKED_BYTES, meter);
    } catch (e) {
      if (e instanceof MeterExhausted) return OVER_METER;

      if (e instanceof ArchiveError) return { ok: false, status: httpStatusOf(e), error: `Refusing to read the tarball: ${e.message}.` } as const;

      return { ok: false, status: 400, error: "The tarball is not a valid gzip'd tar." } as const;
    }

    const ambiguous = ambiguousPaths(files);

    if (ambiguous.length > 0) {
      return {
        ok: false,
        status: 422,
        error: `Refusing to publish: the tarball has duplicate or escaping paths (${ambiguous.slice(0, 5).join(", ")}). Different tools would extract different files from it.`,
      } as const;
    }

    const pj = files.find((f) => f.path === "package.json");

    if (!pj) return { ok: false, status: 400, error: "The tarball has no package.json." } as const;

    // this is the manifest apm stores and serves, so its cap is checked on its bytes before they are decoded
    if (pj.data.length > MAX_MANIFEST_BYTES) return { ok: false, status: 413, error: `The tarball's package.json is over ${MAX_MANIFEST_BYTES / (1024 * 1024)} MB.` } as const;
    let tarManifest: unknown;

    try {
      tarManifest = JSON.parse(new TextDecoder().decode(pj.data));
    } catch {
      return { ok: false, status: 400, error: "The tarball's package.json is not valid JSON." } as const;
    }

    if (!isRecord(tarManifest)) return { ok: false, status: 400, error: "The tarball's package.json is not an object." } as const;

    if (tarManifest.name !== name || tarManifest.version !== version) {
      return { ok: false, status: 422, error: `Manifest mismatch: tarball says ${String(tarManifest.name)}@${String(tarManifest.version)}, request says ${name}@${version}.` } as const;
    }

    const mismatch = manifestMismatch(manifest, tarManifest);

    if (mismatch.length > 0) {
      return {
        ok: false,
        status: 422,
        error: `Manifest mismatch: the publish request does not match the tarball's package.json: ${mismatch.join("; ")}. apm serves metadata from the tarball, so this publish was refused.`,
      } as const;
    }

    let secrets: SecretScan;

    try {
      secrets = findSecrets(files, meter);
    } catch (e) {
      if (e instanceof MeterExhausted) return OVER_METER;
      throw e;
    }

    if (secrets.findings.length > 0) {
      return {
        ok: false,
        status: 422,
        error: `Refusing to publish: ${secrets.findings.map((f) => f.detail).join("; ")}. Remove the file or add a "files" allowlist to package.json, then publish again. Rotate any key that was ever committed.`,
        detail: secrets.findings,
      } as const;
    }

    const warnings = secrets.skipped.map((f) => `${describeSkip(f)} was not scanned for secrets; check it yourself.`);

    const missing = missingEntries(tarManifest, files);

    if (missing.length > 0) {
      return {
        ok: false,
        status: 422,
        error: `Refusing to publish: ${missing.map((m) => `"${m.field}" points to ${m.path}, which is not in the tarball`).join("; ")}. Did you forget to build, or is it excluded by "files"?`,
      } as const;
    }

    if (!existing) {
      if (POPULAR_NAMES.includes(name)) {
        return { ok: false, status: 403, error: `"${name}" is a reserved name (a widely used public package). Publish under your scope (@${user}/${name}) instead.` } as const;
      }

      const upstream = yield* upstreamOrNull;

      if (upstream) {
        const probe = yield* upstream.probe(name);

        if (probe.kind === "found") {
          return {
            ok: false,
            status: 403,
            error: `"${name}" already exists on the public registry. apm shares one namespace with it, so you cannot publish over it here. Publish under your scope (@${user}/${name}) instead.`,
          } as const;
        }

        // scoped names too: during an outage nobody can tell whose @scope/name this is on npm
        if (probe.kind === "unknown") {
          return {
            ok: false,
            status: 503,
            error: `Cannot check whether "${name}" exists on the public registry right now, so a first publish of this name is refused. Try again shortly.`,
          } as const;
        }
      }

      const conflicts = typoConflicts(name);

      if (conflicts.length > 0) {
        return {
          ok: false,
          status: 422,
          error: `Refusing to publish "${name}": ${conflicts.map((c) => c.reason).join("; ")}. Names this close are how typosquatting works. ${name.startsWith("@") ? "Pick a more distinct name." : `Pick a more distinct name or publish under your scope (@${user}/${name}).`}`,
          detail: conflicts,
        } as const;
      }
    }

    const previous = existing ? yield* versionsOf(name) : [];
    const previousPublishers = [...new Set(previous.map((v) => v.published_by))];
    const last = previous[previous.length - 1];
    const prevDeps = last ? new Set(dependencyNames(last.manifest)) : null;
    const addedDependencies = prevDeps ? dependencyNames(tarManifest).filter((d) => !prevDeps.has(d)) : [];
    const deps = yield* checkDependencies(tarManifest);

    const analysis = analyze({
      name,
      manifest: tarManifest,
      files,
      publisher: user,
      previousPublishers,
      riskyDependencies: deps.risky,
      addedDependencies,
      uncheckedDependencies: deps.unchecked,
      meter,
    });

    const served: Record<string, unknown> = { ...tarManifest };

    if (typeof manifest.readme === "string") served.readme = manifest.readme;

    return { ok: true, manifest: served, score: analysis, warnings } as const;
  });

/** Existing local packages one edit away: shown as a warning in name search, never blocking. */
const registryNeighbours = (name: string) =>
  Effect.gen(function* () {
    if (name.startsWith("@") || name.length < 5) return [];
    const names = yield* (yield* Store).listPackageNames();

    return names
      .filter((n) => !n.startsWith("@") && n !== name && n.length >= 5 && editDistance(n, name) === 1)
      .slice(0, 5)
      .map((n) => ({ name: n, distance: 1, reason: `one edit away from "${n}" on this registry` }));
  });

// ---------- version state changes ----------
/** Takes `version` off every dist-tag, moving latest to the highest version still served. Call inside a transaction. */
const moveTagsOff = (name: string, version: string) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const pkg = yield* store.lockPackage(name);

    if (!pkg) return;

    const live = servedVersions(yield* versionsOf(name))
      .map((v) => v.version)
      .filter((v) => v !== version);

    const tags: Record<string, string> = {};

    for (const [t, v] of Object.entries(pkg.distTags)) if (v !== version) tags[t] = v;

    if (!tags.latest) {
      const h = highest(live);

      if (h) tags.latest = h;
    }

    yield* store.setDistTags(name, tags, yield* now);
  });

/** Revokes now when the version is fresh (or forced); otherwise starts a pending revoke. Call inside a transaction. */
const revokeVersion = (v: VersionRecord, actor: string, reason: string, opts: { forceFinal?: boolean } = {}) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const at = yield* now;
    // A fresh version revoked with the owner's second factor is the malware case: final at once, even if
    // other packages depend on it (they are the victims). Older versions that builds rely on get 24h.
    const fresh = at - v.published_at <= FRESH_MS;
    const dependents = yield* store.dependentsOf(v.package);
    const step = transition(v.status, { kind: "revoke", final: opts.forceFinal === true || fresh });
    const status = step.kind === "move" ? step.to : "revoked";
    const final = status === "revoked";
    yield* store.setStatus(v.package, v.version, { status, reason, at, by: actor });
    yield* store.deleteAdvisoriesFor(v.package, v.version);
    yield* store.addAdvisory({
      package: v.package,
      versions: [v.version],
      severity: "critical",
      title: `${v.package}@${v.version} was revoked by its maintainer: ${reason}`,
      detail: reason,
      created_at: at,
      created_by: actor,
    });
    yield* moveTagsOff(v.package, v.version);
    yield* store.addEvent({
      package: v.package,
      kind: final ? "revoke" : "revoke-pending",
      actor,
      at,
      detail: { version: v.version, reason, ...(final ? {} : { finalAt: new Date(at + PENDING_MS).toISOString(), dependents }) },
    });

    return status;
  });

const Password = z.string().min(1).optional();
const Otp = z.string().min(1).optional();
const StateBody = z.object({ name: z.string(), version: z.string(), reason: z.string().optional(), password: Password, otp: Otp });
const IncidentBody = z.object({ since: z.string(), reason: z.string().optional(), password: Password, otp: Otp, dryRun: z.boolean().optional() });
const OwnerBody = z.object({ name: z.string(), user: z.string(), password: Password, otp: Otp });

/** Destructive actions need a fresh second factor for this exact action on top of the bearer token (a password only in legacy mode). */
const reauth = (caller: Caller, proof: { password?: string | undefined; otp?: string | undefined }, action: LiveAction) =>
  Effect.gen(function* () {
    const user = yield* requireUser(caller);
    const refused = yield* secondFactor({ user: user.user, password: proof.password, otp: proof.otp, action });

    if (refused) return yield* Effect.fail(refuse(refused.status, refused.error));

    return user.user;
  });

const requireOwner = (user: string, name: string): Effect.Effect<void, HttpFailure | import("./errors.ts").StoreError, Store> =>
  Effect.gen(function* () {
    const store = yield* Store;

    if (!(yield* store.getPackage(name))) return yield* Effect.fail(refuse(404, `No package named ${name} on this registry.`));
    const owners = yield* store.owners(name);

    if (!owners.includes(user)) return yield* Effect.fail(refuse(403, `Only owners of ${name} can do this. Owners: ${owners.join(", ")}`));
  });

const handleState = (req: Request, caller: Caller, action: "yank" | "unyank" | "revoke" | "restore") =>
  Effect.gen(function* () {
    const store = yield* Store;
    const { name, version, reason, password, otp } = yield* parseBody(req, StateBody);
    const live: LiveAction = { kind: action, name, version };
    let user: string;

    if (action === "revoke" || action === "restore") user = yield* reauth(caller, { password, otp }, live);
    else {
      const who = yield* requireUser(caller);
      // yank and unyank change what installs: a staging token needs a fresh second factor for them
      yield* requireOwner(who.user, name);
      const refused = yield* liveChangeRefusal({ user: who.user, scope: who.scope, action: live, otp });

      if (refused) return fail(refused.status, refused.error);
      user = who.user;
    }

    yield* requireOwner(user, name);
    const at = yield* now;

    return yield* store.tx(
      Effect.gen(function* () {
        // ownership again, under the lock: an owner removed while this waited must not finish the change
        yield* lockOwned(name, user);
        const v = yield* versionOf(name, version);

        if (!v) return fail(404, `No version ${name}@${version}.`);

        if (action === "revoke") {
          if (v.status === "revoked") return json({ ok: true, name, version, status: "revoked", already: true });

          if (v.status === "revoke-pending") {
            if (v.status_by === user) return json({ ok: true, name, version, status: "revoke-pending", finalAt: new Date((v.status_at ?? at) + PENDING_MS).toISOString() });
            // a second owner confirms: final at once
            const step = transition(v.status, { kind: "confirm" });

            if (step.kind !== "move") return json({ ok: true, name, version, status: v.status });
            yield* store.setStatus(name, version, { status: step.to, reason: v.status_reason, at, by: user });
            yield* store.addEvent({ package: name, kind: "revoke", actor: user, at, detail: { version, reason: v.status_reason, confirms: v.status_by } });

            return json({ ok: true, name, version, status: step.to });
          }

          if (!reason) return fail(400, "A reason is required to revoke; it is shown to everyone who has this version installed.");
          const status = yield* revokeVersion(v, user, reason);

          return json({
            ok: true,
            name,
            version,
            status,
            ...(status === "revoke-pending"
              ? {
                  finalAt: new Date(at + PENDING_MS).toISOString(),
                  note: "Hidden from new installs now. Existing lockfiles keep working until it becomes final, or until another owner confirms.",
                }
              : {}),
          });
        }

        if (action === "restore") {
          const step = transition(v.status, { kind: "restore" });

          if (step.kind !== "move") return fail(409, `${name}@${version} is ${v.status}, not revoked.`);
          yield* store.setStatus(name, version, { status: step.to, reason: reason ?? "restored after revoke", at, by: user });
          yield* store.deleteAdvisoriesFor(name, version);
          yield* store.addEvent({ package: name, kind: "restore", actor: user, at, detail: { version, reason: reason ?? null, from: v.status } });

          return json({ ok: true, name, version, status: step.to });
        }

        if (action === "yank") {
          const step = transition(v.status, { kind: "yank" });

          if (step.kind === "refuse") return fail(409, "This version is revoked, which is stronger than a yank.");

          if (step.kind === "same") return json({ ok: true, name, version, status: "yanked", already: true });
          yield* store.setStatus(name, version, { status: step.to, reason: reason ?? null, at, by: user });
          yield* moveTagsOff(name, version);
          yield* store.addEvent({ package: name, kind: "yank", actor: user, at, detail: { version, reason: reason ?? null } });

          return json({ ok: true, name, version, status: step.to });
        }

        const step = transition(v.status, { kind: "unyank" });

        if (step.kind !== "move") return fail(409, `${name}@${version} is ${v.status}, not yanked.`);
        yield* store.setStatus(name, version, { status: step.to, reason: null, at, by: user });
        const pkg = yield* store.getPackage(name);

        if (pkg) {
          const tags = { ...pkg.distTags };
          const latest = tags.latest;

          if (!version.includes("-") && (!latest || order(version, latest) > 0)) tags.latest = version;
          yield* store.setDistTags(name, tags, at);
        }

        yield* store.addEvent({ package: name, kind: "unyank", actor: user, at, detail: { version } });

        return json({ ok: true, name, version, status: step.to });
      }),
    );
  });

const handleIncident = (req: Request, caller: Caller) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const { legacyAuth } = yield* RegistryConfig;
    const body = yield* parseBody(req, IncidentBody);
    // `since` is exclusive: pass the time of the last publish you trust.
    const since = Date.parse(body.since);

    if (Number.isNaN(since)) return fail(400, "since must be an ISO timestamp");
    const at = yield* now;

    if (at - since > INCIDENT_WINDOW_MS) return fail(400, "Incident response reaches back at most 30 days. Revoke older versions one by one (apm revoke).");
    // the range and whether it is a preview are part of what the second factor authorizes
    const command: LiveAction = { kind: "incident", since: canonicalSince(body.since), dryRun: body.dryRun === true };
    const user = yield* reauth(caller, { password: body.password, otp: body.otp }, command);
    const reason = body.reason ?? "account compromised";
    const published = (yield* store.publishedSince(user, since)).filter((v) => v.status !== "revoked");
    // only packages the account still owns: a former owner's old publishes are the current owners' call
    const owned = new Set<string>();

    for (const name of new Set(published.map((v) => v.package))) if ((yield* store.owners(name)).includes(user)) owned.add(name);
    const targets = published.filter((v) => owned.has(v.package));
    const ids = targets.map((v) => `${v.package}@${v.version}`);

    if (body.dryRun) {
      const live = (yield* store.listTokens(user)).filter((t) => t.revoked_at === null).length;

      return json({ ok: true, dryRun: true, user, since: new Date(since).toISOString(), revoked: ids, tokensRevoked: live });
    }

    const statuses: Record<string, string> = {};
    yield* store.tx(
      Effect.gen(function* () {
        // each package is locked, in name order, and its ownership read again under the lock: a package the
        // account stopped owning while this waited is left to its current owners
        for (const name of [...owned].sort()) {
          const pkg = yield* store.lockPackage(name);

          if (!pkg || !(yield* store.owners(name)).includes(user)) continue;

          for (const v of targets.filter((t) => t.package === name)) statuses[`${v.package}@${v.version}`] = yield* revokeVersion(v, user, `incident: ${reason}`);
        }
      }),
    );
    const tokensRevoked = yield* store.revokeTokensOf(user, at);

    return json({
      ok: true,
      user,
      since: new Date(since).toISOString(),
      revoked: Object.keys(statuses),
      statuses,
      tokensRevoked,
      next: legacyAuth
        ? "Every token is revoked. Change your password, log in again with apm login, then read each package's event log."
        : "Every token is revoked. Check your GitHub account's security, run apm login again, then read each package's event log.",
    });
  });

const handleOwners = (req: Request, caller: Caller) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const body = yield* parseBody(req, OwnerBody);
    const remove = req.method === "DELETE";
    const ownerAction: LiveAction = { kind: remove ? "owner-remove" : "owner-add", name: body.name, user: body.user };
    const user = yield* reauth(caller, { password: body.password, otp: body.otp }, ownerAction);
    yield* requireOwner(user, body.name);

    if (!(yield* store.getUser(body.user))) return fail(404, `No user ${body.user}.`);
    const at = yield* now;

    const refused = yield* store.tx(
      Effect.gen(function* () {
        // ownership again, under the lock: an owner removed while this waited must not change the owners
        yield* lockOwned(body.name, user);

        if (remove) {
          const removed = yield* store.removeOwner(body.name, body.user);

          switch (removed) {
            case "removed":
              break;
            case "not-owner":
              return fail(404, `${body.user} is not an owner of ${body.name}.`);
            case "last-owner":
              return fail(409, `${body.user} is the last owner of ${body.name}. Add another owner first: a package with no owners can never be published, yanked or revoked again.`);
            default: {
              const _exhaustive: never = removed;

              return _exhaustive;
            }
          }
        } else yield* store.addOwner(body.name, body.user);
        yield* store.addEvent({ package: body.name, kind: remove ? "owner-remove" : "owner-add", actor: user, at, detail: { user: body.user } });

        return null;
      }),
    );

    if (refused) return refused;

    return json({ ok: true, owners: yield* store.owners(body.name) });
  });

// ---------- read APIs ----------
function previousOf(src: Source, v: VersionRecord): VersionRecord | null {
  const all = src.versions.filter((x) => x.version !== v.version && x.published_at <= v.published_at && x.status !== "revoked");

  return all[all.length - 1] ?? null;
}

const scoreResponse = (src: Source, v0: VersionRecord) =>
  Effect.gen(function* () {
    const at = yield* now;
    const v = yield* ensureAnalyzed(src, v0);
    const report = reportFor(v, at);

    if (!report) {
      const why = notScored(src, v);

      switch (why.kind) {
        case "queued":
          return fail(503, "This version is not scored yet: its tarball is queued for analysis. Try again in a minute.", { pending: true });
        case "unscorable":
          // decided, not waiting: asking again gives the same answer, and installs stay refused
          return fail(422, `${why.text}. It is not installed through apm.`, { unscorable: { reason: why.reason, text: why.text } });
        case "unreadable":
          return fail(404, "No score for this version (the tarball could not be read).");
        default: {
          const _exhaustive: never = why;

          return _exhaustive;
        }
      }
    }

    const prev0 = previousOf(src, v);
    const prev = prev0 ? yield* ensureAnalyzed(src, prev0) : null;
    const prevReport = prev ? reportFor(prev, at, { ignoreRecent: true }) : null;

    return json({
      name: v.package,
      version: v.version,
      source: src.kind,
      status: v.status,
      publishedAt: new Date(v.published_at).toISOString(),
      publishedBy: v.published_by,
      // spelled out, not `...report`: a field added to the report later is not sent until it is named here
      ...sourceFreeReport(v, report),
      ...reviewable(v, report),
      previous: prev && prevReport ? { version: prev.version, score: prevReport.score, grade: prevReport.grade } : null,
      changes: prev && prevReport ? signalChanges(prevReport.signals, report.signals) : [],
    });
  });

// npm accepts "repository" as a string ("github:owner/repo", a git URL) or { url, directory }. The website
// resolves a readme's relative links and images against it.
const Repository = z.union([
  z.string().transform((url) => ({ url, directory: null })),
  z.object({ url: z.string(), directory: z.string().optional() }).transform((r) => ({ url: r.url, directory: r.directory ?? null })),
]);

/** The repository the latest version's manifest names, or null when it names none apm can read. */
const repositoryOf = (v: VersionRecord | null): { url: string; directory: string | null } | null => {
  const parsed = Repository.safeParse(v?.manifest.repository);

  return parsed.success ? parsed.data : null;
};

/** A manifest URL field as written ("homepage", or "bugs" as a string or { url }); the website keeps only http(s). */
const ManifestUrl = z.string().trim().min(1).max(2048);
const Bugs = z.union([ManifestUrl, z.object({ url: ManifestUrl }).transform((b) => b.url)]);

/** The homepage and issue tracker the latest version's manifest names, each null when absent or unreadable. */
const linksOf = (v: VersionRecord | null) => {
  const homepage = ManifestUrl.safeParse(v?.manifest.homepage);
  const bugs = Bugs.safeParse(v?.manifest.bugs);

  return { homepage: homepage.success ? homepage.data : null, bugs: bugs.success ? bugs.data : null };
};

/** The readme a package answer shows, and the version whose publish wrote it (null when unknown or hidden). */
function readmeOf(pkg: { readme: string; readme_version: string | null }, versions: readonly VersionRecord[]) {
  const shown = readmeShown(pkg, versions);

  return { readme: shown.text, readmeVersion: shown.version };
}

const packageResponse = (name: string) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const at = yield* now;
    const src = yield* lookup(name);

    if (!src) return fail(404, "Not found");
    // the row lookup read, so the answer and the versions come from one read of it
    const local = src.kind === "local" ? src.pkg : null;
    const latest0 = src.versions.find((v) => v.version === src.distTags.latest) ?? null;
    const latest = latest0 ? yield* ensureAnalyzed(src, latest0) : null;
    const latestReport = latest ? reportFor(latest, at) : null;
    const latestFree = latest && latestReport ? sourceFreeReport(latest, latestReport) : null;
    const text = local ? packageTextShown(local, src.versions) : null;

    return json({
      name,
      source: src.kind,
      description: text?.description ?? (src.kind === "upstream" ? src.pkg.description : ""),
      keywords: text?.keywords ?? [],
      ...readmeOf(local ?? { readme: src.kind === "upstream" ? src.pkg.readme : "", readme_version: null }, src.versions),
      repository: repositoryOf(latest0),
      ...linksOf(latest0),
      distTags: src.distTags,
      maintainers: src.kind === "local" ? yield* store.owners(name) : src.pkg.maintainers,
      createdAt: local ? new Date(local.created_at).toISOString() : null,
      modifiedAt: local ? new Date(local.modified_at).toISOString() : null,
      latest: latest?.version ?? null,
      // why the latest version has no score, when it has none: queued, or decided never (with the reason)
      unscored: latest && !latestReport ? notScored(src, latest) : null,
      facts: latestFree?.facts ?? null,
      score:
        latest && latestReport && latestFree
          ? { score: latestFree.score, grade: latestFree.grade, notChecked: latestFree.notChecked, capabilities: latestFree.capabilities, declaration: latestFree.declaration, ...reviewable(latest, latestReport) }
          : null,
      versions: [...src.versions]
        .sort((a, b) => newestFirst(a.version, b.version))
        .slice(0, 200)
        .map((v) => {
          const r = reportFor(v, at);

          return {
            version: v.version,
            publishedAt: new Date(v.published_at).toISOString(),
            publishedBy: v.published_by,
            status: v.status,
            statusReason: v.status_reason,
            // a deprecation message is the publisher's text: a withheld version's is not shown (withheld.ts)
            deprecated: isWithheld(v.status) ? null : v.deprecated,
            score: r?.score ?? null,
            grade: r?.grade ?? null,
            unscorable: !r && v.unscorable ? notScored(src, v).text : null,
          };
        }),
    });
  });

/**
 * HEAD /-/apm/v1/packages/<name>: whether the registry knows the package, here or upstream, with no body. The website
 * asks before a package page renders. It reads the package row or npm's packument and nothing else: no answer is
 * built, no version is analysed and no score is read. 503 when npm could not be asked.
 */
const packageExists = (path: string) =>
  Effect.gen(function* () {
    const sp = splitPath(`/${path}`);

    if (!sp || sp.rest.length > 0) return new Response(null, { status: 404 });

    if (yield* (yield* Store).getPackage(sp.name)) return new Response(null, { status: 200 });
    const upstream = yield* upstreamOrNull;

    if (!upstream) return new Response(null, { status: 404 });
    // the listing alone: whether npm has the name needs neither apm's scores nor its dismissals
    const listed = yield* upstream.listing(sp.name);

    if (listed.kind === "unknown") return new Response(null, { status: 503 });

    return new Response(null, { status: listed.kind === "absent" ? 404 : 200 });
  });

/**
 * GET /-/apm/v1/packages/:name/versions/:version: one version's state and score, whatever its age. The package answer
 * lists only the newest 200 versions and carries latest's facts, so a view of any other version reads this.
 * Never cached: the status (yank, revoke) changes at any time.
 */
const versionResponse = (name: string, version: string) =>
  Effect.gen(function* () {
    const at = yield* now;
    const src = yield* lookup(name);

    if (!src) return fail(404, "Not found");
    const v0 = src.versions.find((x) => x.version === version);

    if (!v0) return fail(404, `${name} has no version ${version}.`);
    const v = yield* ensureAnalyzed(src, v0);
    const report = reportFor(v, at);
    // as on the score route: a withheld version's license and not-checked list are rebuilt without its manifest text
    const free = report ? sourceFreeReport(v, report) : null;

    return json(
      {
        name,
        version: v.version,
        source: src.kind,
        status: v.status,
        statusReason: v.status_reason,
        // the publisher's text: a withheld version's is not shown, as in the package answer's version list (withheld.ts)
        deprecated: isWithheld(v.status) ? null : v.deprecated,
        publishedAt: new Date(v.published_at).toISOString(),
        publishedBy: v.published_by,
        facts: free?.facts ?? null,
        score: report && free ? { score: free.score, grade: free.grade, notChecked: free.notChecked, ...reviewable(v, report) } : null,
      },
      200,
      // its score quotes the version's source, so no shared cache may keep it
      { "cache-control": "private, no-store" },
    );
  });

/** Names one /popular-scores request may ask about: the home page shows a dozen. */
export const MAX_POPULAR_NAMES = 24;

/**
 * GET /-/apm/v1/popular-scores?names=a,b,c: the latest version's score of each package, in one answer, so the website's
 * popular list costs one request however many packages it shows. Read-only: it answers from analyses apm already
 * stored and never starts one, so a request naming 24 packages nobody has scored costs no tarball downloads. A name
 * whose latest version has no stored analysis is null.
 */
const popularScoresResponse = (url: URL) =>
  Effect.gen(function* () {
    const at = yield* now;
    const names = [...new Set((url.searchParams.get("names") ?? "").split(",").map((n) => n.trim()).filter((n) => n.length > 0))];

    if (names.length === 0 || names.length > MAX_POPULAR_NAMES) return fail(400, `names must list 1 to ${MAX_POPULAR_NAMES} package names, comma-separated`);

    const packages = yield* Effect.forEach(
      names,
      (name) =>
        Effect.gen(function* () {
          const none = { name, version: null, score: null, grade: null };
          const store = yield* Store;

          // a name apm never scored (no local package, no stored upstream analysis) is null without asking upstream
          if (!(yield* store.getPackage(name)) && (yield* store.upstreamAnalyses(name)).scores.size === 0) return none;
          const src = yield* lookup(name);
          const latest = src ? src.versions.find((v) => v.version === src.distTags.latest) : undefined;
          // an upstream version carries its stored analysis already (upstream.get reads them); none means not scored yet
          const r = latest ? reportFor(latest, at) : null;

          return latest && r ? { name, version: latest.version, score: r.score, grade: r.grade } : none;
        }),
      { concurrency: 4 },
    );

    return json({ packages });
  });

type LimitParse = { kind: "ok"; limit: number } | { kind: "invalid"; error: string };

/** A `limit` query parameter: absent means `fallback`; anything but a whole number from 1 to `max` is an error. */
export function parseLimit(raw: string | null, fallback: number, max: number): LimitParse {
  if (raw === null) return { kind: "ok", limit: fallback };
  const n = /^\d{1,6}$/.test(raw) ? Number(raw) : Number.NaN;

  return Number.isInteger(n) && n >= 1 && n <= max ? { kind: "ok", limit: n } : { kind: "invalid", error: `limit must be a whole number from 1 to ${max} (got "${raw}")` };
}

const eventsResponse = (name: string) =>
  Effect.gen(function* () {
    const store = yield* Store;

    const events = yield* store.eventsFor(name);
    const pkg = yield* store.getPackage(name);

    // a package proxied from upstream has a log only for what apm's reviewers did to it (dismissed evidence)
    if (events.length === 0 && !pkg) return fail(404, "Not found");
    // an upstream version is never withheld; a local one's events keep who, when and which version (withheld.ts).
    // A pending revoke only ever becomes final, so the stored status says whether a version is withheld.
    const withheld = new Set(pkg ? (yield* store.listVersions(name)).filter((v) => isWithheld(v.status)).map((v) => v.version) : []);

    return json({
      name,
      events: events.map((e) => {
        // a detail that is not an object names no version, so nothing in it can be a withheld version's
        const d = StoredEventDetail.safeParse(e.detail);

        return { kind: e.kind, actor: e.actor, at: new Date(e.at).toISOString(), detail: d.success ? eventDetailShown({ kind: e.kind, detail: d.data, withheld }) : e.detail };
      }),
    });
  });

/** The name check answers in parts so a UI can fill each slot as soon as its part is ready. */
export const NAME_PARTS = ["exact", "lookalike", "alternatives"] as const;

export type NamePart = (typeof NAME_PARTS)[number];

export function isNamePart(s: string | null): s is NamePart {
  return NAME_PARTS.some((p) => p === s);
}

/** A package's description as an answer may show it: a withheld publish's text is not (withheld.ts). */
const shownDescription = (src: Source) =>
  Effect.gen(function* () {
    if (src.kind === "upstream") return src.pkg.description;
    const pkg = yield* (yield* Store).getPackage(src.name);

    return pkg ? packageTextShown(pkg, src.versions).description : "";
  });

const exactPart = (query: string, valid: boolean) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const at = yield* now;
    const found = valid ? yield* lookupOrUnknown(query) : null;
    // When npm can't be asked, the name is neither taken nor available: say so instead of "available".
    const unknown = found === "unknown";
    const src = found === "unknown" ? null : found;
    const conflicts = valid && !src ? typoConflicts(query) : [];
    const latestRaw = src ? (src.versions.find((v) => v.version === src.distTags.latest) ?? null) : null;
    const latest0 = src && latestRaw ? yield* ensureAnalyzed(src, latestRaw) : null;
    const latestReport = latest0 ? reportFor(latest0, at) : null;

    return {
      taken: src !== null,
      source: src?.kind ?? null,
      unknown,
      available: valid && !unknown && src === null && conflicts.length === 0,
      owners: src ? (src.kind === "local" ? yield* store.owners(query) : src.pkg.maintainers) : [],
      latest: latest0 ? { version: latest0.version, score: latestReport?.score ?? null, grade: latestReport?.grade ?? null } : null,
      description: src ? yield* shownDescription(src) : null,
      conflicts,
    };
  });

const lookalikePart = (query: string, valid: boolean) =>
  Effect.gen(function* () {
    return {
      // popular names this one could be mistaken for, whether or not it is taken (install-side typo warning)
      lookalikes: valid ? typoConflicts(query) : [],
      similar: valid ? yield* registryNeighbours(query) : [],
    };
  });

/** One suggested name: whether it can be had, and whether that was checked (a placeholder scope is not). */
type Suggestion = { name: string; available: boolean; taken: boolean; unknown: boolean; checked: boolean };

/**
 * Names to try instead. Under the scoped policy only scoped names can be published (a bare name always means the
 * npm package), so every suggestion is scoped: under the signed-in user's scope, checked, or under a placeholder
 * `@you/` scope, unchecked, for someone not signed in. `scope` says which.
 */
const alternativesPart = (query: string, user: string | null) =>
  Effect.gen(function* () {
    const { namePolicy } = yield* RegistryConfig;
    const bare = query.startsWith("@") ? query.slice(query.indexOf("/") + 1) : query;
    const stems = [bare, `${bare}-js`, `${bare}js`, `use-${bare}`, `${bare}-kit`, `${bare}-core`];

    const check = (name: string) =>
      Effect.map(lookupOrUnknown(name), (hit): Suggestion => {
        const taken = hit !== null && hit !== "unknown";
        const cc = taken ? [] : typoConflicts(name);

        return { name, available: hit === null && cc.length === 0, taken, unknown: hit === "unknown", checked: true };
      });

    if (namePolicy === "scoped" && user === null) {
      const suggestions = stems.flatMap((s): Suggestion[] => {
        const name = `@you/${s}`;

        // a placeholder the look-alike guard would refuse under any scope is not worth suggesting
        return isValidPackageName(name) && typoConflicts(name).length === 0 ? [{ name, available: false, taken: false, unknown: false, checked: false }] : [];
      });

      return { scope: null, suggestions };
    }

    const scoped = user === null ? [] : stems.map((s) => `@${user}/${s}`);
    const candidates = namePolicy === "scoped" ? scoped : [...scoped.slice(0, 1), ...stems.slice(1)];

    const suggestions = yield* Effect.forEach(
      candidates.filter((c) => c !== query && isValidPackageName(c)),
      check,
      { concurrency: 4 },
    );

    return { scope: user, suggestions };
  });

export const nameReport = (q: string, user: string | null, part: NamePart | null = null) =>
  Effect.gen(function* () {
    const query = q.trim().toLowerCase();
    const valid = isValidPackageName(query);
    const head = { query, valid };

    if (part !== null) {
      switch (part) {
        case "exact":
          return { ...head, ...(yield* exactPart(query, valid)) };
        case "lookalike":
          return { ...head, ...(yield* lookalikePart(query, valid)) };
        case "alternatives":
          return { ...head, ...(yield* alternativesPart(query, user)) };
        default: {
          const _exhaustive: never = part;

          return _exhaustive;
        }
      }
    }

    const [exact, alternatives] = yield* Effect.all([exactPart(query, valid), alternativesPart(query, user)], { concurrency: 2 });

    return { ...head, ...(yield* lookalikePart(query, valid)), ...exact, ...alternatives };
  });

/** The apm account of a website session, when the request carries one; a request without cookies never builds Better Auth. */
export const sessionUser = (req: Request) =>
  Effect.gen(function* () {
    if (!req.headers.has("cookie")) return null;
    const auth = yield* Auth;
    const session = yield* auth.sessionOf(req);

    return session ? ((yield* auth.apmUserOf(session.authUserId))?.name ?? null) : null;
  });

// ---------- search: local packages merged with the upstream's search ----------
/**
 * A score for an upstream search hit, only when that version was analyzed before. Never fetches a tarball: it reads
 * what latestUpstreamAnalyses found for every hit at once.
 */
function storedUpstreamScore(analyses: ReadonlyMap<string, unknown>, hit: { name: string; version: string; date?: string | null | undefined }, at: number): CompactScore | null {
  const analysis = parseAnalysis(analyses.get(`${hit.name} ${hit.version}`));

  if (!analysis) return null;

  return compact(finalize(analysis, { publishedAt: Date.parse(hit.date ?? "") || 0, now: at, deprecated: null, status: "active", statusReason: null }));
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

const searchResponse = (url: URL) =>
  Effect.gen(function* () {
    const upstream = yield* upstreamOrNull;
    const { text, size, from } = searchPaging(url);
    const local = yield* localSearchObjects(text, compactScore);
    // npm refuses text shorter than two characters, so asking it would only look like an outage
    const up = upstream && text.trim().length >= 2 ? yield* upstream.search(text.trim(), Math.min(250, from + size)) : null;

    // one query for every hit's stored score, not one per hit: they would queue on the request's one connection
    const hits = up?.kind === "ok" ? up.objects : [];
    const analyses = yield* (yield* Store).latestUpstreamAnalyses(hits.map((o) => ({ name: o.package.name, version: o.package.version })));
    const at = yield* now;
    const upstreamHits = hits.map((o) => ({ ...o, source: "npm" as const, apmScore: storedUpstreamScore(analyses, o.package, at) }));

    const merged = mergeSearch({ text, local, upstream: upstreamHits });
    const total = local.length + (up?.kind === "ok" ? Math.max(up.total, upstreamHits.length) : 0);

    return json({ objects: merged.slice(from, from + size), total, time: new Date(yield* now).toUTCString(), upstreamFailed: up?.kind === "unavailable" });
  });

// ---------- recent activity on this registry ----------
const RECENT_KINDS = ["publish", "yank", "unyank", "revoke", "restore"] as const;

/**
 * Left out of the recent feed: the staging smoke check (packages/infra/smoke.ts) signs in as `apm-staging-check` and
 * publishes `@apm-staging-check/smoke-*` on every run. Those versions are checks, not packages anyone would install.
 */
export const RECENT_HIDDEN = { actors: ["apm-staging-check"], scopes: ["@apm-staging-check/"] } as const;
const EventDetail = z.object({ version: z.string(), reason: z.string().nullish() }).loose();

const recentResponse = (url: URL) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const at = yield* now;
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") ?? 12) || 12));
    const seen = new Set<string>();
    const events: Record<string, unknown>[] = [];

    for (const e of yield* store.recentEvents([...RECENT_KINDS], limit * 4, RECENT_HIDDEN)) {
      const d = EventDetail.safeParse(e.detail);

      if (!d.success) continue;
      const key = `${e.package}@${d.data.version}:${e.kind}`;

      if (seen.has(key)) continue;
      seen.add(key);
      const v = yield* versionOf(e.package, d.data.version);
      const r = v ? reportFor(v, at) : null;
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
  });

/** GET /-/apm/v1/recent-packages: the npm packages scored most recently, newest first (the website's sitemap). */
const recentPackagesResponse = (url: URL) =>
  Effect.gen(function* () {
    const parsed = parseLimit(url.searchParams.get("limit"), 50, 200);

    if (parsed.kind === "invalid") return fail(400, parsed.error);
    const rows = yield* (yield* Store).recentlyScored(parsed.limit);

    return json({ packages: rows.map((r) => ({ name: r.package, at: new Date(r.at).toISOString() })) });
  });

// ---------- versions without a score ----------
/** What a decided reason means, in the words every surface uses (score endpoint, install refusals, scan, website). */
const UNSCORABLE_LEAD: Record<Unscorable["reason"], string> = {
  "too-large": "it is too large for apm to analyze",
  unavailable: "the upstream registry does not serve it in a form apm can check",
  unreadable: "its tarball is not a package apm can read",
  "analysis-limit": "its analysis runs past the registry's limits",
};

/**
 * Why a version has no score: "unscorable" when the registry decided it never will be (and why), "queued" when an
 * upstream version is waiting for the analysis queue, "unreadable" for a local version whose tarball was not read.
 * None of them is ever installed as if it passed.
 */
export type NotScored = { kind: "unscorable"; reason: Unscorable["reason"]; text: string } | { kind: "queued"; text: string } | { kind: "unreadable"; text: string };

export function notScored(src: Pick<Source, "kind">, v: VersionRecord): NotScored {
  if (v.unscorable) return { kind: "unscorable", reason: v.unscorable.reason, text: `apm cannot score this version: ${UNSCORABLE_LEAD[v.unscorable.reason]} (${v.unscorable.detail})` };

  if (src.kind === "upstream") return { kind: "queued", text: "not scored yet: queued for analysis" };

  return { kind: "unreadable", text: "could not be analyzed" };
}

// ---------- policy: ~safe view, resolve, scan ----------
export type Policy = { cooldownMs: number; floor: number };

export const DEFAULT_POLICY: Policy = { cooldownMs: COOLDOWN_MS, floor: SCORE_FLOOR };

/**
 * Why a version fails the policy, or null when it passes. A version that was never scored fails. A withheld version's
 * reason is fixed words: the owner's own reason travels in its own field (revokeReason) where an answer gives it.
 */
export function policyBlock(v: VersionRecord, policy: Policy, at: number): string | null {
  const hard = hardBlock(v, policy, at);

  if (hard !== null) return hard;
  const r = reportFor(v, at, { ignoreRecent: true });

  if (!r) return v.unscorable ? notScored({ kind: "upstream" }, v).text : "not scored yet";

  if (r.score < policy.floor) {
    return `score ${r.score}/100 is below ${policy.floor} (${r.signals
      .filter((s) => s.points < 0)
      .map((s) => s.id)
      .join(", ")})`;
  }

  return null;
}

/**
 * Why a version is not installed in any mode: revoked, revocation pending, yanked, or inside the cooldown. None is a
 * score, so each holds in the default mode too; policyBlock adds the score floor and a missing score (strict mode and
 * the ~safe view).
 */
export function hardBlock(v: VersionRecord, policy: Policy, at: number): string | null {
  if (v.status === "revoked") return "revoked by its owner";

  if (v.status === "revoke-pending") return "revocation pending";

  if (v.status === "yanked") return `yanked${v.status_reason ? `: ${v.status_reason}` : ""}`;
  const age = at - v.published_at;

  return age < policy.cooldownMs ? `published ${Math.floor(age / HOUR)}h ago (cooldown ${Math.round(policy.cooldownMs / HOUR)}h)` : null;
}

/** The URL prefix of the safe view: versions past the cooldown that score at or above the floor. */
export const SAFE_PREFIX = "~safe/";

export function safeView(at: number): PackumentView {
  const why = (v: VersionRecord): string | null => policyBlock(v, DEFAULT_POLICY, at);

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

/**
 * `packages`: every name@version the walk checked, so the CLI can pin each scope in the tree to this registry.
 * `digests`: the tarball digest of each of those, which keys its AI review; not sent.
 */
/**
 * `blocks`: what refuses the install in every mode (a dependency inside its cooldown). `warnings`: what strict mode
 * refuses and the default mode installs with a warning (a low or incomplete score, a version apm cannot score, a
 * lookup that failed, the walk's limits); pending versions get theirs only once the resolve stops waiting.
 * `unscorable` and `unavailable` list those two kinds apart. `limited`: the walk stopped at one of its limits.
 */
type Tree = {
  blocks: TreeBlock[];
  warnings: InstallWarning[];
  unchecked: number;
  uncheckedDeps: UncheckedDep[];
  pending: PendingDep[];
  unscorable: (DepRef & { reason: string; via: string[] })[];
  unavailable: { dependency: string; via: string[] }[];
  limited: boolean;
  packages: { name: string; version: string }[];
  digests: (string | null)[];
};

/**
 * A version in the tree with no score yet that the registry will score: an upstream version queued for analysis. Never
 * read as clean, and never as merely unchecked either: a resolve with one waits for it, then answers that it is pending.
 */
type PendingDep = { name: string; version: string; via: string[] };

const MAX_UNCHECKED_LISTED = 50;

/**
 * Dependency lookups (a name and a range to pick a version for) one resolve walk makes at most, failed ones included:
 * the 300 packages it checks plus room for ranges that match nothing, git specs and repeats under another range. A
 * walk past it, which only a tree built to waste the registry's work reaches, reports the rest as unchecked.
 */
export const MAX_WALK_LOOKUPS = 400;

/**
 * Levels of the tree the walk reads, one batch of catalogs each, so a long chain of single dependencies can't make
 * one request a long run of sequential reads. Real trees, read breadth-first with each package once, are far shallower.
 */
export const MAX_WALK_LEVELS = 32;

export type WalkLimits = { maxNodes: number; maxLookups: number; maxLevels: number; maxAnalyses: number };

const WALK_LIMITS: WalkLimits = { maxNodes: 300, maxLookups: MAX_WALK_LOOKUPS, maxLevels: MAX_WALK_LEVELS, maxAnalyses: 40 };

/**
 * Walks the dependency tree the package manager would install (newest active version matching each
 * range, npm: aliases followed to the package they install) and returns the versions that are revoked
 * or score below the floor. Bounded: at most `maxNodes` packages, `maxLookups` lookups, `maxLevels` levels and
 * `maxAnalyses` tarball analyses. Each name's catalog is read once per walk, a level's names in one batch, and each
 * name and range is resolved once. Everything it could not score is counted and listed, never dropped.
 */
const treeBlocks = (root: VersionRecord, policy: Policy, limits: WalkLimits = WALK_LIMITS) =>
  Effect.gen(function* () {
    const at = yield* now;
    const { webUrl } = yield* RegistryConfig;
    const blocks: TreeBlock[] = [];
    const warnings: InstallWarning[] = [];
    const unscorable: Tree["unscorable"] = [];
    const unavailable: Tree["unavailable"] = [];
    let limited = false;
    const uncheckedDeps: UncheckedDep[] = [];
    const pending: PendingDep[] = [];
    const packages: Tree["packages"] = [];
    const digests: Tree["digests"] = [];
    let unchecked = 0;

    const miss = (dependency: string, reason: string, via: string[]): void => {
      unchecked++;

      if (uncheckedDeps.length < MAX_UNCHECKED_LISTED) uncheckedDeps.push({ dependency, reason, via });
    };

    const seen = new Set<string>();
    const catalogs = catalogMemo();
    // what the package manager would pick: the newest active version in range (pulled versions are hidden)
    const resolved = new Map<string, Picked>();
    const active = (v: VersionRecord): boolean => v.status === "active";
    // what decides the pick: the package and the range or tag, not the alias it is installed under
    const lookupKey = (dep: RegistryDependency): string => `${dep.name}\u0000${dep.kind === "tag" ? `tag:${dep.tag}` : dep.range}`;
    let lookups = 0;
    let analyses = 0;
    let loadedLevel = 0;
    const rootId = `${root.package}@${root.version}`;
    const queue = dependencySpecs(root.manifest).map((dep) => ({ dep, via: [rootId], level: 1 }));

    const stop = (qi: number, reason: string): void => {
      const rest = queue.length - qi;
      unchecked += rest;
      uncheckedDeps.push({ dependency: `${rest} more`, reason, via: [rootId] });
      limited = true;
      warnings.push(stateWarning({ kind: "unchecked", name: root.package, version: root.version, text: `${rest} more ${rest === 1 ? "dependency was" : "dependencies were"} not checked: ${reason}`, url: versionUrl(webUrl, root.package, root.version), via: [] }));
    };

    /** The names a level still needs, from `qi` on, for at most as many new lookups as the budget has left. */
    const levelNames = (qi: number, level: number): string[] => {
      const names = new Set<string>();
      const keys = new Set<string>();

      for (let j = qi; j < queue.length && keys.size < limits.maxLookups - lookups; j++) {
        const next = queue[j];

        if (!next || next.level !== level) break;

        if (!isRegistryDependency(next.dep) || resolved.has(lookupKey(next.dep))) continue;
        keys.add(lookupKey(next.dep));
        names.add(next.dep.name);
      }

      return [...names];
    };

    for (let qi = 0; qi < queue.length; qi++) {
      const item = queue[qi];

      if (!item) break;

      if (seen.size >= limits.maxNodes) {
        stop(qi, `the check stops after ${limits.maxNodes} packages`);
        break;
      }

      if (item.level > limits.maxLevels) {
        stop(qi, `the check stops after ${limits.maxLevels} levels of dependencies`);
        break;
      }

      const dep = item.dep;

      if (!isRegistryDependency(dep)) {
        miss(describeDependency(dep), uncheckableReason(dep), item.via);
        continue;
      }

      let picked = resolved.get(lookupKey(dep));

      if (picked === undefined) {
        if (lookups >= limits.maxLookups) {
          stop(qi, `the check stops after ${limits.maxLookups} dependency lookups`);
          break;
        }

        // the first lookup of a level reads every catalog the level needs in one batch
        if (item.level > loadedLevel) {
          yield* catalogs.load(levelNames(qi, item.level));
          loadedLevel = item.level;
        }

        lookups++;
        picked = pickFrom(yield* catalogs.get(dep.name), dep, active);
        resolved.set(lookupKey(dep), picked);
      }

      if (picked.kind === "unavailable") {
        // the registry or npm could not be asked: not a pass, and not the same as a walk limit
        unavailable.push({ dependency: describeDependency(dep), via: item.via });
        warnings.push(stateWarning({ kind: "unavailable", name: dep.name, version: dep.kind === "tag" ? dep.tag : dep.range, text: UNAVAILABLE_TEXT, url: `${webUrl}package/${dep.name}`, via: item.via }));
        continue;
      }

      if (picked.kind !== "found") {
        miss(describeDependency(dep), picked.reason, item.via);
        continue;
      }

      const key = `${dep.name}@${picked.v.version}`;

      if (seen.has(key)) continue;
      seen.add(key);
      packages.push({ name: dep.name, version: picked.v.version });
      const digest = digestOf(picked.v);
      digests.push(digest ? digestLabel(digest) : null);
      let v = picked.v;

      if (!parseAnalysis(v.score)) {
        if (analyses < limits.maxAnalyses) {
          analyses++;
          v = yield* ensureAnalyzed(picked.src, v);
        } else if (picked.src.kind === "upstream" && !v.unscorable) yield* Effect.flatMap(Analysis, (a) => a.enqueue(dep.name, v.version));
      }

      const age = at - v.published_at;
      const r = reportFor(v, at, { ignoreRecent: true });

      // the package manager installs this version whatever its age, so a fresh one blocks the tree like a low score
      if (age < policy.cooldownMs) {
        blocks.push({ name: dep.name, version: v.version, reason: `published ${Math.floor(age / HOUR)}h ago (cooldown ${Math.round(policy.cooldownMs / HOUR)}h)`, via: item.via });
      } else if (!r) {
        const why = notScored(picked.src, v);

        // queued for analysis is pending: the answer waits for it, then warns (strict: 202). A version decided
        // unscorable (too large, unavailable, unreadable, past the analysis limits) or one with no score for any other
        // reason never gets one: a warning (strict: refused), since the package manager would install it
        if (why.kind === "queued") pending.push({ name: dep.name, version: v.version, via: item.via });
        else {
          unscorable.push({ name: dep.name, version: v.version, reason: why.text, via: item.via });
          warnings.push(stateWarning({ kind: "unscorable", name: dep.name, version: v.version, text: why.text, url: versionUrl(webUrl, dep.name, v.version), via: item.via }));
        }
      } else {
        const w = scoreWarning({ name: dep.name, version: v.version, report: r, floor: policy.floor, url: versionUrl(webUrl, dep.name, v.version), via: item.via });

        if (w) warnings.push(w);
      }

      // every package is checked once (seen), every name and range looked up once (resolved), and the walk stops at
      // its limits, counting the rest as unchecked: a cut-off never drops part of the tree without saying so
      for (const d of dependencySpecs(v.manifest)) queue.push({ dep: d, via: [...item.via, key], level: item.level + 1 });
    }

    const tree: Tree = { blocks, warnings, unchecked, uncheckedDeps, pending, unscorable, unavailable, limited, packages, digests };

    return tree;
  });

type DepRef = { name: string; version: string };

/**
 * The AI review standing of every dependency the walk checked. "off" when this registry runs no AI review. A client
 * deciding on an install treats confirmed as do-not-install and the other lists as a reason to look first.
 */
type TreeReviews = { kind: "off" } | { kind: "on"; confirmed: DepRef[]; underReview: DepRef[]; pending: DepRef[]; noAnswer: DepRef[] };

const treeReviews = (tree: Tree) =>
  Effect.gen(function* () {
    if (Option.isNone(yield* Effect.serviceOption(ReviewConfig))) return { kind: "off" } satisfies TreeReviews;
    const standings = yield* reviewStandings(tree.packages.map((p, i) => ({ ...p, digest: tree.digests[i] ?? null })));
    const out: Extract<TreeReviews, { kind: "on" }> = { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] };

    for (const p of tree.packages) {
      const standing = standings.get(`${p.name}@${p.version}`) ?? "not-reviewed";

      switch (standing) {
        case "confirmed":
          out.confirmed.push(p);
          break;
        case "under-review":
          out.underReview.push(p);
          break;
        case "queued":
        case "leased":
          out.pending.push(p);
          break;
        case "no-answer":
        case "failed":
          out.noAnswer.push(p);
          break;
        case "found-nothing":
        case "cleared":
        case "not-reviewed":
          break;
        default: {
          const _exhaustive: never = standing;

          return _exhaustive;
        }
      }
    }

    return out;
  });

/** Whether an apm reviewer confirmed this version malicious. False when this registry runs no AI review. */
const reviewerConfirmed = (v: VersionRecord) =>
  Effect.gen(function* () {
    if (Option.isNone(yield* Effect.serviceOption(ReviewConfig))) return false;
    const digest = digestOf(v);
    const standings = yield* reviewStandings([{ name: v.package, version: v.version, digest: digest ? digestLabel(digest) : null }]);

    return standings.get(`${v.package}@${v.version}`) === "confirmed";
  });

/** The walk as the resolve answer sends it: the internal digests stay out, the AI review standings go in. */
const treeAnswer = (tree: Tree, reviews: TreeReviews) => ({
  blocks: tree.blocks,
  unchecked: tree.unchecked,
  uncheckedDeps: tree.uncheckedDeps,
  pending: tree.pending,
  unscorable: tree.unscorable,
  unavailable: tree.unavailable,
  packages: tree.packages,
  reviews,
});

/**
 * How long a resolve waits for queued analyses to land before it answers that they are pending, and how often it
 * looks. The wait is the database's (one read per look), not CPU. Tests provide a shorter one.
 */
export class ResolveWait extends Context.Service<ResolveWait, { readonly maxMs: number; readonly pollMs: number }>()("@apm/registry/ResolveWait") {}

/** About 20 s: inside the website's 25 s timeout for a resolve, and short of the platform's limits on a request. */
export const RESOLVE_WAIT = { maxMs: 20_000, pollMs: 1_000 } as const;

/** What a client should wait before it asks again about a resolve that is still pending, in seconds. */
export const PENDING_RETRY_AFTER_S = 10;

/** One pass of the resolve: a final answer, or the versions it is waiting on (the root, its dependencies or both). */
type ResolvePass = { kind: "answer"; response: Response } | { kind: "pending"; version: string; pending: PendingDep[]; skipped: { version: string; reason: string; revokeReason: string | null }[] };

/** What policyBlock says of a version with no score that the registry will score: the root of a pending resolve. */
const NOT_SCORED_YET = "not scored yet";

/** Why resolve skips a version an apm reviewer confirmed malicious, in every mode. */
const CONFIRMED_SKIP = "confirmed malicious by an apm reviewer";

const answered = (response: Response): ResolvePass => ({ kind: "answer", response });

const waitingOn = (p: Omit<Extract<ResolvePass, { kind: "pending" }>, "kind">): ResolvePass => ({ kind: "pending", ...p });

/**
 * The resolve answers' modes. `strict` (apm add --strict, APM_STRICT=1): a score under the floor, an incomplete
 * analysis, a version apm cannot score, one still pending after the wait, a dependency the registry could not look
 * up, and a walk cut short at its limits each refuse, as before. Default: each is a warning, and the install goes
 * ahead. `final`: the wait is over, so what is still pending is warned about rather than waited for.
 */
type ResolveMode = { strict: boolean; final: boolean };

const resolvePass = (input: { name: string; range: string; policy: Policy; treePolicy: Policy; src: Source; mode: ResolveMode }) =>
  Effect.gen(function* () {
    const { name, range, policy, treePolicy, src, mode } = input;
    const at = yield* now;
    const { webUrl } = yield* RegistryConfig;
    const tagged = tagTarget(src.distTags, range);
    // A tag keeps its channel: `next` -> 2.0.0-beta.3 may fall back to 2.0.0-beta.2 or a stable release
    // below it, but a stable tag never falls back to a prerelease.
    const base = (v: string): string => v.split("-")[0] ?? v;
    const inChannel = (v: string, t: string): boolean => order(v, t) <= 0 && (!v.includes("-") || (t.includes("-") && base(v) === base(t)));

    const matches = src.versions
      .filter((v) => (tagged ? inChannel(v.version, tagged) : v.version === range || satisfies(v.version, range)))
      .sort((a, b) => newestFirst(a.version, b.version));

    const skipped: { version: string; reason: string; revokeReason: string | null }[] = [];
    let analyzedCount = 0;

    for (const v0 of matches) {
      // analyze a bounded number of candidates; upstream analysis means downloading the tarball
      const v = analyzedCount < 5 ? yield* ensureAnalyzed(src, v0) : v0;
      analyzedCount++;
      // strict skips a version under the floor or with no score; the default mode installs it with a warning. A version
      // an apm reviewer confirmed malicious is skipped in every mode, as a revoked one is
      const policyWhy = mode.strict ? policyBlock(v, policy, at) : hardBlock(v, policy, at);
      const block = policyWhy === null && (yield* reviewerConfirmed(v)) ? CONFIRMED_SKIP : policyWhy;
      const report = reportFor(v, at);
      const unscored = report === null ? notScored(src, v) : null;
      // the newest candidate that passes everything but a score it does not have yet: waited for, never skipped
      const pendingRoot = (block === null || block === NOT_SCORED_YET) && unscored?.kind === "queued";

      if (block === null || pendingRoot) {
        // a pending root's tree is walked too, so its dependencies are queued while it is
        const walked = yield* treeBlocks(v, treePolicy);
        const tree = treeAnswer(walked, yield* treeReviews(walked));
        const newest = { version: v.version, report: embeddedReport(v, report) };

        // a dependency confirmed malicious by an apm reviewer: refused in every mode, since the package manager would
        // install it (the version itself was skipped above)
        const confirmed = tree.reviews.kind === "on" ? tree.reviews.confirmed : [];

        if (confirmed.length > 0) {
          return answered(json({ error: `${name}@${v.version} would install ${confirmed.map((c) => `${c.name}@${c.version}`).join(", ")}, which apm reviewers confirmed ${confirmed.length === 1 ? "is" : "are"} malicious.`, name, range, version: null, skipped, newest, tree, confirmed }, 422));
        }

        // the refused dependencies are the tree's blocks, as the answer lists them
        const refuse = (blocks: TreeBlock[]) =>
          answered(json({ error: `${name}@${v.version} would install dangerous dependencies: ${blocks.map((b) => `${b.name}@${b.version} ${b.reason} via ${b.via.join(" > ")}`).join("; ")}`, name, range, version: null, skipped, newest, tree: { ...tree, blocks } }, 422));

        // a dependency inside its cooldown: not a score, refused in every mode
        if (walked.blocks.length > 0) return refuse(walked.blocks);

        if (mode.strict) {
          // the registry or npm could not be asked about a dependency: not a pass, and a retry may succeed
          if (walked.unavailable.length > 0) {
            return answered(
              json(
                { error: `${name}@${v.version}: ${walked.unavailable.length === 1 ? "a dependency" : `${walked.unavailable.length} dependencies`} ${UNAVAILABLE_TEXT} (${walked.unavailable.map((u) => u.dependency).join(", ")}). Nothing was installed as if it passed; try again in a minute.`, name, range, version: null, unavailable: walked.unavailable, retryAfter: PENDING_RETRY_AFTER_S, skipped, newest, tree },
                503,
                { "cache-control": "no-store", "retry-after": String(PENDING_RETRY_AFTER_S) },
              ),
            );
          }

          const scored = walked.warnings.filter((w) => w.kind !== "unavailable");

          if (scored.length > 0) return refuse(scored.map((w) => ({ name: w.name, version: w.version, reason: w.text, via: w.via })));
        }

        if (!mode.final && (pendingRoot || walked.pending.length > 0)) {
          const pending = [...(pendingRoot ? [{ name, version: v.version, via: [] }] : []), ...walked.pending];

          return waitingOn({ version: v.version, pending, skipped });
        }

        // what installs with a warning: the version itself, then its tree, then what is still pending
        const url = versionUrl(webUrl, name, v.version);
        // judged as the floor judges it: a fresh publish's own signal is the cooldown's business, not the score's
        const judged = reportFor(v, at, { ignoreRecent: true });
        const own = judged ? scoreWarning({ name, version: v.version, report: judged, floor: policy.floor, url, via: [] }) : unscored ? stateWarning({ kind: unscored.kind === "queued" ? "pending" : "unscorable", name, version: v.version, text: unscored.text, url, via: [] }) : null;
        const stillPending = [...(pendingRoot ? [] : walked.pending)].map((p) => stateWarning({ kind: "pending", name: p.name, version: p.version, text: "not scored yet: still being analysed after the registry's wait", url: versionUrl(webUrl, p.name, p.version), via: p.via }));
        const warnings = [...(own ? [own] : []), ...walked.warnings, ...stillPending];

        // the verdict and `apm add` act on this answer: it is never cached, version states change at any time
        return answered(json({ name, range, source: src.kind, version: v.version, report: embeddedReport(v, report), skipped, tree, warnings, policy: { cooldownHours: policy.cooldownMs / HOUR, floor: policy.floor, strict: mode.strict } }, 200, { "cache-control": "no-store" }));
      }

      skipped.push({ version: v.version, reason: block, revokeReason: isWithheld(v.status) ? (v.status_reason ?? "no reason given") : null });

      if (skipped.length >= 20) break;
    }

    const newest = matches[0];
    const newestReport = newest ? reportFor(newest, at) : null;

    return answered(
      json(
        { error: `No version of ${name} matching ${range} passes the policy.`, name, range, version: null, skipped, newest: newest ? { version: newest.version, report: embeddedReport(newest, newestReport) } : null },
        422,
      ),
    );
  });

/** Whether every pending version now has a stored analysis or a decided outcome: one read for all of them. */
const landed = (pending: readonly PendingDep[]) =>
  Effect.gen(function* () {
    const decided = yield* (yield* Store).decidedAnalyses(pending);

    return pending.every((p) => decided.has(`${p.name} ${p.version}`));
  });

/** `strict=1` (or `true`) asks for strict mode; anything else, or nothing, is the default mode. */
const strictParam = (v: string | null | undefined): boolean => v === "1" || v === "true";

/**
 * GET /-/apm/v1/resolve: the newest version in range that passes the policy, and its dependency walk. A version in it
 * that is queued for analysis (the root or a dependency) is waited for: the registry waits up to RESOLVE_WAIT for the
 * queue to score it, polling the database, then answers from what landed. In the default mode what is still pending
 * then is a warning on a 200, like a low score or a dependency it could not look up; in strict mode (`strict=1`)
 * it is a 202 with the pending versions and Retry-After, a lookup that failed is a 503, and a low score a 422.
 */
export const resolveResponse = (url: URL) =>
  Effect.gen(function* () {
    const name = url.searchParams.get("name") ?? "";
    const range = url.searchParams.get("range") || "latest";
    const strict = strictParam(url.searchParams.get("strict"));

    const parsedPolicy = parsePolicy(url);

    if (parsedPolicy.kind === "invalid") return fail(400, parsedPolicy.error);
    const policy = parsedPolicy.policy;
    // A lower floor (apm add --force sends 0) applies to the named package only; its dependencies are
    // always checked at the default floor or the stricter one asked for. The cooldown is the one asked for.
    const treePolicy: Policy = { floor: Math.max(policy.floor, DEFAULT_POLICY.floor), cooldownMs: policy.cooldownMs };

    const first = yield* lookupOrUnknown(name);

    // the package itself could not be looked up: there is no version to install, and a retry may find one
    if (first === "unknown") {
      return json({ error: `${name} ${UNAVAILABLE_TEXT}. Nothing was installed; try again in a minute.`, name, range, version: null, unavailable: [{ dependency: name, via: [] }], retryAfter: PENDING_RETRY_AFTER_S }, 503, { "cache-control": "no-store", "retry-after": String(PENDING_RETRY_AFTER_S) });
    }

    let src = first;
    const wait = Option.getOrElse(yield* Effect.serviceOption(ResolveWait), () => RESOLVE_WAIT);
    const looks = Math.max(0, Math.ceil(wait.maxMs / Math.max(1, wait.pollMs)));
    let waited = 0;

    for (;;) {
      if (!src) return fail(404, `No package named ${name}.`);
      const pass = yield* resolvePass({ name, range, policy, treePolicy, src, mode: { strict, final: false } });

      if (pass.kind === "answer") return pass.response;

      // nothing landed yet: look again until it has or the wait is over, then walk again
      let ready = false;

      while (!ready && waited < looks) {
        yield* Effect.sleep(wait.pollMs);
        waited++;
        ready = yield* landed(pass.pending);
      }

      if (!ready && !strict) {
        // the wait is over: what landed is read afresh, and what is still pending is a warning
        const latest = yield* lookup(name);

        if (!latest) return fail(404, `No package named ${name}.`);
        const last = yield* resolvePass({ name, range, policy, treePolicy, src: latest, mode: { strict, final: true } });

        if (last.kind === "answer") return last.response;
      }

      if (!ready) {
        const listed = pass.pending.slice(0, MAX_UNCHECKED_LISTED);

        return json(
          {
            error: `${name}@${pass.version} is still being analysed: ${pass.pending.length === 1 ? "1 version has" : `${pass.pending.length} versions have`} no score yet (${listed.map((p) => `${p.name}@${p.version}`).join(", ")}${pass.pending.length > listed.length ? ", …" : ""}). Nothing was installed as if it passed; try again in a minute.`,
            name,
            range,
            version: pass.version,
            pending: listed,
            pendingCount: pass.pending.length,
            retryAfter: PENDING_RETRY_AFTER_S,
            skipped: pass.skipped,
          },
          202,
          { "cache-control": "no-store", "retry-after": String(PENDING_RETRY_AFTER_S) },
        );
      }

      // read afresh: a version the queue scored meanwhile comes back with its analysis
      src = yield* lookup(name);
    }
  });

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })), strict: z.boolean().optional() });

/** Packages one scan checks: signed in, and without a token. Each may mean an upstream packument and tarball. */
export const MAX_SCAN = 2000;
export const MAX_SCAN_ANONYMOUS = 200;

/** Upstream lookups one scan runs at once. */
const SCAN_CONCURRENCY = 8;

type ScanAdvisory = { package: string; version: string; level: "fatal" | "warn"; description: string; url: string | null };

type ScanUnchecked = { package: string; version: string; reason: string };

/** A version queued for analysis: not clean and not merely unchecked. The scanner waits for it, then warns (strict: blocks). */
type ScanPending = { package: string; version: string };

/**
 * One package's scan. `flagged`: what the default mode installs with a warning and strict mode refuses, as an
 * advisory at the level the mode gives it, with the warning itself and which list it also goes in.
 */
type ScanOne =
  | { kind: "clean" }
  | { kind: "advisory"; advisory: ScanAdvisory }
  | { kind: "flagged"; advisory: ScanAdvisory; warning: InstallWarning; list: "scored" | "unscorable" | "unavailable" }
  | { kind: "unchecked"; unchecked: ScanUnchecked }
  | { kind: "pending"; unchecked: ScanUnchecked };

const scanOne = (p: { name: string; version: string }, strict: boolean, at: number) =>
  Effect.gen(function* () {
    const { webUrl } = yield* RegistryConfig;
    const unchecked = (reason: string): ScanOne => ({ kind: "unchecked", unchecked: { package: p.name, version: p.version, reason } });
    const url = versionUrl(webUrl, p.name, p.version);
    const level = strict ? "fatal" : "warn";

    const flagged = (warning: InstallWarning, list: Extract<ScanOne, { kind: "flagged" }>["list"]): ScanOne => ({
      kind: "flagged",
      warning,
      list,
      // the link travels in `url`, which bun prints after the description
      advisory: { package: p.name, version: p.version, level, description: `${warningLines(warning).slice(0, -1).join("\n")}${strict ? "" : "\napm lets it install; APM_SCANNER_STRICT=1 refuses it."}`, url: warning.url },
    });

    const src = yield* lookupOrUnknown(p.name);

    // the registry or npm could not be asked: not clean, and kept apart from a version nobody has
    if (src === "unknown") return flagged(stateWarning({ kind: "unavailable", name: p.name, version: p.version, text: UNAVAILABLE_TEXT, url, via: [] }), "unavailable");

    if (src === null) return unchecked("not on this registry or upstream");
    const v0 = src.versions.find((x) => x.version === p.version);

    if (!v0) return unchecked("no such version");

    if (v0.status === "revoked" || v0.status === "revoke-pending") {
      const advisory: ScanAdvisory = { package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version} was revoked by its maintainer: ${v0.status_reason ?? "no reason given"}`, url };

      return { kind: "advisory", advisory } satisfies ScanOne;
    }

    // confirmed malicious by an apm reviewer: refused in every mode
    if (yield* reviewerConfirmed(v0)) {
      return { kind: "advisory", advisory: { package: p.name, version: p.version, level: "fatal", description: `${p.name}@${p.version}: apm reviewers confirmed this version is malicious.`, url } } satisfies ScanOne;
    }

    // a stored analysis of these exact bytes is reused; a version never analyzed is queued
    const v = yield* ensureAnalyzed(src, v0);
    const r = reportFor(v, at, { ignoreRecent: true });

    if (!r) {
      const why = notScored(src, v);

      if (why.kind === "queued") return { kind: "pending", unchecked: { package: p.name, version: p.version, reason: why.text } } satisfies ScanOne;

      // decided, not waiting: no score will come
      return flagged(stateWarning({ kind: "unscorable", name: p.name, version: p.version, text: why.text, url, via: [] }), "unscorable");
    }

    const w = scoreWarning({ name: p.name, version: p.version, report: r, floor: SCORE_FLOOR, url, via: [] });

    return w ? flagged(w, "scored") : ({ kind: "clean" } satisfies ScanOne);
  });

/**
 * POST /-/apm/v1/scan, the Bun scanner's question. A revoked version and one an apm reviewer confirmed malicious are
 * `fatal` advisories in every mode. A score under the floor, an incomplete analysis, a version apm cannot score and a
 * package the registry could not look up are `warn` advisories (strict: `fatal`), each with its warning in
 * `warnings`; `unscorable` and `unavailable` list the last two apart. A queued version is in `pending` (and in
 * `unchecked`, for scanners from before `pending`): the scanner asks again, then warns (strict: blocks).
 */
export const scanResponse = (req: Request, caller: Caller) =>
  Effect.gen(function* () {
    const at = yield* now;
    const body = yield* parseBody(req, ScanBody);
    const strict = body.strict === true || strictParam(new URL(req.url).searchParams.get("strict"));
    const signedIn = caller.kind === "user";
    const cap = signedIn ? MAX_SCAN : MAX_SCAN_ANONYMOUS;
    const seen = new Set<string>();

    const packages = body.packages.filter((p) => {
      const key = `${p.name}@${p.version}`;

      if (seen.has(key)) return false;
      seen.add(key);

      return true;
    });

    const advisories: ScanAdvisory[] = [];
    const warnings: InstallWarning[] = [];
    const unscorable: ScanUnchecked[] = [];
    const unavailable: ScanPending[] = [];
    // Versions the scan could not judge. Missing from `advisories` is not the same as clean.
    const unchecked: ScanUnchecked[] = [];
    // queued versions are listed twice: in `unchecked`, so a scanner from before `pending` never reads one as clean,
    // and in `pending`, which a scanner that knows it waits on
    const pending: ScanPending[] = [];
    const results = yield* Effect.forEach(packages.slice(0, cap), (p) => scanOne(p, strict, at), { concurrency: SCAN_CONCURRENCY });

    for (const r of results) {
      switch (r.kind) {
        case "advisory":
          advisories.push(r.advisory);
          break;
        case "flagged":
          advisories.push(r.advisory);
          warnings.push(r.warning);

          if (r.list === "unscorable") unscorable.push({ package: r.warning.name, version: r.warning.version, reason: r.warning.text });

          if (r.list === "unavailable") unavailable.push({ package: r.warning.name, version: r.warning.version });
          break;
        case "unchecked":
          unchecked.push(r.unchecked);
          break;
        case "pending":
          unchecked.push(r.unchecked);
          pending.push({ package: r.unchecked.package, version: r.unchecked.version });
          break;
        case "clean":
          break;
        default: {
          const _exhaustive: never = r;

          return _exhaustive;
        }
      }
    }

    const over = signedIn
      ? `a scan checks at most ${MAX_SCAN} packages; send the rest in another request`
      : `a scan without a token checks at most ${MAX_SCAN_ANONYMOUS} packages; sign in (apm login) to check up to ${MAX_SCAN}, or send the rest in another request`;

    for (const p of packages.slice(cap)) unchecked.push({ package: p.name, version: p.version, reason: over });
    const answer = { advisories, warnings, unchecked, pending, unscorable, unavailable, strict };

    return json(pending.length > 0 ? { ...answer, retryAfter: PENDING_RETRY_AFTER_S } : answer);
  });

const AuditBody = z.record(z.string(), z.array(z.string()));

type Audit = { advisories: Record<string, unknown[]>; unavailable: string[] };

const audit = (advisories: Record<string, unknown[]>, unavailable: string[]): Audit => ({ advisories, unavailable });

/** Local advisories plus the upstream's for names not published here. `unavailable` names packages whose upstream advisories could not be fetched. */
const collectAdvisories = (query: z.infer<typeof AuditBody>) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const { baseUrl } = yield* RegistryConfig;
    const upstream = yield* upstreamOrNull;
    const out: Record<string, unknown[]> = {};
    const upstreamQuery: Record<string, string[]> = {};

    for (const [name, versions] of Object.entries(query)) {
      if (!(yield* store.getPackage(name))) upstreamQuery[name] = versions;

      const list = (yield* store.advisoriesFor(name)).map((a) => ({
        id: a.id,
        url: `${baseUrl}package/${name}`,
        title: a.title,
        severity: a.severity,
        vulnerable_versions: a.versions.join(" || "),
        cwe: ["CWE-506"],
        cvss: { score: 10, vectorString: null },
      }));

      if (list.length > 0) out[name] = list;
    }

    if (upstream && Object.keys(upstreamQuery).length > 0) {
      const up = yield* upstream.advisories(upstreamQuery);

      switch (up.kind) {
        case "ok":
          for (const [name, list] of Object.entries(up.advisories)) out[name] = [...(out[name] ?? []), ...list];
          break;
        case "unavailable":
          return audit(out, Object.keys(upstreamQuery));
        default: {
          const _exhaustive: never = up;

          return _exhaustive;
        }
      }
    }

    return audit(out, []);
  });

/** npm's bulk advisory endpoint. When part of the answer could not be fetched it is a 503, never a clean {}. */
const bulkAdvisories = (req: Request) =>
  Effect.gen(function* () {
    const query = yield* parseBody(req, AuditBody);
    const audit = yield* collectAdvisories(query);

    if (audit.unavailable.length > 0) {
      return fail(503, `The upstream advisory service did not answer for ${audit.unavailable.length} package(s), so this audit would be incomplete. Try again shortly.`);
    }

    return json(audit.advisories);
  });

/** apm's audit: the same advisories, plus the packages whose advisories could not be fetched. */
const auditResponse = (req: Request) =>
  Effect.gen(function* () {
    const query = yield* parseBody(req, AuditBody);

    return json(yield* collectAdvisories(query));
  });

// ---------- upstream packuments and tarballs ----------
const ABBREV = [
  "name",
  "version",
  "dependencies",
  "optionalDependencies",
  "devDependencies",
  "bundleDependencies",
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
];

function upstreamPackument(base: string, src: Extract<Source, { kind: "upstream" }>, abbreviated: boolean, view: PackumentView | null, at: number): Record<string, unknown> {
  const kept = view ? src.versions.filter(view.keep) : src.versions;
  const versions: Record<string, unknown> = {};
  const time: Record<string, string> = {};

  for (const v of kept) {
    // a view's tarballs stay inside the view, so a lockfile written from it keeps being checked
    // a manifest past the limits apm reads is served without the fields past them: serializing it whole recurses
    // deep enough to overflow the stack and fail the request for every version of the package
    const doc: Record<string, unknown> = { ...servableManifest(v.manifest), dist: { tarball: tarballUrl(`${base}${view?.prefix ?? ""}`, src.name, v.version), shasum: v.shasum, integrity: v.integrity } };
    const r = reportFor(v, at);

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

  if (abbreviated) return { name: src.name, modified: new Date(at).toISOString(), "dist-tags": distTags, versions };

  return {
    _id: src.name,
    name: src.name,
    description: src.pkg.description,
    "dist-tags": distTags,
    versions,
    time,
    // npm's readme has no known owner here, so it is hidden while any version is withheld (withheld.ts)
    readme: readmeShown({ readme: src.pkg.readme, readme_version: null }, src.versions).text,
    maintainers: src.pkg.maintainers.map((name) => ({ name })),
  };
}

/** Packuments and tarballs of packages that only exist upstream; null for anything else. */
export const upstreamRoute = (req: Request, url: URL, viaSafe: boolean) =>
  Effect.gen(function* () {
    const upstream = yield* upstreamOrNull;

    if (!upstream || (req.method !== "GET" && req.method !== "HEAD")) return null;
    const p = url.pathname;

    if (p.startsWith("/-/")) return null;
    const sp = splitPath(p);

    if (!sp || (yield* (yield* Store).getPackage(sp.name))) return null;
    const src = yield* lookup(sp.name);

    if (!src || src.kind !== "upstream") return null;
    const at = yield* now;
    const { baseUrl } = yield* RegistryConfig;

    if (sp.rest[0] === "-" && sp.rest[1]) {
      const m = /^(.*)-(\d+\.\d+\.\d+.*)\.tgz$/.exec(sp.rest[1]);
      const version = m?.[2];

      if (!version) return fail(404, "Not found");
      const got = yield* upstream.tarball(src.pkg, version);

      switch (got.kind) {
        case "absent":
          return fail(404, `${src.name}@${version} is not published upstream.`);
        case "unavailable":
          return fail(502, `Upstream tarball unavailable: ${got.reason}.`);
        case "too-large":
          return fail(502, `Upstream tarball unavailable: ${tooLargeText(got.bytes)}.`);
        case "ok":
          break;
        default: {
          const _exhaustive: never = got;

          return _exhaustive;
        }
      }

      const v = src.versions.find((x) => x.version === version);

      if (viaSafe) {
        // the view serves only what passes its policy, the tarball route included
        const analyzed = v ? yield* ensureAnalyzed(src, v) : null;
        const block = analyzed ? policyBlock(analyzed, DEFAULT_POLICY, at) : "not listed upstream";

        if (block !== null) return fail(404, `${src.name}@${version} is not in this view: ${block}.`);
      } else if (v && !parseAnalysis(v.score)) {
        // Scoring a download happens off the request path: the queue consumer analyzes it.
        yield* (yield* Analysis).enqueue(src.name, version);
      }

      return new Response(req.method === "HEAD" ? null : got.bytes, { headers: { "content-type": "application/octet-stream", "content-length": String(got.bytes.length) } });
    }

    if (sp.rest.length > 0) return null;
    const abbreviated = (req.headers.get("accept") ?? "").includes("application/vnd.npm.install-v1+json");

    if (viaSafe) {
      // score the newest cooled versions before answering; anything left unscored stays hidden
      const cooled = src.versions
        .filter((v) => at - v.published_at >= DEFAULT_POLICY.cooldownMs)
        .sort((a, b) => newestFirst(a.version, b.version))
        .slice(0, 5);

      for (const v of cooled) yield* ensureAnalyzed(src, v);
    }

    const body = upstreamPackument(baseUrl, src, abbreviated, viaSafe ? safeView(at) : null, at);

    return json(body, 200, { "content-type": abbreviated ? "application/vnd.npm.install-v1+json; charset=utf-8" : "application/json", "cache-control": "no-cache" });
  });

// ---------- router ----------
/** The /-/apm/v1/* API (except the account routes), the advisory bulk endpoint and the merged search. Null when not ours. */
export const apmRoute = (req: Request, url: URL, caller: Caller) =>
  Effect.gen(function* () {
    const upstream = yield* upstreamOrNull;
    const p = url.pathname;

    if (p === "/-/npm/v1/security/advisories/bulk" && req.method === "POST") return yield* bulkAdvisories(req);

    if (p === "/-/v1/search" && upstream && (req.method === "GET" || req.method === "HEAD")) return yield* searchResponse(url);

    if (!p.startsWith("/-/apm/v1/")) return null;
    const rest = p.slice("/-/apm/v1/".length);

    if (req.method === "POST") {
      if (rest === "yank" || rest === "unyank" || rest === "revoke" || rest === "restore") return yield* handleState(req, caller, rest);

      if (rest === "incident") return yield* handleIncident(req, caller);

      if (rest === "owners") return yield* handleOwners(req, caller);

      if (rest === "scan") return yield* scanResponse(req, caller);

      if (rest === "audit") return yield* auditResponse(req);
    }

    if (req.method === "DELETE" && rest === "owners") return yield* handleOwners(req, caller);

    if (req.method === "HEAD" && rest.startsWith("packages/")) return yield* packageExists(rest.slice("packages/".length));

    if (req.method !== "GET") return fail(405, "Method not allowed");

    if (rest === "names") {
      const user = url.searchParams.get("user") ?? (caller.kind === "user" ? caller.user : yield* sessionUser(req));
      const part = url.searchParams.get("part");

      if (part !== null && !isNamePart(part)) return fail(400, `part must be one of ${NAME_PARTS.join(", ")}`);

      return json(yield* nameReport(url.searchParams.get("q") ?? "", user, part));
    }

    if (rest === "recent") return yield* recentResponse(url);

    if (rest === "recent-packages") return yield* recentPackagesResponse(url);

    if (rest === "popular-scores") return yield* popularScoresResponse(url);

    if (rest === "resolve") return yield* resolveResponse(url);

    if (rest === "me") return caller.kind === "user" ? json({ username: caller.user }) : fail(401, "Not logged in");

    if (rest.startsWith("score/")) {
      const sp = splitPath(`/${rest.slice("score/".length)}`);

      if (!sp) return fail(404, "Not found");
      const src = yield* lookup(sp.name);

      if (!src) return fail(404, "Not found");
      const spec = sp.rest[0];
      const version = spec ? (tagTarget(src.distTags, spec) ?? spec) : tagTarget(src.distTags, "latest");
      const v = src.versions.find((x) => x.version === version);

      if (!v) return fail(404, "No such version");

      return yield* scoreResponse(src, v);
    }

    if (rest.startsWith("packages/")) {
      const sp = splitPath(`/${rest.slice("packages/".length)}`);

      if (!sp) return fail(404, "Not found");

      if (sp.rest[0] === "events") return yield* eventsResponse(sp.name);

      if (sp.rest[0] === "versions" && sp.rest.length === 2 && sp.rest[1]) return yield* versionResponse(sp.name, sp.rest[1]);

      if (sp.rest.length === 0) return yield* packageResponse(sp.name);
    }

    return null;
  });

export const apmExtensions: Extensions = { onPublish, safeView, compactScore, searchScore: compactScore };

/** Pending revokes past their window become final; the cron writes it down and logs it. */
export const matureRevocations = Effect.gen(function* () {
  const store = yield* Store;
  const at = yield* now;

  for (const v of yield* store.matureRevocations(at - PENDING_MS)) {
    yield* store.addEvent({ package: v.package, kind: "revoke", actor: "registry", at, detail: { version: v.version, reason: "pending revoke became final after 24h" } });
  }
});

export { Blobs };
