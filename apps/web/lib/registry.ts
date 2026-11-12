// Server-side client for the apm registry API. Responses are parsed at this boundary.
import "server-only";
import { cache } from "react";
import { z } from "zod";
import { encodeName, excerptApiPath, fileApiPath, packageApiPath, readmeApiPath, REGISTRY } from "./registry-url";
import { ExcerptAnswer } from "./file-excerpt";
import { POLICIES, type CachePolicy } from "./edge-cache";
import { fetchCachedJson, fetchJson, FILE_TIMEOUT_MS, logUnavailable, type Fetched, type FetchJsonOptions } from "./registry-fetch";
import { NAME_PART_SCHEMAS, type NamePart, type NamePartAnswer, type SearchAnswer, type SearchHit } from "./search-schema";
import { ReviewAnswer } from "./review-schema";
import { RepositoryField } from "./repository";

export type { Fetched } from "./registry-fetch";

// confidence arrived with apm-score-v4; older answers asserted every signal
const Signal = z.object({ id: z.string(), label: z.string(), points: z.number(), evidence: z.array(z.string()), confidence: z.enum(["confirmed", "possible"]).default("confirmed") });

export type Signal = z.infer<typeof Signal>;

/** Evidence an apm reviewer dismissed for this exact version: shown struck through, with the reason. */
const Dismissed = z.object({ signal: z.string(), file: z.string(), line: z.number(), evidence: z.array(z.string()), reason: z.string(), at: z.number() });

export type Dismissed = z.infer<typeof Dismissed>;

/** What a version can do (apm-score-v10), each with its evidence: shown beside the score, never scored on its own. */
const Capability = z.object({
  id: z.enum(["network", "env", "filesystem", "shell", "eval", "native", "install"]),
  label: z.string(),
  status: z.enum(["declared", "undeclared", "not-declared", "unused"]),
  basis: z.enum(["code", "text", "possible", "none"]),
  declared: z.string().optional(),
  evidence: z.array(z.string()),
  names: z.array(z.string()).optional(),
  outside: z.array(z.string()).optional(),
});

export type Capability = z.infer<typeof Capability>;

/** Whether the package declares its capabilities, and what apm could not use in the declaration. */
const Declaration = z.object({ kind: z.enum(["none", "declared"]), notes: z.array(z.string()) });

export type Declaration = z.infer<typeof Declaration>;

// added with apm-score-v10; an older registry or scorer sends neither
const CapabilityFields = { capabilities: z.array(Capability).default([]), declaration: Declaration.nullish() };

// what names an evidence item for a reviewer's dismissal; added with dismissals, an older registry leaves them out.
// `redacted`: the version is revoked and its signals carry no evidence lines. Required: a registry too old to send it
// may not redact either, so its answer is refused as unreadable rather than shown (packages/infra/deploy.ts).
const Reviewable = { scorer: z.string().optional(), digest: z.string().nullish(), dismissed: z.array(Dismissed).default([]), redacted: z.boolean() };

const Facts = z.object({
  moduleFormat: z.enum(["esm", "cjs", "dual"]),
  types: z.enum(["bundled", "none"]),
  installScripts: z.boolean(),
  hasBin: z.boolean(),
  license: z.string().nullable(),
  fileCount: z.number(),
  unpackedSize: z.number(),
  dependencyCount: z.number(),
});

export type Facts = z.infer<typeof Facts>;

/** A version's full score as the package answer (latest) and the versions route (any version) carry it. */
const PackageScore = z.object({ score: z.number(), grade: z.string(), signals: z.array(Signal), notChecked: z.array(z.string()).optional(), ...Reviewable, ...CapabilityFields });

const PackageInfo = z.object({
  name: z.string(),
  source: z.enum(["local", "upstream"]),
  description: z.string(),
  readme: z.string(),
  // the version whose publish wrote the readme, null when unknown or hidden. Required, like `redacted`: a registry that
  // does not send it does not know whose readme it is, so it can't hide one a revoke took (packages/infra/deploy.ts)
  readmeVersion: z.string().nullable(),
  // added after apm-score-v5; an older registry leaves it out
  repository: RepositoryField.nullish(),
  // added with the readme fallback; raw manifest strings, made safe by package-links.ts before they are links
  homepage: z.string().nullish(),
  bugs: z.string().nullish(),
  distTags: z.record(z.string(), z.string()),
  maintainers: z.array(z.string()),
  latest: z.string().nullable(),
  facts: Facts.nullable(),
  score: PackageScore.nullable(),
  versions: z.array(
    z.object({
      version: z.string(),
      publishedAt: z.string(),
      publishedBy: z.string(),
      status: z.string(),
      statusReason: z.string().nullable(),
      deprecated: z.string().nullable(),
      score: z.number().nullable(),
      grade: z.string().nullable(),
    }),
  ),
});

export type PackageInfo = z.infer<typeof PackageInfo>;

const Events = z.object({ events: z.array(z.object({ kind: z.string(), actor: z.string(), at: z.string(), detail: z.unknown() })) });

export type PackageEvent = z.infer<typeof Events>["events"][number];

// One object of /-/v1/search. Read per object so one odd upstream hit can't empty the list.
const WireHit = z.object({
  source: z.enum(["local", "npm"]).default("local"),
  package: z.object({ name: z.string(), version: z.string(), description: z.string().nullish(), date: z.string().nullish() }),
  apmScore: z.object({ score: z.number(), grade: z.string() }).nullish(),
  downloads: z.object({ weekly: z.number() }).nullish(),
});

const WireSearch = z.object({ total: z.number(), upstreamFailed: z.boolean().default(false), objects: z.array(z.unknown()) });

const Recent = z.object({
  events: z.array(
    z.object({
      package: z.string(),
      version: z.string(),
      kind: z.enum(["publish", "yank", "unyank", "revoke", "restore"]),
      actor: z.string(),
      at: z.string(),
      reason: z.string().nullable(),
      status: z.string().nullable(),
      score: z.number().nullable(),
      grade: z.string().nullable(),
    }),
  ),
});

export type RecentEvent = z.infer<typeof Recent>["events"][number];

/**
 * Reads a registry path. Failures other than a 404 are logged here, once, with the path and the reason. Read from the
 * registry every time unless `cache` is set, which only source-free answers may set (fetchCachedJson); a read that
 * sends `headers` (a visitor's cookie) is never cached.
 */
async function getJson<T>(
  path: string,
  schema: z.ZodType<T>,
  opts: { signal?: AbortSignal; headers?: HeadersInit; cache?: { policy: CachePolicy; keep: (value: T) => boolean } } = {},
): Promise<Fetched<T>> {
  const options: FetchJsonOptions<T> = { url: `${REGISTRY}${path}`, schema, signal: opts.signal };

  if (opts.headers !== undefined) options.headers = opts.headers;
  const result = opts.cache !== undefined && opts.headers === undefined ? await fetchCachedJson({ ...options, cache: opts.cache.policy, keep: opts.cache.keep }) : await fetchJson(options);

  if (result.kind === "unavailable" && !opts.signal?.aborted) logUnavailable(path.split("?")[0] ?? path, result.reason);

  return result;
}

/**
 * A package's answer, with its readme and its latest score's evidence: read from the registry on every view, and
 * shared within one request only (React cache), so the page and its metadata read it once.
 */
export const getPackage = cache((name: string): Promise<Fetched<PackageInfo>> => getJson(packageApiPath(name), PackageInfo));

export async function getEvents(name: string): Promise<Fetched<PackageEvent[]>> {
  const r = await getJson(`-/apm/v1/packages/${encodeName(name)}/events`, Events, { cache: { policy: POLICIES.events, keep: () => true } });

  return r.kind === "ok" ? { kind: "ok", value: r.value.events } : r;
}

const reviewPath = (name: string, version: string): string => `-/apm/v1/review/${encodeName(name)}/${encodeURIComponent(version)}`;

/**
 * The public AI review of one version, read from the registry on every view (its findings quote the package). "missing"
 * when the registry has AI review off or does not know the version.
 */
export const getReview = (name: string, version: string): Promise<Fetched<ReviewAnswer>> => getJson(reviewPath(name, version), ReviewAnswer);

const VersionInfo = z.object({ version: z.string(), status: z.string(), statusReason: z.string().nullable(), deprecated: z.string().nullable(), facts: Facts.nullable(), score: PackageScore.nullable() });

/** One version's state, facts and score, whatever its age (the package answer lists the newest 200). */
export const getVersionInfo = (name: string, version: string): Promise<Fetched<z.infer<typeof VersionInfo>>> => getJson(`-/apm/v1/packages/${encodeName(name)}/versions/${encodeURIComponent(version)}`, VersionInfo);

const VersionScore = z.object({ version: z.string(), score: z.number(), grade: z.string(), signals: z.array(Signal), notChecked: z.array(z.string()).optional(), ...Reviewable, ...CapabilityFields });

export type VersionScore = z.infer<typeof VersionScore>;

/** One version's full score, for a version other than latest, read from the registry on every view (its evidence quotes the package). */
export const getVersionScore = (name: string, version: string): Promise<Fetched<VersionScore>> =>
  getJson(`-/apm/v1/score/${encodeName(name)}/${encodeURIComponent(version)}`, VersionScore);

const FileHead = { name: z.string(), version: z.string(), path: z.string(), size: z.number() };

const FileAnswer = z.discriminatedUnion("kind", [
  z.object({ ...FileHead, kind: z.literal("text"), text: z.string() }),
  z.object({ ...FileHead, kind: z.literal("binary") }),
  z.object({ ...FileHead, kind: z.literal("too-large"), limit: z.number() }),
]);

export type FileAnswer = z.infer<typeof FileAnswer>;

/** A 1 MB file is at most a few MB as JSON (escapes). */
const FILE_MAX_BYTES = 8 * 1024 * 1024;

/** One file of one version, as text, or why it isn't shown. Read from the registry on every view, which refuses a revoked version. */
export async function getFile(input: { name: string; version: string; path: string }): Promise<Fetched<FileAnswer>> {
  const path = fileApiPath(input);
  const result = await fetchJson({ url: `${REGISTRY}${path}`, schema: FileAnswer, maxBytes: FILE_MAX_BYTES, timeoutMs: FILE_TIMEOUT_MS });

  if (result.kind === "unavailable") logUnavailable(path.split("?")[0] ?? path, result.reason);

  return result;
}

/** Lines around one line of a file of any size (the file view's excerpt of a file over 1 MB). */
export async function getExcerpt(input: { name: string; version: string; path: string; line: number; context: number }): Promise<Fetched<ExcerptAnswer>> {
  const path = excerptApiPath(input);
  const result = await fetchJson({ url: `${REGISTRY}${path}`, schema: ExcerptAnswer, timeoutMs: FILE_TIMEOUT_MS });

  // a line past the end (416) and a revoked version (410) are answers the view explains, not outages
  if (result.kind === "unavailable" && !(result.reason.kind === "status" && (result.reason.status === 416 || result.reason.status === 410))) logUnavailable(path.split("?")[0] ?? path, result.reason);

  return result;
}

/** The README npm would pick from a version's tarball, for packages whose packument has no readme. "missing" when there is none. */
export async function getTarballReadme(input: { name: string; version: string }): Promise<Fetched<FileAnswer>> {
  const path = readmeApiPath(input);
  const result = await fetchJson({ url: `${REGISTRY}${path}`, schema: FileAnswer, maxBytes: FILE_MAX_BYTES, timeoutMs: FILE_TIMEOUT_MS });

  if (result.kind === "unavailable") logUnavailable(path, result.reason);

  return result;
}

export async function getRecent(limit: number): Promise<Fetched<RecentEvent[]>> {
  const r = await getJson(`-/apm/v1/recent?limit=${limit}`, Recent);

  return r.kind === "ok" ? { kind: "ok", value: r.value.events } : r;
}

/** One part of the name check. `cookie` is the visitor's session, so alternatives are checked under their own scope. */
export async function checkNamePart<P extends NamePart>(input: { q: string; part: P; signal?: AbortSignal; cookie?: string | null }): Promise<NamePartAnswer[P] | null> {
  const { q, part } = input;
  const r = await getJson(`-/apm/v1/names?q=${encodeURIComponent(q)}&part=${part}`, NAME_PART_SCHEMAS[part], input.cookie ? { signal: input.signal, headers: { cookie: input.cookie } } : { signal: input.signal });

  return r.kind === "ok" ? r.value : null;
}

/** A search object from npm. One with no source is the registry's own (WireHit's default), so it is not one of these. */
const NpmObject = z.object({ source: z.literal("npm") });

/**
 * Whether a search answer is npm's packages only. A local package's description and keywords change the moment one of
 * its versions is revoked (the revoked publish's text is withheld), so an answer with a local package is never cached.
 */
export function npmOnly(wire: { objects: readonly unknown[] }): boolean {
  return wire.objects.every((o) => NpmObject.safeParse(o).success);
}

/** Registry search (apm packages merged with npm's), trimmed to what the search page shows. Null when the registry is down. */
export async function search(q: string, signal?: AbortSignal): Promise<SearchAnswer | null> {
  const r = await getJson(`-/v1/search?text=${encodeURIComponent(q)}&size=20`, WireSearch, { signal, cache: { policy: POLICIES.search, keep: npmOnly } });

  if (r.kind !== "ok") return null;
  const wire = r.value;
  const hits: SearchHit[] = [];

  for (const raw of wire.objects) {
    const o = WireHit.safeParse(raw);

    if (!o.success) continue;
    const { package: p } = o.data;
    hits.push({
      name: p.name,
      version: p.version,
      description: p.description ?? "",
      date: p.date ?? null,
      source: o.data.source,
      score: o.data.apmScore ?? null,
      weeklyDownloads: o.data.downloads?.weekly ?? null,
    });
  }

  return { query: q, hits, total: wire.total, upstreamFailed: wire.upstreamFailed };
}
