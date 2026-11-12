// Server-side client for the apm registry API. Responses are parsed at this boundary.
import "server-only";
import { z } from "zod";
import { encodeName, excerptApiPath, fileApiPath, packageApiPath, readmeApiPath, REGISTRY, servableKey } from "./registry-url";
import { ExcerptAnswer } from "./file-excerpt";
import { POLICIES, type CachePolicy } from "./edge-cache";
import { fetchJson, logUnavailable, MAX_REGISTRY_TIMEOUT_MS, type Fetched, type FetchJsonOptions, type SourceGate } from "./registry-fetch";
import { packageGate, reviewGate, scoreGate } from "./source-gates";
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

// what names an evidence item for a reviewer's dismissal; added with dismissals, an older registry leaves them out.
// `redacted`: the version is revoked and its evidence names files and lines only; added with that redaction.
const Reviewable = { scorer: z.string().optional(), digest: z.string().nullish(), dismissed: z.array(Dismissed).default([]), redacted: z.boolean().default(false) };

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

const PackageInfo = z.object({
  name: z.string(),
  source: z.enum(["local", "upstream"]),
  description: z.string(),
  readme: z.string(),
  // added after apm-score-v5; an older registry leaves it out
  repository: RepositoryField.nullish(),
  // added with the readme fallback; raw manifest strings, made safe by package-links.ts before they are links
  homepage: z.string().nullish(),
  bugs: z.string().nullish(),
  distTags: z.record(z.string(), z.string()),
  maintainers: z.array(z.string()),
  latest: z.string().nullable(),
  facts: Facts.nullable(),
  score: z.object({ score: z.number(), grade: z.string(), signals: z.array(Signal), notChecked: z.array(z.string()).optional(), ...Reviewable }).nullable(),
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
 * Reads a registry path. Failures other than a 404 are logged here, once, with the path and the reason. With `cache`,
 * the answer comes from the edge cache when it has one; a read that sends `headers` (a visitor's cookie) never does.
 */
async function getJson<T>(path: string, schema: z.ZodType<T>, opts: { signal?: AbortSignal; headers?: HeadersInit; cache?: CachePolicy; gate?: SourceGate<T> } = {}): Promise<Fetched<T>> {
  const options: FetchJsonOptions<T> = { url: `${REGISTRY}${path}`, schema, signal: opts.signal };

  if (opts.headers !== undefined) options.headers = opts.headers;
  else if (opts.cache !== undefined) options.cache = opts.cache;

  if (opts.gate !== undefined) options.gate = opts.gate;
  const signal = opts.signal;
  const result = await fetchJson(options);

  if (result.kind === "unavailable" && !signal?.aborted) logUnavailable(path.split("?")[0] ?? path, result.reason);

  return result;
}

export const getPackage = (name: string): Promise<Fetched<PackageInfo>> => getJson(packageApiPath(name), PackageInfo, { cache: POLICIES.package, gate: packageGate() });

export async function getEvents(name: string): Promise<Fetched<PackageEvent[]>> {
  const r = await getJson(`-/apm/v1/packages/${encodeName(name)}/events`, Events, { cache: POLICIES.events });

  return r.kind === "ok" ? { kind: "ok", value: r.value.events } : r;
}

/** The public AI review of one version. "missing" when the registry has AI review off or does not know the version. */
export const getReview = (name: string, version: string): Promise<Fetched<ReviewAnswer>> => getJson(`-/apm/v1/review/${encodeName(name)}/${encodeURIComponent(version)}`, ReviewAnswer, { cache: POLICIES.review, gate: reviewGate() });

const VersionScore = z.object({ version: z.string(), score: z.number(), grade: z.string(), signals: z.array(Signal), notChecked: z.array(z.string()).optional(), ...Reviewable });

/** One version's full score, for a version other than latest. */
export const getVersionScore = (name: string, version: string): Promise<Fetched<z.infer<typeof VersionScore>>> =>
  getJson(`-/apm/v1/score/${encodeName(name)}/${encodeURIComponent(version)}`, VersionScore, { cache: POLICIES.versionScore, gate: scoreGate() });

const FileHead = { name: z.string(), version: z.string(), path: z.string(), size: z.number() };

const FileAnswer = z.discriminatedUnion("kind", [
  z.object({ ...FileHead, kind: z.literal("text"), text: z.string() }),
  z.object({ ...FileHead, kind: z.literal("binary") }),
  z.object({ ...FileHead, kind: z.literal("too-large"), limit: z.number() }),
]);

export type FileAnswer = z.infer<typeof FileAnswer>;

/** A 1 MB file is at most a few MB as JSON (escapes), and the first read of a big upstream tarball takes a while. */
const FILE_MAX_BYTES = 8 * 1024 * 1024;
const FILE_TIMEOUT_MS = MAX_REGISTRY_TIMEOUT_MS;

/** One file of one version, as text, or why it isn't shown. */
export async function getFile(input: { name: string; version: string; path: string }): Promise<Fetched<FileAnswer>> {
  const path = fileApiPath(input);
  const result = await fetchJson({ url: `${REGISTRY}${path}`, schema: FileAnswer, maxBytes: FILE_MAX_BYTES, timeoutMs: FILE_TIMEOUT_MS, cache: POLICIES.versionFile, servable: servableKey(input) });

  if (result.kind === "unavailable") logUnavailable(path.split("?")[0] ?? path, result.reason);

  return result;
}

/** Lines around one line of a file of any size (the file view's excerpt of a file over 1 MB). */
export async function getExcerpt(input: { name: string; version: string; path: string; line: number; context: number }): Promise<Fetched<ExcerptAnswer>> {
  const path = excerptApiPath(input);
  const result = await fetchJson({ url: `${REGISTRY}${path}`, schema: ExcerptAnswer, timeoutMs: FILE_TIMEOUT_MS, cache: POLICIES.versionFile, servable: servableKey(input) });

  // a line past the end (416) is an answer the view explains, not an outage
  if (result.kind === "unavailable" && !(result.reason.kind === "status" && result.reason.status === 416)) logUnavailable(path.split("?")[0] ?? path, result.reason);

  return result;
}

/** The README npm would pick from a version's tarball, for packages whose packument has no readme. "missing" when there is none. */
export async function getTarballReadme(input: { name: string; version: string }): Promise<Fetched<FileAnswer>> {
  const path = readmeApiPath(input);
  const result = await fetchJson({ url: `${REGISTRY}${path}`, schema: FileAnswer, maxBytes: FILE_MAX_BYTES, timeoutMs: FILE_TIMEOUT_MS, cache: POLICIES.versionFile, servable: servableKey(input) });

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

/** Registry search (apm packages merged with npm's), trimmed to what the search page shows. Null when the registry is down. */
export async function search(q: string, signal?: AbortSignal): Promise<SearchAnswer | null> {
  const r = await getJson(`-/v1/search?text=${encodeURIComponent(q)}&size=20`, WireSearch, { signal, cache: POLICIES.search });

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
