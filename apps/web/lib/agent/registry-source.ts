// The agent views' port (./source.ts) over the real registry. Answers are parsed here, at the network boundary.
import "server-only";
import { z } from "zod";
import { ExcerptAnswer } from "../file-excerpt";
import { getExcerpt, getPackage, getRecent, getReview, getVersionScore, search, type Fetched } from "../registry";
import { fetchJson, logUnavailable, readCappedText, REGISTRY_TIMEOUT_MS, withTimeout } from "../registry-fetch";
import { registryFetch } from "../registry-transport";
import { encodeName, REGISTRY } from "../registry-url";
import { AlternativesPart, ExactPart, LookalikePart } from "../search-schema";
import { parseJson } from "./json";
import { parseResolve, type AgentSource, type NameReport, type ResolveOutcome } from "./source";

const NameReportWire = ExactPart.extend(LookalikePart.omit({ query: true, valid: true }).shape).extend(AlternativesPart.omit({ query: true, valid: true }).shape);

/** /resolve walks the dependency tree and may score a tarball first, so it gets longer than a plain read. */
const RESOLVE_TIMEOUT_MS = 25_000;

async function resolve(input: { name: string; range: string }): Promise<ResolveOutcome> {
  const path = `-/apm/v1/resolve?${new URLSearchParams({ name: input.name, range: input.range })}`;

  try {
    const res = await registryFetch(`${REGISTRY}${path}`, { cache: "no-store", headers: { accept: "application/json" }, signal: withTimeout(RESOLVE_TIMEOUT_MS) });
    const body = await readCappedText(res, 2 * 1024 * 1024);

    if (body.kind === "too-large") return { kind: "unavailable" };
    // a body that is not JSON reads as unavailable
    const out = parseResolve(res.status, parseJson(body.text)?.value ?? null);

    if (out.kind === "unavailable") logUnavailable("-/apm/v1/resolve", { kind: "status", status: res.status });

    return out;
  } catch (error) {
    logUnavailable("-/apm/v1/resolve", { kind: "network", message: error instanceof Error ? error.message : "fetch failed" });

    return { kind: "unavailable" };
  }
}

async function names(input: { name: string; scope: string | null }): Promise<NameReport | null> {
  const params = new URLSearchParams({ q: input.name });

  if (input.scope) params.set("user", input.scope);
  const r = await fetchJson({ url: `${REGISTRY}-/apm/v1/names?${params}`, schema: NameReportWire, timeoutMs: REGISTRY_TIMEOUT_MS });

  if (r.kind === "unavailable") logUnavailable("-/apm/v1/names", r.reason);

  return r.kind === "ok" ? r.value : null;
}

export const registrySource: AgentSource = {
  package: getPackage,
  versionScore: ({ name, version }) => getVersionScore(name, version),
  review: ({ name, version }) => getReview(name, version),
  resolve,
  search: ({ query }) => search(query),
  names,
  excerpt: (input): Promise<Fetched<ExcerptAnswer>> => getExcerpt(input),
};

const LatestScore = z.object({ version: z.string(), score: z.number(), grade: z.string() });

export type LatestScore = z.infer<typeof LatestScore>;

/** The latest version's score only, for the home page's popular list. A short budget: the list never waits long. */
export async function latestScore(name: string, timeoutMs: number): Promise<Fetched<LatestScore>> {
  return fetchJson({ url: `${REGISTRY}-/apm/v1/score/${encodeName(name)}`, schema: LatestScore, timeoutMs });
}

const RecentPackages = z.object({ packages: z.array(z.object({ name: z.string(), at: z.string() })) });

/** Packages for the sitemap: recent activity on this registry, then the npm packages it scored most recently. */
export async function sitemapPackages(): Promise<{ package: string; at: string }[]> {
  const [events, scored] = await Promise.all([
    getRecent(50),
    fetchJson({ url: `${REGISTRY}-/apm/v1/recent-packages?limit=100`, schema: RecentPackages }),
  ]);

  const fromEvents = events.kind === "ok" ? events.value.map((e) => ({ package: e.package, at: e.at })) : [];
  const fromScores = scored.kind === "ok" ? scored.value.packages.map((p) => ({ package: p.name, at: p.at })) : [];

  return [...fromEvents, ...fromScores];
}
