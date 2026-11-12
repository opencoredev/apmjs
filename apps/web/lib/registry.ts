// Server-side client for the apm registry API. Responses are parsed at this boundary.
import "server-only";
import { z } from "zod";
import { NAME_PART_SCHEMAS, type NamePart, type NamePartAnswer, type SearchAnswer, type SearchHit } from "./search-schema";

export const REGISTRY = (process.env.APM_REGISTRY ?? "http://127.0.0.1:4873/").replace(/\/?$/, "/");

const Signal = z.object({ id: z.string(), label: z.string(), points: z.number(), evidence: z.array(z.string()) });

export type Signal = z.infer<typeof Signal>;

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
  distTags: z.record(z.string(), z.string()),
  maintainers: z.array(z.string()),
  latest: z.string().nullable(),
  facts: Facts.nullable(),
  score: z.object({ score: z.number(), grade: z.string(), signals: z.array(Signal), notChecked: z.array(z.string()).optional() }).nullable(),
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

function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

async function getJson<T>(path: string, schema: z.ZodType<T>, signal?: AbortSignal): Promise<T | null> {
  try {
    const res = await fetch(`${REGISTRY}${path}`, { cache: "no-store", headers: { accept: "application/json" }, signal });

    if (!res.ok) return null;
    const parsed = schema.safeParse(await res.json());

    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export const getPackage = (name: string) => getJson(`-/apm/v1/packages/${encodeName(name)}`, PackageInfo);
export const getEvents = async (name: string) => (await getJson(`-/apm/v1/packages/${encodeName(name)}/events`, Events))?.events ?? [];
export const getRecent = async (limit: number) => (await getJson(`-/apm/v1/recent?limit=${limit}`, Recent))?.events ?? [];

export async function checkNamePart<P extends NamePart>(q: string, part: P, signal?: AbortSignal): Promise<NamePartAnswer[P] | null> {
  return getJson(`-/apm/v1/names?q=${encodeURIComponent(q)}&part=${part}`, NAME_PART_SCHEMAS[part], signal);
}

/** Registry search (apm packages merged with npm's), trimmed to what the search page shows. Null when the registry is down. */
export async function search(q: string, signal?: AbortSignal): Promise<SearchAnswer | null> {
  const wire = await getJson(`-/v1/search?text=${encodeURIComponent(q)}&size=20`, WireSearch, signal);

  if (!wire) return null;
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
