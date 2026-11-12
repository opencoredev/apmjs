// Server-side client for the apm registry API. Responses are parsed at this boundary.
import "server-only";
import { z } from "zod";

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

const NameCheck = z.object({
  query: z.string(),
  valid: z.boolean(),
  taken: z.boolean(),
  source: z.string().nullable(),
  available: z.boolean(),
  unknown: z.boolean().default(false),
  owners: z.array(z.string()),
  latest: z.object({ version: z.string(), score: z.number().nullable(), grade: z.string().nullable() }).nullable(),
  description: z.string().nullable(),
  conflicts: z.array(z.object({ name: z.string(), reason: z.string() })),
  similar: z.array(z.object({ name: z.string(), reason: z.string() })),
  lookalikes: z.array(z.object({ name: z.string(), reason: z.string() })),
  suggestions: z.array(z.object({ name: z.string(), available: z.boolean(), taken: z.boolean() })),
});
export type NameCheck = z.infer<typeof NameCheck>;

const Search = z.object({
  total: z.number(),
  objects: z.array(
    z.object({
      package: z.object({ name: z.string(), version: z.string(), description: z.string(), date: z.string(), publisher: z.object({ username: z.string() }) }),
      apmScore: z.object({ score: z.number(), grade: z.string(), signals: z.array(z.string()) }).nullable(),
    }),
  ),
});
export type SearchResult = z.infer<typeof Search>["objects"][number];

function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

async function getJson<T>(path: string, schema: z.ZodType<T>): Promise<T | null> {
  try {
    const res = await fetch(`${REGISTRY}${path}`, { cache: "no-store", headers: { accept: "application/json" } });
    if (!res.ok) return null;
    const parsed = schema.safeParse(await res.json());
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export const getPackage = (name: string) => getJson(`-/apm/v1/packages/${encodeName(name)}`, PackageInfo);
export const getEvents = async (name: string) => (await getJson(`-/apm/v1/packages/${encodeName(name)}/events`, Events))?.events ?? [];
export const checkName = (q: string) => getJson(`-/apm/v1/names?q=${encodeURIComponent(q)}`, NameCheck);
export const search = async (q: string) => (await getJson(`-/v1/search?text=${encodeURIComponent(q)}&size=25`, Search))?.objects ?? [];
