// Versions the OSSF malicious-packages feed (github.com/ossf/malicious-packages) lists, read through OSV's batch query
// (api.osv.dev). The feed's advisories carry MAL- ids and report malicious code in exactly the versions they name, so a
// listed name@version from npm is refused in every mode, like one an apm reviewer confirmed, and the answer cites the
// ids. Only the exact version counts: getsolara@1.0.1 is listed, the security-holding getsolara@1.0.0 npm serves today
// is not. A package published on this registry is not npm's, so callers ask only about npm's (listedOnNpm in apm.ts).
//
// One request spends at most REQUEST_BUDGET_MS waiting on OSV, across every lookup it makes (a resolve's root pages,
// its walk and the walk again after a wait): the feed is built per request, and only time spent waiting on OSV counts,
// so a slow walk does not use it up. Once it is spent, or OSV failed once, the request reads only what is cached. A lookup OSV does not answer in full is logged, reads as nothing listed
// (an outage of the feed must not stop installs) and is not kept; a full answer is kept per isolate for CACHE_MS.
import { Context, Effect, Layer, Option, Result } from "effect";
import { z } from "zod";
import { isValidPackageName } from "@apm/core";

export type PackageVersion = { readonly name: string; readonly version: string };

/** A version the feed lists, with its MAL- advisory ids. */
export type ListedMalicious = { name: string; version: string; ids: string[] };

export class KnownMalicious extends Context.Service<KnownMalicious, { readonly lookup: (pkgs: readonly PackageVersion[]) => Effect.Effect<ListedMalicious[]> }>()("@apm/registry/KnownMalicious") {}

/** How long a lookup's answer is kept. A version newly listed is refused within this long. */
const CACHE_MS = 10 * 60_000;
const MAX_CACHED = 20_000;

/** OSV's limit on one batch query. */
export const OSV_BATCH = 1000;

/** What one request may spend waiting on OSV, all its lookups together. */
export const REQUEST_BUDGET_MS = 3_000;

/** Pages of one version's advisories followed past the batch answer's first. */
const MAX_PAGES = 3;
const MAX_VERSION_LENGTH = 256;

const Vulns = z.array(z.object({ id: z.string() })).optional();
const BatchAnswer = z.object({ results: z.array(z.object({ vulns: Vulns, next_page_token: z.string().optional() })) });
const QueryAnswer = z.object({ vulns: Vulns, next_page_token: z.string().optional() });

/** One version asked about, and the two request shapes OSV takes. */
type OsvQuery = { package: { name: string; ecosystem: "npm" }; version: string };

type OsvBatchQuery = { queries: OsvQuery[] };

type OsvPageQuery = OsvQuery & { page_token: string };

const keyOf = (p: PackageVersion): string => `${p.name}@${p.version}`;

/** An npm coordinate worth asking about: a valid name and a version of a plain shape. */
const askable = (p: PackageVersion): boolean => isValidPackageName(p.name) && p.version.length > 0 && p.version.length <= MAX_VERSION_LENGTH && /^[\w.+-]+$/.test(p.version);

/** The isolate's answers, by OSV root and name@version, oldest first: a request's layer is built per request, this outlives it. */
const CACHE = new Map<string, { ids: string[]; until: number }>();

function remember(key: string, ids: string[], until: number): void {
  CACHE.delete(key);
  CACHE.set(key, { ids, until });

  for (const oldest of CACHE.keys()) {
    if (CACHE.size <= MAX_CACHED) break;
    CACHE.delete(oldest);
  }
}

const malOnly = (vulns: z.infer<typeof Vulns>): string[] => (vulns ?? []).map((v) => v.id).filter((id) => id.startsWith("MAL-"));

/** The live feed at `baseUrl` (OSV's API root, ending in a slash), with one request's budget. */
export function osvFeed(baseUrl: string, fetcher: typeof fetch = fetch): Layer.Layer<KnownMalicious> {
  return Layer.sync(KnownMalicious, () => {
    /** Time this request has spent waiting on OSV, and whether it stopped asking (a failure). */
    let spentMs = 0;
    let stopped = false;
    const cacheKey = (p: PackageVersion): string => `${baseUrl} ${keyOf(p)}`;

    /** POSTs `body` to OSV within the request's budget and parses the answer with `schema`. */
    const post = <S extends z.ZodType>(path: "v1/querybatch" | "v1/query", body: OsvBatchQuery | OsvPageQuery, schema: S) =>
      Effect.tryPromise({
        try: async (): Promise<z.output<S>> => {
          const left = REQUEST_BUDGET_MS - spentMs;

          if (left <= 0) throw new Error("the request's OSV budget is spent");
          const t0 = Date.now();

          try {
            const res = await fetcher(`${baseUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(left) });

            if (res.status !== 200) {
              await res.body?.cancel();
              throw new Error(`OSV answered ${res.status}`);
            }

            const parsed = schema.safeParse(await res.json());

            if (!parsed.success) throw new Error("OSV answered in an unexpected shape");

            return parsed.data;
          } finally {
            spentMs += Date.now() - t0;
          }
        },
        catch: (cause) => cause,
      });

    const queryOf = (p: PackageVersion): OsvQuery => ({ package: { name: p.name, ecosystem: "npm" }, version: p.version });

    /**
     * The MAL- ids for each of `chunk`, in order: null for a version whose later pages could not be read and that
     * shows no MAL- id so far (unresolved: not kept). Fails only when the batch itself was not answered.
     */
    const ask = (chunk: readonly PackageVersion[]) =>
      Effect.gen(function* () {
        const batch = yield* post("v1/querybatch", { queries: chunk.map(queryOf) }, BatchAnswer);

        if (batch.results.length !== chunk.length) return yield* Effect.fail(new Error("OSV answered in an unexpected shape"));

        return yield* Effect.forEach(chunk, (p, j) =>
          Effect.gen(function* () {
            const first = batch.results[j];
            const ids = malOnly(first?.vulns);
            let token = first?.next_page_token;

            for (let page = 0; token !== undefined && ids.length === 0; page++) {
              const next = page < MAX_PAGES ? yield* Effect.result(post("v1/query", { ...queryOf(p), page_token: token }, QueryAnswer)) : null;

              if (next === null || Result.isFailure(next)) {
                console.error(JSON.stringify({ event: "osv-page", name: p.name, version: p.version, error: next === null ? "more pages than apm reads" : String(next.failure) }));

                return null;
              }

              ids.push(...malOnly(next.success.vulns));
              token = next.success.next_page_token;
            }

            return ids;
          }),
        );
      });

    return KnownMalicious.of({
      lookup: (pkgs) =>
        Effect.gen(function* () {
          const now = Date.now();
          const wanted = new Map(pkgs.filter(askable).map((p) => [keyOf(p), p]));
          const known = new Map<string, string[]>();
          const missing: PackageVersion[] = [];

          for (const [key, p] of wanted) {
            const hit = CACHE.get(cacheKey(p));

            if (hit && hit.until > now) known.set(key, hit.ids);
            else missing.push(p);
          }

          for (let i = 0; i < missing.length && !stopped && spentMs < REQUEST_BUDGET_MS; i += OSV_BATCH) {
            const chunk = missing.slice(i, i + OSV_BATCH);
            const got = yield* Effect.result(ask(chunk));

            if (Result.isFailure(got)) {
              console.error(JSON.stringify({ event: "osv-lookup", packages: chunk.length, error: String(got.failure) }));
              // no more waiting on OSV in this request: what is cached still counts
              stopped = true;
              break;
            }

            chunk.forEach((p, j) => {
              const ids = got.success[j];

              if (ids === null || ids === undefined) return;
              remember(cacheKey(p), ids, now + CACHE_MS);
              known.set(keyOf(p), ids);
            });
          }

          return [...wanted].flatMap(([key, p]) => {
            const ids = known.get(key) ?? [];

            return ids.length > 0 ? [{ name: p.name, version: p.version, ids }] : [];
          });
        }),
    });
  });
}

/** The versions among `pkgs` the feed lists; none when this registry runs without the feed. */
export const listedMalicious = (pkgs: readonly PackageVersion[]) =>
  Effect.gen(function* () {
    const feed = yield* Effect.serviceOption(KnownMalicious);

    return Option.isNone(feed) || pkgs.length === 0 ? [] : yield* feed.value.lookup(pkgs);
  });

/** Why a listed version is refused, citing its advisories. */
export function maliciousText(m: ListedMalicious): string {
  return `known malicious: the OSSF malicious-packages feed lists ${m.name}@${m.version} (${m.ids.join(", ")})`;
}
