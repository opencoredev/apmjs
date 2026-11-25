// Versions the OSSF malicious-packages feed (github.com/ossf/malicious-packages) lists, read through OSV's batch query
// (api.osv.dev). The feed's advisories carry MAL- ids and report malicious code in exactly the versions they name, so a
// listed name@version is refused in every mode, like one an apm reviewer confirmed, and the answer cites the ids. Only
// the exact version counts: getsolara@1.0.1 is listed, the security-holding getsolara@1.0.0 npm serves today is not.
// A lookup OSV does not answer is logged and reads as nothing listed (an outage of the feed must not stop installs),
// and is not kept; an answer is kept per isolate for CACHE_MS, so a hot package costs one query per isolate.
import { Context, Effect, Layer, Option, Result } from "effect";
import { z } from "zod";

export type PackageVersion = { readonly name: string; readonly version: string };

/** A version the feed lists, with its MAL- advisory ids. */
export type ListedMalicious = { name: string; version: string; ids: string[] };

export class KnownMalicious extends Context.Service<KnownMalicious, { readonly lookup: (pkgs: readonly PackageVersion[]) => Effect.Effect<ListedMalicious[]> }>()("@apm/registry/KnownMalicious") {}

/** How long a lookup's answer is kept. A version newly listed is refused within this long. */
const CACHE_MS = 10 * 60_000;
const MAX_CACHED = 20_000;

/** OSV's limit on one batch query. */
const BATCH = 1000;
const TIMEOUT_MS = 3_000;

const BatchAnswer = z.object({ results: z.array(z.object({ vulns: z.array(z.object({ id: z.string() })).optional() })) });

const keyOf = (p: PackageVersion): string => `${p.name}@${p.version}`;

/** The isolate's answers, by OSV root and name@version: a request's layer is built per request, this outlives it. */
const CACHE = new Map<string, { ids: string[]; until: number }>();

/** The live feed at `baseUrl` (OSV's API root, ending in a slash). */
export function osvFeed(baseUrl: string, fetcher: typeof fetch = fetch): Layer.Layer<KnownMalicious> {
  const cacheKey = (p: PackageVersion): string => `${baseUrl} ${keyOf(p)}`;

  const query = (pkgs: readonly PackageVersion[]) =>
    Effect.tryPromise({
      try: async (): Promise<string[][]> => {
        const res = await fetcher(`${baseUrl}v1/querybatch`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ queries: pkgs.map((p) => ({ package: { name: p.name, ecosystem: "npm" }, version: p.version })) }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });

        if (res.status !== 200) {
          await res.body?.cancel();
          throw new Error(`OSV answered ${res.status}`);
        }

        const parsed = BatchAnswer.safeParse(await res.json());

        if (!parsed.success || parsed.data.results.length !== pkgs.length) throw new Error("OSV answered in an unexpected shape");

        return parsed.data.results.map((r) => (r.vulns ?? []).map((v) => v.id).filter((id) => id.startsWith("MAL-")));
      },
      catch: (cause) => cause,
    });

  return Layer.succeed(
    KnownMalicious,
    KnownMalicious.of({
      lookup: (pkgs) =>
        Effect.gen(function* () {
          const now = Date.now();
          const wanted = new Map(pkgs.map((p) => [keyOf(p), p]));
          const known = new Map<string, string[]>();
          const ask: PackageVersion[] = [];

          for (const [key, p] of wanted) {
            const hit = CACHE.get(cacheKey(p));

            if (hit && hit.until > now) known.set(key, hit.ids);
            else ask.push(p);
          }

          for (let i = 0; i < ask.length; i += BATCH) {
            const chunk = ask.slice(i, i + BATCH);
            const got = yield* Effect.result(query(chunk));

            if (Result.isFailure(got)) {
              console.error(JSON.stringify({ event: "osv-lookup", packages: chunk.length, error: String(got.failure) }));
              continue;
            }

            if (CACHE.size + chunk.length > MAX_CACHED) CACHE.clear();

            chunk.forEach((p, j) => {
              const ids = got.success[j] ?? [];
              CACHE.set(cacheKey(p), { ids, until: now + CACHE_MS });
              known.set(keyOf(p), ids);
            });
          }

          return [...wanted].flatMap(([key, p]) => {
            const ids = known.get(key) ?? [];

            return ids.length > 0 ? [{ name: p.name, version: p.version, ids }] : [];
          });
        }),
    }),
  );
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
