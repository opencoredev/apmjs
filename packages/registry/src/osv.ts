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
//
// The npm protocol routes (packuments, version documents, dist-tags and tarballs, plain and ~safe) ask about a whole
// name instead (advisoriesFor): one batch query for the package with no version returns only the ids of every advisory
// OSV has for it, a few hundred bytes even for next, and each MAL- id among them is then read for the versions it
// names. So a packument of thousands of versions costs one small query, and nothing more unless the name is listed. A
// name's answer is kept for NAME_FRESH_MS in the isolate and in the data center's cache, and while OSV cannot be asked
// an answer up to NAME_STALE_MS old is used instead of nothing, so an outage fails open only for a name not asked about
// in that long.
import { Context, Effect, Layer, Option, Result } from "effect";
import semver from "semver";
import { z } from "zod";
import { isPossibleNpmName, isValidPackageName } from "@apm/core";
import { matchWithin, within } from "./deadline.ts";

export type PackageVersion = { readonly name: string; readonly version: string };

/** A version the feed lists, with its MAL- advisory ids. */
export type ListedMalicious = { name: string; version: string; ids: string[] };

/** One range of an advisory's affected versions, as OSV writes its events (SEMVER and ECOSYSTEM ranges). */
const RangeEvents = z.array(z.object({ introduced: z.string().optional(), fixed: z.string().optional(), last_affected: z.string().optional(), limit: z.string().optional() }));

/** One MAL- advisory's affected versions of one npm name: the exact versions it lists and its ranges. */
const AdvisorySchema = z.object({ id: z.string(), versions: z.array(z.string()), ranges: z.array(RangeEvents) });

export type Advisory = z.infer<typeof AdvisorySchema>;

export class KnownMalicious extends Context.Service<
  KnownMalicious,
  {
    readonly lookup: (pkgs: readonly PackageVersion[]) => Effect.Effect<ListedMalicious[]>;
    /** The MAL- advisories OSV has for every version of npm's `name`: none when it has none or could not be asked. */
    readonly advisoriesFor: (name: string) => Effect.Effect<readonly Advisory[]>;
  }
>()("@apm/registry/KnownMalicious") {}

/** How long a lookup's answer is kept. A version newly listed is refused within this long. */
const CACHE_MS = 10 * 60_000;
const MAX_CACHED = 20_000;

/** OSV's limit on one batch query. */
export const OSV_BATCH = 1000;

/** What one request may spend waiting on OSV, all its lookups together. */
export const REQUEST_BUDGET_MS = 3_000;

/** How long a name's advisories are kept (advisoriesFor). A version newly listed is withheld within this long. */
export const NAME_FRESH_MS = 5 * 60_000;

/** How old a name's kept advisories may be and still be used while OSV cannot be asked. */
export const NAME_STALE_MS = 24 * 60 * 60_000;
const MAX_NAMES = 20_000;

/** How long an isolate stops asking OSV at a root about names once a first page went unanswered, using what it kept. */
const NAME_BACKOFF_MS = 30_000;

/** Until when this isolate does not ask OSV at each root about names (wall clock), after a first page went unanswered. */
const BACKOFF = new Map<string, number>();

/** How long a read of, or a write to, the data center's copy of a name's advisories is waited for. */
const SHARED_MS = 150;

/** Pages of one version's advisories followed past the batch answer's first. */
const MAX_PAGES = 3;
const MAX_VERSION_LENGTH = 256;

const Vulns = z.array(z.object({ id: z.string() })).optional();
const BatchAnswer = z.object({ results: z.array(z.object({ vulns: Vulns, next_page_token: z.string().optional() })) });
const QueryAnswer = z.object({ vulns: Vulns, next_page_token: z.string().optional() });

const VulnAnswer = z.object({
  id: z.string(),
  withdrawn: z.string().optional(),
  affected: z
    .array(z.object({ package: z.object({ name: z.string(), ecosystem: z.string() }).optional(), versions: z.array(z.string()).optional(), ranges: z.array(z.object({ type: z.string(), events: RangeEvents })).optional() }))
    .optional(),
});

/** One version asked about, every version of a name (a page of it past the first), and the request shapes OSV takes. */
type OsvQuery = { package: { name: string; ecosystem: "npm" }; version: string };

type OsvNameQuery = { package: { name: string; ecosystem: "npm" }; page_token?: string };

type OsvBatchQuery = { queries: (OsvQuery | OsvNameQuery)[] };

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

/** A name's advisories as kept: when OSV gave them (wall clock), in the isolate and in the data center's cache. */
/** A name's complete answer as kept: when it was asked for (wall clock), in the isolate and in the data center's cache. */
const NameEntry = z.object({ fetchedAt: z.number(), advisories: z.array(AdvisorySchema) });

type NameEntry = z.infer<typeof NameEntry>;

/** The isolate's answers per name, by OSV root and name, oldest first. */
const NAMES = new Map<string, NameEntry>();

/**
 * Keeps `entry` as the name's answer unless one asked for later is kept already (a slower request's answer must not
 * replace a newer one), and returns the answer kept.
 */
function rememberName(key: string, entry: NameEntry): NameEntry {
  const current = NAMES.get(key);

  if (current !== undefined && current.fetchedAt > entry.fetchedAt) return current;
  NAMES.delete(key);
  NAMES.set(key, entry);

  for (const oldest of NAMES.keys()) {
    if (NAMES.size <= MAX_NAMES) break;
    NAMES.delete(oldest);
  }

  return entry;
}

/** The data center's cache key of a name's advisories. This host is never fetched; it only names the entry. */
const sharedKey = (key: string): Request => new Request(`https://osv-cache.apmjs.internal/v2/${encodeURIComponent(key)}`);

/** The data center's copy of a name's advisories, or null: none outside a Worker, a miss, a late or unreadable one. */
async function sharedRead(key: string): Promise<NameEntry | null> {
  if (typeof caches === "undefined") return null;
  const got = await matchWithin({ cache: caches.default, key: sharedKey(key), ms: SHARED_MS, operation: "osv-copy" });

  if (got.kind !== "hit") return null;
  const body = await within(got.res.json(), SHARED_MS);

  if (body.kind !== "done") return null;
  const parsed = NameEntry.safeParse(body.value);

  return parsed.success ? parsed.data : null;
}

/** What the Worker keeps running after the response (ctx.waitUntil), or null outside one. */
export type FeedBackground = ((work: Promise<void>) => void) | null;

/** How long a copy written to the data center's cache is kept running after the response. */
const SHARED_WRITE_MS = 5_000;

/** Gives the data center a copy of a name's advisories after the response, in the request's waitUntil when it has one. */
function sharedWrite(key: string, entry: NameEntry, background: FeedBackground): void {
  if (typeof caches === "undefined") return;
  const res = new Response(JSON.stringify(entry), { headers: { "content-type": "application/json", "cache-control": `max-age=${NAME_STALE_MS / 1000}` } });
  const put = within(caches.default.put(sharedKey(key), res), SHARED_WRITE_MS).then(() => undefined);

  if (background === null) void put;
  else background(put);
}



/** What one advisory OSV sent says about npm's `name`: nothing when it is withdrawn or names no version of it. */
function advisoryOf(name: string, vuln: z.infer<typeof VulnAnswer>): Advisory[] {
  if (vuln.withdrawn !== undefined) return [];
  const mine = (vuln.affected ?? []).filter((a) => a.package?.ecosystem === "npm" && a.package.name === name);
  const versions = mine.flatMap((a) => a.versions ?? []);
  const ranges = mine.flatMap((a) => (a.ranges ?? []).filter((r) => r.type === "SEMVER" || r.type === "ECOSYSTEM").map((r) => r.events));

  return versions.length === 0 && ranges.length === 0 ? [] : [{ id: vuln.id, versions, ranges }];
}

/** An event's bound as a version, "0" lowest of all; null when it is not one. */
const boundOf = (v: string): string | null => (v === "0" ? "0.0.0-0" : semver.valid(v));

/** Whether `version` (valid semver) is below one of a range's limits ("*" is none), as OSV requires when it has any. */
function beforeLimits(events: z.infer<typeof RangeEvents>, version: string): boolean {
  const limits = events.flatMap((e) => (e.limit === undefined ? [] : [e.limit]));

  return limits.length === 0 || limits.some((l) => l === "*" || (semver.valid(l) !== null && semver.lt(version, l)));
}

/** Whether `version` (valid semver) is in one range, by OSV's rule: the last event at or below it decides. */
function inRange(events: z.infer<typeof RangeEvents>, version: string): boolean {
  if (!beforeLimits(events, version)) return false;

  const points = events.flatMap((e) => {
    const raw = e.introduced ?? e.fixed ?? e.last_affected;
    const at = raw === undefined ? null : boundOf(raw);

    return at === null ? [] : [{ at, kind: e.introduced !== undefined ? "introduced" : e.fixed !== undefined ? "fixed" : "last_affected" }];
  });

  let affected = false;

  for (const p of points.toSorted((a, b) => semver.compare(a.at, b.at))) {
    if (p.kind === "introduced" && semver.gte(version, p.at)) affected = true;
    else if (p.kind === "fixed" && semver.gte(version, p.at)) affected = false;
    else if (p.kind === "last_affected" && semver.gt(version, p.at)) affected = false;
  }

  return affected;
}

/** Whether one advisory names `version`: listed exactly, or within one of its ranges. */
function affects(a: Advisory, version: string): boolean {
  if (a.versions.includes(version)) return true;
  const valid = semver.valid(version);

  return valid !== null && a.ranges.some((events) => inRange(events, valid));
}

/** The versions among `versions` that `advisories` (npm's `name`'s) name, each with the ids that name it. */
export function listedAmong(name: string, advisories: readonly Advisory[], versions: readonly string[]): Map<string, ListedMalicious> {
  const out = new Map<string, ListedMalicious>();

  if (advisories.length === 0) return out;

  for (const version of versions) {
    const ids = advisories.flatMap((a) => (affects(a, version) ? [a.id] : []));

    if (ids.length > 0) out.set(version, { name, version, ids });
  }

  return out;
}

/** The live feed at `baseUrl` (OSV's API root, ending in a slash), with one request's budget; `background` keeps its cache writes. */
export function osvFeed(baseUrl: string, fetcher: typeof fetch = fetch, background: FeedBackground = null): Layer.Layer<KnownMalicious> {
  return Layer.sync(KnownMalicious, () => {
    /** Time this request has spent waiting on OSV, and whether it stopped asking (a failure). */
    let spentMs = 0;
    let stopped = false;
    const cacheKey = (p: PackageVersion): string => `${baseUrl} ${keyOf(p)}`;

    /** Asks OSV at `path` (a POST of `body`, or a GET when it is null) within the request's budget and parses the answer with `schema`. */
    const post = <S extends z.ZodType>(path: string, body: OsvBatchQuery | OsvPageQuery | null, schema: S) =>
      Effect.tryPromise({
        try: async (): Promise<z.output<S>> => {
          const left = REQUEST_BUDGET_MS - spentMs;

          if (left <= 0) throw new Error("the request's OSV budget is spent");
          const t0 = Date.now();

          try {
            const init: RequestInit =
              body === null
                ? { method: "GET", headers: { accept: "application/json" }, signal: AbortSignal.timeout(left) }
                : { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(left) };

            const res = await fetcher(`${baseUrl}${path}`, init);

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

    /**
     * The MAL- advisories OSV has for npm's `name`, with the versions each names, and whether that is all of them. Each
     * page's MAL- ids are read before the next page is asked for, so a slow later page cannot spend the budget before
     * what was found is known. A later page or an advisory that could not be read leaves the answer partial, keeping
     * every advisory that was read. Fails only when the first page was not answered.
     */
    const askName = (name: string) =>
      Effect.gen(function* () {
        const advisories: Advisory[] = [];
        /** The MAL- ids whose advisory was read: what OSV says of them now is in `advisories`, a withdrawal included. */
        const read = new Set<string>();
        let token: string | undefined;
        let complete = true;

        for (let page = 0; ; page++) {
          const query: OsvNameQuery = { package: { name, ecosystem: "npm" } };

          if (token !== undefined) query.page_token = token;
          const asked = yield* Effect.result(post("v1/querybatch", { queries: [query] }, BatchAnswer));
          const first = Result.isSuccess(asked) && asked.success.results.length === 1 ? asked.success.results[0] : undefined;

          if (first === undefined) {
            if (page === 0) return yield* Effect.fail(Result.isFailure(asked) ? asked.failure : new Error("OSV answered in an unexpected shape"));
            complete = false;
            break;
          }

          const ids = malOnly(first.vulns).filter((id) => !read.has(id));
          const details = yield* Effect.forEach(ids, (id) => Effect.result(post(`v1/vulns/${encodeURIComponent(id)}`, null, VulnAnswer)), { concurrency: "unbounded" });

          details.forEach((r, i) => {
            if (Result.isFailure(r)) {
              complete = false;

              return;
            }

            read.add(ids[i] ?? "");
            advisories.push(...advisoryOf(name, r.success));
          });

          token = first.next_page_token;

          if (token === undefined) break;

          if (page >= MAX_PAGES) {
            complete = false;
            break;
          }
        }

        return { advisories, complete, read };
      });

    return KnownMalicious.of({
      advisoriesFor: (name) =>
        Effect.gen(function* () {
          if (!isPossibleNpmName(name)) return [];
          const key = `${baseUrl} ${name}`;
          const now = Date.now();
          const youngerThan = (e: NameEntry, ms: number): boolean => e.fetchedAt <= now && now - e.fetchedAt < ms;
          const local = NAMES.get(key) ?? null;

          if (local !== null && youngerThan(local, NAME_FRESH_MS)) return local.advisories;
          const shared = yield* Effect.promise(() => sharedRead(key).catch(() => null));

          if (shared !== null && youngerThan(shared, NAME_FRESH_MS)) return rememberName(key, shared).advisories;
          // the newest answer kept, while it is young enough: what is answered when OSV is not asked (fail open past that)
          const newest = [local, shared].flatMap((e) => (e !== null && youngerThan(e, NAME_STALE_MS) ? [e] : [])).toSorted((a, b) => b.fetchedAt - a.fetchedAt)[0] ?? null;
          const kept = newest?.advisories ?? [];

          if (stopped || spentMs >= REQUEST_BUDGET_MS || (BACKOFF.get(baseUrl) ?? 0) > now) return kept;
          const got = yield* Effect.result(askName(name));

          if (Result.isSuccess(got) && got.success.complete) {
            const entry = { fetchedAt: now, advisories: got.success.advisories };
            const winner = rememberName(key, entry);

            if (winner === entry) sharedWrite(key, entry, background);

            return winner.advisories;
          }

          console.error(JSON.stringify({ event: "osv-name", name, error: Result.isSuccess(got) ? "partial answer" : String(got.failure) }));
          // no more waiting on OSV in this request: what is kept still counts
          stopped = true;

          if (Result.isFailure(got)) {
            // the first page went unanswered: OSV is taken as down at this root for a while
            BACKOFF.set(baseUrl, now + NAME_BACKOFF_MS);

            return kept;
          }

          // a partial answer is not kept, so the next request asks again; this one withholds what it read (OSV's word,
          // a withdrawal included) and, for what it could not read, what the kept answer says
          const { advisories: found, read } = got.success;

          return [...found, ...kept.filter((a) => !read.has(a.id))];
        }),
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

/** The MAL- advisories of npm's `name`; none when this registry runs without the feed. */
export const advisoriesOf = (name: string) =>
  Effect.gen(function* () {
    const feed = yield* Effect.serviceOption(KnownMalicious);

    return Option.isNone(feed) ? [] : yield* feed.value.advisoriesFor(name);
  });

/** The versions among `versions` of npm's `name` the feed lists, by version; none without the feed. */
export const listedVersionsOf = (name: string, versions: readonly string[]) =>
  Effect.map(advisoriesOf(name), (advisories) => listedAmong(name, advisories, versions));

/** Why a listed version is refused, citing its advisories. */
export function maliciousText(m: ListedMalicious): string {
  return `known malicious: the OSSF malicious-packages feed lists ${m.name}@${m.version} (${m.ids.join(", ")})`;
}

/** What the tarball routes answer for a listed version: 403, citing its advisories. */
export function listedTarballText(m: ListedMalicious): string {
  return `${maliciousText(m)}, so apm does not serve it. See https://osv.dev/vulnerability/${m.ids[0] ?? ""}`;
}

/** The header npm prints (as "npm notice") from any registry answer: the packument routes name what they withheld. */
export const NOTICE_HEADER = "npm-notice";

const NOTICE_MAX = 400;

/**
 * The notice of a packument that withholds versions of `name` the feed lists, or null when it lists none: npm prints
 * it before it reports that no version matched, so `npm install name@<listed>` says why. ASCII only, as a header must be.
 */
export function listedNotice(name: string, advisories: readonly Advisory[]): string | null {
  if (advisories.length === 0) return null;
  const range = (events: Advisory["ranges"][number]) => events.map((e) => (e.introduced !== undefined ? `>=${e.introduced}` : e.fixed !== undefined ? `<${e.fixed}` : `<=${e.last_affected ?? ""}`)).join(" ");
  const each = advisories.map((a) => `${a.id}: ${[...a.versions, ...a.ranges.map(range)].join(", ")}`).join("; ");
  const text = `apm withholds ${name} versions the OSSF malicious-packages feed lists as malicious (${each})`.replace(/[^\x20-\x7e]/g, "?");

  return text.length <= NOTICE_MAX ? text : `${text.slice(0, NOTICE_MAX - 3)}...`;
}

/**
 * The headers a packument adds when it withholds versions of `name` the feed lists: the notice, and no-store, since npm
 * prints a notice only from an answer it did not keep (one from its cache carries x-local-cache). Nothing otherwise.
 */
export function noticeHeaders(name: string, advisories: readonly Advisory[]): Record<string, string> {
  const notice = listedNotice(name, advisories);

  return notice === null ? {} : { [NOTICE_HEADER]: notice, "cache-control": "no-store" };
}

/** The lines the install packument's stamp adds for a name's advisories (upstream.ts installStamp), in a stable order. */
export const advisoryLines = (advisories: readonly Advisory[]): string[] => advisories.map((a) => `osv ${JSON.stringify(a)}`).toSorted();
