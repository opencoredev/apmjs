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
import { readCapped } from "./http.ts";
import { ISOLATE_POOL, type Lease, RequestMemory } from "./memory.ts";
import { WEIGHTS } from "./packument-read.ts";

export type PackageVersion = { readonly name: string; readonly version: string };

/** A version the feed lists, with its MAL- advisory ids. */
export type ListedMalicious = { name: string; version: string; ids: string[] };

/** One range of an advisory's affected versions, as OSV writes its events (SEMVER and ECOSYSTEM ranges). */
const RangeEvents = z.array(z.object({ introduced: z.string().optional(), fixed: z.string().optional(), last_affected: z.string().optional(), limit: z.string().optional() }));

/** One MAL- advisory's affected versions of one npm name: the exact versions it lists and its ranges. */
/** `every`: withheld unread by apm, so it names every version of the name (everyVersion), never one OSV wrote. */
const AdvisorySchema = z.object({ id: z.string(), versions: z.array(z.string()), ranges: z.array(RangeEvents), every: z.literal(true).optional() });

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

/**
 * The most MAL- advisories of one name read whole (advisoriesFor), and the most of one read. A page's advisories are
 * read all at once, so none of them starts after the request's OSV budget is spent. An advisory past these bounds is not
 * read, so which versions it names is not known: it withholds every version of the name (everyVersion), and the answer
 * is partial, so it is not kept.
 */
export const MAX_ADVISORIES = 64;
export const MAX_ADVISORY_BYTES = 256 * 1024;

/** An answer from OSV over the bytes the read allows. */
class OverCap extends Error {}

/** An advisory's answer the request had no room left to hold. */
class OverBudget extends Error {}

/** What a MAL- advisory apm did not read for being past a bound is taken to name: every version of the name. */
const everyVersion = (id: string): Advisory => ({ id, versions: [], ranges: [[{ introduced: "0" }]], every: true });

/**
 * What reading one advisory holds of the request's lease (RequestMemory), per byte. While it is read: the chunks
 * readCapped holds and the copy it joins them into, MAX_ADVISORY_BYTES of each, so a last chunk past the cap of up to as
 * many again fits. Then, while it is decoded, parsed and the advisory taken out of it: its text, and at most a container
 * for every two bytes (WEIGHTS). What is taken out of it is kept for the rest of the request, charged the same.
 */
const READ_WEIGHT = 2 * WEIGHTS.text;
const PARSE_WEIGHT = 2 * WEIGHTS.text + WEIGHTS.parse * WEIGHTS.text + WEIGHTS.container / 2;

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

/** A name's complete answer as kept in the data center's cache: when it was asked for (wall clock), and its advisories. */
const NameEntry = z.object({ fetchedAt: z.number(), advisories: z.array(AdvisorySchema) });

type NameEntry = z.infer<typeof NameEntry>;

/**
 * When an answer was asked of OSV (`at`, wall clock), and `seq`, which orders the asks made in the same millisecond: a
 * copy from the data center's cache is 0, before this isolate's own. Complete answers and the observations of each
 * advisory are ordered by the same stamp.
 */
type Stamp = { readonly at: number; readonly seq: number };

/** Whether `a` was asked for after `b`; anything is after nothing. */
const newerThan = (a: Stamp, b: Stamp | null | undefined): boolean => b === null || b === undefined || a.at > b.at || (a.at === b.at && a.seq > b.seq);

/**
 * OSV's newest word on one MAL- advisory of a name, and when it was asked for: the versions it names here, or null when
 * it was read withdrawn or naming nothing here, or a complete answer asked for later left it out.
 */
type Observation = Stamp & { readonly advisory: Advisory | null };

/**
 * What the isolate knows of a name's advisories, by OSV root and name: its newest complete answer's stamp, and the
 * newest observation of each advisory, from complete and partial answers alike. A partial answer is OSV's word on the
 * advisories it read, though not on the name; so each advisory is decided by the newest answer that read it (Sol on
 * #59: a whole answer per name let an older complete answer undo a newer partial one, either way). A complete answer
 * is also OSV's word on every advisory it does not list, seen here before or not: an older answer that lands after it
 * cannot bring back one it left out (Sol on 6f206c5).
 */
type NameState = { complete: Stamp | null; readonly ids: Map<string, Observation> };

/** The isolate's knowledge per name, by OSV root and name, least recently updated first. */
const NAMES = new Map<string, NameState>();

/**
 * The most the isolate keeps of names' advisories, as weight (their text, PARSE_WEIGHT a character), taken from the
 * isolate's pool while kept (Sol on fb84083: the kept advisories were bounded by count only, and charged to the request
 * that read them, past its end). Oldest names go first; a name that does not fit is not kept.
 */
const NAMES_WEIGHT = 2 * 1024 * 1024;

/** The weight each kept name holds, under `namesLease` (opened on first use). */
const NAMES_HELD = new Map<string, number>();
let namesLease: Lease | null = null;

/** Lets go of the name under `key` and what it holds. */
function forget(key: string): void {
  namesLease?.give(NAMES_HELD.get(key) ?? 0);
  NAMES_HELD.delete(key);
  NAMES.delete(key);
}

/** `state` kept for `key`, newest, charged its weight; the oldest names let go of while it does not fit, and it too when it still does not. */
function keep(key: string, state: NameState): void {
  const lease = (namesLease ??= ISOLATE_POOL.cache(NAMES_WEIGHT));
  const weight = [...state.ids].reduce((n, [id, o]) => n + (id.length + (o.advisory === null ? 0 : JSON.stringify(o.advisory).length)) * PARSE_WEIGHT, 0);

  forget(key);

  for (const oldest of NAMES.keys()) {
    if (NAMES.size < MAX_NAMES && lease.take(weight)) {
      NAMES.set(key, state);
      NAMES_HELD.set(key, weight);

      return;
    }

    forget(oldest);
  }

  if (lease.take(weight)) {
    NAMES.set(key, state);
    NAMES_HELD.set(key, weight);
  }
}

/** The order of this isolate's asks of OSV about names; a copy from the data center's cache is 0. */
let asks = 0;

/**
 * Takes in what an answer asked for at `stamp` read: `found`, the advisories among the `read` ids that name the name,
 * and with `complete`, that no other advisory does. Each advisory takes the newest word on it: its newest observation,
 * else the newest complete answer, which said it was not listed. So an answer that lands after a newer one changes
 * nothing the newer one said. Observations and the complete stamp past NAME_STALE_MS are dropped.
 */
function observe(input: { key: string; stamp: Stamp; read: ReadonlySet<string>; found: readonly Advisory[]; complete: boolean; now: number }): NameState {
  const { key, stamp } = input;
  const state = NAMES.get(key) ?? { complete: null, ids: new Map<string, Observation>() };

  for (const id of input.read) if (newerThan(stamp, state.ids.get(id) ?? state.complete)) state.ids.set(id, { ...stamp, advisory: input.found.find((a) => a.id === id) ?? null });

  if (input.complete) {
    for (const [id, o] of state.ids) if (!input.read.has(id) && newerThan(stamp, o)) state.ids.set(id, { ...stamp, advisory: null });

    if (newerThan(stamp, state.complete)) state.complete = stamp;
  }

  for (const [id, o] of state.ids) if (input.now - o.at >= NAME_STALE_MS) state.ids.delete(id);

  if (state.complete !== null && input.now - state.complete.at >= NAME_STALE_MS) state.complete = null;
  keep(key, state);

  return state;
}

/** Whether the newest complete answer of the name under `key` was asked for at `stamp`. */
const newestComplete = (key: string, stamp: Stamp): boolean => {
  const c = NAMES.get(key)?.complete ?? null;

  return c !== null && c.at === stamp.at && c.seq === stamp.seq;
};

/** The advisories `state` (a name's) names by its newest observations at `now`, each while it is young enough. */
function answerOf(state: NameState | undefined, now: number): Advisory[] {
  return [...(state?.ids.values() ?? [])].flatMap((o) => (o.advisory !== null && o.at <= now && now - o.at < NAME_STALE_MS ? [o.advisory] : []));
}

/** The data center's cache key of a name's advisories. This host is never fetched; it only names the entry. */
const sharedKey = (key: string): Request => new Request(`https://osv-cache.apmjs.internal/v2/${encodeURIComponent(key)}`);

/** The data center's copy of a name's advisories, or null: none outside a Worker, a miss, a late or unreadable one. */
/**
 * The most of a copy read from the data center's cache: past it, a miss. It is read under the request's `lease` as an
 * advisory is (READ_WEIGHT, PARSE_WEIGHT), and is a miss when that does not fit (Sol on fb84083: read whole, uncharged).
 */
const SHARED_MAX_BYTES = 1024 * 1024;

async function sharedRead(key: string, lease: Lease | null): Promise<NameEntry | null> {
  if (typeof caches === "undefined") return null;
  const room = SHARED_MAX_BYTES * READ_WEIGHT;

  if (lease !== null && !lease.take(room)) return null;

  try {
    const got = await matchWithin({ cache: caches.default, key: sharedKey(key), ms: SHARED_MS, operation: "osv-copy" });

    if (got.kind !== "hit") return null;
    const bytes = await within(readCapped(got.res, SHARED_MAX_BYTES), SHARED_MS);

    if (bytes.kind !== "done" || bytes.value === null) return null;
    const parsing = bytes.value.length * PARSE_WEIGHT;

    if (lease !== null && !lease.take(parsing)) return null;

    try {
      const parsed = NameEntry.safeParse(JSON.parse(new TextDecoder().decode(bytes.value)));

      return parsed.success ? parsed.data : null;
    } finally {
      lease?.give(parsing);
    }
  } finally {
    lease?.give(room);
  }
}

/** What the Worker keeps running after the response (ctx.waitUntil), or null outside one. */
export type FeedBackground = ((work: Promise<void>) => void) | null;

/** How long a copy written to the data center's cache is kept running after the response. */
const SHARED_WRITE_MS = 5_000;

/** Each name's copy being written to the data center's cache, by key: a write starts once the one before it is done. */
const WRITING = new Map<string, Promise<void>>();

/**
 * Gives the data center a copy of a name's complete answer asked for at `stamp`, after the response, in the request's
 * waitUntil when it has one. The writes of one name run one after another, each only while its answer is still the
 * isolate's newest complete one, so this isolate never leaves an older answer's copy over a newer one's (Sol on
 * 6f206c5: two answers of one millisecond were told apart by their time only).
 */
function sharedWrite(key: string, stamp: Stamp, entry: NameEntry, background: FeedBackground): void {
  if (typeof caches === "undefined" || !newestComplete(key, stamp)) return;

  // the next write waits for this put itself, not for the response's wait on it: a put past SHARED_WRITE_MS keeps running,
  // and one after it must not finish first (Sol on fb84083)
  const put = (WRITING.get(key) ?? Promise.resolve())
    .then(async () => {
      if (!newestComplete(key, stamp)) return;
      const res = new Response(JSON.stringify(entry), { headers: { "content-type": "application/json", "cache-control": `max-age=${NAME_STALE_MS / 1000}` } });

      await caches.default.put(sharedKey(key), res);
    })
    .catch(() => undefined);

  WRITING.set(key, put);
  void put.then(() => {
    if (WRITING.get(key) === put) WRITING.delete(key);
  });

  if (background !== null) background(within(put, SHARED_WRITE_MS).then(() => undefined));
}


/** What one advisory OSV sent says about npm's `name`: nothing when it is withdrawn or names no version of it. */
function advisoryOf(name: string, vuln: z.infer<typeof VulnAnswer>): Advisory[] {
  if (vuln.withdrawn !== undefined) return [];
  const mine = (vuln.affected ?? []).filter((a) => a.package?.ecosystem === "npm" && a.package.name === name);
  const versions = mine.flatMap((a) => a.versions ?? []);
  const ranges = mine.flatMap((a) => (a.ranges ?? []).filter((r) => r.type === "SEMVER" || r.type === "ECOSYSTEM").map((r) => r.events));

  return versions.length === 0 && ranges.length === 0 ? [] : [{ id: vuln.id, versions, ranges }];
}

/** An answer of OSV, read whole and parsed with `schema`. */
const parsedWith =
  <S extends z.ZodType>(schema: S) =>
  async (res: Response): Promise<z.output<S>> => {
    const parsed = schema.safeParse(await res.json());

    if (!parsed.success) throw new Error("OSV answered in an unexpected shape");

    return parsed.data;
  };

/**
 * What one MAL- advisory's answer says of npm's `name`, read under `lease` (none outside a request): at most
 * MAX_ADVISORY_BYTES of it (OverCap past that), decoded and parsed while what that holds is charged (OverBudget when it
 * does not fit), and what is taken out of it charged for the rest of the request.
 */
const advisoryRead =
  (name: string, lease: Lease | null) =>
  async (res: Response): Promise<Advisory[]> => {
    const bytes = await readCapped(res, MAX_ADVISORY_BYTES);

    if (bytes === null) throw new OverCap(`OSV answered more than ${MAX_ADVISORY_BYTES} bytes`);
    const parsing = bytes.length * PARSE_WEIGHT;

    if (lease !== null && !lease.take(parsing)) throw new OverBudget("no room left in the request to read the advisory");

    try {
      const parsed = VulnAnswer.safeParse(JSON.parse(new TextDecoder().decode(bytes)));

      if (!parsed.success) throw new Error("OSV answered in an unexpected shape");
      const found = advisoryOf(name, parsed.data);

      if (lease !== null && !lease.take(JSON.stringify(found).length * PARSE_WEIGHT)) throw new OverBudget("no room left in the request to keep the advisory");

      return found;
    } finally {
      lease?.give(parsing);
    }
  };

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

/**
 * Whether one advisory names `version`: every version when apm withheld it unread (everyVersion), SemVer or not (Sol on
 * fb84083: its range from 0 missed a version npm lists outside SemVer's grammar); else listed exactly, or within one of
 * its ranges.
 */
function affects(a: Advisory, version: string): boolean {
  if (a.every === true || a.versions.includes(version)) return true;
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
    /** Reads of OSV in flight, and since when one has been (wall clock): waits that overlap count once. */
    let inFlight = 0;
    let busySince = 0;
    const spent = (): number => spentMs + (inFlight > 0 ? Date.now() - busySince : 0);
    let stopped = false;
    const cacheKey = (p: PackageVersion): string => `${baseUrl} ${keyOf(p)}`;

    /**
     * Asks OSV at `path` (a POST of `body`, or a GET when it is null) within the request's budget, its answer read by
     * `take` (parsedWith, advisoryRead).
     */
    const post = <T>(path: string, body: OsvBatchQuery | OsvPageQuery | null, take: (res: Response) => Promise<T>) =>
      Effect.tryPromise({
        try: async (): Promise<T> => {
          const left = REQUEST_BUDGET_MS - spent();

          if (left <= 0) throw new Error("the request's OSV budget is spent");

          if (inFlight++ === 0) busySince = Date.now();

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

            return await take(res);
          } finally {
            if (--inFlight === 0) spentMs += Date.now() - busySince;
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
        const batch = yield* post("v1/querybatch", { queries: chunk.map(queryOf) }, parsedWith(BatchAnswer));

        if (batch.results.length !== chunk.length) return yield* Effect.fail(new Error("OSV answered in an unexpected shape"));

        return yield* Effect.forEach(chunk, (p, j) =>
          Effect.gen(function* () {
            const first = batch.results[j];
            const ids = malOnly(first?.vulns);
            let token = first?.next_page_token;

            for (let page = 0; token !== undefined && ids.length === 0; page++) {
              const next = page < MAX_PAGES ? yield* Effect.result(post("v1/query", { ...queryOf(p), page_token: token }, parsedWith(QueryAnswer))) : null;

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
     * what was found is known; a page's are read all at once, under `lease` (advisoryRead). A later page or an advisory
     * that could not be read leaves the answer partial, keeping every advisory that was read. One past MAX_ADVISORIES
     * reads, over MAX_ADVISORY_BYTES or with no room left in the request is `withheld`: which versions it names is not
     * known. One that failed otherwise is read again when a later page lists it, while reads are left (Sol on #58).
     * Fails only when the first page was not answered.
     */
    const askName = (name: string, lease: Lease | null) =>
      Effect.gen(function* () {
        const advisories: Advisory[] = [];
        /** The MAL- ids whose advisory was read: what OSV says of them now is in `advisories`, a withdrawal included. */
        const read = new Set<string>();
        const withheld = new Set<string>();
        /** MAL- ids whose read failed and that no later page's read has recovered. */
        const failed = new Set<string>();
        /** Advisory reads started, against MAX_ADVISORIES. */
        let reads = 0;
        let token: string | undefined;
        let complete = true;

        /** One advisory's read: room for its bytes is taken from `lease` before it starts, and given back once it is read. */
        const readOne = (id: string) =>
          Effect.gen(function* () {
            const room = MAX_ADVISORY_BYTES * READ_WEIGHT;

            if (lease !== null && !lease.take(room)) return { kind: "withheld" } as const;
            const got = yield* Effect.result(post(`v1/vulns/${encodeURIComponent(id)}`, null, advisoryRead(name, lease))).pipe(Effect.ensuring(Effect.sync(() => lease?.give(room))));

            if (Result.isSuccess(got)) return { kind: "read", advisories: got.success } as const;

            return got.failure instanceof OverCap || got.failure instanceof OverBudget ? ({ kind: "withheld" } as const) : ({ kind: "failed" } as const);
          });

        for (let page = 0; ; page++) {
          const query: OsvNameQuery = { package: { name, ecosystem: "npm" } };

          if (token !== undefined) query.page_token = token;
          const asked = yield* Effect.result(post("v1/querybatch", { queries: [query] }, parsedWith(BatchAnswer)));
          const first = Result.isSuccess(asked) && asked.success.results.length === 1 ? asked.success.results[0] : undefined;

          if (first === undefined) {
            if (page === 0) return yield* Effect.fail(Result.isFailure(asked) ? asked.failure : new Error("OSV answered in an unexpected shape"));
            complete = false;
            break;
          }

          const unsettled = [...new Set(malOnly(first.vulns))].filter((id) => !read.has(id) && !withheld.has(id));
          const ids = unsettled.slice(0, Math.max(0, MAX_ADVISORIES - reads));

          reads += ids.length;

          for (const id of unsettled.slice(ids.length)) {
            complete = false;
            withheld.add(id);
          }

          const details = yield* Effect.forEach(ids, readOne, { concurrency: "unbounded" });

          details.forEach((d, i) => {
            const id = ids[i] ?? "";

            failed.delete(id);

            if (d.kind === "read") {
              read.add(id);
              advisories.push(...d.advisories);

              return;
            }

            if (d.kind === "failed") failed.add(id);
            else {
              complete = false;
              withheld.add(id);
            }
          });

          token = first.next_page_token;

          if (token === undefined) break;

          if (page >= MAX_PAGES) {
            complete = false;
            break;
          }
        }

        // a read that failed and was recovered on a later page leaves the answer complete (Sol on fb84083)
        return { advisories, complete: complete && failed.size === 0, read, withheld };
      });

    /**
     * What this request answered for a name after a partial answer: every later read in it gets the same. What the
     * partial answer read is kept in the isolate per advisory (observe), never in the data center's cache.
     */
    const partials = new Map<string, Advisory[]>();

    return KnownMalicious.of({
      advisoriesFor: (name) =>
        Effect.gen(function* () {
          if (!isPossibleNpmName(name)) return [];
          const partial = partials.get(name);

          // this request already had a partial answer for the name: every later read in it gets the same
          if (partial !== undefined) return partial;
          const key = `${baseUrl} ${name}`;
          const lease = Option.getOrNull(yield* Effect.serviceOption(RequestMemory));

          /**
           * What is known of the name: the isolate's, else what this request took in and the isolate could not keep
           * (keep), so an answer it read is never left out for want of room.
           */
          let mine: NameState | undefined;
          const known = (): NameState | undefined => NAMES.get(key) ?? mine;

          const fresh = (now: number): boolean => {
            const at = known()?.complete?.at ?? null;

            return at !== null && at <= now && now - at < NAME_FRESH_MS;
          };

          const asked = Date.now();

          if (fresh(asked)) return answerOf(known(), asked);
          const shared = yield* Effect.promise(() => sharedRead(key, lease).catch(() => null));
          // the cache read is waited for: what it found, and what another request learned meanwhile, is judged as of
          // when it came back (Sol on 6f206c5)
          const now = Date.now();

          // a copy from the data center's cache is a complete answer like this isolate's own, fresh or stale: it retires
          // what older answers said of the advisories it leaves out
          if (shared !== null && shared.fetchedAt <= now && now - shared.fetchedAt < NAME_STALE_MS) {
            mine = observe({ key, stamp: { at: shared.fetchedAt, seq: 0 }, read: new Set(shared.advisories.map((a) => a.id)), found: shared.advisories, complete: true, now });
          }

          if (fresh(now)) return answerOf(known(), now);

          // OSV is not asked: what is known, each advisory while it is young enough (fail open past that)
          if (stopped || spent() >= REQUEST_BUDGET_MS || (BACKOFF.get(baseUrl) ?? 0) > now) return answerOf(known(), now);
          // stamped as the ask starts
          const stamp: Stamp = { at: Date.now(), seq: ++asks };
          const got = yield* Effect.result(askName(name, lease));
          // the answer is taken in as of when it was asked for, and what is answered is read from the state after it, so
          // an answer asked for later that landed first is neither undone nor left out (Sol on #59, finding 3)
          const after = Date.now();

          if (Result.isSuccess(got) && got.success.complete) {
            const { advisories, read } = got.success;

            mine = observe({ key, stamp, read, found: advisories, complete: true, now: after });
            sharedWrite(key, stamp, { fetchedAt: stamp.at, advisories }, background);

            return answerOf(known(), after);
          }

          console.error(JSON.stringify({ event: "osv-name", name, error: Result.isSuccess(got) ? "partial answer" : String(got.failure) }));
          // no more waiting on OSV in this request: what is kept still counts
          stopped = true;

          if (Result.isFailure(got)) {
            // the first page went unanswered: OSV is taken as down at this root for a while
            BACKOFF.set(baseUrl, stamp.at + NAME_BACKOFF_MS);

            return answerOf(known(), after);
          }

          // a partial answer is OSV's word on the advisories it read (a withdrawal included), never on the name: it is
          // kept for those, and for the rest what was known stands, but for one it withheld, which names every version
          // here, whatever was known of it. The next request asks again
          const { read, advisories, withheld } = got.success;

          mine = observe({ key, stamp, read, found: advisories, complete: false, now: after });
          const answer = [...answerOf(known(), after).filter((a) => !withheld.has(a.id)), ...[...withheld].map(everyVersion)];

          partials.set(name, answer);

          return answer;
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

          for (let i = 0; i < missing.length && !stopped && spent() < REQUEST_BUDGET_MS; i += OSV_BATCH) {
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
