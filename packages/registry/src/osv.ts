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
import { type Block, ISOLATE_POOL, type Lease, RequestMemory } from "./memory.ts";
import { WEIGHTS } from "./packument-read.ts";

export type PackageVersion = { readonly name: string; readonly version: string };

/** A version the feed lists, with its MAL- advisory ids. */
/** `unchecked`: those of `ids` that name it only as a hold (every version: not read, or not held), never as OSV wrote. */
export type ListedMalicious = { name: string; version: string; ids: string[]; unchecked?: string[] };

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
 * it was read withdrawn or naming nothing here.
 */
type Observation = Stamp & { readonly advisory: Advisory | null };

/**
 * What the isolate knows of a name's advisories, by OSV root and name: its newest complete answer's stamp, and the
 * newest observation of each advisory, from complete and partial answers alike. A partial answer is OSV's word on the
 * advisories it read, though not on the name; so each advisory is decided by the newest answer that read it (Sol on
 * #59: a whole answer per name let an older complete answer undo a newer partial one, either way). A complete answer
 * is also OSV's word on every advisory it does not list, seen here before or not: an older answer that lands after it
 * cannot bring back one it left out (Sol on 6f206c5). An advisory with no observation newer than the complete answer
 * is what that answer said of it, so none is kept for it (Sol on dd47451: each complete answer stamped every advisory
 * it left out anew, and they were kept for ever). `hold`: the newest stamp of what the isolate had no room to keep of
 * the name (shed): until a complete answer asked for after it, the name is withheld whole.
 */
type NameState = { complete: Stamp | null; hold: Stamp | null; readonly ids: Map<string, Observation> };

/** The isolate's knowledge per name, by OSV root and name, least recently updated first. */
const NAMES = new Map<string, NameState>();

/**
 * The most the isolate keeps of names' observations and of its copies being written, as weight (PARSE_WEIGHT a
 * character, and OBSERVATION_WEIGHT each), under a lease of its own from the isolate's pool, apart from npm's cache and
 * its limit (Sol on fb84083 and c752a16). A name short of room is held (shed): its stamps are kept, so no older answer
 * can undo a newer one, and it is withheld whole.
 */
const NAMES_WEIGHT = 2 * 1024 * 1024;

/** What one kept observation holds besides its text: its entry in the map and the object. */
const OBSERVATION_WEIGHT = 2 * WEIGHTS.container;

/** What advisoriesFor answers with for a name it has held (shed) or whose copy it could not read: every version. */
export const HELD = "APM-OSV-HELD";
const UNREAD_COPY = "APM-OSV-COPY-UNREAD";

/** Whether `id` is one of apm's holds (HELD, UNREAD_COPY), not an advisory OSV wrote. */
export const isHold = (id: string): boolean => id === HELD || id === UNREAD_COPY;

/** The block of each kept name's observations under names(); a request that answers from it holds it too (answerOf). */
const BLOCKS = new Map<string, Block>();

/** What BLOCKS weigh together: what shedding every name could give names() back. */
let blocksWeight = 0;

/** Lets go of the block of the name under `key`, if it has one. */
function dropBlock(key: string): void {
  const block = BLOCKS.get(key);

  if (block === undefined) return;
  names().drop(block);
  blocksWeight -= block.weight;
  BLOCKS.delete(key);
}

/** The names a request is asking OSV about now, and how many: none of them is forgotten for MAX_NAMES (keep). */
const ASKING = new Map<string, number>();

let namesLease: Lease | null = null;

/** The lease of what the isolate keeps of names, opened on first use: under the pool's pressure, the oldest names shed. */
function names(): Lease {
  if (namesLease !== null) return namesLease;
  const made = ISOLATE_POOL.request(NAMES_WEIGHT);

  namesLease = made;
  ISOLATE_POOL.onPressure((need) => {
    let freed = 0;

    // only a block no request holds gives the pool room: one a request holds stays precise (Sol on 91901e5)
    for (const [key, block] of BLOCKS) {
      if (freed >= need) return;

      if (made.soleHolder(block)) freed += shed(key);
    }
  });

  return made;
}

/** `state` held: its observations let go of, `hold` the newest stamp among them, so the name is withheld whole. */
function holdWhole(state: NameState): void {
  for (const o of state.ids.values()) if (newerThan(o, state.hold)) state.hold = { at: o.at, seq: o.seq };
  state.ids.clear();
}

/** Lets go of what the name under `key` holds, its stamps kept: it is held (holdWhole). What the pool got back. */
function shed(key: string): number {
  const block = BLOCKS.get(key);

  if (block === undefined) return 0;
  const freed = names().soleHolder(block) ? block.weight : 0;

  dropBlock(key);
  const state = NAMES.get(key);

  if (state !== undefined) holdWhole(state);

  return freed;
}

/** Lets go of the name under `key` and what it holds. */
function forget(key: string): void {
  dropBlock(key);
  NAMES.delete(key);
}

/**
 * `state` kept for `key`, newest, its observations charged as a block; past MAX_NAMES the oldest names not being asked
 * about are let go of. When they do not fit, the oldest names are shed, and when they still do not, this one is held:
 * its stamps are kept all the same (Sol on c752a16: a name that did not fit lost its newest stamp).
 */
function keep(key: string, state: NameState): void {
  const lease = names();

  dropBlock(key);
  NAMES.delete(key);
  NAMES.set(key, state);

  for (const oldest of NAMES.keys()) {
    if (NAMES.size <= MAX_NAMES) break;

    if (!ASKING.has(oldest)) forget(oldest);
  }

  const weight = [...state.ids].reduce((n, [id, o]) => n + OBSERVATION_WEIGHT + (id.length + (o.advisory === null ? 0 : JSON.stringify(o.advisory).length)) * PARSE_WEIGHT, 0);

  if (weight === 0) return;

  // more than shedding every other name could make room for: only this one is held (Sol on 18281c9)
  if (weight > lease.limit - (lease.taken - blocksWeight)) {
    holdWhole(state);

    return;
  }

  let taken = lease.take(weight);

  for (const oldest of BLOCKS.keys()) {
    if (taken) break;
    shed(oldest);
    taken = lease.take(weight);
  }

  if (!taken) {
    holdWhole(state);

    return;
  }

  BLOCKS.set(key, lease.seal(weight));
  blocksWeight += weight;
}

/** The order of this isolate's asks of OSV about names; a copy from the data center's cache is 0. */
let asks = 0;

/**
 * Takes in what an answer asked for at `stamp` read: `found`, the advisories among the `read` ids that name the name,
 * and with `complete`, that no other advisory does. Each advisory takes the newest word on it: its newest observation,
 * else the newest complete answer, which said it was not listed. So an answer that lands after a newer one changes
 * nothing the newer one said. A complete answer asked for after the name was held ends the hold. Observations, the
 * complete stamp and the hold past NAME_STALE_MS are dropped.
 */
function observe(input: { key: string; stamp: Stamp; read: ReadonlySet<string>; found: readonly Advisory[]; complete: boolean; now: number }): void {
  const { key, stamp } = input;
  const state = NAMES.get(key) ?? { complete: null, hold: null, ids: new Map<string, Observation>() };

  for (const id of input.read) if (newerThan(stamp, state.ids.get(id) ?? state.complete)) state.ids.set(id, { ...stamp, advisory: input.found.find((a) => a.id === id) ?? null });

  if (input.complete) {
    // what it leaves out it says is not listed: the complete stamp says so, once it is the newest
    for (const [id, o] of state.ids) if (!input.read.has(id) && newerThan(stamp, o)) state.ids.delete(id);

    if (newerThan(stamp, state.complete)) state.complete = stamp;

    if (state.hold !== null && newerThan(stamp, state.hold)) state.hold = null;
  }

  // an advisory not listed, no newer than the newest complete answer: that answer says as much
  for (const [id, o] of state.ids) if (input.now - o.at >= NAME_STALE_MS || (o.advisory === null && state.complete !== null && !newerThan(o, state.complete))) state.ids.delete(id);

  if (state.complete !== null && input.now - state.complete.at >= NAME_STALE_MS) state.complete = null;

  if (state.hold !== null && input.now - state.hold.at >= NAME_STALE_MS) state.hold = null;
  keep(key, state);
}

/** Whether the newest complete answer of the name under `key` was asked for at `stamp`. */
const newestComplete = (key: string, stamp: Stamp): boolean => {
  const c = NAMES.get(key)?.complete ?? null;

  return c !== null && c.at === stamp.at && c.seq === stamp.seq;
};

/**
 * The advisories the name under `key` names by its newest observations at `now`, each while it is young enough, and
 * HELD while it is held. The request's `lease` holds their block, so it stays charged while the request refers to it
 * (Sol on c752a16); with no room for it, each names every version.
 */
function answerOf(key: string, now: number, lease: Lease | null): Advisory[] {
  const state = NAMES.get(key);
  const block = BLOCKS.get(key);
  const unheld = block !== undefined && lease !== null && !lease.hold(block);
  const young = (s: Stamp): boolean => s.at <= now && now - s.at < NAME_STALE_MS;
  const named = [...(state?.ids ?? [])].flatMap(([id, o]) => (o.advisory !== null && young(o) ? [unheld ? everyVersion(id) : o.advisory] : []));

  return state?.hold != null && young(state.hold) ? [...named, everyVersion(HELD)] : named;
}

/** The data center's cache key of a name's advisories. This host is never fetched; it only names the entry. */
const sharedKey = (key: string): Request => new Request(`https://osv-cache.apmjs.internal/v2/${encodeURIComponent(key)}`);

/**
 * The most of a copy read from the data center's cache. It is read under the request's `lease` as an advisory is
 * (READ_WEIGHT, PARSE_WEIGHT).
 */
const SHARED_MAX_BYTES = 1024 * 1024;

/**
 * The data center's copy of a name's advisories: none (outside a Worker too), the copy, or "unread": one is there that
 * could not be read (too large, too late, unreadable, no room in the request), so it is not known to list nothing (Sol
 * on c752a16: read as none, a refusal let the name be served as unlisted).
 */
type SharedCopy = { kind: "miss" } | { kind: "hit"; entry: NameEntry } | { kind: "unread" };

/**
 * The copy of the name under `key`. Its read holds its room, and the request's lease open, until it has ended and what
 * it read is parsed: one past SHARED_MS is cancelled first (Sol on c752a16: its room was given back while it still read).
 * A copy read stays charged to the request until it ends, as an advisory does.
 */
async function sharedRead(key: string, lease: Lease | null): Promise<SharedCopy> {
  if (typeof caches === "undefined") return { kind: "miss" };
  const got = await matchWithin({ cache: caches.default, key: sharedKey(key), ms: SHARED_MS, operation: "osv-copy" });

  // a lookup past its deadline may have found one (Sol on dd47451)
  if (got.kind === "late") return { kind: "unread" };

  if (got.kind === "miss") return { kind: "miss" };
  const room = SHARED_MAX_BYTES * READ_WEIGHT;

  if (lease !== null && !lease.take(room)) {
    void got.res.body?.cancel().catch(() => undefined);

    return { kind: "unread" };
  }

  const letGo = lease?.retain() ?? (() => undefined);

  const settle = (): void => {
    lease?.give(room);
    letGo();
  };

  const stop = new AbortController();
  const reading = readCapped(got.res, SHARED_MAX_BYTES, stop.signal);
  const bytes = await within(reading, SHARED_MS);

  if (bytes.kind === "late") {
    stop.abort();
    void reading.finally(settle).catch(() => undefined);

    return { kind: "unread" };
  }

  // the read has ended; its room is kept until what it read is parsed or let go of (Sol on dd47451)
  try {
    if (bytes.kind !== "done" || bytes.value === null) return { kind: "unread" };
    const parsing = bytes.value.length * PARSE_WEIGHT;

    if (lease !== null && !lease.take(parsing)) return { kind: "unread" };

    try {
      const parsed = NameEntry.safeParse(JSON.parse(new TextDecoder().decode(bytes.value)));

      if (parsed.success) return { kind: "hit", entry: parsed.data };
    } catch {
      // not JSON: unread
    }

    lease?.give(parsing);

    return { kind: "unread" };
  } finally {
    settle();
  }
}

/** What the Worker keeps running after the response (ctx.waitUntil), or null outside one. */
export type FeedBackground = ((work: Promise<void>) => void) | null;

/** How long a copy written to the data center's cache is kept running after the response. */
const SHARED_WRITE_MS = 5_000;

/** A copy to write: its answer's stamp, its text, and the weight that text holds of names() until it is written. */
type Copy = { readonly stamp: Stamp; readonly text: string; readonly weight: number };

/** A name's writes: the newest copy waiting for the one being written, and the promise of them all. */
type Writes = { next: Copy | null; done: Promise<void> };

/**
 * Each name's copy being written to the data center's cache, by key: the writes running, and the newest copy waiting
 * for them, which a newer one replaces. So a put that never ends holds back one copy of its name, charged (Sol on
 * c752a16: the queue grew unbounded and uncharged).
 */
const WRITING = new Map<string, Writes>();

/**
 * Gives the data center a copy of a name's complete answer asked for at `stamp`, after the response, in the request's
 * waitUntil when it has one. The writes of one name run one after another, each only while its answer is still the
 * isolate's newest complete one, so this isolate never leaves an older answer's copy over a newer one's (Sol on
 * 6f206c5); the next waits for the put itself, not the response's wait on it (Sol on fb84083). Its text is charged to
 * names() from now until it is written, and it is not written when that does not fit.
 */
function sharedWrite(key: string, stamp: Stamp, entry: NameEntry, background: FeedBackground): void {
  if (typeof caches === "undefined" || !newestComplete(key, stamp)) return;
  const text = JSON.stringify(entry);
  const copy: Copy = { stamp, text, weight: text.length * READ_WEIGHT };

  if (!names().take(copy.weight)) return;
  const running = WRITING.get(key);

  if (running !== undefined) {
    if (running.next !== null) names().give(running.next.weight);
    running.next = copy;

    if (background !== null) background(within(running.done, SHARED_WRITE_MS).then(() => undefined));

    return;
  }

  const slot: Writes = { next: copy, done: Promise.resolve() };

  WRITING.set(key, slot);
  slot.done = (async () => {
    for (let w = slot.next; w !== null; w = slot.next) {
      slot.next = null;

      try {
        if (newestComplete(key, w.stamp)) await caches.default.put(sharedKey(key), new Response(w.text, { headers: { "content-type": "application/json", "cache-control": `max-age=${NAME_STALE_MS / 1000}` } }));
      } catch {
        // a copy not written is asked for again by the next isolate that has none
      } finally {
        names().give(w.weight);
      }
    }

    WRITING.delete(key);
  })();

  if (background !== null) background(within(slot.done, SHARED_WRITE_MS).then(() => undefined));
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
  async (res: Response, signal: AbortSignal): Promise<Advisory[]> => {
    const bytes = await readCapped(res, MAX_ADVISORY_BYTES, signal);

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
    const naming = advisories.filter((a) => affects(a, version));
    const ids = naming.map((a) => a.id);
    const unchecked = naming.flatMap((a) => (a.every === true || isHold(a.id) ? [a.id] : []));

    if (ids.length > 0) out.set(version, unchecked.length > 0 ? { name, version, ids, unchecked } : { name, version, ids });
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
    const post = <T>(path: string, body: OsvBatchQuery | OsvPageQuery | null, take: (res: Response, signal: AbortSignal) => Promise<T>, settled: () => void = () => undefined) =>
      Effect.tryPromise({
        // `interrupted` aborts when the effect is interrupted: the fetch and its read stop then, and `settled` runs only
        // once they have (Sol on 18281c9: the read's room was given back while its stream was still open)
        try: async (interrupted): Promise<T> => {
          try {
            const left = REQUEST_BUDGET_MS - spent();

            if (left <= 0) throw new Error("the request's OSV budget is spent");

            if (inFlight++ === 0) busySince = Date.now();

            try {
              const signal = AbortSignal.any([interrupted, AbortSignal.timeout(left)]);

              const init: RequestInit =
                body === null
                  ? { method: "GET", headers: { accept: "application/json" }, signal }
                  : { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(body), signal };

              const res = await fetcher(`${baseUrl}${path}`, init);

              if (res.status !== 200) {
                await res.body?.cancel();
                throw new Error(`OSV answered ${res.status}`);
              }

              return await take(res, signal);
            } finally {
              if (--inFlight === 0) spentMs += Date.now() - busySince;
            }
          } finally {
            settled();
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

        /** One advisory's read: room for its bytes is taken from `lease` before it starts, and given back once its read has ended. */
        const readOne = (id: string) =>
          Effect.gen(function* () {
            const room = MAX_ADVISORY_BYTES * READ_WEIGHT;

            if (lease !== null && !lease.take(room)) return { kind: "withheld" } as const;
            // the room, and the request's lease, are held until the read itself has ended, interrupted or not
            const letGo = lease?.retain() ?? (() => undefined);

            const got = yield* Effect.result(
              post(`v1/vulns/${encodeURIComponent(id)}`, null, advisoryRead(name, lease), () => {
                lease?.give(room);
                letGo();
              }),
            );

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

    /** What advisoriesFor answers for npm's `name`, kept in the isolate under `key`, asked about under the request's `lease`. */
    const lookupName = (name: string, key: string, lease: Lease | null) =>
      Effect.gen(function* () {
        // a name held (keep) is asked about again
        const fresh = (now: number): boolean => {
          const state = NAMES.get(key);
          const at = state?.complete?.at ?? null;

          return state !== undefined && state.hold === null && at !== null && at <= now && now - at < NAME_FRESH_MS;
        };

        const asked = Date.now();

        if (fresh(asked)) return answerOf(key, asked, lease);
        const shared = yield* Effect.promise((): Promise<SharedCopy> => sharedRead(key, lease).catch((): SharedCopy => ({ kind: "unread" })));
        // the cache read is waited for: what it found, and what another request learned meanwhile, is judged as of
        // when it came back (Sol on 6f206c5)
        const now = Date.now();

        // a copy from the data center's cache is a complete answer like this isolate's own, fresh or stale: it retires
        // what older answers said of the advisories it leaves out
        if (shared.kind === "hit" && shared.entry.fetchedAt <= now && now - shared.entry.fetchedAt < NAME_STALE_MS) {
          const { fetchedAt, advisories } = shared.entry;

          observe({ key, stamp: { at: fetchedAt, seq: 0 }, read: new Set(advisories.map((a) => a.id)), found: advisories, complete: true, now });
        }

        if (fresh(now)) return answerOf(key, now, lease);

        /**
         * What is known while OSV gives no complete answer, each advisory while it is young enough (fail open past that);
         * but a copy that could not be read may list what nothing here knows of, so then every version is withheld (Sol
         * on c752a16).
         */
        const known = (at: number): Advisory[] => [...answerOf(key, at, lease), ...(shared.kind === "unread" ? [everyVersion(UNREAD_COPY)] : [])];

        // OSV is not asked
        if (stopped || spent() >= REQUEST_BUDGET_MS || (BACKOFF.get(baseUrl) ?? 0) > now) return known(now);
        // stamped as the ask starts
        const stamp: Stamp = { at: Date.now(), seq: ++asks };
        const got = yield* Effect.result(askName(name, lease));
        // the answer is taken in as of when it was asked for, and what is answered is read from the state after it, so
        // an answer asked for later that landed first is neither undone nor left out (Sol on #59, finding 3)
        const after = Date.now();

        if (Result.isSuccess(got) && got.success.complete) {
          const { advisories, read } = got.success;

          observe({ key, stamp, read, found: advisories, complete: true, now: after });
          sharedWrite(key, stamp, { fetchedAt: stamp.at, advisories }, background);

          return answerOf(key, after, lease);
        }

        console.error(JSON.stringify({ event: "osv-name", name, error: Result.isSuccess(got) ? "partial answer" : String(got.failure) }));
        // no more waiting on OSV in this request: what is kept still counts
        stopped = true;

        if (Result.isFailure(got)) {
          // the first page went unanswered: OSV is taken as down at this root for a while
          BACKOFF.set(baseUrl, stamp.at + NAME_BACKOFF_MS);

          return known(after);
        }

        // a partial answer is OSV's word on the advisories it read (a withdrawal included), never on the name: it is
        // kept for those, and for the rest what was known stands, but for one it withheld, which names every version
        // here, whatever was known of it. The next request asks again
        const { read, advisories, withheld } = got.success;

        observe({ key, stamp, read, found: advisories, complete: false, now: after });
        const answer = [...known(after).filter((a) => !withheld.has(a.id)), ...[...withheld].map(everyVersion)];

        partials.set(name, answer);

        return answer;
      });

    return KnownMalicious.of({
      advisoriesFor: (name) =>
        Effect.gen(function* () {
          if (!isPossibleNpmName(name)) return [];
          const partial = partials.get(name);

          // this request already had a partial answer for the name: every later read in it gets the same
          if (partial !== undefined) return partial;
          const key = `${baseUrl} ${name}`;
          const lease = Option.getOrNull(yield* Effect.serviceOption(RequestMemory));

          ASKING.set(key, (ASKING.get(key) ?? 0) + 1);

          return yield* lookupName(name, key, lease).pipe(
            Effect.ensuring(
              Effect.sync(() => {
                const n = (ASKING.get(key) ?? 1) - 1;

                if (n > 0) ASKING.set(key, n);
                else ASKING.delete(key);
              }),
            ),
          );
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

/**
 * Why a listed version is refused, citing its advisories; or, when only apm's holds name it (isHold), that it could not
 * be checked against the feed, never that the feed lists it (Sol on dd47451).
 */
export function maliciousText(m: ListedMalicious): string {
  const listed = m.ids.filter((id) => !isHold(id) && m.unchecked?.includes(id) !== true);

  return listed.length > 0
    ? `known malicious: the OSSF malicious-packages feed lists ${m.name}@${m.version} (${listed.join(", ")})`
    : `not checked: apm could not check ${m.name}@${m.version} against the OSSF malicious-packages feed just now (${m.ids.join(", ")})`;
}

/** What the tarball routes answer for a listed version: 403, citing its advisories, and the first one's page at OSV. */
export function listedTarballText(m: ListedMalicious): string {
  const first = m.ids.find((id) => !isHold(id) && m.unchecked?.includes(id) !== true);

  return first === undefined ? `${maliciousText(m)}, so apm does not serve it. Try again shortly.` : `${maliciousText(m)}, so apm does not serve it. See https://osv.dev/vulnerability/${first}`;
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
  const listed = advisories.filter((a) => !isHold(a.id) && a.every !== true);
  const each = listed.map((a) => `${a.id}: ${[...a.versions, ...a.ranges.map(range)].join(", ")}`).join("; ");
  const parts = [...(listed.length > 0 ? [`versions the OSSF malicious-packages feed lists as malicious (${each})`] : []), ...(listed.length < advisories.length ? ["every version for now, as it could not check them against the OSSF malicious-packages feed"] : [])];
  const text = `apm withholds ${name} ${parts.join(", and ")}`.replace(/[^\x20-\x7e]/g, "?");

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
