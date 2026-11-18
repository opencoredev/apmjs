// Install checks answered in the data center (APM_INSTALL_CHECKS=edge, worker.ts). The install document and the tarball
// redirect of a package only npm has depend on two facts the database holds: whether the name is published here, and
// which of its versions an apm reviewer confirmed malicious. The install block list in R2 (blocklist.ts) holds both,
// is never less strict than the database, and is written by every write that adds either before that write commits.
// This module keeps each isolate's read of it (an "edge view"), so a request for an npm package needs no Postgres
// round trip (us-east-2) when the view says nothing refuses it.
//
// How fresh an answer is. A view is dated from when the R2 read that made it began (a copy from the data center's
// cache keeps the date of the R2 read it was made from), by the reading isolate's clock. A view clears a name with a
// clearance carrying that date, and the route asks `stillClear` again immediately before it commits its answer, after
// every wait (npm's document included): an answer is given only while its view is under EDGE_VIEW_MAX_AGE_MS (4 s)
// old, and anything older takes the database path. So an entry put on the list at P is in every view behind an answer
// given after P + 4 s + L + S, where L is the CPU time the answering request spent since its last I/O (Workers' clocks
// stand still while code runs, so the clock it checks lags by that much) and S how far the clock of the isolate that
// read R2 runs ahead of the answering one (a copy dated more than 250 ms ahead is not used).
//
// - A confirmed version: review.ts puts it on the list before the decision commits, so every edge refuses it from
//   4 s + L + S after the put.
// - A name published here: the publish puts it on the list, then waits FIRST_PUBLISH_HOLD_MS (8 s) before it opens the
//   transaction that creates it (server.ts fenceNewName). That covers the 4 s and leaves 4 s for L + S, so npm's
//   tarball or document is never served under a name that exists here unless an answering request spent nearly 4 s of
//   CPU between its last I/O and its answer. Every writer holds the fence (PublishFence), whatever the read mode, so a
//   build that reads edge views can roll out only once no build without the fence is publishing (docs/DEPLOY.md).
// - Revoke, yank, restore, deprecate and dist-tags change only packages published here, which never pass this check.
//
// How a view is read. A request that finds its isolate's view 2 s old (EDGE_REFRESH_AFTER_MS) starts the next read in
// the background (ctx.waitUntil) and answers without waiting for it, so steady traffic never waits for one. A request that finds none young enough reads it first,
// waiting at most EDGE_READ_DEADLINE_MS (300 ms) before it takes the database path instead. An isolate runs one read
// at a time, until that read settles: a request that finds one running waits for it, on its own timer, until that
// read's deadline (no promise is shared between requests, as Workers require), and one that comes after the deadline
// waits not at all and takes the database path; no second read starts while the first is out, however slow R2 is. A
// read's whole life is one promise held by the waitUntil of the request that started it: it settles when the read
// does, or after READ_LIFETIME_MS (10 s), when the read is abandoned and whatever it brings later is dropped unused.
// The isolate's one read ends exactly when that promise settles, never because time passed on a clock, so a second
// read never starts while the first can still land. The read starts before its request's response, so the promise
// settles well inside the 30 s that waitUntil may run after it; a stalled R2 costs an isolate one read per 10 s. A read
// first tries the data center's copy (the Cache API, written by the isolate that last read R2, used while under 2 s
// old), then R2.
//
// What a view does not decide goes to the database path as before: a name it lists as published here or with any
// confirmed version, a list missing, unreadable, never synced or not synced for LIST_STALE_MS (15 minutes: the cron
// syncs every 10), and any read that failed (a failure is kept like a view, so an R2 outage costs one read per window,
// not one per request). The cron's sync remains the backstop for anything written to the database without the list
// (by hand, or a test's SQL). Each isolate logs what its views decided once a minute (`edge-checks`), one count per
// request for how it was finally answered (a clearance that aged out before the answer counts as `expired` alone), so
// the R2 reads and the share of requests that fell back can be measured in production.
//
// A download answered from a view asks about its analysis after the answer, in the waitUntil of the request that
// accepted it and no other: it waits its turn for one of the isolate's QUEUED_MAX asks for at most ASK_WAIT_MS (5 s),
// then is dropped and forgotten, so a later download of it asks again. A turn takes its ask in the same step that sees
// it free, so no two turns take one ask. The ask itself, its statements, its queue send and their cleanup, gets
// ASK_DEADLINE_MS (15 s): past it the ask is aborted, its slot freed, the timeout counted (`queueTimeouts`) and the
// download asked about again after 5 s. So no accepted ask depends on another request's lifetime, and each request's
// work after its answer ends by 20 s, well inside the 30 s Workers allow.
import { Context, Duration, Effect, Layer, Option } from "effect";
import { BLOCKLIST_KEY, parseList, type BlocklistBody, type BlocklistReader } from "./blocklist.ts";

/** How long a view may decide an answer, from when the R2 read that made it began. */
export const EDGE_VIEW_MAX_AGE_MS = 4_000;

/** How old a view is before a request that uses it starts the next read after its response. */
export const EDGE_REFRESH_AFTER_MS = EDGE_VIEW_MAX_AGE_MS / 2;

/** How long a first publish waits after its name is on the list, before it opens the transaction that creates it. */
export const FIRST_PUBLISH_HOLD_MS = 2 * EDGE_VIEW_MAX_AGE_MS;

/** How long a request waits for a view before it takes the database path. */
export const EDGE_READ_DEADLINE_MS = 300;

/** A list the cron has not synced for this long decides nothing: a sync was missed. */
export const LIST_STALE_MS = 15 * 60_000;

/** A copy dated more than this ahead of the reader's clock is not used: isolates' clocks agree closer than this. */
const CLOCK_SKEW_MS = 250;

/** How often a request waiting on another request's read looks for its result. */
const POLL_MS = 10;

/**
 * How long a read may be out before it is abandoned: its promise settles then, what it brings later is dropped, and the
 * isolate may start another. Counted from the read's start, which comes before its request's response, so the timer
 * fires well inside the 30 s a Worker's waitUntil may run after that response.
 */
export const READ_LIFETIME_MS = 10_000;

/** How often an isolate logs what its views decided. */
const REPORT_EVERY_MS = 60_000;

/** Header of the data center's copy: when the R2 read it was made from began. */
const READ_AT = "x-apm-edge-read-at";

/** Why a view decides nothing. */
type Undecided = "missing" | "unreadable" | "never-synced" | "stale" | "failed";

/** What a view says of the list: the names it decides, or why it decides nothing. */
type Seen = { kind: "list"; local: ReadonlySet<string>; flagged: ReadonlySet<string> } | { kind: "none"; why: Undecided };

/** One read of the list. `readAt` is when the R2 read began, by the clock of the isolate that made it. */
export type EdgeView = { readonly readAt: number; readonly seen: Seen };

/**
 * Why a request takes the database path instead of the edge's answer. "unservable" is a name the view cleared whose
 * tarball npm's document does not let the edge redirect to (no such version, no checksum, another URL).
 */
export type EdgeFallback = "published-here" | "confirmed" | "no-view" | "slow-read" | "expired" | "unservable";

/** A view's word that nothing refuses a name: good only while `stillClear` says so, asked just before the answer. */
export type Clearance = { readonly kind: "clear"; readonly readAt: number };

export type EdgeVerdict = Clearance | { kind: "database"; reason: EdgeFallback };

/** What the edge checks use of the data center's cache (caches.default in a Worker). */
export type ColoCache = { match(key: string): Promise<Response | undefined>; put(key: string, res: Response): Promise<void> };

/** What an isolate logs once a minute: counts since its last line. */
export type EdgeReport = Readonly<
  Record<"clear" | EdgeFallback | "r2Reads" | "coloHits" | "readFailures" | "readTimeouts" | "queueSkipped" | "queueLate" | "queueFailures" | "queueTimeouts", number>
>;

export type EdgeOptions = {
  readonly bucket: BlocklistReader;
  /** The data center's cache, or null (outside a Worker, or on a workers.dev address, where it keeps nothing). */
  readonly cache: ColoCache | null;
  /** Where the data center's copy is kept: one key per registry (its public URL), so stages never share one. */
  readonly cacheKey: string;
  readonly now: () => number;
  /** Runs work after the response (ExecutionContext.waitUntil); null outside a request. */
  readonly background: ((work: Promise<void>) => void) | null;
  /** Where the once-a-minute counts go; null keeps none. */
  readonly report: ((counts: EdgeReport) => void) | null;
  /**
   * The view's age limit, how long a request waits for a read, how long a read may be out, how long an ask waits its
   * turn and how long it may run. Tests shorten them.
   */
  readonly maxAgeMs?: number;
  readonly readDeadlineMs?: number;
  readonly readLifetimeMs?: number;
  readonly askWaitMs?: number;
  readonly askDeadlineMs?: number;
};

function viewOf(list: BlocklistBody, readAt: number): EdgeView {
  if (list.syncedAt === null) return { readAt, seen: { kind: "none", why: "never-synced" } };

  if (readAt - list.syncedAt > LIST_STALE_MS) return { readAt, seen: { kind: "none", why: "stale" } };

  return { readAt, seen: { kind: "list", local: new Set(list.local.map((e) => e.name)), flagged: new Set(list.confirmed.map((e) => e.name)) } };
}

/** What `view` says of `name`, as of when it was read: the route still asks `stillClear` before it answers. */
export function verdictOf(view: EdgeView, name: string): EdgeVerdict {
  if (view.seen.kind === "none") return { kind: "database", reason: "no-view" };

  if (view.seen.local.has(name)) return { kind: "database", reason: "published-here" };

  if (view.seen.flagged.has(name)) return { kind: "database", reason: "confirmed" };

  return { kind: "clear", readAt: view.readAt };
}

type Counts = { -readonly [K in keyof EdgeReport]: number };

const zero = (): Counts => ({
  clear: 0,
  "published-here": 0,
  confirmed: 0,
  "no-view": 0,
  "slow-read": 0,
  expired: 0,
  unservable: 0,
  r2Reads: 0,
  coloHits: 0,
  readFailures: 0,
  readTimeouts: 0,
  queueSkipped: 0,
  queueLate: 0,
  queueFailures: 0,
  queueTimeouts: 0,
});

/** What an isolate keeps per bucket: its view, the read it is running (when it began), the downloads it asked about. */
type Held = {
  view: EdgeView | null;
  /** When the isolate's one read began, until its life (startRead) settles; null while none is out. */
  reading: number | null;
  /** How many reads have landed: a request waiting on another's read looks for this to move. */
  landed: number;
  counts: Counts;
  reportedAt: number | null;
  /** name@version → the time before which it is not asked about again. */
  asked: Map<string, number>;
  /** Asks running now, and the turns of the downloads waiting for one of them to finish, first come first. */
  running: number;
  waiting: number[];
  /** The next turn handed out. */
  turn: number;
};

/** Each bucket's state in this isolate (one bucket per Worker; a WeakMap so a test's bucket goes with it). */
const isolates = new WeakMap<BlocklistReader, Held>();

function heldFor(bucket: BlocklistReader): Held {
  const found = isolates.get(bucket);

  if (found !== undefined) return found;
  const made: Held = { view: null, reading: null, landed: 0, counts: zero(), reportedAt: null, asked: new Map(), running: 0, waiting: [], turn: 0 };

  isolates.set(bucket, made);

  return made;
}

/** Whether a view read at `readAt` may decide an answer at `at`: under `maxAgeMs` old, and not from the future. */
const usable = (readAt: number, at: number, maxAgeMs: number): boolean => at - readAt >= -CLOCK_SKEW_MS && at - readAt < maxAgeMs;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** `work`'s result, or null once `ms` passed first. */
async function within<T>(work: Promise<T>, ms: number): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  const late = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), ms);
  });

  try {
    return await Promise.race([work, late]);
  } finally {
    clearTimeout(timer);
  }
}

/** The data center's copy, when another isolate read R2 under `refreshMs` before `at`; null otherwise or on any failure. */
async function coloCopy(o: EdgeOptions, at: number, refreshMs: number): Promise<EdgeView | null> {
  if (o.cache === null) return null;

  try {
    const res = await o.cache.match(o.cacheKey);

    if (res === undefined) return null;
    const readAt = Number(res.headers.get(READ_AT));

    if (!Number.isFinite(readAt) || !usable(readAt, at, refreshMs)) {
      await res.body?.cancel();

      return null;
    }

    const parsed = parseList(await res.text());

    return parsed.kind === "ok" ? viewOf(parsed.list, readAt) : null;
  } catch {
    return null;
  }
}

/** Puts this isolate's read in the data center's cache, for as long as a view may be used; a failure costs nothing. */
async function keepCopy(o: EdgeOptions, text: string, readAt: number, maxAgeMs: number): Promise<void> {
  if (o.cache === null) return;

  try {
    const headers = new Headers({ "content-type": "application/json", "cache-control": `public, max-age=${Math.max(1, Math.floor(maxAgeMs / 1000))}`, [READ_AT]: String(readAt) });

    await o.cache.put(o.cacheKey, new Response(text, { headers }));
  } catch {
    // the next isolate reads R2 itself
  }
}

/** A read begun at `readAt`: the view, and the list's text when it came from R2 and may be copied for the data center. */
async function readView(o: EdgeOptions, held: Held, readAt: number, maxAgeMs: number): Promise<{ view: EdgeView; text: string | null }> {
  const copy = await coloCopy(o, readAt, maxAgeMs / 2);

  if (copy !== null) {
    held.counts.coloHits++;

    return { view: copy, text: null };
  }

  held.counts.r2Reads++;

  try {
    const obj = await o.bucket.get(BLOCKLIST_KEY);

    if (obj === null) return { view: { readAt, seen: { kind: "none", why: "missing" } }, text: null };
    const text = await obj.text();
    const parsed = parseList(text);

    if (parsed.kind !== "ok") return { view: { readAt, seen: { kind: "none", why: "unreadable" } }, text: null };
    const view = viewOf(parsed.list, readAt);

    return { view, text: view.seen.kind === "list" ? text : null };
  } catch {
    held.counts.readFailures++;

    return { view: { readAt, seen: { kind: "none", why: "failed" } }, text: null };
  }
}

/** Keeps `next` unless the isolate already holds a view read later. */
function keep(held: Held, next: EdgeView): void {
  if (held.view === null || next.readAt >= held.view.readAt) held.view = next;
}

/**
 * Starts this isolate's one read. Its life is one promise: the read, or null once `lifetimeMs` passed first, when the
 * read is abandoned and anything it brings later is never looked at. The isolate's one read ends when that promise
 * settles, and only then. A view that lands is kept at once, then copied for the data center (bounded the same way).
 * The returned promise is the view (null for an abandoned read), for the request that started it; the rest runs in its
 * background when there is one.
 */
function startRead(o: EdgeOptions, held: Held, maxAgeMs: number, lifetimeMs: number): Promise<EdgeView | null> {
  const readAt = o.now();

  held.reading = readAt;

  const life = within(readView(o, held, readAt, maxAgeMs), lifetimeMs).then((r) => {
    if (r === null) held.counts.readTimeouts++;
    else keep(held, r.view);
    held.landed++;
    held.reading = null;

    return r;
  });

  const done = life.then(async (r) => {
    if (r !== null && r.text !== null) await within(keepCopy(o, r.text, readAt, maxAgeMs), lifetimeMs);
  });

  o.background?.(done);

  return life.then((r) => (r === null ? null : r.view));
}

/** What a request may decide from: a view young enough now, or why it has none. */
type Lookup = { kind: "view"; view: EdgeView } | { kind: "slow" } | { kind: "expired" };

/** `view` if it may still decide at this moment (a read that took long can be past its age when it lands). */
function checked(o: EdgeOptions, view: EdgeView | null, maxAgeMs: number): Lookup {
  if (view === null) return { kind: "slow" };

  return usable(view.readAt, o.now(), maxAgeMs) ? { kind: "view", view } : { kind: "expired" };
}

/**
 * The view a request may decide from now: this isolate's while it is young enough (starting the next read after the
 * response once it is half its age limit), else a new one, waited for until the read's deadline. Never fails.
 */
export async function currentView(o: EdgeOptions): Promise<Lookup> {
  const maxAgeMs = o.maxAgeMs ?? EDGE_VIEW_MAX_AGE_MS;
  const deadlineMs = o.readDeadlineMs ?? EDGE_READ_DEADLINE_MS;
  const lifetimeMs = o.readLifetimeMs ?? READ_LIFETIME_MS;
  const held = heldFor(o.bucket);
  const at = o.now();
  const view = held.view;
  // the isolate's one read stays its one read until its life settles: one past its deadline sends requests to the
  // database path at once (the loop below does not wait), and none starts beside it, however long it has been out
  const running = held.reading;

  if (view !== null && usable(view.readAt, at, maxAgeMs)) {
    if (at - view.readAt >= maxAgeMs / 2 && running === null && o.background !== null) void startRead(o, held, maxAgeMs, lifetimeMs);

    return { kind: "view", view };
  }

  if (running === null) return checked(o, await within(startRead(o, held, maxAgeMs, lifetimeMs), deadlineMs), maxAgeMs);

  // another request's read: looked for on this request's own timer, until that read's deadline; past it, not at all
  const landed = held.landed;

  for (let waited = Math.max(0, at - running); waited < deadlineMs; waited += POLL_MS) {
    await sleep(POLL_MS);

    if (held.landed !== landed) return checked(o, held.view, maxAgeMs);
  }

  return { kind: "slow" };
}

/** Counts one decision, and sends the counts on once REPORT_EVERY_MS has passed since the last line. */
function count(o: EdgeOptions, held: Held, key: keyof Counts): void {
  held.counts[key]++;
  const at = o.now();

  if (held.reportedAt === null) held.reportedAt = at;

  if (o.report === null || at - held.reportedAt < REPORT_EVERY_MS) return;
  o.report(held.counts);
  held.counts = zero();
  held.reportedAt = at;
}

/** How long a download's analysis is not asked about again once asked, and after a failed ask. */
const ASKED_MS = 60_000;
const FAILED_RETRY_MS = 5_000;

/**
 * How many downloads an isolate remembers; how many asks it runs at once; how many downloads wait for one of those to
 * finish, each in the waitUntil of the request that accepted it, for at most ASK_WAIT_MS; how long an ask may run. A
 * download past both is skipped and not remembered, so a later download of it is asked about. An ask is a database statement and, for a
 * version not yet queued, an insert (production's round trip is 65 to 105 ms), so QUEUED_MAX at a time get through
 * WAITING_MAX in ASK_WAIT_MS while asks average under 0.33 s; slower, the late ones are dropped, counted and asked again
 * on a later download. One cold npm install of 83 new packages (scripts/perf/npm-install-bench.ts) fits. An ask (a
 * statement gives up at 8 s, db-health.ts; a queue send at 4 s, analysis.ts) is aborted at ASK_DEADLINE_MS whatever it
 * waits on, so the wait plus one ask ends by 20 s, well inside the 30 s a request's waitUntil may run after its response.
 */
const ASKED_MAX = 10_000;
export const QUEUED_MAX = 8;
export const WAITING_MAX = 120;
export const ASK_WAIT_MS = 5_000;
export const ASK_DEADLINE_MS = 15_000;

/** How often a download waiting its turn looks for a free ask. */
const TURN_POLL_MS = 25;

/** Remembers `key` until `until`, oldest first out past ASKED_MAX. */
function remember(asked: Map<string, number>, key: string, until: number): void {
  asked.delete(key);
  asked.set(key, until);

  if (asked.size > ASKED_MAX) {
    const oldest = asked.keys().next();

    if (!oldest.done) asked.delete(oldest.value);
  }
}

/** Whether `key` is not to be asked about at `at` (a clock that went back forgets it). */
function askedLately(asked: Map<string, number>, key: string, at: number): boolean {
  const until = asked.get(key);

  return until !== undefined && at < until && until - at <= ASKED_MS;
}

/** What asking about one download's analysis came to: "failed" is asked again after FAILED_RETRY_MS. */
export type AskOutcome = "asked" | "failed";

/** One ask: the download, and the signal that aborts it once ASK_DEADLINE_MS passed. */
export type AskInput = { readonly name: string; readonly version: string; readonly signal: AbortSignal };

export type EdgeChecksApi = {
  /** What this isolate's view says of `name`: a clearance for npm's answer, or why the database decides. */
  readonly verdict: (name: string) => Effect.Effect<EdgeVerdict>;
  /**
   * Whether `clearance` may still decide an answer: asked immediately before the answer, after every wait. It counts
   * the request as cleared, or as expired.
   */
  readonly stillClear: (clearance: Clearance) => Effect.Effect<boolean>;
  /** For a clearance the route could not answer from (npm's document did not let it): counts the request as unservable. */
  readonly declined: Effect.Effect<void>;
  /** A download answered from the view: its analysis asked about after the response, as the database path does inline. */
  readonly downloaded: (input: { name: string; version: string }) => Effect.Effect<void>;
};

export class EdgeChecks extends Context.Service<EdgeChecks, EdgeChecksApi>()("@apm/registry/EdgeChecks") {
  /** `later` asks about a download's analysis after the response, on services of its own, until aborted (worker.ts). */
  static layer(o: EdgeOptions, later: (input: AskInput) => Promise<AskOutcome>): Layer.Layer<EdgeChecks> {
    const maxAgeMs = o.maxAgeMs ?? EDGE_VIEW_MAX_AGE_MS;
    const held = heldFor(o.bucket);

    const verdict = (name: string): Effect.Effect<EdgeVerdict> =>
      Effect.map(
        Effect.promise(() => currentView(o)),
        (found): EdgeVerdict => {
          const decided: EdgeVerdict = found.kind === "view" ? verdictOf(found.view, name) : { kind: "database", reason: found.kind === "slow" ? "slow-read" : "expired" };

          // a clearance is counted when the route uses it (stillClear) or cannot (declined): once, as it was answered
          if (decided.kind === "database") count(o, held, decided.reason);

          return decided;
        },
      );

    const stillClear = (clearance: Clearance): Effect.Effect<boolean> =>
      Effect.sync(() => {
        const clear = usable(clearance.readAt, o.now(), maxAgeMs);

        count(o, held, clear ? "clear" : "expired");

        return clear;
      });

    const declined: Effect.Effect<void> = Effect.sync(() => count(o, held, "unservable"));

    const askWaitMs = o.askWaitMs ?? ASK_WAIT_MS;
    const askDeadlineMs = o.askDeadlineMs ?? ASK_DEADLINE_MS;

    /**
     * One ask, aborted once `askDeadlineMs` passed whatever it waits on. A failure or a timeout is asked again after
     * FAILED_RETRY_MS instead of a minute.
     */
    const ask = async (input: { name: string; version: string }): Promise<void> => {
      const abort = new AbortController();

      const outcome = await within(
        later({ ...input, signal: abort.signal }).catch((): AskOutcome => "failed"),
        askDeadlineMs,
      );

      if (outcome === "asked") return;

      if (outcome === null) abort.abort();
      remember(held.asked, `${input.name}@${input.version}`, o.now() + FAILED_RETRY_MS);
      count(o, held, outcome === null ? "queueTimeouts" : "queueFailures");
    };

    /**
     * Takes an ask for `turn` when it is among the first in line, one for each ask free now. The check, leaving the line
     * and taking the ask happen in one step, with no await between, so turns that look on the same tick never take more
     * asks than are free.
     */
    const take = (turn: number): boolean => {
      const place = held.waiting.indexOf(turn);

      if (place < 0 || place >= QUEUED_MAX - held.running) return false;
      held.waiting.splice(place, 1);
      held.running++;

      return true;
    };

    /**
     * Waits for `turn` to take an ask, on this request's own timer, for at most ASK_WAIT_MS; false when it did not. A
     * turn that took none leaves the line.
     */
    const awaitTurn = async (turn: number): Promise<boolean> => {
      for (let waited = 0; !take(turn); waited += TURN_POLL_MS) {
        if (waited >= askWaitMs) {
          const at = held.waiting.indexOf(turn);

          if (at >= 0) held.waiting.splice(at, 1);

          return false;
        }

        await sleep(TURN_POLL_MS);
      }

      return true;
    };

    /** One accepted download: its turn, then its ask, all in the waitUntil of the request that accepted it. */
    const run = async (input: { name: string; version: string }, key: string): Promise<void> => {
      const turn = held.turn++;

      held.waiting.push(turn);

      if (!(await awaitTurn(turn))) {
        // not asked: forgotten, so the next download of it asks again
        held.asked.delete(key);
        count(o, held, "queueLate");

        return;
      }

      // the ask was taken by awaitTurn, in the step that saw it free
      try {
        await ask(input);
      } finally {
        held.running--;
      }
    };

    const downloaded = (input: { name: string; version: string }): Effect.Effect<void> =>
      Effect.suspend(() => {
        const key = `${input.name}@${input.version}`;

        if (askedLately(held.asked, key, o.now())) return Effect.void;

        if (held.running + held.waiting.length >= QUEUED_MAX + WAITING_MAX) {
          count(o, held, "queueSkipped");

          return Effect.void;
        }

        remember(held.asked, key, o.now() + ASKED_MS);
        const work = run(input, key);

        if (o.background !== null) {
          o.background(work);

          return Effect.void;
        }

        return Effect.promise(() => work);
      });

    return Layer.succeed(EdgeChecks, EdgeChecks.of({ verdict, stillClear, declined, downloaded }));
  }
}

/**
 * A first publish's wait between putting its name on the list and opening the transaction that creates it. Every
 * Worker holds it whatever its read mode (worker.ts), so edge views can be turned on while older builds still publish
 * only once those builds are gone; outside a Worker (the Node dev server, unit tests) there is none.
 */
export class PublishFence extends Context.Service<PublishFence, { readonly hold: Effect.Effect<void> }>()("@apm/registry/PublishFence") {
  static layer(holdMs: number): Layer.Layer<PublishFence> {
    return Layer.succeed(PublishFence, PublishFence.of({ hold: holdMs > 0 ? Effect.sleep(Duration.millis(holdMs)) : Effect.void }));
  }
}

/** The publish fence's wait when this registry holds one; nothing otherwise. */
export const holdForEdges: Effect.Effect<void> = Effect.flatMap(Effect.serviceOption(PublishFence), (fence) => (Option.isSome(fence) ? fence.value.hold : Effect.void));
