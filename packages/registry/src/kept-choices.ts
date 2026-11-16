// What a read of an upstream package chose of it, kept with npm's ETag (migration 0021, upstream.ts `chosen`). A
// choice is named by a key that says everything it reads (a dependency's range or tag, a resolve root's page): it
// reads only the packument's version numbers, states and dist-tags, so the same key chooses the same versions of the
// same packument, and while npm answers 304 for the ETag a row was kept for, its choices hold. A row is kept for one
// document: the exact URL the packument was asked for at, which answered directly (no redirect), with a strong ETag
// (review of 3aacc2a, finding 1; re-check of 3366a36, findings 3 and 4). Each choice keeps when the whole read it was
// made from fetched its packument, and answers for at most KEPT_CHOICES_MAX_AGE_MS from then (finding 2 of both).
// Bounded: a row keeps at most KEPT_CHOICES_MAX_CHOICES choices and KEPT_CHOICES_MAX_TEXT bytes as Postgres stores it,
// and the table at most KEPT_CHOICES_CAPACITY rows (db.ts, writeChoices), so no caller can grow it without bound.
//
// Keeping is strictly second to answering (re-check of 3366a36, finding 1): what it holds while a batch is chosen (the
// rows read, the rows planned) is charged to a lease of its own (KeptSide), never the request's, taken only from room
// the pool has free, and given up before anything else when an answer needs room. Rows are written after the batch's
// answers are made, one at a time, each under a short reservation of the request's lease given back before the next.
import { Context, Effect } from "effect";
import { Clock } from "./clock.ts";
import { Store, storableJson, type KeptChoices, type KeptChoicesRow, type StoreApi, type VersionRecord } from "./db.ts";
import type { StoreError } from "./errors.ts";
import type { BackgroundLease, Lease, MemoryPool, RequestMemory } from "./memory.ts";
import { WEIGHTS } from "./packument-read.ts";
import { jsonBound, SUMMARY_MANIFEST_FIELDS, summaryVersion, textReadWeight, versionAllowance, type Reserve } from "./walk-catalog.ts";

/** One choice a reader makes of a package's versions, named by `key` (see above), newest first. */
export type Choice = { readonly key: string; readonly choose: (pkg: { readonly distTags: Record<string, string>; readonly versions: readonly VersionRecord[] }) => readonly VersionRecord[] };

/** What a reader is handed of a package: its name, dist-tags and the versions each of its choices took, by key. */
export type Chosen = { readonly name: string; readonly distTags: Record<string, string>; readonly versions: ReadonlyMap<string, readonly VersionRecord[]> };

/** The most rows upstream_choices holds: about what a few thousand resolves of different trees fill. */
export const KEPT_CHOICES_CAPACITY = 5_000;

/**
 * The most bytes a kept row may be as Postgres stores it (octet_length of its jsonb text; next's root page of 21
 * versions is about 31 K, sharp's 30 K, a pick 1.5 K).
 */
export const KEPT_CHOICES_MAX_TEXT = 64 * 1024;

/**
 * How long after the whole read it was made from fetched its packument a choice answers npm's 304s. Past it the
 * packument is read whole again, as a 200 is: what a whole read does beside choosing (the AI review's look at the
 * versions npm lists, which tries again on the next whole read when it could not run) waits at most this long, and
 * so would anything an ETag got wrong. A choice made from the isolate cache is as old as the read that filled it, and
 * a later whole read under the same ETag keeps an older choice's time, so nothing makes a choice young again.
 */
export const KEPT_CHOICES_MAX_AGE_MS = 60 * 60_000;

/** The most choices one row keeps, on every write: a package asked for under more ranges at once keeps none. */
export const KEPT_CHOICES_MAX_CHOICES = 16;

/** The most one batch's kept rows may hold once read. */
export const KEPT_CHOICES_READ_ALLOWANCE = 8 * 1024 * 1024;

/** The sweep drops a row nobody asked about for this long. */
export const KEPT_CHOICES_DROP_MS = 7 * 24 * 60 * 60_000;

/** What reading kept text is charged per octet, separator and object: textReadWeight's terms. */
export const KEPT_TEXT_WEIGHTS = { octet: 2 * WEIGHTS.text + WEIGHTS.parse * WEIGHTS.text, node: WEIGHTS.container + WEIGHTS.dictKey, object: WEIGHTS.hiddenClass } as const;

/**
 * Whether `etag` is one a row may be kept for and validated with: a strong validator. A weak one (`W/...`) says two
 * representations are only equivalent, not the same bytes, and no ETag says nothing (re-check of 3366a36, finding 3).
 */
export const isStrongEtag = (etag: string | null): etag is string => etag !== null && etag !== "" && !etag.startsWith("W/");

/** Something the cache holds on its side: its weight, and whether a read is using it right now (then it is kept). */
type Holding = { readonly weight: number; inUse: boolean; dropped: boolean; readonly onDrop: () => void };

/** The sides open in each pool, so the pool's pressure reaches them all; the reclaimer is registered once a pool. */
const openSides = new WeakMap<MemoryPool, Set<KeptSide>>();

/**
 * What keeping choices holds while one batch is chosen: a background lease of the pool, never the request's, that
 * takes only room the pool has free (it never makes the pool give up the isolate cache's entries), and whose holdings
 * the pool takes back first when anything else needs room (a holding in use is skipped). Closed when the batch ends.
 */
export class KeptSide implements Reserve {
  private readonly holdings = new Set<Holding>();
  private readonly lease: BackgroundLease;
  private readonly pool: MemoryPool;

  private constructor(pool: MemoryPool) {
    this.pool = pool;
    this.lease = pool.backgroundLease();
  }

  /** A side of `pool`'s, open until close(). */
  static open(pool: MemoryPool): KeptSide {
    let sides = openSides.get(pool);

    if (sides === undefined) {
      const made = new Set<KeptSide>();
      sides = made;
      openSides.set(pool, made);
      pool.onPressure(
        (need) => {
          let freed = 0;

          for (const side of made) {
            if (freed >= need) return;
            freed += side.reclaim(need - freed);
          }
        },
        { first: true },
      );
    }

    const side = new KeptSide(pool);
    sides.add(side);

    return side;
  }

  /** Takes `n` from the room the pool has free, or nothing and false: it never asks the pool to make room. */
  take(n: number): boolean {
    if (n <= 0) return true;

    if (this.pool.unused < n) return false;

    return this.lease.take(n);
  }

  give(n: number): void {
    this.lease.give(n);
  }

  /** The room take() may have at most now. */
  get room(): number {
    return this.pool.unused;
  }

  /** `weight`, already taken, held until let go or dropped under pressure; `onDrop` forgets what it stood for. */
  hold(weight: number, onDrop: () => void): Holding {
    const h: Holding = { weight, inUse: false, dropped: false, onDrop };
    this.holdings.add(h);

    return h;
  }

  /**
   * `plan` (its one charge already taken) held until it is written or the side closes. Taking it back drops the string
   * and its charge together; a claimed plan is pinned (in use), so the pool skips it until it is done.
   */
  holdPlan(plan: KeptPlan): PlanHandle {
    let slot: KeptPlan | null = plan;

    const held = this.hold(plan.weight, () => {
      slot = null;
    });

    return {
      document: plan.document,
      claim: () => {
        if (slot !== null) held.inUse = true;

        return slot;
      },
      done: () => {
        slot = null;
        held.inUse = false;
        this.letGo(held);
      },
    };
  }

  /** A holding given back: its owner is done with it. */
  letGo(h: Holding): void {
    if (h.dropped || !this.holdings.delete(h)) return;
    h.dropped = true;
    this.give(h.weight);
  }

  /** Holdings not in use given back until `need` is freed; how much was. */
  private reclaim(need: number): number {
    let freed = 0;

    for (const h of this.holdings) {
      if (freed >= need) break;

      if (h.inUse) continue;
      this.letGo(h);
      h.onDrop();
      freed += h.weight;
    }

    return freed;
  }

  /** Everything given back; the side is no longer asked for room. */
  close(): void {
    for (const h of this.holdings) this.letGo(h);
    this.lease.release();
    openSides.get(this.pool)?.delete(this);
  }
}

/** A kept row as read, with what reading it holds, taken from the side it was read under. */
export type HeldRow = KeptChoicesRow & { readonly weight: number };

/**
 * The kept rows of `documents`, read under a reservation from `side` taken before they are sent (at most
 * KEPT_CHOICES_READ_ALLOWANCE, less when the pool has less room free) and settled to what they hold. What stays taken
 * is each row's weight; the caller holds or gives it back. None when nothing fits.
 */
export const keptRowsWithin = (input: { store: StoreApi; documents: readonly string[]; side: KeptSide; at: number }) =>
  Effect.gen(function* () {
    const { store, documents, side, at } = input;
    const out = new Map<string, HeldRow>();
    const allowance = Math.min(KEPT_CHOICES_READ_ALLOWANCE, side.room);

    if (documents.length === 0 || allowance === 0 || !side.take(allowance)) return out;
    const rows = yield* store.keptChoicesOf({ documents, allowance, weights: KEPT_TEXT_WEIGHTS, at }).pipe(Effect.onError(() => Effect.sync(() => side.give(allowance))));
    const held = rows.map((r) => ({ ...r, weight: textReadWeight(r.size) }));
    const total = held.reduce((n, r) => n + r.weight, 0);

    // the statement weighs each row as textReadWeight does; were it ever to send more, that is charged or dropped
    if (total > allowance && !side.take(total - allowance)) {
      side.give(allowance);

      return out;
    }

    if (total < allowance) side.give(allowance - total);

    for (const r of held) out.set(r.document, r);

    return out;
  });

/** Whether the choice `key` of `kept` may answer at `at`: kept, younger than KEPT_CHOICES_MAX_AGE_MS, with every record. */
export function choiceHolds(kept: KeptChoices, key: string, at: number): boolean {
  const list = kept.lists[key];

  return list !== undefined && at - list.at < KEPT_CHOICES_MAX_AGE_MS && list.versions.every((v) => kept.records[v] !== undefined);
}

type KeptRecord = KeptChoices["records"][string];

/** A version's record as a row keeps it: its manifest summarized (summaryVersion), without its score. */
function keptRecord(v: VersionRecord): KeptRecord {
  const { score: _score, unscorable: _unscorable, ...record } = summaryVersion(v).summary;

  return record;
}

const COLON = 0x3a;
const COMMA = 0x2c;

/**
 * The most bytes `text` (JSON) is as Postgres stores it as jsonb: its UTF-8 bytes (a surrogate pair is four, a lone
 * surrogate three as U+FFFD), and a space after every colon and comma, which jsonb's text puts there. Counted without
 * encoding it.
 */
export function storedBytes(text: string): number {
  let n = 0;

  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);

    if (c < 0x80) n += c === COLON || c === COMMA ? 2 : 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      n += 4;
      i++;
    } else n += 3;
  }

  return n;
}

/** `text`'s UTF-8 bytes, exactly (a lone surrogate is three, as U+FFFD): what the driver sends of it. */
export function utf8Bytes(text: string): number {
  let n = 0;

  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);

    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      n += 4;
      i++;
    } else n += 3;
  }

  return n;
}

/** What `text` holds on the heap: a byte a character while every character is at most U+00FF, else two. */
function heapBytes(text: string): number {
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) > 0xff) return 2 * text.length;

  return text.length;
}

/**
 * A row planned, before it is written: one string, the row's JSON text exactly as it is written, and nothing else.
 * `bytes`: its UTF-8 bytes, what the driver sends; `weight`: what it is charged, its UTF-8 bytes or what the string
 * holds on the heap, whichever is more (re-check of 51fc813: a plan holds no object graph whose parts are charged apart).
 */
export type KeptPlan = { readonly document: string; readonly etag: string; readonly text: string; readonly bytes: number; readonly weight: number };

/**
 * A planned row as the side holds it. `claim` gives its text and pins it, so the pool cannot take it back while it is
 * written; null once the pool took it back, and then the write is skipped. `done` lets it go, string and charge
 * together.
 */
export type PlanHandle = { readonly document: string; readonly claim: () => KeptPlan | null; readonly done: () => void };

/**
 * The row `versions` (each choice's versions, by key, made at `at`) make of a package read whole, or validated, with
 * npm's strong `etag` from `document`: only this read's choices, written as one string. Older choices kept for the
 * same ETag are merged into it by the database when it is written (db.ts, writeChoices), never read back here.
 *
 * Every allocation is reserved from `reserve` before it is made, from an upper bound counted on the input: the head
 * (dist-tags and lists) and its text, each record's summary and its text (versionAllowance), then the joined text. What stays taken
 * is the plan's one charge (KeptPlan.weight); every object it was built from is dropped. null, with nothing left
 * taken, when this read alone makes more than KEPT_CHOICES_MAX_CHOICES choices, when the dist-tags alone pass
 * KEPT_CHOICES_MAX_TEXT, when it does not fit, when Postgres would refuse it (U+0000 in jsonb), or when it is past
 * KEPT_CHOICES_MAX_TEXT bytes as stored.
 */
export function keptPlan(input: { document: string; etag: string; distTags: Record<string, string>; versions: ReadonlyMap<string, readonly VersionRecord[]>; reserve: Reserve; at: number }): KeptPlan | null {
  const { reserve, at } = input;

  if (input.versions.size > KEPT_CHOICES_MAX_CHOICES) return null;
  let tagChars = 0;

  // a character is at least a byte: dist-tags that alone pass the cap are refused before anything is built
  for (const [tag, v] of Object.entries(input.distTags)) tagChars += tag.length + v.length;

  if (tagChars > KEPT_CHOICES_MAX_TEXT) return null;
  let taken = 0;

  const take = (n: number): boolean => {
    if (!reserve.take(n)) return false;
    taken += n;

    return true;
  };

  const fail = (): null => {
    reserve.give(taken);

    return null;
  };

  // the head (the dist-tags and each choice's versions) and its text, reserved from a bound counted on the input before
  // any of it is built (review of acdb8eb, finding 2): the dist-tags as jsonBound bounds them, each key and version at
  // six characters a unit (the longest JSON escape), and each container and value of the lists at the most it takes
  let headLength = jsonBound(input.distTags).length + 64;
  let headNodes = 8;

  for (const [key, vs] of input.versions) {
    headLength += 6 * key.length + 64;
    headNodes += 6 + vs.length;

    for (const v of vs) headLength += 6 * v.version.length + 3;
  }

  if (!take(4 * headLength + headNodes * (WEIGHTS.container + WEIGHTS.dictKey + WEIGHTS.hiddenClass + WEIGHTS.value))) return fail();
  const head = { distTags: input.distTags, lists: Object.fromEntries([...input.versions].map(([key, vs]) => [key, { at, versions: vs.map((v) => v.version) }])) };
  const headText = JSON.stringify(head);
  // each record once, as `"<version>":<record>`, each charged as the string it is once its summary is let go
  const pieces: string[] = [];
  const seen = new Set<string>();

  for (const vs of input.versions.values()) {
    for (const v of vs) {
      if (seen.has(v.version)) continue;
      seen.add(v.version);
      // its summary (versionAllowance), and its piece of text at two bytes a character of an upper bound on its length:
      // the record's own fields and its cut manifest as JSON, and the version as the piece's key
      const fields = Object.keys(v).filter((k) => k !== "score" && k !== "unscorable" && k !== "manifest");
      const textBound = jsonBound(v, fields).length + jsonBound(v.manifest, [...SUMMARY_MANIFEST_FIELDS, "scripts"]).length + 2 * v.version.length + 16;
      const allowance = versionAllowance(v) + 2 * textBound;

      if (!take(allowance)) return fail();
      const piece = `${JSON.stringify(v.version)}:${JSON.stringify(keptRecord(v))}`;
      reserve.give(allowance);
      taken -= allowance;

      if (!take(heapBytes(piece))) return fail();
      pieces.push(piece);
    }
  }

  // the joined text, at two bytes a character of its length
  const length = headText.length - 1 + ',"records":{'.length + pieces.reduce((n, p) => n + p.length + 1, 0) + "}}".length;

  if (!take(2 * length)) return fail();
  const text = `${headText.slice(0, -1)},"records":{${pieces.join(",")}}}`;
  const bytes = utf8Bytes(text);

  if (storedBytes(text) > KEPT_CHOICES_MAX_TEXT || storableJson(text) !== text) return fail();
  // the head, the pieces and their objects are dropped here: the text is all the plan holds, and all it is charged
  const weight = Math.max(bytes, heapBytes(text));
  reserve.give(taken - weight);

  return { document: input.document, etag: input.etag, text, bytes, weight };
}

/** The installed driver's (@effect/sql-pg 4.1.2) shared message writer starts at this size and doubles from it (PgProtocol.ts, Writer). */
const DRIVER_POOL_BYTES = 8192;

/** The upsert's SQL text (about 2.4 KB) and the Parse, Describe, Execute and Sync messages around a write, at most. */
const DRIVER_STATEMENT_BYTES = 8192;

/** What a write's other parameters take beside the row's text: each document and ETag the statement names, and its numbers. */
const DRIVER_PARAMS_SLACK = 1024;

/**
 * An upper bound on what the database driver allocates to send one row's upsert (review of acdb8eb, finding 1), from
 * the installed @effect/sql-pg 4.1.2's code: its message writer (PgProtocol.ts, Writer) encodes a string parameter
 * longer than 48 characters by reserving three bytes per UTF-16 unit, and when a message outgrows its buffer it
 * allocates a new one from 8 KiB doubling until it fits, copying the message across, so for a moment the old and the
 * new buffer are both held (at most twice the final buffer); the Parse message may need a fresh 8 KiB one; then the
 * connection copies the whole frame, Parse, Bind and the rest, into one more buffer for the socket (PgConnection.ts,
 * concat). The row's text is the Bind's largest parameter; the document and ETag appear a few times each.
 */
export function driverWriteBytes(plan: Pick<KeptPlan, "text" | "document" | "etag">): number {
  const bind = 3 * plan.text.length + 4 * 3 * (plan.document.length + plan.etag.length) + DRIVER_PARAMS_SLACK;
  let buffer = DRIVER_POOL_BYTES;

  while (buffer < bind) buffer *= 2;

  return 2 * buffer + DRIVER_POOL_BYTES + bind + DRIVER_STATEMENT_BYTES;
}

/**
 * Writes the planned rows the side still holds, one at a time in one transaction (db.ts, writeChoices, which merges
 * each into the row kept for the same document and ETag, and skips the whole write when another writer holds the
 * lock). Each plan is claimed first, so the pool cannot take it back while it is written, then what the driver
 * allocates to send it (driverWriteBytes) is reserved from `lease`, the row written, and both given back before the
 * next. A plan the pool took back, or whose driver allowance does not fit, is skipped. Every plan is let go once it is written or skipped. A
 * store error is logged, never the answer's.
 */
export const keepPlans = (input: { store: StoreApi; plans: readonly PlanHandle[]; at: number; lease: Lease }): Effect.Effect<void> => {
  const last = [...new Map(input.plans.map((p) => [p.document, p] as const)).values()];

  if (last.length === 0) return Effect.void;

  return input.store
    .writeChoices({ at: input.at, capacity: KEPT_CHOICES_CAPACITY, maxBytes: KEPT_CHOICES_MAX_TEXT, maxChoices: KEPT_CHOICES_MAX_CHOICES, maxAgeMs: KEPT_CHOICES_MAX_AGE_MS }, (put) =>
      Effect.forEach(
        last,
        (handle) => {
          const plan = handle.claim();

          if (plan === null) return Effect.void;
          // what the driver allocates for this write, reserved while the plan is pinned
          const driver = driverWriteBytes(plan);

          if (!input.lease.take(driver)) {
            handle.done();

            return Effect.void;
          }

          return put({ document: plan.document, etag: plan.etag, text: plan.text }).pipe(
            Effect.ensuring(
              Effect.sync(() => {
                input.lease.give(driver);
                handle.done();
              }),
            ),
          );
        },
        { discard: true },
      ),
    )
    .pipe(
      Effect.catchTag("StoreError", (e: StoreError) => Effect.logWarning("kept choices not written", { documents: last.length, operation: e.operation })),
      Effect.ensuring(
        Effect.sync(() => {
          for (const handle of input.plans) handle.done();
        }),
      ),
    );
};

/**
 * Writes kept choices after the response (worker.ts: ctx.waitUntil, on a connection and a memory lease of its own),
 * so an answer never waits on keeping (combined review of 67d8658, finding 4). `write` is handed the run's store and
 * lease. Absent outside a Worker request (unit tests, the sweep, the queue): the write runs before the answer, and
 * still never waits on another writer's lock.
 */
export class ChoicesWriter extends Context.Service<ChoicesWriter, { readonly later: (write: Effect.Effect<void, never, Store | RequestMemory>) => Effect.Effect<void> }>()("@apm/registry/ChoicesWriter") {}

/** The cron's part: drops the rows nobody asked about for KEPT_CHOICES_DROP_MS. */
export const dropStaleChoices = Effect.gen(function* () {
  const at = yield* (yield* Clock).now;

  yield* (yield* Store).dropKeptChoices({ askedBefore: at - KEPT_CHOICES_DROP_MS });
});
