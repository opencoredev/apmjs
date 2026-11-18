// What the install routes must refuse, kept where they can read it without Postgres: one JSON object in the registry's
// R2 bucket. It lists every package published on apm (its data lives only in Postgres, so during an outage a request for
// one is refused, never answered from npm under the same name) and every version an apm reviewer confirmed malicious
// (by its tarball's digest, as confirmed.ts matches them). degraded.ts reads it while the database is down.
//
// The list is never less strict than the database. A write that blocks something adds it here before its transaction
// commits (a first publish, from commitVersion; a confirmed review, from review.ts), and fails without changing
// anything when the add fails, so nothing is ever blocked in Postgres and missing here. Nothing in a request removes an
// entry: the cron's sync (`sync`) rewrites the list from the database every 10 minutes, keeping what the database holds
// plus whatever was added in the last SYNC_GRACE_MS (a block whose transaction may still be committing). A dismissed
// review or a publish that rolled back stays blocked here until then, which fails closed. Every write is a
// read-modify-write guarded by the object's ETag, so two writers never lose each other's entries.
//
// With APM_INSTALL_CHECKS=edge, each isolate also answers install reads of npm's packages from its read of the list
// (edge-checks.ts), under 4 s old when the answer is made.
//
// Until a sync has written the list (`syncedAt` null: a new stage, or an object that could not be read), degraded.ts
// refuses every install: it cannot tell an apm package from an npm one.
import { Context, Effect, Layer, Option } from "effect";
import type * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { Guard } from "./db-health.ts";
import { orDeadline, R2_GET_MS, readAllWithin } from "./deadline.ts";
import { BlobError, StoreError } from "./errors.ts";

/** The object's key in the registry's bucket. Tarballs live under sha512/ and file views under files/. */
export const BLOCKLIST_KEY = "state/install-blocklist.json";

/** How long an entry added by a write is kept by a sync that does not find it in the database. */
export const SYNC_GRACE_MS = 15 * 60_000;

/** How many times a write tries again when another writer changed the object between its read and its put. */
const WRITE_TRIES = 6;

const LocalEntry = z.object({ name: z.string(), addedAt: z.number() });
const ConfirmedEntry = z.object({ name: z.string(), version: z.string(), digest: z.string(), addedAt: z.number() });

const BlocklistBody = z.object({
  format: z.literal(1),
  /** When the cron last rewrote the list from the database; null until it has. */
  syncedAt: z.number().nullable(),
  local: z.array(LocalEntry),
  confirmed: z.array(ConfirmedEntry),
});

export type BlocklistBody = z.infer<typeof BlocklistBody>;

/** A version an apm reviewer confirmed malicious, by its tarball's digest label (digest.ts). */
export type ConfirmedVersion = { readonly name: string; readonly version: string; readonly digest: string };

/** What a write blocks. */
export type Blocks = { readonly local?: readonly string[]; readonly confirmed?: readonly ConfirmedVersion[] };

/** What the database says should be blocked, as the cron reads it. */
export type BlockTruth = { readonly local: readonly string[]; readonly confirmed: readonly ConfirmedVersion[] };

/** The list as read from R2. "unreadable" holds the object's ETag so a write can replace it. */
export type BlocklistRead = { kind: "ok"; list: BlocklistBody; etag: string } | { kind: "missing" } | { kind: "unreadable"; reason: string; etag: string };

const EMPTY: BlocklistBody = { format: 1, syncedAt: null, local: [], confirmed: [] };

const confirmedKey = (c: ConfirmedVersion): string => `${c.name}\u0000${c.version}\u0000${c.digest}`;

/**
 * `list` with `blocks` asserted at `at`. An entry already there is asserted again: its `addedAt` moves to `at`, so a
 * write whose transaction is about to commit always has the whole grace period, even when an older copy of the same
 * entry was about to age out (a review dismissed, then confirmed again while the cron read the dismissed state).
 */
export function withBlocks(list: BlocklistBody, blocks: Blocks, at: number): BlocklistBody {
  const local = new Map(list.local.map((e) => [e.name, e]));
  const confirmed = new Map(list.confirmed.map((e) => [confirmedKey(e), e]));

  for (const name of blocks.local ?? []) local.set(name, { name, addedAt: at });

  for (const c of blocks.confirmed ?? []) confirmed.set(confirmedKey(c), { name: c.name, version: c.version, digest: c.digest, addedAt: at });

  return { ...list, local: [...local.values()], confirmed: [...confirmed.values()] };
}

/**
 * The list a sync writes: everything `truth` holds, plus entries of `list` asserted within SYNC_GRACE_MS of `at`, whose
 * transactions may not have committed when the database was read. Each entry keeps the time a write last asserted it:
 * a sync never makes an entry young again, and never ages one a write just asserted.
 */
export function reconciled(list: BlocklistBody, truth: BlockTruth, at: number): BlocklistBody {
  const recent = (e: { addedAt: number }): boolean => e.addedAt > at - SYNC_GRACE_MS;
  const firstLocal = new Map(list.local.map((e) => [e.name, e.addedAt]));
  const firstConfirmed = new Map(list.confirmed.map((e) => [confirmedKey(e), e.addedAt]));
  const local = new Set([...truth.local, ...list.local.filter(recent).map((e) => e.name)]);
  const confirmed = new Map<string, ConfirmedVersion>([...truth.confirmed, ...list.confirmed.filter(recent)].map((c) => [confirmedKey(c), c]));

  return {
    format: 1,
    syncedAt: at,
    local: [...local].map((name) => ({ name, addedAt: firstLocal.get(name) ?? at })),
    confirmed: [...confirmed].map(([key, c]) => ({ name: c.name, version: c.version, digest: c.digest, addedAt: firstConfirmed.get(key) ?? at })),
  };
}

/** What the list says about one package name. */
export type NameVerdict = { kind: "local" } | { kind: "upstream"; confirmed: readonly ConfirmedVersion[] };

export function verdictFor(list: BlocklistBody, name: string): NameVerdict {
  if (list.local.some((e) => e.name === name)) return { kind: "local" };

  return { kind: "upstream", confirmed: list.confirmed.filter((e) => e.name === name) };
}

/** What reading the list uses of an R2 bucket: an object's body and ETag. */
export type BlocklistReader = { get(key: string): Promise<{ readonly body: ReadableStream<Uint8Array>; readonly etag: string } | null> };

/**
 * A bound on a whole read of the list, its get and its body together: past `ms` (or once `signal` aborts) the read
 * fails, and a body still coming is cancelled.
 */
export type ReadBound = { readonly ms: number; readonly operation: string; readonly signal?: AbortSignal };

/** A put's options as the list writes them: always conditional on what it read. */
export type BlocklistPut = {
  readonly httpMetadata: { readonly contentType: string };
  readonly customMetadata: Readonly<Record<string, string>>;
  readonly onlyIf: { readonly etagMatches: string } | { readonly etagDoesNotMatch: "*" };
};

/** What the list's reads and writes use of an R2 bucket. A put answers null when its condition did not hold. */
export type BlocklistBucket = BlocklistReader & {
  put(key: string, value: string, options: BlocklistPut): Promise<object | null>;
};

/** The list's text parsed, or why it cannot be used. */
export function parseList(text: string): { kind: "ok"; list: BlocklistBody } | { kind: "unreadable"; reason: string } {
  let raw: unknown;

  try {
    raw = JSON.parse(text);
  } catch {
    return { kind: "unreadable", reason: "it is not JSON" };
  }

  const parsed = BlocklistBody.safeParse(raw);

  return parsed.success ? { kind: "ok", list: parsed.data } : { kind: "unreadable", reason: "it is not in the expected shape" };
}

/**
 * The list as the degraded routes and the health check read it: parsed whole, or why it cannot be used. With `bound`,
 * the get and the body share its deadline, and the body is read through a reader this owns, cancelled at the deadline
 * or when `bound.signal` aborts (deadline.ts, readAllWithin): nothing reads on after its caller gave up.
 */
export async function readFrom(bucket: BlocklistReader, bound: ReadBound | null = null): Promise<BlocklistRead> {
  const start = performance.now();

  const obj =
    bound === null
      ? await bucket.get(BLOCKLIST_KEY)
      : await orDeadline({ work: bucket.get(BLOCKLIST_KEY), ms: bound.ms, operation: bound.operation, onLate: (late) => void late?.body.cancel().catch(() => undefined) });

  if (obj === null) return { kind: "missing" };

  const bytes =
    bound === null
      ? new Uint8Array(await new Response(obj.body).arrayBuffer())
      : await readAllWithin({ source: obj.body, ms: Math.max(0, Math.round(bound.ms - (performance.now() - start))), operation: `${bound.operation}-body`, signal: bound.signal });

  const parsed = parseList(new TextDecoder().decode(bytes));

  return parsed.kind === "ok" ? { kind: "ok", list: parsed.list, etag: obj.etag } : { kind: "unreadable", reason: parsed.reason, etag: obj.etag };
}

/**
 * A put that lands only on the object `read` saw: on the same ETag when there was one, and only while the key is still
 * absent when there was none (R2's `If-None-Match: *`, atomic like the ETag match). Null when another writer got in
 * between.
 */
function putOver(bucket: BlocklistBucket, read: BlocklistRead, body: string, syncedAt: number | null): Promise<object | null> {
  const onlyIf = read.kind === "missing" ? ({ etagDoesNotMatch: "*" } as const) : { etagMatches: read.etag };

  return bucket.put(BLOCKLIST_KEY, body, { httpMetadata: { contentType: "application/json" }, customMetadata: { syncedAt: String(syncedAt ?? "") }, onlyIf });
}

/**
 * Replaces the list with `change` of what is there, retrying when another writer got in between. Every write is
 * conditional on what it read, creation included, so no writer replaces an entry it did not see.
 */
export async function rewrite(bucket: BlocklistBucket, change: (current: BlocklistBody) => BlocklistBody): Promise<BlocklistBody> {
  for (let attempt = 0; attempt < WRITE_TRIES; attempt++) {
    const read = await readFrom(bucket);
    // an unreadable list is replaced by one that has never been synced, so installs stay refused until the cron's sync
    const current = read.kind === "ok" ? read.list : EMPTY;
    const next = change(current);
    const written = await putOver(bucket, read, JSON.stringify(next), next.syncedAt);

    if (written !== null) return next;
    await new Promise((resolve) => setTimeout(resolve, 20 + Math.floor(Math.random() * 40) * (attempt + 1)));
  }

  throw new Error(`the block list changed under ${WRITE_TRIES} writes in a row`);
}

/**
 * How long an isolate uses its read of the list for the fast tarball path (fast-tarball.ts, Blocklist.recent). That
 * path reads the database on the same request, which sees every committed block at once; the list adds only blocks
 * whose transaction is still committing, which it was given before their commit, so a read this old misses nothing the
 * database will not refuse a moment later. Every other reader (degraded.ts, the health check, the writes) reads R2.
 */
export const BLOCKLIST_RECENT_MS = 5_000;

type RecentRead = { readonly at: number; readonly read: Promise<BlocklistRead> };

/**
 * Each bucket's latest read, in this isolate (one bucket per Worker; a WeakMap so a test's bucket goes with it). A read
 * that failed is never kept, and a write by this isolate drops it.
 */
const recentReads = new WeakMap<BlocklistReader, RecentRead>();

/**
 * The list as read from `bucket` within BLOCKLIST_RECENT_MS of `at`: this isolate's last read while it is that young
 * (one read in flight is shared by every request that asks meanwhile), else a new one. A read that throws is not kept,
 * so the next request reads R2 again.
 */
export function recentFrom(bucket: BlocklistReader, at: number, bound: ReadBound | null = null): Promise<BlocklistRead> {
  const kept = recentReads.get(bucket);

  if (kept !== undefined && at - kept.at >= 0 && at - kept.at < BLOCKLIST_RECENT_MS) return kept.read;
  const read = readFrom(bucket, bound);
  const entry = { at, read };

  recentReads.set(bucket, entry);
  read.catch(() => {
    if (recentReads.get(bucket) === entry) recentReads.delete(bucket);
  });

  return read;
}

/** Drops this isolate's recent read of `bucket`'s list: called on every write, so this isolate never reads around its own. */
function forgetRecent(bucket: BlocklistReader): void {
  recentReads.delete(bucket);
}

export type BlocklistApi = {
  readonly read: Effect.Effect<BlocklistRead, BlobError>;
  /** The list as this isolate read it within BLOCKLIST_RECENT_MS: for the fast tarball path only, which reads the database too. */
  readonly recent: Effect.Effect<BlocklistRead, BlobError>;
  /** Adds `blocks` to the list. Call it before the transaction that blocks them commits, and fail that transaction when this fails. */
  readonly block: (blocks: Blocks) => Effect.Effect<void, BlobError>;
  /** Rewrites the list from what the database holds (`reconciled`), and records that it did. */
  readonly sync: (truth: BlockTruth) => Effect.Effect<BlocklistBody, BlobError>;
};

export class Blocklist extends Context.Service<Blocklist, BlocklistApi>()("@apm/registry/Blocklist") {
  static r2(bucket: BlocklistBucket, now: () => number = Date.now): Layer.Layer<Blocklist> {
    const attempt = <A>(operation: string, run: (signal: AbortSignal) => Promise<A>): Effect.Effect<A, BlobError> =>
      Effect.tryPromise({ try: (signal) => run(signal), catch: (cause) => new BlobError({ operation: `blocklist.${operation}`, key: BLOCKLIST_KEY, cause }) });

    return Layer.succeed(
      Blocklist,
      Blocklist.of({
        // what a request reads is bounded (deadline.ts): past R2_GET_MS the read failed, and the request answers as it
        // does when R2 fails (degraded.ts refuses; the fast tarball path waits 300 ms at most anyway)
        // (its body is cancelled then, and when the request is interrupted); the recent read is shared between requests,
        // so one request that ends does not cancel it, but its own deadline does
        read: attempt("read", (signal) => readFrom(bucket, { ms: R2_GET_MS, operation: "blocklist-read", signal })),
        recent: attempt("recent", () => recentFrom(bucket, now(), { ms: R2_GET_MS, operation: "blocklist-recent" })),
        block: (blocks) =>
          (blocks.local ?? []).length === 0 && (blocks.confirmed ?? []).length === 0
            ? Effect.void
            : Effect.asVoid(attempt("block", () => rewrite(bucket, (list) => withBlocks(list, blocks, now())).finally(() => forgetRecent(bucket)))),
        sync: (truth) => attempt("sync", () => rewrite(bucket, (list) => reconciled(list, truth, now())).finally(() => forgetRecent(bucket))),
      }),
    );
  }
}

/**
 * Adds `blocks` to the list when this run has one (the Worker always does; unit tests that build their own services may
 * not). Called inside the transaction that blocks them, so a failed add fails the write.
 */
export const blockBeforeCommit = (blocks: Blocks): Effect.Effect<void, BlobError> =>
  Effect.flatMap(Effect.serviceOption(Blocklist), (b) => (Option.isSome(b) ? b.value.block(blocks) : Effect.void));

const TruthRows = z.object({ name: z.string() }).array();
const ConfirmedRows = z.object({ package: z.string(), version: z.string(), digest: z.string() }).array();

/** What the database blocks: every package published here and every confirmed review. */
export const blockTruth = (sql: SqlClient.SqlClient): Effect.Effect<BlockTruth, StoreError, Guard> =>
  Effect.gen(function* () {
    const guard = yield* Guard;
    const names = TruthRows.safeParse(yield* guard.statement("blocklist.packages", sql`SELECT name FROM packages ORDER BY name`));
    const confirmed = ConfirmedRows.safeParse(yield* guard.statement("blocklist.confirmed", sql`SELECT package, version, digest FROM reviews WHERE human_state = 'confirmed' ORDER BY package, version`));

    if (!names.success) return yield* Effect.fail(new StoreError({ operation: "blocklist.packages: parse", cause: names.error }));

    if (!confirmed.success) return yield* Effect.fail(new StoreError({ operation: "blocklist.confirmed: parse", cause: confirmed.error }));

    return { local: names.data.map((r) => r.name), confirmed: confirmed.data.map((r) => ({ name: r.package, version: r.version, digest: r.digest })) };
  });
