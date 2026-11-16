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
// Until a sync has written the list (`syncedAt` null: a new stage, or an object that could not be read), degraded.ts
// refuses every install: it cannot tell an apm package from an npm one.
import { Context, Effect, Layer, Option } from "effect";
import type * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { Guard } from "./db-health.ts";
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

/** What reading the list uses of an R2 bucket: an object's text and ETag. */
export type BlocklistReader = { get(key: string): Promise<{ text(): Promise<string>; readonly etag: string } | null> };

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

/** The list as the degraded routes and the health check read it: parsed whole, or why it cannot be used. */
export async function readFrom(bucket: BlocklistReader): Promise<BlocklistRead> {
  const obj = await bucket.get(BLOCKLIST_KEY);

  if (obj === null) return { kind: "missing" };
  let raw: unknown;

  try {
    raw = JSON.parse(await obj.text());
  } catch {
    return { kind: "unreadable", reason: "it is not JSON", etag: obj.etag };
  }

  const parsed = BlocklistBody.safeParse(raw);

  return parsed.success ? { kind: "ok", list: parsed.data, etag: obj.etag } : { kind: "unreadable", reason: "it is not in the expected shape", etag: obj.etag };
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

export type BlocklistApi = {
  readonly read: Effect.Effect<BlocklistRead, BlobError>;
  /** Adds `blocks` to the list. Call it before the transaction that blocks them commits, and fail that transaction when this fails. */
  readonly block: (blocks: Blocks) => Effect.Effect<void, BlobError>;
  /** Rewrites the list from what the database holds (`reconciled`), and records that it did. */
  readonly sync: (truth: BlockTruth) => Effect.Effect<BlocklistBody, BlobError>;
};

export class Blocklist extends Context.Service<Blocklist, BlocklistApi>()("@apm/registry/Blocklist") {
  static r2(bucket: R2Bucket, now: () => number = Date.now): Layer.Layer<Blocklist> {
    const attempt = <A>(operation: string, run: () => Promise<A>): Effect.Effect<A, BlobError> =>
      Effect.tryPromise({ try: run, catch: (cause) => new BlobError({ operation: `blocklist.${operation}`, key: BLOCKLIST_KEY, cause }) });

    return Layer.succeed(
      Blocklist,
      Blocklist.of({
        read: attempt("read", () => readFrom(bucket)),
        block: (blocks) =>
          (blocks.local ?? []).length === 0 && (blocks.confirmed ?? []).length === 0 ? Effect.void : Effect.asVoid(attempt("block", () => rewrite(bucket, (list) => withBlocks(list, blocks, now())))),
        sync: (truth) => attempt("sync", () => rewrite(bucket, (list) => reconciled(list, truth, now()))),
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
