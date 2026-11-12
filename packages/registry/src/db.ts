// Postgres storage for the registry (Neon through Hyperdrive in production). Rows are parsed into domain
// types here, at the storage boundary. Every method is an Effect that fails with StoreError.
import { Context, Effect, Layer, Redacted } from "effect";
import type { SqlError } from "effect/sql/SqlError";
import * as SqlClient from "effect/sql/SqlClient";
import { PgClient } from "@effect/sql-pg";
import { z } from "zod";
import { applyDismissals, dependencySpecs, isRegistryDependency, parseAnalysis, SCORER, type Analysis, type EvidenceDismissal } from "@apm/core";
import { createHash, randomBytes } from "node:crypto";
import { digestLabel, digestOf } from "./digest.ts";
import { CHALLENGE_MS, CONFIRMATION_MS, FAILURE_WINDOW_MS, GRANT_MS, MAX_FAILURES, isConfirmationId, type ConfirmationId } from "./factors.ts";
import { StoreError } from "./errors.ts";

export type VersionStatus = "active" | "yanked" | "revoke-pending" | "revoked";

export type StagedStatus = "pending" | "approved" | "rejected" | "expired";

export type StoredScope = "publish" | "stage" | "legacy";

/** int8 columns arrive as bigint; every time and size here fits a double. */
const Int = z.union([z.bigint(), z.number()]).transform((n) => Number(n));
const IntOrNull = Int.nullable();
const JsonObject = z.record(z.string(), z.unknown());

/** A package.json, as stored and served: any JSON object. Its fields are read with the parsers in @apm/core. */
export const Manifest = JsonObject;

export type Manifest = z.infer<typeof Manifest>;

const UserRow = z.object({
  name: z.string(),
  password_hash: z.string(),
  email: z.string(),
  created_at: Int,
  auth_user_id: z.string().nullable(),
  github_id: z.string().nullable(),
  github_login: z.string().nullable(),
});

const TokenRow = z.object({
  token_hash: z.string(),
  user: z.string(),
  label: z.string(),
  scope: z.enum(["publish", "stage", "legacy"]),
  created_at: Int,
  expires_at: IntOrNull,
  revoked_at: IntOrNull,
});

const PackageRow = z.object({
  name: z.string(),
  created_at: Int,
  modified_at: Int,
  dist_tags: z.record(z.string(), z.string()),
  description: z.string(),
  keywords: z.array(z.string()),
  readme: z.string(),
});

const VersionRow = z.object({
  package: z.string(),
  version: z.string(),
  manifest: JsonObject,
  shasum: z.string(),
  integrity: z.string(),
  size: Int,
  tarball_key: z.string(),
  published_at: Int,
  published_by: z.string(),
  deprecated: z.string().nullable(),
  status: z.enum(["active", "yanked", "revoke-pending", "revoked"]),
  status_reason: z.string().nullable(),
  status_at: IntOrNull,
  status_by: z.string().nullable(),
  score: z.unknown(),
});

const AdvisoryRow = z.object({
  id: Int,
  package: z.string(),
  versions: z.array(z.string()),
  severity: z.string(),
  title: z.string(),
  detail: z.string(),
  created_at: Int,
  created_by: z.string(),
});

const StagedRow = z.object({
  id: z.string(),
  package: z.string(),
  version: z.string(),
  manifest: JsonObject,
  shasum: z.string(),
  integrity: z.string(),
  size: Int,
  tarball_key: z.string(),
  tag: z.string(),
  readme: z.string().nullable(),
  score: z.unknown(),
  staged_by: z.string(),
  staged_at: Int,
  expires_at: Int,
  status: z.enum(["pending", "approved", "rejected", "expired"]),
  decided_at: IntOrNull,
  decided_by: z.string().nullable(),
});

const DismissalRow = z.object({
  id: Int,
  scorer: z.string(),
  package: z.string(),
  version: z.string(),
  digest: z.string(),
  signal: z.string(),
  file: z.string(),
  line: Int,
  reason: z.string(),
  dismissed_by: z.string(),
  dismissed_at: Int,
  restored_by: z.string().nullable(),
  restored_at: IntOrNull,
});

/** A piece of score evidence an apm reviewer dismissed, by the exact bytes, scorer, signal, file and line it cites. */
export type DismissalRecord = z.infer<typeof DismissalRow>;

/** What names one evidence item: the version's exact tarball digest, the scorer that cited it, the signal, the file and the line. */
export type DismissalKey = { package: string; version: string; digest: string; scorer: string; signal: string; file: string; line: number };

/** The live dismissals made for exactly this version's bytes, as the scorer reads them. */
function dismissalsFor(rows: readonly DismissalRecord[], version: string, digest: string | null): EvidenceDismissal[] {
  return rows.flatMap((r) => (digest !== null && r.version === version && r.digest === digest ? [{ scorer: r.scorer, signal: r.signal, file: r.file, line: r.line, reason: r.reason, at: r.dismissed_at }] : []));
}

/**
 * A stored analysis with the evidence dismissed for exactly these bytes left out (and listed as dismissed), so every
 * reader (the version page, the packument's score, `~safe`, the install gate) scores without it. A dismissal for
 * another digest, version or scorer does not apply. Null when the stored value is not an analysis.
 */
export function dismissedAnalysis(analysis: Analysis | null, list: readonly EvidenceDismissal[]): Analysis | null {
  return analysis && list.length > 0 ? applyDismissals(analysis, list) : analysis;
}

function versionDigest(v: { integrity: string; shasum: string }): string | null {
  const d = digestOf(v);

  return d ? digestLabel(d) : null;
}

const EventRow = z.object({ id: Int, package: z.string(), kind: z.string(), actor: z.string(), at: Int, detail: z.unknown() });

export type User = z.infer<typeof UserRow>;

export type Token = z.infer<typeof TokenRow>;

const PackageOut = PackageRow.transform(({ dist_tags, ...rest }) => ({ ...rest, distTags: dist_tags }));

export type PackageRecord = z.output<typeof PackageOut>;

export type VersionRecord = z.infer<typeof VersionRow>;

export type Advisory = z.infer<typeof AdvisoryRow>;

export type StagedRecord = z.infer<typeof StagedRow>;

export type NewStaged = Omit<StagedRecord, "status" | "decided_at" | "decided_by">;

/** Who and what the recent-activity feed leaves out: check accounts and the scopes they publish under. */
export type RecentHidden = { actors: readonly string[]; scopes: readonly string[] };

export type EventRecord = z.infer<typeof EventRow>;

export type NewVersion = Omit<VersionRecord, "status" | "status_reason" | "status_at" | "status_by" | "deprecated">;

export type Linked = { provider: string; accountId: string };

const PasskeyRow = z.object({ id: z.string(), credentialID: z.string(), publicKey: z.string(), counter: Int, transports: z.string().nullable() });

/** One of an account's passkeys (Better Auth's table): the public key is base64 COSE, as WebAuthn registered it. */
export type PasskeyRecord = z.infer<typeof PasskeyRow>;

/** Faults a test can switch on for one request (worker-test.ts); the deployed Worker never passes any. */
export type StoreFault = "event-insert";

export type AuthProfile = { name: string; email: string; image: string | null };

/** What is waiting for approval: versions and bytes one user staged, and versions waiting for one package. */
export type StagedLoad = { byUser: number; bytesByUser: number; byPackage: number };

/** Most versions waiting per account and per package, and most bytes (tarballs plus metadata) per account. */
export type StageLimits = { perUser: number; perPackage: number; bytesPerUser: number };

/** How an atomic staged insert went: stored, already waiting for this name@version, or over a quota. */
export type StageInsert = { kind: "staged" } | { kind: "duplicate"; id: string } | { kind: "over"; quota: "package" | "user" | "bytes"; load: StagedLoad };

/** One password attempt counted before the hash check, or the account is locked out. */
export type PasswordAttempt = "reserved" | "locked";

// Serializes staged inserts so two concurrent uploads cannot both pass the quota checks (staged uploads are rare).
const STAGED_INSERT_LOCK = 0x617_06d_5747;

// The first key of the two-key advisory locks on blob keys ("blob"); the second is the key's hash. Two-key
// advisory locks never conflict with one-key ones such as STAGED_INSERT_LOCK.
const BLOB_LOCK_CLASS = 0x626c_6f62;

/** One attempt taken from an account's second-factor budget, or the budget is spent. */
export type Reservation = { kind: "locked" } | { kind: "reserved"; id: number };

/** Better Auth's TOTP row: the encrypted secret and recovery codes, and whether setup finished. */
export type TwoFactorRecord = { secret: string; backupCodes: string; verified: boolean };

/** A staged score as the jsonb text the row stores, or null. */
const scoreJson = ({ score }: Pick<NewStaged, "score">): string | null => (score === null || score === undefined ? null : JSON.stringify(score));

const hashOf = (secret: string): string => createHash("sha256").update(secret).digest("hex");

/** 16 random bytes as 22 base64url characters: a confirmation or challenge id. Only its hash is stored. */
function newConfirmationId(): ConfirmationId {
  const id = randomBytes(16).toString("base64url");

  if (!isConfirmationId(id)) throw new Error("16 random bytes did not make a 22-character id");

  return id;
}

export type StoreApi = {
  readonly tx: <A, E, R>(effect: Effect.Effect<A, E, R>) => Effect.Effect<A, E | StoreError, R>;

  readonly getUser: (name: string) => Effect.Effect<User | null, StoreError>;
  readonly getUserByAuthId: (authUserId: string) => Effect.Effect<User | null, StoreError>;
  readonly createUser: (
    u: Pick<User, "name" | "password_hash" | "email" | "created_at"> & Partial<Pick<User, "auth_user_id" | "github_id" | "github_login">>,
  ) => Effect.Effect<boolean, StoreError>;
  readonly bindUser: (name: string, link: { authUserId: string; githubId: string; githubLogin: string }) => Effect.Effect<void, StoreError>;

  readonly setGitHubProfile: (githubId: string, login: string, at: number) => Effect.Effect<void, StoreError>;
  readonly gitHubLogin: (githubId: string) => Effect.Effect<string | null, StoreError>;

  /** The GitHub login shown for a name, refreshed after a GitHub rename. The name itself never changes. */
  readonly setGitHubLogin: (name: string, login: string) => Effect.Effect<void, StoreError>;
  /** Wrong passwords for `user` in the current window: the count and when the window started. */
  readonly passwordFailures: (user: string) => Effect.Effect<{ count: number; since: number } | null, StoreError>;
  readonly setPasswordFailures: (user: string, f: { count: number; since: number } | null) => Effect.Effect<void, StoreError>;
  /**
   * Counts one password attempt before it is checked, in one statement: "locked" when the account already has
   * `max` failures inside the window. Concurrent guesses each take one, so none sees a stale count. A correct
   * password clears the count afterwards (setPasswordFailures(user, null)).
   */
  readonly reservePasswordAttempt: (input: { user: string; now: number; max: number; windowMs: number }) => Effect.Effect<PasswordAttempt, StoreError>;

  readonly insertStaged: (s: NewStaged) => Effect.Effect<void, StoreError>;
  /**
   * Stores a staged upload only if nothing else waits for the same name@version and the quotas still allow it,
   * in one transaction serialized with every other staged insert: two concurrent uploads cannot both pass.
   */
  readonly insertStagedWithin: (s: NewStaged, limits: StageLimits) => Effect.Effect<StageInsert, StoreError>;
  readonly getStaged: (id: string) => Effect.Effect<StagedRecord | null, StoreError>;
  readonly pendingStaged: (name: string, version: string, now: number) => Effect.Effect<StagedRecord | null, StoreError>;
  readonly pendingFor: (user: string, now: number) => Effect.Effect<StagedRecord[], StoreError>;
  /** Moves a pending row to a final status; false when it was no longer pending. A rejected upload keeps only its audit fields. */
  readonly decideStaged: (id: string, d: { status: Exclude<StagedStatus, "pending">; at: number; by: string }) => Effect.Effect<boolean, StoreError>;
  /**
   * Versions still waiting for approval at `now`: how many and how many bytes `user` staged, and how many wait
   * for `name`. Bytes count the tarball and the metadata the row keeps (manifest, readme, score).
   */
  readonly pendingStagedLoad: (input: { user: string; name: string; now: number }) => Effect.Effect<StagedLoad, StoreError>;
  /** Marks pending rows past their deadline as expired and drops their manifest, readme and score; returns their tarball keys. */
  readonly expireStaged: (now: number) => Effect.Effect<{ id: string; tarball_key: string }[], StoreError>;
  /** Whether any version or pending staged row still points at this blob. */
  readonly blobReferenced: (key: string) => Effect.Effect<boolean, StoreError>;
  /**
   * Holds a tarball's blob key for the rest of the transaction. An upload holds it "shared" from writing the
   * object until its version or staged row is inserted; cleanup holds it "exclusive" while it checks for
   * references and deletes the object. So cleanup never deletes an object an upload is about to point at.
   */
  readonly lockBlob: (key: string, mode: "shared" | "exclusive") => Effect.Effect<void, StoreError>;

  readonly insertToken: (t: Token) => Effect.Effect<void, StoreError>;
  readonly getToken: (hash: string) => Effect.Effect<Token | null, StoreError>;
  readonly listTokens: (user: string) => Effect.Effect<Token[], StoreError>;
  readonly revokeToken: (hash: string, at: number) => Effect.Effect<void, StoreError>;
  readonly revokeTokensOf: (user: string, at: number) => Effect.Effect<number, StoreError>;

  readonly getPackage: (name: string) => Effect.Effect<PackageRecord | null, StoreError>;
  /** The package row locked for the rest of the transaction. */
  readonly lockPackage: (name: string) => Effect.Effect<PackageRecord | null, StoreError>;
  readonly listPackages: () => Effect.Effect<PackageRecord[], StoreError>;
  readonly listPackageNames: () => Effect.Effect<string[], StoreError>;
  /** Creates the package with its first owner; false when it already existed. */
  readonly createPackage: (name: string, at: number, owner: string) => Effect.Effect<boolean, StoreError>;
  readonly updatePackageMeta: (
    name: string,
    meta: { modifiedAt: number; description?: string; keywords?: string[]; readme?: string },
  ) => Effect.Effect<void, StoreError>;
  readonly setDistTags: (name: string, tags: Record<string, string>, at: number) => Effect.Effect<void, StoreError>;
  readonly owners: (name: string) => Effect.Effect<string[], StoreError>;
  readonly ownersOf: (names: readonly string[]) => Effect.Effect<Map<string, string[]>, StoreError>;
  readonly addOwner: (name: string, user: string) => Effect.Effect<void, StoreError>;
  /** Removes an owner unless that would leave the package with none; the count is read under the package lock. */
  readonly removeOwner: (name: string, user: string) => Effect.Effect<"removed" | "not-owner" | "last-owner", StoreError>;

  readonly listVersions: (name: string) => Effect.Effect<VersionRecord[], StoreError>;
  readonly activeVersionsOf: (names: readonly string[]) => Effect.Effect<VersionRecord[], StoreError>;
  readonly getVersion: (name: string, version: string) => Effect.Effect<VersionRecord | null, StoreError>;
  /** Inserts the version; false when that version already exists. */
  readonly insertVersion: (v: NewVersion) => Effect.Effect<boolean, StoreError>;
  readonly setDeprecated: (name: string, version: string, message: string | null) => Effect.Effect<void, StoreError>;
  readonly setStatus: (
    name: string,
    version: string,
    s: { status: VersionStatus; reason: string | null; at: number; by: string },
  ) => Effect.Effect<void, StoreError>;
  /** Pending revocations at or before `cutoff` become final. Returns the versions that changed. */
  readonly matureRevocations: (cutoff: number) => Effect.Effect<{ package: string; version: string }[], StoreError>;
  /** Names of local packages whose active versions depend on `name`. */
  readonly dependentsOf: (name: string) => Effect.Effect<string[], StoreError>;
  /** Versions `user` published after `since` that are not revoked, across every package. */
  readonly publishedSince: (user: string, since: number) => Effect.Effect<VersionRecord[], StoreError>;

  /** The current scorer's analyses of this package, keyed by `${version} ${digest}`. */
  readonly upstreamAnalyses: (name: string) => Effect.Effect<Map<string, unknown>, StoreError>;
  /**
   * For display where the tarball digest is not known (search hits): each version's newest current-scorer analysis,
   * keyed `"<name> <version>"`, in one query however many versions are asked for.
   */
  readonly latestUpstreamAnalyses: (versions: readonly { name: string; version: string }[]) => Effect.Effect<Map<string, unknown>, StoreError>;
  readonly setUpstreamAnalysis: (input: { name: string; version: string; digest: string; analysis: unknown; at: number }) => Effect.Effect<void, StoreError>;
  /** Records that a version was sent for analysis; false when it was sent less than `staleMs` ago. */
  readonly claimAnalysisJob: (name: string, version: string, now: number, staleMs: number) => Effect.Effect<boolean, StoreError>;
  /** Drops the reservation claimAnalysisJob made at `claimedAt` (when the queue refused the job); a newer claim stays. */
  readonly releaseAnalysisJob: (name: string, version: string, claimedAt: number) => Effect.Effect<void, StoreError>;

  readonly deleteAdvisoriesFor: (name: string, version: string) => Effect.Effect<void, StoreError>;
  readonly addAdvisory: (a: Omit<Advisory, "id">) => Effect.Effect<number, StoreError>;
  readonly advisoriesFor: (name: string) => Effect.Effect<Advisory[], StoreError>;

  /** Live dismissals (not undone) on these packages. */
  readonly dismissalsOf: (names: readonly string[]) => Effect.Effect<DismissalRecord[], StoreError>;
  /** Records a dismissal; false when that exact item is already dismissed. */
  readonly addDismissal: (d: DismissalKey & { reason: string; by: string; at: number }) => Effect.Effect<boolean, StoreError>;
  /** Undoes a live dismissal; the row it undid, or null when the item was not dismissed. */
  readonly restoreDismissal: (d: DismissalKey & { by: string; at: number }) => Effect.Effect<DismissalRecord | null, StoreError>;
  /** The live (not undone) dismissal of exactly this item, or null. */
  readonly liveDismissal: (d: DismissalKey) => Effect.Effect<DismissalRecord | null, StoreError>;

  readonly addEvent: (e: { package: string; kind: string; actor: string; at: number; detail?: unknown }) => Effect.Effect<void, StoreError>;
  readonly eventsFor: (name: string) => Effect.Effect<EventRecord[], StoreError>;
  /** The latest events of `kinds`, leaving out those by `hiddenActors` or on packages under `hiddenScopes` (`@scope/`). */
  readonly recentEvents: (kinds: readonly string[], limit: number, hidden: RecentHidden) => Effect.Effect<EventRecord[], StoreError>;

  /** Better Auth's rows, read for apm's own account views. */
  readonly accountsOf: (authUserId: string) => Effect.Effect<Linked[], StoreError>;
  readonly authProfile: (authUserId: string) => Effect.Effect<AuthProfile | null, StoreError>;
  readonly authFactors: (authUserId: string) => Effect.Effect<{ totp: boolean; passkeys: number }, StoreError>;
  readonly twoFactor: (authUserId: string) => Effect.Effect<TwoFactorRecord | null, StoreError>;
  /** Finishes authenticator setup: the secret is verified and 2FA is on. */
  readonly enableTwoFactor: (authUserId: string) => Effect.Effect<void, StoreError>;
  /** Replaces the recovery codes if they are still `expected`: of two requests spending one code, one wins. */
  readonly swapBackupCodes: (input: { authUserId: string; expected: string; next: string }) => Effect.Effect<boolean, StoreError>;
  /** Deletes a Better Auth session by token and returns its user id. */
  readonly takeSession: (token: string) => Effect.Effect<string | null, StoreError>;

  // ---------- the second-factor ledger ----------
  /**
   * Takes one attempt from the account's budget before a code is checked. Unsettled attempts count, so concurrent
   * guesses cannot all see a fresh budget; an attempt left pending by a crash expires with the window.
   */
  readonly reserveAttempt: (input: { authUserId: string; at: number }) => Effect.Effect<Reservation, StoreError>;
  /** Records how a reserved attempt ended. A success clears the account's earlier failures. */
  readonly settleAttempt: (input: { id: number; authUserId: string; ok: boolean }) => Effect.Effect<void, StoreError>;
  /** Accepts a TOTP time step once: false when this step, or a later one, was already accepted. */
  readonly acceptStep: (input: { authUserId: string; step: number }) => Effect.Effect<boolean, StoreError>;
  /** A WebAuthn challenge made for one action (`action`, its canonical key) from one session. Returns its id. */
  readonly addPasskeyChallenge: (input: { sessionToken: string; authUserId: string; action: string; challenge: string; at: number }) => Effect.Effect<ConfirmationId, StoreError>;
  /** Takes the challenge `id` made for exactly this session and action, once; null when there is none, it was used, or it expired. */
  readonly takePasskeyChallenge: (input: { id: string; sessionToken: string; authUserId: string; action: string; at: number }) => Effect.Effect<string | null, StoreError>;
  /** The account's passkeys, as WebAuthn verifies them. */
  readonly passkeysOf: (authUserId: string) => Effect.Effect<PasskeyRecord[], StoreError>;
  readonly setPasskeyCounter: (input: { id: string; counter: number }) => Effect.Effect<void, StoreError>;
  /** A factor check made for one action from one session: what that action spends. */
  readonly issueConfirmation: (input: {
    sessionToken: string;
    authUserId: string;
    action: string;
    factor: "totp" | "recovery" | "passkey";
    at: number;
  }) => Effect.Effect<{ id: ConfirmationId; expiresAt: number }, StoreError>;
  /** Deletes passkey challenges and confirmations that expired before `before`: nothing can spend them any more. */
  readonly purgeConfirmations: (before: number) => Effect.Effect<void, StoreError>;
  /** Spends confirmation `id` on `action` from this session, once. False when it is for another session or action, was used, or expired. */
  readonly consumeConfirmation: (input: { id: string; sessionToken: string; authUserId: string; action: string; at: number }) => Effect.Effect<boolean, StoreError>;
  /** A person confirmed one CLI command on the website. */
  readonly grant: (input: { authUserId: string; action: string; at: number }) => Effect.Effect<{ expiresAt: number }, StoreError>;
  /** Uses a confirmation of exactly this command, once. */
  readonly consumeGrant: (input: { authUserId: string; action: string; at: number }) => Effect.Effect<boolean, StoreError>;
};

export class Store extends Context.Service<Store, StoreApi>()("@apm/registry/Store") {
  /** The store over a Postgres URL (Hyperdrive's connection string on Workers). One connection per request. */
  /**
   * The store over a Postgres URL (Hyperdrive's connection string on Workers), one connection per request. The
   * layer also provides that connection's SqlClient, for modules that own their own tables (review.ts).
   */
  static postgres(url: string, faults: ReadonlySet<StoreFault> = new Set()): Layer.Layer<Store | SqlClient.SqlClient, StoreError> {
    return Layer.effectContext(
      Effect.gen(function* () {
        const services = yield* Layer.build(PgClient.layer({ url: Redacted.make(url), maxConnections: 1 })).pipe(
          Effect.mapError((cause) => new StoreError({ operation: "connect", cause })),
        );

        const store = yield* make(faults).pipe(Effect.provide(services));

        return Context.add(services, Store, store);
      }),
    );
  }
}

const one = <S extends z.ZodType>(row: S) => z.array(row).transform((rows) => rows[0] ?? null);
const all = <S extends z.ZodType>(row: S) => z.array(row);
const none = z.array(z.unknown()).transform(() => undefined);
const changed = z.array(z.unknown()).transform((rows) => rows.length > 0);
const count = z.array(z.unknown()).transform((rows) => rows.length);

const make = (faults: ReadonlySet<StoreFault>) => Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  const run = <S extends z.ZodType>(operation: string, effect: Effect.Effect<ReadonlyArray<unknown>, SqlError>, schema: S): Effect.Effect<z.output<S>, StoreError> =>
    effect.pipe(
      Effect.mapError((cause) => new StoreError({ operation, cause })),
      Effect.flatMap((rows) => {
        const parsed = schema.safeParse(rows);

        return parsed.success ? Effect.succeed(parsed.data) : Effect.fail(new StoreError({ operation: `${operation}: parse`, cause: parsed.error }));
      }),
    );

  const getPackage = (name: string) => run("getPackage", sql`SELECT * FROM packages WHERE name = ${name}`, one(PackageOut));

  /** A stored score as stored, or, with dismissals for its bytes, the analysis without them. */
  const withList = (stored: VersionRecord["score"], list: readonly EvidenceDismissal[]): VersionRecord["score"] =>
    list.length === 0 ? stored : (dismissedAnalysis(parseAnalysis(stored), list) ?? stored);

  const dismissalsOf = (names: readonly string[]): Effect.Effect<DismissalRecord[], StoreError> =>
    names.length === 0
      ? Effect.succeed([])
      : run("dismissalsOf", sql`SELECT * FROM evidence_dismissals WHERE package = ANY(${names}) AND restored_at IS NULL ORDER BY dismissed_at, id`, all(DismissalRow));

  /** Versions as they are scored: what an apm reviewer dismissed for exactly these bytes is left out. */
  const withDismissals = (rows: VersionRecord[]): Effect.Effect<VersionRecord[], StoreError> =>
    rows.length === 0
      ? Effect.succeed(rows)
      : Effect.map(dismissalsOf([...new Set(rows.map((v) => v.package))]), (ds) =>
          ds.length === 0 ? rows : rows.map((v) => ({ ...v, score: withList(v.score, dismissalsFor(ds.filter((d) => d.package === v.package), v.version, versionDigest(v))) })),
        );

  const insertStaged = (s: NewStaged) =>
    run(
      "insertStaged",
      sql`INSERT INTO staged (id, package, version, manifest, shasum, integrity, size, tarball_key, tag, readme, score, staged_by, staged_at, expires_at)
          VALUES (${s.id}, ${s.package}, ${s.version}, ${JSON.stringify(s.manifest)}::jsonb, ${s.shasum}, ${s.integrity}, ${s.size}, ${s.tarball_key}, ${s.tag},
                  ${s.readme}, ${scoreJson(s)}::jsonb, ${s.staged_by}, ${s.staged_at}, ${s.expires_at})`,
      none,
    );

  // Bytes a staged row holds count the tarball and the metadata kept with it: manifest, readme and score.
  const pendingStagedLoad = (input: { user: string; name: string; now: number }) =>
    run(
      "pendingStagedLoad",
      sql`SELECT
            (SELECT count(*) FROM staged WHERE status = 'pending' AND expires_at > ${input.now} AND staged_by = ${input.user}) AS by_user,
            (SELECT COALESCE(sum(size + octet_length(manifest::text) + COALESCE(octet_length(readme), 0) + COALESCE(octet_length(score::text), 0)), 0) FROM staged WHERE status = 'pending' AND expires_at > ${input.now} AND staged_by = ${input.user}) AS bytes_by_user,
            (SELECT count(*) FROM staged WHERE status = 'pending' AND expires_at > ${input.now} AND package = ${input.name}) AS by_package`,
      z.tuple([z.object({ by_user: Int, bytes_by_user: Int.or(z.string().transform(Number)), by_package: Int })]).transform(([row]) => ({
        byUser: row.by_user,
        bytesByUser: row.bytes_by_user,
        byPackage: row.by_package,
      })),
    );

  const api: StoreApi = {
    tx: (effect) => sql.withTransaction(effect).pipe(Effect.catchTag("SqlError", (cause) => Effect.fail(new StoreError({ operation: "transaction", cause })))),

    getUser: (name) => run("getUser", sql`SELECT * FROM users WHERE name = ${name}`, one(UserRow)),
    getUserByAuthId: (id) => run("getUserByAuthId", sql`SELECT * FROM users WHERE auth_user_id = ${id}`, one(UserRow)),
    createUser: (u) =>
      run(
        "createUser",
        sql`INSERT INTO users (name, password_hash, email, created_at, auth_user_id, github_id, github_login)
            VALUES (${u.name}, ${u.password_hash}, ${u.email}, ${u.created_at}, ${u.auth_user_id ?? null}, ${u.github_id ?? null}, ${u.github_login ?? null})
            ON CONFLICT (name) DO NOTHING RETURNING name`,
        changed,
      ),
    bindUser: (name, link) =>
      run("bindUser", sql`UPDATE users SET auth_user_id = ${link.authUserId}, github_id = ${link.githubId}, github_login = ${link.githubLogin} WHERE name = ${name}`, none),

    setGitHubProfile: (githubId, login, at) =>
      run(
        "setGitHubProfile",
        sql`INSERT INTO github_profiles (github_id, login, updated_at) VALUES (${githubId}, ${login}, ${at})
            ON CONFLICT (github_id) DO UPDATE SET login = EXCLUDED.login, updated_at = EXCLUDED.updated_at`,
        none,
      ),
    gitHubLogin: (githubId) => run("gitHubLogin", sql`SELECT login FROM github_profiles WHERE github_id = ${githubId}`, one(z.object({ login: z.string() }).transform((r) => r.login))),

    setGitHubLogin: (name, login) => run("setGitHubLogin", sql`UPDATE users SET github_login = ${login} WHERE name = ${name}`, none),
    passwordFailures: (user) => run("passwordFailures", sql`SELECT count, since FROM password_failures WHERE "user" = ${user}`, one(z.object({ count: Int, since: Int }))),
    setPasswordFailures: (user, f) =>
      f === null
        ? run("setPasswordFailures", sql`DELETE FROM password_failures WHERE "user" = ${user}`, none)
        : run(
            "setPasswordFailures",
            sql`INSERT INTO password_failures ("user", count, since) VALUES (${user}, ${f.count}, ${f.since})
                ON CONFLICT ("user") DO UPDATE SET count = EXCLUDED.count, since = EXCLUDED.since`,
            none,
          ),

    reservePasswordAttempt: (input) =>
      run(
        "reservePasswordAttempt",
        // one upsert under the row lock: a live window at the limit changes nothing and returns no row
        sql`INSERT INTO password_failures AS f ("user", count, since) VALUES (${input.user}, 1, ${input.now})
            ON CONFLICT ("user") DO UPDATE SET
              count = CASE WHEN ${input.now} - f.since < ${input.windowMs} THEN f.count + 1 ELSE 1 END,
              since = CASE WHEN ${input.now} - f.since < ${input.windowMs} THEN f.since ELSE ${input.now} END
            WHERE NOT (${input.now} - f.since < ${input.windowMs} AND f.count >= ${input.max})
            RETURNING count`,
        changed.transform((reserved): PasswordAttempt => (reserved ? "reserved" : "locked")),
      ),

    insertStaged: (s) => insertStaged(s),
    insertStagedWithin: (s, limits) =>
      api.tx(
        Effect.gen(function* () {
          yield* run("insertStagedWithin: lock", sql`SELECT pg_advisory_xact_lock(${STAGED_INSERT_LOCK})`, none);
          const now = s.staged_at;

          const waiting = yield* run(
            "insertStagedWithin: pending",
            sql`SELECT id FROM staged WHERE package = ${s.package} AND version = ${s.version} AND status = 'pending' AND expires_at > ${now} LIMIT 1`,
            one(z.object({ id: z.string() })),
          );

          if (waiting) return { kind: "duplicate", id: waiting.id } satisfies StageInsert;
          const load = yield* pendingStagedLoad({ user: s.staged_by, name: s.package, now });

          if (load.byPackage >= limits.perPackage) return { kind: "over", quota: "package", load } satisfies StageInsert;

          if (load.byUser >= limits.perUser) return { kind: "over", quota: "user", load } satisfies StageInsert;
          // this upload's bytes, counted by the database the way pendingStagedLoad counts the rows it keeps

          const bytes = yield* run(
            "insertStagedWithin: bytes",
            sql`SELECT ${s.size}::bigint + octet_length(${JSON.stringify(s.manifest)}::jsonb::text)
                  + COALESCE(octet_length(${s.readme}::text), 0)
                  + COALESCE(octet_length(${scoreJson(s)}::jsonb::text), 0) AS bytes`,
            z.tuple([z.object({ bytes: Int.or(z.string().transform(Number)) })]).transform(([row]) => row.bytes),
          );

          if (load.bytesByUser + bytes > limits.bytesPerUser) return { kind: "over", quota: "bytes", load } satisfies StageInsert;
          yield* insertStaged(s);

          return { kind: "staged" } satisfies StageInsert;
        }),
      ),
    getStaged: (id) => run("getStaged", sql`SELECT * FROM staged WHERE id = ${id}`, one(StagedRow)),
    pendingStaged: (name, version, now) =>
      run(
        "pendingStaged",
        sql`SELECT * FROM staged WHERE package = ${name} AND version = ${version} AND status = 'pending' AND expires_at > ${now}
            ORDER BY staged_at DESC LIMIT 1`,
        one(StagedRow),
      ),
    pendingFor: (user, now) =>
      run(
        "pendingFor",
        sql`SELECT * FROM staged WHERE status = 'pending' AND expires_at > ${now}
              AND (staged_by = ${user} OR package IN (SELECT package FROM owners WHERE "user" = ${user}))
            ORDER BY staged_at DESC LIMIT 100`,
        all(StagedRow),
      ),
    decideStaged: (id, d) =>
      run(
        "decideStaged",
        d.status === "approved"
          ? sql`UPDATE staged SET status = ${d.status}, decided_at = ${d.at}, decided_by = ${d.by} WHERE id = ${id} AND status = 'pending' RETURNING id`
          : sql`UPDATE staged SET status = ${d.status}, decided_at = ${d.at}, decided_by = ${d.by}, manifest = '{}'::jsonb, readme = NULL, score = NULL
                WHERE id = ${id} AND status = 'pending' RETURNING id`,
        changed,
      ),
    pendingStagedLoad: (input) => pendingStagedLoad(input),
    expireStaged: (now) =>
      run(
        "expireStaged",
        sql`UPDATE staged SET status = 'expired', decided_at = ${now}, decided_by = 'registry', manifest = '{}'::jsonb, readme = NULL, score = NULL
            WHERE status = 'pending' AND expires_at <= ${now} RETURNING id, tarball_key`,
        all(z.object({ id: z.string(), tarball_key: z.string() })),
      ),
    blobReferenced: (key) =>
      run(
        "blobReferenced",
        sql`SELECT 1 AS x FROM versions WHERE tarball_key = ${key}
            UNION ALL SELECT 1 AS x FROM staged WHERE tarball_key = ${key} AND status = 'pending' LIMIT 1`,
        changed,
      ),

    lockBlob: (key, mode) =>
      mode === "shared"
        ? run("lockBlob: shared", sql`SELECT pg_advisory_xact_lock_shared(${BLOB_LOCK_CLASS}::int, hashtext(${key})) IS NULL AS locked`, none)
        : run("lockBlob: exclusive", sql`SELECT pg_advisory_xact_lock(${BLOB_LOCK_CLASS}::int, hashtext(${key})) IS NULL AS locked`, none),

    insertToken: (t) =>
      run(
        "insertToken",
        sql`INSERT INTO tokens (token_hash, "user", label, scope, created_at, expires_at, revoked_at)
            VALUES (${t.token_hash}, ${t.user}, ${t.label}, ${t.scope}, ${t.created_at}, ${t.expires_at}, ${t.revoked_at})`,
        none,
      ),
    getToken: (hash) => run("getToken", sql`SELECT * FROM tokens WHERE token_hash = ${hash}`, one(TokenRow)),
    listTokens: (user) => run("listTokens", sql`SELECT * FROM tokens WHERE "user" = ${user} ORDER BY created_at DESC`, all(TokenRow)),
    revokeToken: (hash, at) => run("revokeToken", sql`UPDATE tokens SET revoked_at = ${at} WHERE token_hash = ${hash} AND revoked_at IS NULL`, none),
    revokeTokensOf: (user, at) =>
      run("revokeTokensOf", sql`UPDATE tokens SET revoked_at = ${at} WHERE "user" = ${user} AND revoked_at IS NULL RETURNING token_hash`, count),

    getPackage,
    lockPackage: (name) => run("lockPackage", sql`SELECT * FROM packages WHERE name = ${name} FOR UPDATE`, one(PackageOut)),
    listPackages: () => run("listPackages", sql`SELECT * FROM packages ORDER BY name`, all(PackageOut)),
    listPackageNames: () => run("listPackageNames", sql`SELECT name FROM packages ORDER BY name`, all(z.object({ name: z.string() }).transform((r) => r.name))),
    createPackage: (name, at, owner) =>
      run(
        "createPackage",
        sql`WITH created AS (
              INSERT INTO packages (name, created_at, modified_at) VALUES (${name}, ${at}, ${at}) ON CONFLICT (name) DO NOTHING RETURNING name
            )
            INSERT INTO owners (package, "user") SELECT name, ${owner} FROM created RETURNING package`,
        changed,
      ),
    updatePackageMeta: (name, meta) =>
      run(
        "updatePackageMeta",
        sql`UPDATE packages SET modified_at = ${meta.modifiedAt},
              description = COALESCE(${meta.description ?? null}, description),
              keywords = COALESCE(${meta.keywords === undefined ? null : JSON.stringify(meta.keywords)}::jsonb, keywords),
              readme = COALESCE(${meta.readme ?? null}, readme)
            WHERE name = ${name}`,
        none,
      ),
    setDistTags: (name, tags, at) => run("setDistTags", sql`UPDATE packages SET dist_tags = ${JSON.stringify(tags)}::jsonb, modified_at = ${at} WHERE name = ${name}`, none),
    owners: (name) => run("owners", sql`SELECT "user" FROM owners WHERE package = ${name} ORDER BY "user"`, all(z.object({ "user": z.string() }).transform((r) => r.user))),
    ownersOf: (names) =>
      names.length === 0
        ? Effect.succeed(new Map<string, string[]>())
        : run(
            "ownersOf",
            sql`SELECT package, "user" FROM owners WHERE package = ANY(${names}) ORDER BY package, "user"`,
            all(z.object({ package: z.string(), user: z.string() })).transform((rows) => {
              const out = new Map<string, string[]>();

              for (const row of rows) out.set(row.package, [...(out.get(row.package) ?? []), row.user]);

              return out;
            }),
          ),
    addOwner: (name, user) => run("addOwner", sql`INSERT INTO owners (package, "user") VALUES (${name}, ${user}) ON CONFLICT DO NOTHING`, none),
    removeOwner: (name, user) =>
      sql
        .withTransaction(
          Effect.gen(function* () {
            yield* run("removeOwner: lock", sql`SELECT name FROM packages WHERE name = ${name} FOR UPDATE`, none);
            const owners = yield* run("removeOwner: owners", sql`SELECT "user" FROM owners WHERE package = ${name}`, all(z.object({ "user": z.string() }).transform((r) => r.user)));

            if (!owners.includes(user)) return "not-owner" as const;

            if (owners.length <= 1) return "last-owner" as const;
            yield* run("removeOwner", sql`DELETE FROM owners WHERE package = ${name} AND "user" = ${user}`, none);

            return "removed" as const;
          }),
        )
        .pipe(Effect.catchTag("SqlError", (cause) => Effect.fail(new StoreError({ operation: "removeOwner", cause })))),

    listVersions: (name) => Effect.flatMap(run("listVersions", sql`SELECT * FROM versions WHERE package = ${name} ORDER BY published_at, seq`, all(VersionRow)), withDismissals),
    activeVersionsOf: (names) =>
      names.length === 0
        ? Effect.succeed([])
        : run(
            "activeVersionsOf",
            sql`SELECT * FROM versions WHERE package = ANY(${names}) AND status = 'active' ORDER BY package, published_at, seq`,
            all(VersionRow),
          ).pipe(Effect.flatMap(withDismissals)),
    getVersion: (name, version) =>
      run("getVersion", sql`SELECT * FROM versions WHERE package = ${name} AND version = ${version}`, one(VersionRow)).pipe(
        Effect.flatMap((v) => (v === null ? Effect.succeed(null) : Effect.map(withDismissals([v]), (got) => got[0] ?? null))),
      ),
    insertVersion: (v) =>
      run(
        "insertVersion",
        sql`INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, score)
            VALUES (${v.package}, ${v.version}, ${JSON.stringify(v.manifest)}::jsonb, ${v.shasum}, ${v.integrity}, ${v.size}, ${v.tarball_key},
                    ${v.published_at}, ${v.published_by}, ${v.score === null || v.score === undefined ? null : JSON.stringify(v.score)}::jsonb)
            ON CONFLICT (package, version) DO NOTHING RETURNING version`,
        changed,
      ),
    setDeprecated: (name, version, message) =>
      run("setDeprecated", sql`UPDATE versions SET deprecated = ${message} WHERE package = ${name} AND version = ${version}`, none),
    setStatus: (name, version, s) =>
      run(
        "setStatus",
        sql`UPDATE versions SET status = ${s.status}, status_reason = ${s.reason}, status_at = ${s.at}, status_by = ${s.by}
            WHERE package = ${name} AND version = ${version}`,
        none,
      ),
    matureRevocations: (cutoff) =>
      run(
        "matureRevocations",
        sql`UPDATE versions SET status = 'revoked' WHERE status = 'revoke-pending' AND status_at <= ${cutoff} RETURNING package, version`,
        all(z.object({ package: z.string(), version: z.string() })),
      ),
    dependentsOf: (name) =>
      run(
        "dependentsOf",
        // strpos narrows the scan to manifests that mention the name; dependencySpecs decides, so npm: aliases
        // count under the package they install, not under their key
        sql`SELECT package, manifest FROM versions WHERE status = 'active' AND package <> ${name} AND strpos(manifest::text, ${name}) > 0`,
        all(z.object({ package: z.string(), manifest: JsonObject })).transform((rows) => {
          const out = new Set<string>();

          for (const row of rows) {
            const m = row.manifest;

            if (dependencySpecs(m).some((d) => isRegistryDependency(d) && d.name === name)) out.add(row.package);
            const peers = JsonObject.safeParse(m.peerDependencies);

            if (peers.success && name in peers.data) out.add(row.package);
          }

          return [...out].sort();
        }),
      ),
    publishedSince: (user, since) =>
      run(
        "publishedSince",
        sql`SELECT * FROM versions WHERE published_by = ${user} AND published_at > ${since} AND status <> 'revoked' ORDER BY package, published_at, seq`,
        all(VersionRow),
      ).pipe(Effect.flatMap(withDismissals)),

    upstreamAnalyses: (name) =>
      Effect.gen(function* () {
        const rows = yield* run(
          "upstreamAnalyses",
          sql`SELECT version, digest, analysis FROM upstream_analysis WHERE package = ${name} AND scorer = ${SCORER}`,
          all(z.object({ version: z.string(), digest: z.string(), analysis: z.unknown() })),
        );

        const dismissals = rows.length === 0 ? [] : yield* dismissalsOf([name]);

        return new Map(rows.map((row) => [`${row.version} ${row.digest}`, withList(row.analysis, dismissalsFor(dismissals, row.version, row.digest))]));
      }),
    latestUpstreamAnalyses: (versions) =>
      Effect.gen(function* () {
        if (versions.length === 0) return new Map<string, unknown>();

        const names = versions.map((v) => v.name);
        const numbers = versions.map((v) => v.version);

        const rows = yield* run(
          "latestUpstreamAnalyses",
          sql`SELECT DISTINCT ON (u.package, u.version) u.package, u.version, u.digest, u.analysis
              FROM upstream_analysis u
              JOIN unnest(${names}::text[], ${numbers}::text[]) AS wanted(package, version) ON u.package = wanted.package AND u.version = wanted.version
              WHERE u.scorer = ${SCORER}
              ORDER BY u.package, u.version, u.analyzed_at DESC`,
          all(z.object({ package: z.string(), version: z.string(), digest: z.string(), analysis: z.unknown() })),
        );

        const dismissals = yield* dismissalsOf([...new Set(rows.map((r) => r.package))]);

        return new Map(
          rows.map((r) => [`${r.package} ${r.version}`, withList(r.analysis, dismissalsFor(dismissals.filter((d) => d.package === r.package), r.version, r.digest))]),
        );
      }),
    setUpstreamAnalysis: (input) =>
      run(
        "setUpstreamAnalysis",
        sql`INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at)
            VALUES (${input.name}, ${input.version}, ${input.digest}, ${SCORER}, ${JSON.stringify(input.analysis)}::jsonb, ${input.at})
            ON CONFLICT (package, version, digest, scorer) DO UPDATE SET analysis = EXCLUDED.analysis, analyzed_at = EXCLUDED.analyzed_at`,
        none,
      ),
    claimAnalysisJob: (name, version, now, staleMs) =>
      run(
        "claimAnalysisJob",
        sql`INSERT INTO analysis_jobs (package, version, queued_at) VALUES (${name}, ${version}, ${now})
            ON CONFLICT (package, version) DO UPDATE SET queued_at = EXCLUDED.queued_at
            WHERE analysis_jobs.queued_at <= ${now - staleMs}
            RETURNING package`,
        changed,
      ),

    releaseAnalysisJob: (name, version, claimedAt) =>
      run("releaseAnalysisJob", sql`DELETE FROM analysis_jobs WHERE package = ${name} AND version = ${version} AND queued_at = ${claimedAt}`, none),

    deleteAdvisoriesFor: (name, version) =>
      run("deleteAdvisoriesFor", sql`DELETE FROM advisories WHERE package = ${name} AND versions ? ${version}`, none),
    addAdvisory: (a) =>
      run(
        "addAdvisory",
        sql`INSERT INTO advisories (package, versions, severity, title, detail, created_at, created_by)
            VALUES (${a.package}, ${JSON.stringify(a.versions)}::jsonb, ${a.severity}, ${a.title}, ${a.detail}, ${a.created_at}, ${a.created_by}) RETURNING id`,
        one(z.object({ id: Int })).transform((row) => row?.id ?? 0),
      ),
    advisoriesFor: (name) => run("advisoriesFor", sql`SELECT * FROM advisories WHERE package = ${name} ORDER BY id`, all(AdvisoryRow)),

    dismissalsOf,
    addDismissal: (d) =>
      run(
        "addDismissal",
        sql`INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at)
            VALUES (${d.scorer}, ${d.package}, ${d.version}, ${d.digest}, ${d.signal}, ${d.file}, ${d.line}, ${d.reason}, ${d.by}, ${d.at})
            ON CONFLICT (package, version, digest, scorer, signal, file, line) WHERE restored_at IS NULL DO NOTHING RETURNING id`,
        changed,
      ),
    restoreDismissal: (d) =>
      run(
        "restoreDismissal",
        sql`UPDATE evidence_dismissals SET restored_by = ${d.by}, restored_at = ${d.at}
            WHERE package = ${d.package} AND version = ${d.version} AND digest = ${d.digest} AND scorer = ${d.scorer}
              AND signal = ${d.signal} AND file = ${d.file} AND line = ${d.line} AND restored_at IS NULL
            RETURNING *`,
        one(DismissalRow),
      ),
    liveDismissal: (d) =>
      run(
        "liveDismissal",
        sql`SELECT * FROM evidence_dismissals
            WHERE package = ${d.package} AND version = ${d.version} AND digest = ${d.digest} AND scorer = ${d.scorer}
              AND signal = ${d.signal} AND file = ${d.file} AND line = ${d.line} AND restored_at IS NULL`,
        one(DismissalRow),
      ),
    addEvent: (e) =>
      run(
        "addEvent",
        // a test's forced failure is a real statement error, so it aborts the transaction the way a lost insert would
        faults.has("event-insert") ? sql`SELECT 1 / 0` : sql`INSERT INTO events (package, kind, actor, at, detail) VALUES (${e.package}, ${e.kind}, ${e.actor}, ${e.at}, ${JSON.stringify(e.detail ?? {})}::jsonb)`,
        none,
      ),
    eventsFor: (name) => run("eventsFor", sql`SELECT * FROM events WHERE package = ${name} ORDER BY at DESC, id DESC`, all(EventRow)),
    recentEvents: (kinds, limit, hidden) =>
      kinds.length === 0
        ? Effect.succeed([])
        : run(
            "recentEvents",
            sql`SELECT * FROM events WHERE kind = ANY(${kinds}) AND NOT (actor = ANY(${hidden.actors})) AND NOT (split_part(package, '/', 1) || '/' = ANY(${hidden.scopes})) ORDER BY at DESC, id DESC LIMIT ${limit}`,
            all(EventRow),
          ),

    accountsOf: (authUserId) =>
      run(
        "accountsOf",
        sql`SELECT "providerId", "accountId" FROM account WHERE "userId" = ${authUserId} ORDER BY "createdAt"`,
        all(z.object({ providerId: z.string(), accountId: z.string() }).transform((row) => ({ provider: row.providerId, accountId: row.accountId }))),
      ),
    authProfile: (authUserId) =>
      run(
        "authProfile",
        sql`SELECT name, email, image FROM "user" WHERE id = ${authUserId}`,
        one(z.object({ name: z.string(), email: z.string(), image: z.string().nullable() })),
      ),
    authFactors: (authUserId) =>
      run(
        "authFactors",
        sql`SELECT COALESCE((SELECT "twoFactorEnabled" FROM "user" WHERE id = ${authUserId}), false) AS totp,
                   (SELECT count(*) FROM passkey WHERE "userId" = ${authUserId}) AS passkeys`,
        z.tuple([z.object({ totp: z.boolean().nullable(), passkeys: Int })]).transform(([row]) => ({ totp: row.totp === true, passkeys: row.passkeys })),
      ),
    twoFactor: (authUserId) =>
      run(
        "twoFactor",
        sql`SELECT secret, "backupCodes", verified FROM "twoFactor" WHERE "userId" = ${authUserId} LIMIT 1`,
        one(
          z
            .object({ secret: z.string(), backupCodes: z.string(), verified: z.boolean().nullable() })
            .transform((row) => ({ secret: row.secret, backupCodes: row.backupCodes, verified: row.verified !== false })),
        ),
      ),
    enableTwoFactor: (authUserId) =>
      sql
        .withTransaction(
          Effect.all(
            [
              run("enableTwoFactor", sql`UPDATE "twoFactor" SET verified = true WHERE "userId" = ${authUserId}`, none),
              run("enableTwoFactor", sql`UPDATE "user" SET "twoFactorEnabled" = true WHERE id = ${authUserId}`, none),
            ],
            { discard: true },
          ),
        )
        .pipe(Effect.catchTag("SqlError", (cause) => Effect.fail(new StoreError({ operation: "enableTwoFactor", cause })))),
    swapBackupCodes: (input) =>
      run(
        "swapBackupCodes",
        sql`UPDATE "twoFactor" SET "backupCodes" = ${input.next} WHERE "userId" = ${input.authUserId} AND "backupCodes" = ${input.expected} RETURNING id`,
        changed,
      ),
    takeSession: (token) => run("takeSession", sql`DELETE FROM session WHERE token = ${token} RETURNING "userId"`, one(z.object({ userId: z.string() }).transform((r) => r.userId))),

    reserveAttempt: (input) =>
      sql
        .withTransaction(
          Effect.gen(function* () {
            // one account's reservations queue behind each other, so the count below is never stale
            yield* run("reserveAttempt: lock", sql`SELECT pg_advisory_xact_lock(hashtextextended(${input.authUserId}, 0)) IS NULL AS locked`, none);

            const used = yield* run(
              "reserveAttempt: count",
              sql`SELECT count(*) AS n FROM factor_attempts WHERE auth_user_id = ${input.authUserId} AND at > ${input.at - FAILURE_WINDOW_MS} AND outcome <> 'ok'`,
              z.tuple([z.object({ n: Int })]).transform(([row]) => row.n),
            );

            if (used >= MAX_FAILURES) return { kind: "locked" } satisfies Reservation;

            const id = yield* run(
              "reserveAttempt: insert",
              sql`INSERT INTO factor_attempts (auth_user_id, at, outcome) VALUES (${input.authUserId}, ${input.at}, 'pending') RETURNING id`,
              z.tuple([z.object({ id: Int })]).transform(([row]) => row.id),
            );

            return { kind: "reserved", id } satisfies Reservation;
          }),
        )
        .pipe(Effect.catchTag("SqlError", (cause) => Effect.fail(new StoreError({ operation: "reserveAttempt", cause })))),
    settleAttempt: (input) =>
      sql
        .withTransaction(
          Effect.gen(function* () {
            yield* run("settleAttempt", sql`UPDATE factor_attempts SET outcome = ${input.ok ? "ok" : "bad"} WHERE id = ${input.id}`, none);

            if (input.ok) yield* run("settleAttempt: clear", sql`DELETE FROM factor_attempts WHERE auth_user_id = ${input.authUserId} AND outcome = 'bad'`, none);
          }),
        )
        .pipe(Effect.catchTag("SqlError", (cause) => Effect.fail(new StoreError({ operation: "settleAttempt", cause })))),
    acceptStep: (input) =>
      run(
        "acceptStep",
        sql`INSERT INTO totp_steps (auth_user_id, step) VALUES (${input.authUserId}, ${input.step})
            ON CONFLICT (auth_user_id) DO UPDATE SET step = EXCLUDED.step WHERE totp_steps.step < EXCLUDED.step
            RETURNING step`,
        changed,
      ),
    addPasskeyChallenge: (input) => {
      const id = newConfirmationId();

      return run(
        "addPasskeyChallenge",
        sql`INSERT INTO passkey_challenges (id_hash, session_hash, auth_user_id, action, challenge, created_at, expires_at, used_at)
            VALUES (${hashOf(id)}, ${hashOf(input.sessionToken)}, ${input.authUserId}, ${input.action}, ${input.challenge}, ${input.at}, ${input.at + CHALLENGE_MS}, NULL)`,
        none,
      ).pipe(Effect.as(id));
    },
    takePasskeyChallenge: (input) =>
      run(
        "takePasskeyChallenge",
        sql`UPDATE passkey_challenges SET used_at = ${input.at}
            WHERE id_hash = ${hashOf(input.id)} AND session_hash = ${hashOf(input.sessionToken)} AND auth_user_id = ${input.authUserId}
              AND action = ${input.action} AND used_at IS NULL AND created_at <= ${input.at} AND expires_at > ${input.at}
            RETURNING challenge`,
        one(z.object({ challenge: z.string() }).transform((r) => r.challenge)),
      ),
    passkeysOf: (authUserId) =>
      run("passkeysOf", sql`SELECT id, "credentialID", "publicKey", counter, transports FROM passkey WHERE "userId" = ${authUserId} ORDER BY "createdAt", id`, all(PasskeyRow)),
    setPasskeyCounter: (input) => run("setPasskeyCounter", sql`UPDATE passkey SET counter = ${input.counter} WHERE id = ${input.id}`, none),
    issueConfirmation: (input) => {
      const id = newConfirmationId();
      const expiresAt = input.at + CONFIRMATION_MS;

      return run(
        "issueConfirmation",
        sql`INSERT INTO factor_confirmations (id_hash, session_hash, auth_user_id, action, factor, created_at, expires_at, used_at)
            VALUES (${hashOf(id)}, ${hashOf(input.sessionToken)}, ${input.authUserId}, ${input.action}, ${input.factor}, ${input.at}, ${expiresAt}, NULL)`,
        none,
      ).pipe(Effect.as({ id, expiresAt }));
    },
    purgeConfirmations: (before) =>
      Effect.all(
        [
          run("purgeConfirmations: challenges", sql`DELETE FROM passkey_challenges WHERE expires_at < ${before}`, none),
          run("purgeConfirmations: confirmations", sql`DELETE FROM factor_confirmations WHERE expires_at < ${before}`, none),
        ],
        { discard: true },
      ),
    consumeConfirmation: (input) =>
      run(
        "consumeConfirmation",
        sql`UPDATE factor_confirmations SET used_at = ${input.at}
            WHERE id_hash = ${hashOf(input.id)} AND session_hash = ${hashOf(input.sessionToken)} AND auth_user_id = ${input.authUserId}
              AND action = ${input.action} AND used_at IS NULL AND created_at <= ${input.at} AND expires_at > ${input.at}
            RETURNING id_hash`,
        changed,
      ),
    grant: (input) =>
      run(
        "grant",
        sql`INSERT INTO cli_grants (id, auth_user_id, action, created_at, expires_at, used_at)
            VALUES (${randomBytes(16).toString("base64url")}, ${input.authUserId}, ${input.action}, ${input.at}, ${input.at + GRANT_MS}, NULL)`,
        none,
      ).pipe(Effect.as({ expiresAt: input.at + GRANT_MS })),
    consumeGrant: (input) =>
      run(
        "consumeGrant",
        sql`UPDATE cli_grants SET used_at = ${input.at}
            WHERE id = (
              SELECT id FROM cli_grants
              WHERE auth_user_id = ${input.authUserId} AND action = ${input.action} AND used_at IS NULL
                AND created_at <= ${input.at} AND expires_at > ${input.at}
              ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
            ) AND used_at IS NULL
            RETURNING id`,
        changed,
      ),
  };

  return Store.of(api);
});
