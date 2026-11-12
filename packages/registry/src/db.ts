// Postgres storage for the registry (Neon through Hyperdrive in production). Rows are parsed into domain
// types here, at the storage boundary. Every method is an Effect that fails with StoreError.
import { Context, Effect, Layer, Redacted } from "effect";
import type { SqlError } from "effect/sql/SqlError";
import * as SqlClient from "effect/sql/SqlClient";
import { PgClient } from "@effect/sql-pg";
import { z } from "zod";
import { dependencySpecs, isRegistryDependency, SCORER } from "@apm/core";
import { createHash, randomBytes } from "node:crypto";
import { FAILURE_WINDOW_MS, GRANT_MS, MAX_FAILURES, PASSKEY_PROOF_MS } from "./factors.ts";
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

const EventRow = z.object({ id: Int, package: z.string(), kind: z.string(), actor: z.string(), at: Int, detail: z.unknown() });

export type User = z.infer<typeof UserRow>;

export type Token = z.infer<typeof TokenRow>;

const PackageOut = PackageRow.transform(({ dist_tags, ...rest }) => ({ ...rest, distTags: dist_tags }));

export type PackageRecord = z.output<typeof PackageOut>;

export type VersionRecord = z.infer<typeof VersionRow>;

export type Advisory = z.infer<typeof AdvisoryRow>;

export type StagedRecord = z.infer<typeof StagedRow>;

export type NewStaged = Omit<StagedRecord, "status" | "decided_at" | "decided_by">;

export type EventRecord = z.infer<typeof EventRow>;

export type NewVersion = Omit<VersionRecord, "status" | "status_reason" | "status_at" | "status_by" | "deprecated">;

export type Linked = { provider: string; accountId: string };

export type AuthProfile = { name: string; email: string; image: string | null };

/** What is waiting for approval: versions and bytes one user staged, and versions waiting for one package. */
export type StagedLoad = { byUser: number; bytesByUser: number; byPackage: number };

/** One attempt taken from an account's second-factor budget, or the budget is spent. */
export type Reservation = { kind: "locked" } | { kind: "reserved"; id: number };

/** Better Auth's TOTP row: the encrypted secret and recovery codes, and whether setup finished. */
export type TwoFactorRecord = { secret: string; backupCodes: string; verified: boolean };

const hashOf = (secret: string): string => createHash("sha256").update(secret).digest("hex");

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

  readonly insertStaged: (s: NewStaged) => Effect.Effect<void, StoreError>;
  readonly getStaged: (id: string) => Effect.Effect<StagedRecord | null, StoreError>;
  readonly pendingStaged: (name: string, version: string, now: number) => Effect.Effect<StagedRecord | null, StoreError>;
  readonly pendingFor: (user: string, now: number) => Effect.Effect<StagedRecord[], StoreError>;
  /** Moves a pending row to a final status; false when it was no longer pending. */
  readonly decideStaged: (id: string, d: { status: Exclude<StagedStatus, "pending">; at: number; by: string }) => Effect.Effect<boolean, StoreError>;
  /** Versions still waiting for approval at `now`: how many and how many bytes `user` staged, and how many wait for `name`. */
  readonly pendingStagedLoad: (input: { user: string; name: string; now: number }) => Effect.Effect<StagedLoad, StoreError>;
  /** Marks pending rows past their deadline as expired; returns their tarball keys. */
  readonly expireStaged: (now: number) => Effect.Effect<{ id: string; tarball_key: string }[], StoreError>;
  /** Whether any version or pending staged row still points at this blob. */
  readonly blobReferenced: (key: string) => Effect.Effect<boolean, StoreError>;

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
  /** For display where the tarball digest is not known (search hits): the newest current-scorer analysis. */
  readonly latestUpstreamAnalysis: (name: string, version: string) => Effect.Effect<unknown, StoreError>;
  readonly setUpstreamAnalysis: (input: { name: string; version: string; digest: string; analysis: unknown; at: number }) => Effect.Effect<void, StoreError>;
  /** Records that a version was sent for analysis; false when it was sent less than `staleMs` ago. */
  readonly claimAnalysisJob: (name: string, version: string, now: number, staleMs: number) => Effect.Effect<boolean, StoreError>;

  readonly deleteAdvisoriesFor: (name: string, version: string) => Effect.Effect<void, StoreError>;
  readonly addAdvisory: (a: Omit<Advisory, "id">) => Effect.Effect<number, StoreError>;
  readonly advisoriesFor: (name: string) => Effect.Effect<Advisory[], StoreError>;

  readonly addEvent: (e: { package: string; kind: string; actor: string; at: number; detail?: unknown }) => Effect.Effect<void, StoreError>;
  readonly eventsFor: (name: string) => Effect.Effect<EventRecord[], StoreError>;
  readonly recentEvents: (kinds: readonly string[], limit: number) => Effect.Effect<EventRecord[], StoreError>;

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
  /** A passkey check made the session `sessionToken`; it can authorize one action from that session. */
  readonly recordPasskeyProof: (input: { sessionToken: string; authUserId: string; at: number }) => Effect.Effect<void, StoreError>;
  /** Spends this session's passkey check on `purpose`. False when there is none, it expired, or it was spent. */
  readonly consumePasskeyProof: (input: { sessionToken: string; authUserId: string; purpose: string; at: number }) => Effect.Effect<boolean, StoreError>;
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
  static postgres(url: string): Layer.Layer<Store | SqlClient.SqlClient, StoreError> {
    return Layer.effectContext(
      Effect.gen(function* () {
        const services = yield* Layer.build(PgClient.layer({ url: Redacted.make(url), maxConnections: 1 })).pipe(
          Effect.mapError((cause) => new StoreError({ operation: "connect", cause })),
        );
        const store = yield* make.pipe(Effect.provide(services));

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

const make = Effect.gen(function* () {
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

    insertStaged: (s) =>
      run(
        "insertStaged",
        sql`INSERT INTO staged (id, package, version, manifest, shasum, integrity, size, tarball_key, tag, readme, score, staged_by, staged_at, expires_at)
            VALUES (${s.id}, ${s.package}, ${s.version}, ${JSON.stringify(s.manifest)}::jsonb, ${s.shasum}, ${s.integrity}, ${s.size}, ${s.tarball_key}, ${s.tag},
                    ${s.readme}, ${s.score === null || s.score === undefined ? null : JSON.stringify(s.score)}::jsonb, ${s.staged_by}, ${s.staged_at}, ${s.expires_at})`,
        none,
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
        sql`UPDATE staged SET status = ${d.status}, decided_at = ${d.at}, decided_by = ${d.by} WHERE id = ${id} AND status = 'pending' RETURNING id`,
        changed,
      ),
    pendingStagedLoad: (input) =>
      run(
        "pendingStagedLoad",
        sql`SELECT
              (SELECT count(*) FROM staged WHERE status = 'pending' AND expires_at > ${input.now} AND staged_by = ${input.user}) AS by_user,
              (SELECT COALESCE(sum(size), 0) FROM staged WHERE status = 'pending' AND expires_at > ${input.now} AND staged_by = ${input.user}) AS bytes_by_user,
              (SELECT count(*) FROM staged WHERE status = 'pending' AND expires_at > ${input.now} AND package = ${input.name}) AS by_package`,
        z.tuple([z.object({ by_user: Int, bytes_by_user: Int.or(z.string().transform(Number)), by_package: Int })]).transform(([row]) => ({
          byUser: row.by_user,
          bytesByUser: row.bytes_by_user,
          byPackage: row.by_package,
        })),
      ),
    expireStaged: (now) =>
      run(
        "expireStaged",
        sql`UPDATE staged SET status = 'expired', decided_at = ${now}, decided_by = 'registry'
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

    listVersions: (name) => run("listVersions", sql`SELECT * FROM versions WHERE package = ${name} ORDER BY published_at, seq`, all(VersionRow)),
    activeVersionsOf: (names) =>
      names.length === 0
        ? Effect.succeed([])
        : run(
            "activeVersionsOf",
            sql`SELECT * FROM versions WHERE package = ANY(${names}) AND status = 'active' ORDER BY package, published_at, seq`,
            all(VersionRow),
          ),
    getVersion: (name, version) =>
      run("getVersion", sql`SELECT * FROM versions WHERE package = ${name} AND version = ${version}`, one(VersionRow)),
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
      ),

    upstreamAnalyses: (name) =>
      run(
        "upstreamAnalyses",
        sql`SELECT version, digest, analysis FROM upstream_analysis WHERE package = ${name} AND scorer = ${SCORER}`,
        all(z.object({ version: z.string(), digest: z.string(), analysis: z.unknown() })).transform(
          (rows) => new Map(rows.map((row) => [`${row.version} ${row.digest}`, row.analysis])),
        ),
      ),
    latestUpstreamAnalysis: (name, version) =>
      run(
        "latestUpstreamAnalysis",
        sql`SELECT analysis FROM upstream_analysis WHERE package = ${name} AND version = ${version} AND scorer = ${SCORER} ORDER BY analyzed_at DESC LIMIT 1`,
        one(z.object({ analysis: z.unknown() })).transform((row) => row?.analysis ?? null),
      ),
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

    addEvent: (e) =>
      run(
        "addEvent",
        sql`INSERT INTO events (package, kind, actor, at, detail) VALUES (${e.package}, ${e.kind}, ${e.actor}, ${e.at}, ${JSON.stringify(e.detail ?? {})}::jsonb)`,
        none,
      ),
    eventsFor: (name) => run("eventsFor", sql`SELECT * FROM events WHERE package = ${name} ORDER BY at DESC, id DESC`, all(EventRow)),
    recentEvents: (kinds, limit) =>
      kinds.length === 0
        ? Effect.succeed([])
        : run("recentEvents", sql`SELECT * FROM events WHERE kind = ANY(${kinds}) ORDER BY at DESC, id DESC LIMIT ${limit}`, all(EventRow)),

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
    recordPasskeyProof: (input) =>
      run(
        "recordPasskeyProof",
        sql`INSERT INTO passkey_proofs (session_hash, auth_user_id, created_at, expires_at, used_at, used_for)
            VALUES (${hashOf(input.sessionToken)}, ${input.authUserId}, ${input.at}, ${input.at + PASSKEY_PROOF_MS}, NULL, NULL)
            ON CONFLICT (session_hash) DO UPDATE SET auth_user_id = EXCLUDED.auth_user_id, created_at = EXCLUDED.created_at,
              expires_at = EXCLUDED.expires_at, used_at = NULL, used_for = NULL`,
        none,
      ),
    consumePasskeyProof: (input) =>
      run(
        "consumePasskeyProof",
        sql`UPDATE passkey_proofs SET used_at = ${input.at}, used_for = ${input.purpose}
            WHERE session_hash = ${hashOf(input.sessionToken)} AND auth_user_id = ${input.authUserId} AND used_at IS NULL
              AND created_at <= ${input.at} AND expires_at > ${input.at}
            RETURNING session_hash`,
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
