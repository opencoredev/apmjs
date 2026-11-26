// Postgres storage for the registry (Neon through Hyperdrive in production). Rows are parsed into domain
// types here, at the storage boundary. Every method is an Effect that fails with StoreError.
import { Context, Duration, Effect, Layer } from "effect";
import type { SqlError } from "effect/sql/SqlError";
import * as SqlClient from "effect/sql/SqlClient";
import { PgClient } from "@effect/sql-pg";
import { z } from "zod";
import { applyDismissals, dependencySpecs, isRegistryDependency, parseAnalysis, PREVIOUS_SCORER, reusableAnalysis, SCORER, type Analysis, type EvidenceDismissal, type NameHistory } from "@apm/core";
import { createHash, randomBytes } from "node:crypto";
import { digestLabel, digestOf } from "./digest.ts";
import { CHALLENGE_MS, CONFIRMATION_MS, FAILURE_WINDOW_MS, GRANT_MS, MAX_FAILURES, isConfirmationId, type ConfirmationId } from "./factors.ts";
import { StoreError } from "./errors.ts";
import { timed, timingOrNull } from "./timing.ts";
import { connectionOptions, Guard, guardFor, RequestConnections, type DatabaseGuard, type GuardTimings } from "./db-health.ts";

export type VersionStatus = "active" | "yanked" | "revoke-pending" | "revoked";

export type StagedStatus = "pending" | "approved" | "rejected" | "expired";

export type StoredScope = "publish" | "stage" | "legacy";

/** int8 columns arrive as bigint; every time and size here fits a double. */
const Int = z.union([z.bigint(), z.number()]).transform((n) => Number(n));
const IntOrNull = Int.nullable();

/** What popular-scores answers for one package: its latest version's score, or nulls when none is stored yet. */
export type LatestScore = { name: string; version: string; score: number; grade: string } | { name: string; version: null; score: null; grade: null };

/** A kept LatestScore and when it was worked out. */
export type KeptLatestScore = { score: LatestScore; computedAt: number };

/** A latest_scores row: the table's CHECK keeps version, score and grade all set or all null. */
const KeptLatestScoreRow = z
  .union([
    z.object({ package: z.string(), version: z.string(), score: Int, grade: z.string(), computed_at: Int }),
    z.object({ package: z.string(), version: z.null(), score: z.null(), grade: z.null(), computed_at: Int }),
  ])
  .transform((r): KeptLatestScore => ({
    score: r.version === null ? { name: r.package, version: null, score: null, grade: null } : { name: r.package, version: r.version, score: r.score, grade: r.grade },
    computedAt: r.computed_at,
  }));

/** A kept_packages row: the summary as stored (kept-package.ts parses it) and when it was worked out. */
const KeptPackageRow = z.object({ summary: z.unknown(), computed_at: Int }).transform((r) => ({ summary: r.summary, computedAt: r.computed_at }));

export type KeptPackageRow = z.output<typeof KeptPackageRow>;

/** A kept answer is marked asked about at most this often, so a busy home page writes once an hour per name. */
const LATEST_SCORE_ASKED_MARK_MS = 60 * 60_000;
const JsonObject = z.record(z.string(), z.unknown());

/** A package.json, as stored and served: any JSON object. Its fields are read with the parsers in @apm/core. */
export const Manifest = JsonObject;

export type Manifest = z.infer<typeof Manifest>;

/** What serving one upstream tarball reads (Store.tarballRead): `confirmed` holds digest labels of that version's tarball. */
const TarballReadRow = z.object({ local: z.boolean(), confirmed: z.array(z.string()), decided: z.boolean(), queued: z.boolean() });

export type TarballRead = z.infer<typeof TarballReadRow>;

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
  /** The version whose publish wrote `readme`; null on rows written before migration 0008 (owner unknown). */
  readme_version: z.string().nullable(),
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
  /** Insert order: two publishes in the same millisecond are ordered by it, as every version query orders them. */
  seq: Int,
  published_by: z.string(),
  deprecated: z.string().nullable(),
  status: z.enum(["active", "yanked", "revoke-pending", "revoked"]),
  status_reason: z.string().nullable(),
  status_at: IntOrNull,
  status_by: z.string().nullable(),
  score: z.unknown(),
});

/**
 * A version as far as choosing among them goes: its number, age, order and state, without its manifest or score. What
 * a resolve reads of every version of a package before it reads the few it picks (review of 93274c8, finding 5).
 */
const VersionHeadRow = VersionRow.pick({ version: true, published_at: true, seq: true, status: true, status_reason: true, status_at: true });

export type VersionHead = z.infer<typeof VersionHeadRow>;

/**
 * What a column's JSON text holds, counted in the database without sending the text: its length in UTF-8 bytes (never
 * fewer than its UTF-16 units), the colons, commas and `[` in it, and the `{`. jsonWeight's terms (walk-catalog.ts).
 */
const TextSize = z.object({ octets: z.number().int().min(0), separators: z.number().int().min(0), objects: z.number().int().min(0) });

export type TextSize = z.infer<typeof TextSize>;

/** npm's record of an upstream package's name that each of its versions carries (core NameHistory, upstream.ts). */
const NameHistoryRow = z.object({ first: z.number(), fifth: z.number().nullable() });

/** A version's record as upstream_choices keeps it (migration 0021): its manifest summarized, and no score. */
const KeptRecord = VersionRow.omit({ score: true }).extend({ history: NameHistoryRow.optional() });

/**
 * What upstream_choices keeps of an upstream package (upstream.ts, chosen): its dist-tags, the versions each choice took,
 * newest first, by the choice's key, with when that choice was made (`at`, ms), and the record of every one of them.
 */
export const KeptChoices = z.object({
  distTags: z.record(z.string(), z.string()),
  lists: z.record(z.string(), z.object({ at: z.number(), versions: z.array(z.string()) })),
  records: z.record(z.string(), KeptRecord),
});

export type KeptChoices = z.infer<typeof KeptChoices>;

/**
 * A kept row as read: the document it was kept for (the URL the packument was asked for at), the ETag of the
 * packument its choices were made from, when it was last written (`fetchedAt`), and the size of its text as sent.
 */
export type KeptChoicesRow = { document: string; etag: string; fetchedAt: number; kept: KeptChoices; size: TextSize };

/** What a read of kept rows is charged per octet, per separator and per object of their text (textReadWeight). */
export type TextCoefficients = { octet: number; node: number; object: number };

const KeptChoicesOut = z
  .object({ document: z.string(), etag: z.string(), fetched_at: Int, kept: KeptChoices, octets: Int, separators: Int, objects: Int })
  .transform((r): KeptChoicesRow => ({ document: r.document, etag: r.etag, fetchedAt: r.fetched_at, kept: r.kept, size: { octets: r.octets, separators: r.separators, objects: r.objects } }));

const VersionSizeRow = z
  .object({
    package: z.string(),
    version: z.string(),
    manifest_octets: z.number().int().min(0),
    manifest_separators: z.number().int().min(0),
    manifest_objects: z.number().int().min(0),
    score_octets: z.number().int().min(0),
    score_separators: z.number().int().min(0),
    score_objects: z.number().int().min(0),
  })
  .transform((r) => ({
    package: r.package,
    version: r.version,
    manifest: TextSize.parse({ octets: r.manifest_octets, separators: r.manifest_separators, objects: r.manifest_objects }),
    score: TextSize.parse({ octets: r.score_octets, separators: r.score_separators, objects: r.score_objects }),
  }));

/** The size of a version row's manifest and score, as versionSizes reads them: what reading the row whole holds. */
export type VersionSize = z.output<typeof VersionSizeRow>;

/** A package as choosing among its versions needs it: its name and dist-tags. */
export type PackageTags = { name: string; distTags: Record<string, string> };

/** A local package's dist-tags and its versions as heads (localHeadsOf). */
export type LocalHeads = { pkg: PackageTags; heads: VersionHead[] };

/** One row of localHeadsOf: a package, and one of its versions as a head (none for a package with no versions). */
const LocalHeadRow = z.object({
  name: z.string(),
  dist_tags: z.record(z.string(), z.string()),
  version: z.string().nullable(),
  published_at: Int.nullable(),
  seq: Int.nullable(),
  status: VersionRow.shape.status.nullable(),
  status_reason: z.string().nullable(),
  status_at: IntOrNull,
});

/** A version as far as the package text it wrote goes (withheld.ts): its description and keywords, unparsed. */
const TextSourceRow = VersionRow.pick({ package: true, status: true, status_at: true, published_at: true, seq: true })
  .extend({ description: z.unknown(), keywords: z.unknown() })
  .transform(({ description, keywords, ...v }) => ({ ...v, manifest: { description, keywords } }));

/** One version of a package with a withheld version, as withheldPackageText reads it. */
export type VersionText = Omit<z.output<typeof TextSourceRow>, "package">;

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

/**
 * Why the current scorer will never score an upstream version (migration 0010): its tarball is over the download or
 * unpack cap (too-large), the upstream serves it in no form apm can check (unavailable), it is not a package apm can
 * read (unreadable), or its analysis kept running past the platform's CPU limit (analysis-limit).
 */
export const UnscorableReason = z.enum(["too-large", "unavailable", "unreadable", "analysis-limit"]);

export type Unscorable = { readonly reason: z.infer<typeof UnscorableReason>; readonly detail: string };

/**
 * An outcome as recorded: the decision and the checksum label (digestLabel) of the tarball it was decided for. Null
 * when it was decided for no tarball (npm no longer lists the version) or recorded before migration 0022: it then
 * names no bytes, and nothing that depends on which bytes they were (the website's readme skip) may trust it.
 */
export type RecordedUnscorable = Unscorable & { readonly digest: string | null };

/**
 * A version as stored; an upstream one also carries why it can never be scored, when that is decided, and npm's record
 * of its package's name (`history`, which the score reads: core settleEstablishedName).
 */
export type VersionRecord = z.infer<typeof VersionRow> & { unscorable?: RecordedUnscorable; history?: NameHistory };

/**
 * The runs of a version so far, the one starting included, as Store.startAnalysis finds them. `starts` counts every
 * run begun; of those, `fetchFailures` ended unable to fetch the version and `failures` ended with an error they
 * reported. The rest began and never stored anything: the platform ended them, for a reason it does not tell the run.
 * `reportedStart` is the start number of the latest run that reported how it ended (a failure or a fetch failure),
 * null when none has (migration 0017).
 */
export type RunHistory = { starts: number; fetchFailures: number; fetchFailedSince: number | null; failures: number; reportedStart: number | null };

/** What starting a run came to (Store.startAnalysis). */
export type AnalysisStart = ({ kind: "started" } & RunHistory) | { kind: "running" } | { kind: "decided" };

/** A package's stored scores (keyed `${version} ${digest}`) and the versions decided unscorable (keyed by version). */
export type UpstreamAnalyses = { scores: Map<string, unknown>; unscorable: Map<string, RecordedUnscorable> };

/** One row of upstreamAnalysesOf's and upstreamAnalysesFor's answer: an analysis, a decided outcome or a live dismissal. */
const AnalysisItem = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("analysis"), package: z.string(), version: z.string(), digest: z.string(), payload: z.unknown() }),
  z.object({ kind: z.literal("decided"), package: z.string(), version: z.string(), digest: z.string().nullable(), payload: z.object({ outcome: UnscorableReason, detail: z.string().nullable() }) }),
  z.object({ kind: z.literal("dismissal"), payload: DismissalRow }),
]);

/**
 * An upstream version's exact bytes, by its tarball digest's label: what upstreamAnalysesFor reads the analyses of.
 * `trimmed`: without PAGE_TRIMMED's members, for a reader that works out only its score and grade (and whether it has one).
 * A null digest is a version npm lists no checksum for: it has no analysis or dismissal, only an outcome (unavailable).
 */
export type AnalysisKey = { readonly package: string; readonly version: string; readonly digest: string | null; readonly trimmed?: boolean };

/** An upstream package's analyses, its live dismissals and what it cannot score, as pageRead reads them. */
const AnalysesColumns = {
  analyses: z.array(z.object({ version: z.string(), digest: z.string(), analysis: z.unknown() })),
  dismissals: z.array(DismissalRow),
  unscorable: z.array(z.object({ version: z.string(), outcome: UnscorableReason, detail: z.string().nullable(), digest: z.string().nullable() })),
};

/** Store.pageRead's one row: the local columns, empty unless `pkg` is there, and the upstream ones, empty unless it is not. */
const PageReadRow = z.object({
  pkg: PackageOut.nullable(),
  versions: z.array(VersionRow),
  owners: z.array(z.string()),
  kept: KeptPackageRow.nullable(),
  ...AnalysesColumns,
  // the versions whose analyses came whole (PageScores)
  shown: z.array(z.string()),
});

/**
 * Which of an upstream package's stored analyses Store.pageRead sends: none, or every one, those of `versions` and of
 * the versions the kept summary's dist-tags in `tags` name whole, and every other one without PAGE_TRIMMED's members.
 */
export type PageScores = { kind: "none" } | { kind: "shown"; versions: readonly string[]; tags: readonly string[] };

/**
 * Members of a stored analysis a package page's read leaves out of the versions it does not show (PageScores): the
 * files apm did not read and the capabilities, nine tenths of next@16.4.6's 300 KB analysis (2,656 files), which every
 * read of next's page sent for each of its scored versions. No score or grade is worked out from them (core finalize,
 * readingOf, settleEstablishedName; reusableAnalysis reads `skipped` only of an apm-score-v10 analysis, and the query
 * sends one only when apm_v10_reusable found it empty), so a version's place in the list reads the same.
 * packages/registry/test/page-read.test.ts holds the two readings to each other.
 */
export const PAGE_TRIMMED = ["skipped", "capabilities"] as const;

/**
 * What Store.pageRead found: a package published here with its versions (each with its dismissals left out, as
 * listVersions has them) and owners, or an upstream package's kept summary (null when none is kept), its scores, and
 * the versions whose analyses came whole (PageScores).
 */
export type PageRow =
  | { kind: "local"; pkg: PackageRecord; versions: VersionRecord[]; owners: string[] }
  | { kind: "upstream"; kept: KeptPackageRow | null; analyses: UpstreamAnalyses; whole: ReadonlySet<string> };

/** What Store.fileRead found: a package published here (files.ts reads its one version on its own), or pageRead's upstream row. */
export type FileRow = { kind: "local" } | Extract<PageRow, { kind: "upstream" }>;

export type Advisory = z.infer<typeof AdvisoryRow>;

export type StagedRecord = z.infer<typeof StagedRow>;

export type NewStaged = Omit<StagedRecord, "status" | "decided_at" | "decided_by">;

/** Who and what the recent-activity feed leaves out: check accounts and the scopes they publish under. */
export type RecentHidden = { actors: readonly string[]; scopes: readonly string[] };

export type EventRecord = z.infer<typeof EventRow>;

export type NewVersion = Omit<VersionRecord, "seq" | "status" | "status_reason" | "status_at" | "status_by" | "deprecated">;

export type Linked = { provider: string; accountId: string };

const PasskeyRow = z.object({ id: z.string(), credentialID: z.string(), publicKey: z.string(), counter: Int, transports: z.string().nullable() });

/** One of an account's passkeys (Better Auth's table): the public key is base64 COSE, as WebAuthn registered it. */
export type PasskeyRecord = z.infer<typeof PasskeyRow>;

const PasskeyListRow = z.object({ id: z.string(), name: z.string().nullable(), aaguid: z.string().nullable(), created_at: IntOrNull, last_used_at: IntOrNull });

/** One of an account's passkeys as the account page lists it: no key material. Times are epoch ms; null when unknown. */
export type PasskeySummary = { id: string; name: string | null; aaguid: string | null; createdAt: number | null; lastUsedAt: number | null };

/** How removing a passkey ended: `last-way-in` when it is the account's only passkey and no enabled provider is linked. */
export type PasskeyRemoval = "removed" | "missing" | "last-way-in";

/** The OAuth providers an account can sign in with, when the deploy has them on. */
export type SignInProvider = "github" | "vercel";

/** One answer from one of the account's passkeys: `credentialID` as WebAuthn names it, `at` in epoch ms. */
export type PasskeyUse = { authUserId: string; credentialID: string; at: number };

/** How long the write of a passkey's last use may take before it is dropped. */
export const PASSKEY_USE_WAIT_MS = 500;

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

// Serializes new latest_scores rows so two at once cannot both pass the capacity check (new rows are rare: a package's first ask).
const LATEST_SCORE_INSERT_LOCK = 0x617_06d_4c53;

// Serializes new kept_packages rows the same way (a package's first view after apm scored it).
const KEPT_PACKAGE_INSERT_LOCK = 0x617_06d_4b50;

/** The advisory lock a page's seeding admissions queue on (admitSeedJobs): "apmSA". */
const SEED_ADMISSION_LOCK = 0x617_06d_5341;

/** The advisory lock writers of upstream_choices take (writeChoices): one writer at a time, and a busy lock skips the write. */
export const KEPT_CHOICES_INSERT_LOCK = 0x617_06d_4b43;

/** How often a read marks a kept row asked: the cron drops rows by it, a week at a time. */
const KEPT_CHOICES_ASKED_MARK_MS = 60 * 60_000;

// The first key of the two-key advisory locks on blob keys ("blob"); the second is the key's hash. Two-key
// advisory locks never conflict with one-key ones such as STAGED_INSERT_LOCK.
const BLOB_LOCK_CLASS = 0x626c_6f62;

/** One attempt taken from an account's second-factor budget, or the budget is spent. */
export type Reservation = { kind: "locked" } | { kind: "reserved"; id: number };

/** Better Auth's TOTP row: the encrypted secret and recovery codes, and whether setup finished. */
export type TwoFactorRecord = { secret: string; backupCodes: string; verified: boolean };

/** A staged score as the jsonb text the row stores, or null. */
/** A staged upload's score as jsonb text, with NUL and lone surrogates made storable like every other score (storableJson). */
const scoreJson = ({ score }: Pick<NewStaged, "score">): string | null => (score === null || score === undefined ? null : storableJson(JSON.stringify(score)));

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
    meta: { modifiedAt: number; description?: string; keywords?: string[]; readme?: { text: string; version: string } },
  ) => Effect.Effect<void, StoreError>;
  readonly setDistTags: (name: string, tags: Record<string, string>, at: number) => Effect.Effect<void, StoreError>;
  readonly owners: (name: string) => Effect.Effect<string[], StoreError>;
  /** The names a user publishes: every package under their scope (`@user/`) and every one they own, by name, at most `limit`. */
  readonly packagesOf: (input: { user: string; limit: number }) => Effect.Effect<string[], StoreError>;
  readonly ownersOf: (names: readonly string[]) => Effect.Effect<Map<string, string[]>, StoreError>;
  readonly addOwner: (name: string, user: string) => Effect.Effect<void, StoreError>;
  /** Removes an owner unless that would leave the package with none; the count is read under the package lock. */
  readonly removeOwner: (name: string, user: string) => Effect.Effect<"removed" | "not-owner" | "last-owner", StoreError>;

  readonly listVersions: (name: string) => Effect.Effect<VersionRecord[], StoreError>;
  /**
   * Each name this registry has, with its dist-tags and every version as a head (number, age, order, state), in publish
   * order: what choosing among its versions needs, in one statement, without its readme, manifests or scores.
   */
  readonly localHeadsOf: (names: readonly string[]) => Effect.Effect<Map<string, LocalHeads>, StoreError>;
  /**
   * The size of each given version's manifest and score, counted in the database, so a reader can reserve memory for
   * the rows before versionsWithin sends them. One it does not have is left out.
   */
  readonly versionSizes: (versions: readonly { package: string; version: string }[]) => Effect.Effect<VersionSize[], StoreError>;
  /**
   * The versions `sizes` names, whole, in publish order, each only while its manifest and score still measure no more
   * than `sizes` says: a row that grew after it was measured is left out, so it is never read past what was reserved
   * for it (review of 16fc8b5, finding 5). One statement, so each row is measured as it is sent.
   */
  readonly versionsWithin: (sizes: readonly VersionSize[]) => Effect.Effect<VersionRecord[], StoreError>;
  readonly activeVersionsOf: (names: readonly string[]) => Effect.Effect<VersionRecord[], StoreError>;
  /**
   * Every version of each package that has a revoked or revoke-pending version, with only what packageTextShown reads
   * (withheld.ts), in publish order, in one query. Those packages' row text may be a withheld publish's.
   */
  readonly withheldPackageText: () => Effect.Effect<Map<string, VersionText[]>, StoreError>;
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

  /** The current scorer's analyses of this package and the versions it decided it cannot score: upstreamAnalysesOf for one name. */
  readonly upstreamAnalyses: (name: string) => Effect.Effect<UpstreamAnalyses, StoreError>;
  /** upstreamAnalyses for several packages in three statements, keyed by package name; a package with neither is left out. */
  readonly upstreamAnalysesOf: (names: readonly string[]) => Effect.Effect<Map<string, UpstreamAnalyses>, StoreError>;
  /**
   * upstreamAnalysesOf for exactly these versions' bytes, in one statement: their analyses, their decided outcomes and
   * the live dismissals for them, keyed by package name. What it holds grows with the versions asked for, never with a
   * package's history.
   */
  readonly upstreamAnalysesFor: (keys: readonly AnalysisKey[]) => Effect.Effect<Map<string, UpstreamAnalyses>, StoreError>;
  /**
   * Whether upstreamAnalyses would find a score for the package (its scores are not empty), without reading one: an
   * analysis by the current scorer, or an apm-score-v10 one it reuses. currentScore keeps every row that filter passes.
   */
  readonly upstreamScored: (name: string) => Effect.Effect<boolean, StoreError>;
  /**
   * Whether upstreamAnalysesFor(keys) would find a score for one of them, or with `outcomes` an outcome decided for one
   * (by version, whatever its digest), without reading either: kept-package admission (admitted) of versions a read
   * left out. currentScore keeps every row the scorer filter passes, so a row is a score.
   */
  readonly upstreamAdmitted: (input: { keys: readonly AnalysisKey[]; outcomes: boolean }) => Effect.Effect<boolean, StoreError>;
  /**
   * The kept popular-scores answers for these names (migration 0019), never one for a package published on apm. Marks
   * them asked about at `at`, at most once an hour each, so the sweep keeps refreshing them.
   */
  readonly latestScores: (input: { names: readonly string[]; at: number }) => Effect.Effect<KeptLatestScore[], StoreError>;
  /**
   * Keeps a popular-scores answer worked out at `at` for a name asked about at `at`. A kept one is replaced; a new row
   * is added only while the table holds fewer than `capacity`. Which names may have a row is the caller's call (apm.ts).
   */
  readonly keepLatestScore: (input: { score: LatestScore; at: number; capacity: number }) => Effect.Effect<void, StoreError>;
  /** Replaces a kept answer with one the sweep worked out at `at`; when it was asked about stays as it was. */
  readonly refreshLatestScore: (input: { score: LatestScore; at: number }) => Effect.Effect<void, StoreError>;
  /** Kept answers asked about at or after `askedSince` and worked out before `computedBefore`, oldest first, as kept. */
  readonly latestScoresToRefresh: (input: { askedSince: number; computedBefore: number; limit: number }) => Effect.Effect<KeptLatestScore[], StoreError>;
  /** Drops kept answers last asked about before `askedBefore`, or the one for `name`. */
  readonly dropLatestScores: (input: { kind: "asked-before"; askedBefore: number } | { kind: "name"; name: string }) => Effect.Effect<void, StoreError>;
  /**
   * The kept page summary of an upstream package (migration 0020) and when it was worked out, never one for a package
   * published on apm. Marks it asked about at `at`, at most once an hour, so the sweep keeps refreshing it. The summary
   * is as stored: kept-package.ts parses it.
   */
  readonly keptPackage: (input: { name: string; at: number }) => Effect.Effect<KeptPackageRow | null, StoreError>;
  /**
   * What a package page's read starts from, in one round trip: getPackage, then for a package published here
   * listVersions and owners, else keptPackage (marking it asked about the same way) and upstreamAnalyses as `scores`
   * says (PageScores). One statement, so one snapshot: nothing it returns is older than the statement.
   */
  readonly pageRead: (input: { name: string; at: number; scores: PageScores }) => Effect.Effect<PageRow, StoreError>;
  /** pageRead for a file or readme view: a local package's row alone, without its versions, owners or their scores. */
  readonly fileRead: (input: { name: string; at: number; scores: PageScores }) => Effect.Effect<FileRow, StoreError>;
  /**
   * Keeps a summary worked out at `at` for a name asked about at `at`. A kept one is replaced; a new row is added only
   * while the table holds fewer than `capacity`. Which names may have a row is the caller's call (kept-package.ts).
   */
  readonly keepPackage: (input: { name: string; summary: unknown; at: number; capacity: number }) => Effect.Effect<void, StoreError>;
  /** Replaces a kept summary with one the sweep worked out at `at`; when it was asked about stays as it was. */
  readonly refreshKeptPackage: (input: { name: string; summary: unknown; at: number }) => Effect.Effect<void, StoreError>;
  /**
   * Claims the refresh of a kept summary worked out before `computedBefore` that no refresh claimed since
   * `claimedBefore`. The summary's npm ETag when this caller should refresh it; null when it should not.
   */
  readonly claimKeptRefresh: (input: { name: string; at: number; computedBefore: number; claimedBefore: number }) => Effect.Effect<{ etag: string | null } | null, StoreError>;
  /**
   * Marks a kept summary worked out at `at` as it is: npm still sends the packument it was cut from, the one with
   * `etag`. Only that summary, and only forward: a summary replaced since, or one worked out later, is left alone.
   */
  readonly touchKeptPackage: (input: { name: string; at: number; etag: string }) => Effect.Effect<void, StoreError>;
  /**
   * Kept summaries asked about at or after `askedSince`, worked out before `computedBefore` and due again at `at` (no
   * failed refresh holds them back), oldest first.
   */
  readonly keptPackagesToRefresh: (input: { askedSince: number; computedBefore: number; at: number; limit: number }) => Effect.Effect<string[], StoreError>;
  /**
   * Records a refresh npm did not answer: the next waits `retryMs` doubled for each failure in a row before it, at most
   * `maxRetryMs`. A refresh that succeeds clears it.
   */
  readonly failKeptRefresh: (input: { name: string; at: number; retryMs: number; maxRetryMs: number }) => Effect.Effect<void, StoreError>;
  /** Drops kept summaries last asked about before `askedBefore`, or the one for `name`. */
  readonly dropKeptPackages: (input: { kind: "asked-before"; askedBefore: number } | { kind: "name"; name: string }) => Effect.Effect<void, StoreError>;
  /**
   * The kept choices of each of `documents` (migration 0021), in one statement, each sent only while what the rows sent
   * so far hold once read (textReadWeight, by `weights`) stays within `allowance`; a row past it is left out. Each one
   * sent is marked asked at `at` (at most once an hour), so the cron keeps it.
   */
  readonly keptChoicesOf: (input: { documents: readonly string[]; allowance: number; weights: TextCoefficients; at: number }) => Effect.Effect<KeptChoicesRow[], StoreError>;
  /**
   * Keeps each row (its JSON text, as `text`) at most `maxBytes` as Postgres stores it, in one statement with each value
   * its own parameter: a document that has one is replaced; a new one is added only while the table holds fewer than
   * `capacity`. Writers queue behind each other, so two cannot both take the last place. The rows name distinct documents.
   */
  readonly keepChoices: (input: { rows: readonly { document: string; etag: string; text: string }[]; at: number; capacity: number; maxBytes: number; maxChoices: number; maxAgeMs: number }) => Effect.Effect<void, StoreError>;
  /**
   * keepChoices a row at a time: `write` is run inside one transaction that holds the writers' lock, and each `put`
   * keeps one row (at most `maxBytes` as stored; a new one only while the table holds fewer than `capacity`), so the
   * caller can build each row's text just before it is put and let it go just after (kept-choices.ts, keepPlans).
   * Keeping is optional: when another writer holds the lock, nothing is written and `write` is not run, rather than
   * waiting on it (combined review of 67d8658, finding 4). Each `put` is merged into the row kept for the same
   * document and ETag here, in the database: its choices that hold (younger than `maxAgeMs`) and fit beside the new
   * ones (`maxChoices`, `maxBytes`) stay; the Worker never reads them back to merge (re-check of 51fc813).
   */
  readonly writeChoices: <E, R>(input: { at: number; capacity: number; maxBytes: number; maxChoices: number; maxAgeMs: number }, write: (put: (row: { document: string; etag: string; text: string }) => Effect.Effect<void, StoreError>) => Effect.Effect<void, E, R>) => Effect.Effect<void, E | StoreError, R>;
  /** Drops kept choices nobody asked about since `askedBefore`. */
  readonly dropKeptChoices: (input: { askedBefore: number }) => Effect.Effect<void, StoreError>;
  /**
   * For display where the tarball digest is not known (search hits): each version's newest current-scorer analysis,
   * keyed `"<name> <version>"`, in one query however many versions are asked for.
   */
  readonly latestUpstreamAnalyses: (versions: readonly { name: string; version: string }[]) => Effect.Effect<Map<string, unknown>, StoreError>;
  readonly setUpstreamAnalysis: (input: { name: string; version: string; digest: string; analysis: unknown; at: number }) => Effect.Effect<void, StoreError>;
  /** Records that a version was sent for analysis; false when it was sent less than `staleMs` ago. */
  readonly claimAnalysisJob: (name: string, version: string, now: number, staleMs: number) => Effect.Effect<boolean, StoreError>;
  /** claimAnalysisJob for several versions of one package in one statement: the versions it claimed now. Never waits on a lock. */
  readonly claimAnalysisJobs: (input: { name: string; versions: readonly string[]; now: number; staleMs: number }) => Effect.Effect<string[], StoreError>;
  /**
   * claimAnalysisJobs for a page's seeding, under one global quota: at most `max` jobs (any package, any caller) claimed
   * since `since`. Admissions queue behind each other on an advisory lock, each counts under a fresh snapshot once it
   * holds it, and claims only the room left, so concurrent seeds never pass the quota between them (review of 4ac264b,
   * P2: one claim from 59 reached 67, four at once 91). Demand claims (claimAnalysisJob, claimAnalysisJobs) never take
   * the lock, so a user's own ask is never held behind seeding; one landing beside an admission can pass the quota by
   * its own rows, never by a seed's.
   */
  readonly admitSeedJobs: (input: { name: string; versions: readonly string[]; now: number; staleMs: number; since: number; max: number }) => Effect.Effect<string[], StoreError>;
  /**
   * Up to `limit` kept summaries of packages asked about since `askedSince`, the ones seeded longest ago (or never) first,
   * each marked seeded at `at` in the same statement (migration 0024), for the cron's seeding (kept-package.ts).
   */
  readonly keptPackagesToSeed: (input: { askedSince: number; seededBefore: number; at: number; limit: number }) => Effect.Effect<{ name: string; summary: unknown }[], StoreError>;
  /** Drops the reservation claimAnalysisJob made at `claimedAt` (when the queue refused the job); a newer claim stays. */
  readonly releaseAnalysisJob: (name: string, version: string, claimedAt: number) => Effect.Effect<void, StoreError>;
  /** Records that the current scorer will never score this version, and why. */
  /** `digest`: the checksum label of the tarball the outcome was decided for, null when there is none (RecordedUnscorable). */
  readonly setUnscorable: (input: { name: string; version: string; unscorable: Unscorable; digest: string | null; at: number }) => Effect.Effect<void, StoreError>;
  /**
   * Counts a run of this version as begun, before it does anything, and says how many have begun (this one included)
   * and how many of those ended unable to fetch the version (`fetchFailures`). "running" when another run began less
   * than `runMs` ago and may still be going; "decided" when the version already has an outcome.
   */
  readonly startAnalysis: (input: { name: string; version: string; now: number; runMs: number }) => Effect.Effect<AnalysisStart, StoreError>;
  /**
   * Records that a run ended because the upstream could not be asked or would not serve the tarball yet: its start
   * stays counted, `fetch_failures` goes up, `errorClass` is kept, the first such failure's time is kept, and the run
   * counts as ended (started `runMs` before `now`), so the queue's next delivery or the sweep may start it again.
   * Returns the fetch failures so far; null when already decided.
   */
  readonly failFetch: (input: { name: string; version: string; errorClass: string; now: number; runMs: number }) => Effect.Effect<number | null, StoreError>;
  /**
   * Records that a run failed with an error it reported: its start stays counted, `errorClass` is kept, and the run
   * counts as ended (started `runMs` before `now`), so the next delivery or the sweep may start it again. Returns how
   * many runs of it have failed, this one included; null when the version already has an outcome.
   */
  readonly failAnalysis: (input: { name: string; version: string; errorClass: string; now: number; runMs: number }) => Effect.Effect<number | null, StoreError>;
  /**
   * Runs `startAnalysis` counted that began at or before `before` and never ended: no outcome, and no analysis of the
   * version by the current scorer. The record a run leaves before it starts, so the cron sweep finds what the platform
   * stopped (analysis.ts, `recover`). At most `limit`, the ones the sweep picked longest ago (or never) first, and each
   * picked is marked picked at `now`: a row the sweep cannot settle moves to the back instead of being picked forever.
   */
  readonly unfinishedAnalyses: (input: { before: number; limit: number; now: number }) => Effect.Effect<{ name: string; version: string }[], StoreError>;
  /**
   * Jobs the queue accepted at or before `before` (analysis_jobs) that never began a run: no analysis by the current
   * scorer, no outcome, and no run begun. A job the queue gave up on before its first run left only this behind. At
   * most `limit`, longest queued first; requeueing one claims it again, which moves it to the back.
   */
  readonly acceptedAnalyses: (input: { before: number; limit: number }) => Effect.Effect<{ name: string; version: string }[], StoreError>;
  /**
   * Which of these upstream versions the current scorer has decided: an analysis stored, or an outcome. Keyed
   * `"<name> <version>"`. One read however many are asked for, and nothing of the analyses themselves: what a resolve
   * waiting for the queue polls.
   */
  readonly decidedAnalyses: (versions: readonly { name: string; version: string }[]) => Effect.Effect<Set<string>, StoreError>;
  /** The tarballs of `name` an apm reviewer confirmed malicious, each as its version and digest label (confirmed.ts). */
  readonly confirmedReviews: (name: string) => Effect.Effect<{ version: string; digest: string }[], StoreError>;
  /**
   * What the install packument of a package only npm has needs from the database, in one round trip: whether the name
   * is published here (then it is not npm's to serve), and the versions apm reviewers confirmed malicious, as
   * confirmedReviews reads them, in a stable order.
   */
  readonly installRead: (name: string) => Effect.Effect<{ local: boolean; confirmed: { version: string; digest: string }[] }, StoreError>;
  /**
   * What serving one upstream tarball needs from the database, in one round trip (fast-tarball.ts): whether the name
   * is published here, the digests of `version`'s tarball an apm reviewer confirmed malicious (confirmedReviews,
   * for that version), whether the current scorer has an analysis or a decided outcome for it (decidedAnalyses), and
   * whether it was queued for analysis after `queuedSince` (claimAnalysisJob would not claim it again).
   */
  readonly tarballRead: (input: { name: string; version: string; queuedSince: number }) => Effect.Effect<TarballRead, StoreError>;

  readonly deleteAdvisoriesFor: (name: string, version: string) => Effect.Effect<void, StoreError>;
  readonly addAdvisory: (a: Omit<Advisory, "id">) => Effect.Effect<number, StoreError>;
  readonly advisoriesFor: (name: string) => Effect.Effect<Advisory[], StoreError>;
  /** Names among `names` that are published locally on this registry, in one query. */
  readonly existingPackages: (names: readonly string[]) => Effect.Effect<Set<string>, StoreError>;
  /** Local advisories across every package in `names`, in one query. */
  readonly advisoriesForPackages: (names: readonly string[]) => Effect.Effect<Advisory[], StoreError>;

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
  /** npm packages this registry scored most recently (a package page or an install asked for them), newest first. */
  readonly recentlyScored: (limit: number) => Effect.Effect<{ package: string; at: number }[], StoreError>;

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
  /** The account's passkeys for the account page, oldest first: the same rows authFactors counts. */
  readonly passkeyList: (authUserId: string) => Effect.Effect<PasskeySummary[], StoreError>;
  /**
   * Records that the account's passkey `credentialID` answered at `at` (a sign-in or a factor check), giving up after
   * PASSKEY_USE_WAIT_MS. Display only: the Worker runs it after the response on a Store of its own (worker.ts).
   */
  readonly notePasskeyUse: (input: PasskeyUse) => Effect.Effect<void, StoreError>;
  /**
   * Deletes the account's passkey `id`, unless it is the account's last way to sign in: its only passkey, with no linked
   * account of a provider in `providers` (the ones this deploy signs in with).
   */
  readonly removePasskey: (input: { authUserId: string; id: string; providers: readonly SignInProvider[] }) => Effect.Effect<PasskeyRemoval, StoreError>;
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
  static postgres(url: string, faults: ReadonlySet<StoreFault> = new Set(), timings: GuardTimings = {}): Layer.Layer<Store | SqlClient.SqlClient | Guard, StoreError> {
    return Layer.effectContext(
      Effect.gen(function* () {
        // this request's connections, which its guard closes at once when it takes the database as unavailable
        const conns = new RequestConnections();

        const services = yield* Layer.build(PgClient.layer({ ...connectionOptions(url, conns, timings.stallMs), maxConnections: 1 })).pipe(
          Effect.mapError((cause) => new StoreError({ operation: "connect", cause })),
        );

        const guard = guardFor(timings, conns);
        const store = yield* make(faults, guard).pipe(Effect.provide(services));

        return Context.add(Context.add(services, Store, store), Guard, guard);
      }),
    );
  }
}

const one = <S extends z.ZodType>(row: S) => z.array(row).transform((rows) => rows[0] ?? null);

/**
 * JSON text for a jsonb column whose strings quote a package (an analysis's evidence, a review's findings). Postgres
 * refuses U+0000 and unpaired surrogates in jsonb text, so a quote of a binary file made the whole write fail: on
 * staging, ac 1.0.2's evidence quoted db/000741.ldb and every run of it lost its store. JSON.stringify writes exactly
 * those two as \u escapes (a paired surrogate stays a character), so each such escape, and no escaped backslash
 * before a "u", becomes U+FFFD.
 */
export function storableJson(json: string): string {
  return json.replace(/(?<!\\)((?:\\\\)*)\\u(?:0000|d[89a-f][0-9a-f]{2})/gi, "$1\\ufffd");
}

const all = <S extends z.ZodType>(row: S) => z.array(row);
const none = z.array(z.unknown()).transform(() => undefined);
const changed = z.array(z.unknown()).transform((rows) => rows.length > 0);
const count = z.array(z.unknown()).transform((rows) => rows.length);

const make = (faults: ReadonlySet<StoreFault>, guard: DatabaseGuard) => Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const timeQuery = timed(yield* timingOrNull, "db");

  const run = <S extends z.ZodType>(operation: string, effect: Effect.Effect<ReadonlyArray<unknown>, SqlError>, schema: S): Effect.Effect<z.output<S>, StoreError> =>
    guard.statement(operation, timeQuery(effect)).pipe(
      Effect.flatMap((rows) => {
        const parsed = schema.safeParse(rows);

        return parsed.success ? Effect.succeed(parsed.data) : Effect.fail(new StoreError({ operation: `${operation}: parse`, cause: parsed.error }));
      }),
    );

  const getPackage = (name: string) => run("getPackage", sql`SELECT * FROM packages WHERE name = ${name}`, one(PackageOut));

  /**
   * A stored upstream analysis as the current scorer reads it (reusableAnalysis: its own, or an apm-score-v10 one it would
   * store the same), with what was dismissed for its bytes left out; none when the current scorer would not take it.
   * Whether it is reusable is decided on the analysis as stored, before any dismissal.
   */
  const currentScore = (stored: VersionRecord["score"], list: readonly EvidenceDismissal[]): VersionRecord["score"][] => {
    // the query chose the row (apm_v10_reusable); one that does not parse is passed on as stored, as before, and reads
    // as not scored; one that parses and is not reusable is left out
    const parsed = parseAnalysis(stored);

    if (parsed === null) return [withList(stored, list)];
    const current = reusableAnalysis(parsed);

    return current === null ? [] : [withList(current, list)];
  };

  /** A stored score as stored, or, with dismissals for its bytes, the analysis without them. */
  const withList = (stored: VersionRecord["score"], list: readonly EvidenceDismissal[]): VersionRecord["score"] =>
    list.length === 0 ? stored : (dismissedAnalysis(parseAnalysis(stored), list) ?? stored);

  /**
   * The rows of upstreamAnalysesOf or upstreamAnalysesFor by package: each analysis scored with the dismissals for its
   * bytes, the current scorer's replacing a reused v10 one (rows come oldest scorer first), and what was decided.
   */
  const analysesByPackage = (items: readonly z.output<typeof AnalysisItem>[]): Map<string, UpstreamAnalyses> => {
    const out = new Map<string, UpstreamAnalyses>();

    const of = (name: string): UpstreamAnalyses => {
      const got = out.get(name) ?? { scores: new Map<string, unknown>(), unscorable: new Map<string, RecordedUnscorable>() };

      out.set(name, got);

      return got;
    };

    const rows = items.flatMap((i) => (i.kind === "analysis" ? [{ package: i.package, version: i.version, digest: i.digest, analysis: i.payload }] : []));
    const decided = items.flatMap((i) => (i.kind === "decided" ? [{ package: i.package, version: i.version, digest: i.digest, ...i.payload }] : []));
    const dismissals = items.flatMap((i) => (i.kind === "dismissal" ? [i.payload] : []));

    for (const r of rows) for (const score of currentScore(r.analysis, dismissalsFor(dismissals.filter((d) => d.package === r.package), r.version, r.digest))) of(r.package).scores.set(`${r.version} ${r.digest}`, score);

    for (const d of decided) of(d.package).unscorable.set(d.version, { reason: d.outcome, detail: d.detail ?? "", digest: d.digest });

    return out;
  };

  const dismissalsOf = (names: readonly string[]): Effect.Effect<DismissalRecord[], StoreError> =>
    names.length === 0
      ? Effect.succeed([])
      : run("dismissalsOf", sql`SELECT * FROM evidence_dismissals WHERE package = ANY(${names}) AND restored_at IS NULL ORDER BY dismissed_at, id`, all(DismissalRow));

  /** `rows` as they are scored, given the live dismissals of their packages: what was dismissed for exactly these bytes is left out. */
  const dismissedFrom = (rows: VersionRecord[], ds: readonly DismissalRecord[]): VersionRecord[] =>
    ds.length === 0 ? rows : rows.map((v) => ({ ...v, score: withList(v.score, dismissalsFor(ds.filter((d) => d.package === v.package), v.version, versionDigest(v))) }));

  /** Versions as they are scored: what an apm reviewer dismissed for exactly these bytes is left out. */
  const withDismissals = (rows: VersionRecord[]): Effect.Effect<VersionRecord[], StoreError> =>
    rows.length === 0 ? Effect.succeed(rows) : Effect.map(dismissalsOf([...new Set(rows.map((v) => v.package))]), (ds) => dismissedFrom(rows, ds));

  /** An upstream package's scores keyed by "<version> <digest>", each with its dismissed evidence left out, and what it cannot score. */
  const analysesOf = (analyses: z.output<typeof PageReadRow>["analyses"], dismissals: readonly DismissalRecord[], unscorable: z.output<typeof PageReadRow>["unscorable"]): UpstreamAnalyses => ({
    // rows come oldest scorer first, so the current scorer's analysis of the same bytes replaces a reused v10 one
    scores: new Map(analyses.flatMap((a) => currentScore(a.analysis, dismissalsFor(dismissals, a.version, a.digest)).map((score) => [`${a.version} ${a.digest}`, score] as const))),
    unscorable: new Map(unscorable.map((u) => [u.version, { reason: u.outcome, detail: u.detail ?? "", digest: u.digest }] as const)),
  });

  /**
   * The statement behind pageRead and fileRead. With `local: "none"` a local package's versions and owners are left out:
   * every version's whole score of a busy local package is megabytes, and a file view needs one version.
   */
  const pageRow = ({ name, at, scores, local }: { name: string; at: number; scores: PageScores; local: "versions" | "none" }) =>
    Effect.gen(function* () {
      const read = scores.kind === "shown";
      const versions = scores.kind === "shown" ? [...scores.versions] : [];
      const tags = scores.kind === "shown" ? [...scores.tags] : [];
      const withVersions = local === "versions";

      return yield* run(
        withVersions ? "pageRead" : "fileRead",
        sql`WITH asked AS (
              UPDATE kept_packages SET asked_at = ${at} WHERE package = ${name} AND asked_at < ${at - LATEST_SCORE_ASKED_MARK_MS}
            ),
            p AS (SELECT * FROM packages WHERE name = ${name}),
            shown AS (
              SELECT v AS version FROM unnest(${versions}::text[]) AS v
              UNION SELECT k.summary -> 'distTags' ->> t FROM kept_packages k, unnest(${tags}::text[]) AS t WHERE k.package = ${name}
            ),
            listed AS (
              SELECT jsonb_array_elements(k.summary -> 'versions') ->> 'version' AS version FROM kept_packages k WHERE k.package = ${name} AND jsonb_typeof(k.summary -> 'versions') = 'array'
            )
            SELECT
              (SELECT to_jsonb(p) FROM p) AS pkg,
              (SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.published_at, v.seq), '[]'::jsonb)
                 FROM versions v WHERE ${withVersions} AND v.package = ${name} AND EXISTS (SELECT 1 FROM p)) AS versions,
              (SELECT coalesce(jsonb_agg(o."user" ORDER BY o."user"), '[]'::jsonb)
                 FROM owners o WHERE ${withVersions} AND o.package = ${name} AND EXISTS (SELECT 1 FROM p)) AS owners,
              (SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.dismissed_at, e.id), '[]'::jsonb)
                 FROM evidence_dismissals e WHERE e.package = ${name} AND e.restored_at IS NULL) AS dismissals,
              (SELECT jsonb_build_object('summary', k.summary, 'computed_at', k.computed_at)
                 FROM kept_packages k WHERE k.package = ${name} AND NOT EXISTS (SELECT 1 FROM p)) AS kept,
              (SELECT coalesce(jsonb_agg(jsonb_build_object('version', u.version, 'digest', u.digest,
                        'analysis', CASE WHEN u.version IN (SELECT version FROM shown) THEN u.analysis ELSE u.analysis - ${[...PAGE_TRIMMED]}::text[] END) ORDER BY u.scorer), '[]'::jsonb)
                 FROM upstream_analysis u WHERE ${read} AND u.package = ${name} AND u.version IN (SELECT version FROM listed) AND (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis))) AND NOT EXISTS (SELECT 1 FROM p)) AS analyses,
              (SELECT coalesce(jsonb_agg(jsonb_build_object('version', o.version, 'outcome', o.outcome, 'detail', o.detail, 'digest', o.digest) ORDER BY o.scorer), '[]'::jsonb)
                 FROM analysis_outcomes o WHERE ${read} AND o.package = ${name} AND o.version IN (SELECT version FROM listed) AND (o.scorer = ${SCORER} OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))) AND o.outcome IS NOT NULL AND NOT EXISTS (SELECT 1 FROM p)) AS unscorable,
              (SELECT coalesce(jsonb_agg(version), '[]'::jsonb) FROM shown WHERE version IS NOT NULL AND ${read}) AS shown`,
        z.tuple([PageReadRow]).transform(([r]) => r),
      );
    });

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
    // BEGIN, COMMIT and ROLLBACK are bounded by the connection (db-health.ts, watchedSocket) and the whole by guard.transaction
    tx: (effect) => guard.transaction("transaction", sql.withTransaction(effect)),

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
              readme = COALESCE(${meta.readme?.text ?? null}, readme),
              readme_version = COALESCE(${meta.readme?.version ?? null}, readme_version)
            WHERE name = ${name}`,
        none,
      ),
    setDistTags: (name, tags, at) => run("setDistTags", sql`UPDATE packages SET dist_tags = ${JSON.stringify(tags)}::jsonb, modified_at = ${at} WHERE name = ${name}`, none),
    owners: (name) => run("owners", sql`SELECT "user" FROM owners WHERE package = ${name} ORDER BY "user"`, all(z.object({ "user": z.string() }).transform((r) => r.user))),
    packagesOf: ({ user, limit }) =>
      run(
        "packagesOf",
        sql`SELECT name FROM packages WHERE starts_with(name, ${`@${user}/`})
            UNION SELECT package AS name FROM owners WHERE "user" = ${user}
            ORDER BY name LIMIT ${limit}`,
        all(z.object({ name: z.string() }).transform((r) => r.name)),
      ),
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
      guard.transaction(
        "removeOwner",
        sql.withTransaction(
          Effect.gen(function* () {
            yield* run("removeOwner: lock", sql`SELECT name FROM packages WHERE name = ${name} FOR UPDATE`, none);
            const owners = yield* run("removeOwner: owners", sql`SELECT "user" FROM owners WHERE package = ${name}`, all(z.object({ "user": z.string() }).transform((r) => r.user)));

            if (!owners.includes(user)) return "not-owner" as const;

            if (owners.length <= 1) return "last-owner" as const;
            yield* run("removeOwner", sql`DELETE FROM owners WHERE package = ${name} AND "user" = ${user}`, none);

            return "removed" as const;
          }),
        )),

    listVersions: (name) => Effect.flatMap(run("listVersions", sql`SELECT * FROM versions WHERE package = ${name} ORDER BY published_at, seq`, all(VersionRow)), withDismissals),
    localHeadsOf: (names) =>
      names.length === 0
        ? Effect.succeed(new Map<string, LocalHeads>())
        : run(
            "localHeadsOf",
            sql`SELECT p.name, p.dist_tags, v.version, v.published_at, v.seq, v.status, v.status_reason, v.status_at
                FROM packages p LEFT JOIN versions v ON v.package = p.name
                WHERE p.name = ANY(${[...new Set(names)]})
                ORDER BY p.name, v.published_at, v.seq`,
            all(LocalHeadRow).transform((rows) => {
              const out = new Map<string, LocalHeads>();

              for (const r of rows) {
                const at = out.get(r.name) ?? { pkg: { name: r.name, distTags: r.dist_tags }, heads: [] };

                if (r.version !== null && r.published_at !== null && r.seq !== null && r.status !== null) at.heads.push({ version: r.version, published_at: r.published_at, seq: r.seq, status: r.status, status_reason: r.status_reason, status_at: r.status_at });
                out.set(r.name, at);
              }

              return out;
            }),
          ),
    versionSizes: (versions) =>
      versions.length === 0
        ? Effect.succeed([])
        : run(
            "versionSizes",
            sql`SELECT package, version,
                       octet_length(m)::int AS manifest_octets,
                       (octet_length(m) - octet_length(translate(m, ':,[', '')))::int AS manifest_separators,
                       (octet_length(m) - octet_length(replace(m, '{', '')))::int AS manifest_objects,
                       octet_length(s)::int AS score_octets,
                       (octet_length(s) - octet_length(translate(s, ':,[', '')))::int AS score_separators,
                       (octet_length(s) - octet_length(replace(s, '{', '')))::int AS score_objects
                FROM (SELECT v.package, v.version, v.manifest::text AS m, coalesce(v.score::text, '') AS s
                      FROM versions v JOIN unnest(${versions.map((x) => x.package)}::text[], ${versions.map((x) => x.version)}::text[]) AS w(package, version)
                        ON w.package = v.package AND w.version = v.version) AS t`,
            all(VersionSizeRow),
          ),
    versionsWithin: (sizes) =>
      sizes.length === 0
        ? Effect.succeed([])
        : Effect.flatMap(
            run(
              "versionsWithin",
              sql`SELECT v.* FROM versions v
                  JOIN unnest(${sizes.map((x) => x.package)}::text[], ${sizes.map((x) => x.version)}::text[],
                              ${sizes.map((x) => x.manifest.octets)}::int[], ${sizes.map((x) => x.manifest.separators)}::int[], ${sizes.map((x) => x.manifest.objects)}::int[],
                              ${sizes.map((x) => x.score.octets)}::int[], ${sizes.map((x) => x.score.separators)}::int[], ${sizes.map((x) => x.score.objects)}::int[])
                       AS s(package, version, mo, ms, mb, so, ss, sb) ON s.package = v.package AND s.version = v.version
                  CROSS JOIN LATERAL (SELECT v.manifest::text AS m, coalesce(v.score::text, '') AS t) AS c
                  WHERE octet_length(c.m) <= s.mo AND octet_length(c.m) - octet_length(translate(c.m, ':,[', '')) <= s.ms AND octet_length(c.m) - octet_length(replace(c.m, '{', '')) <= s.mb
                    AND octet_length(c.t) <= s.so AND octet_length(c.t) - octet_length(translate(c.t, ':,[', '')) <= s.ss AND octet_length(c.t) - octet_length(replace(c.t, '{', '')) <= s.sb
                  ORDER BY v.package, v.published_at, v.seq`,
              all(VersionRow),
            ),
            withDismissals,
          ),
    activeVersionsOf: (names) =>
      names.length === 0
        ? Effect.succeed([])
        : run(
            "activeVersionsOf",
            sql`SELECT * FROM versions WHERE package = ANY(${names}) AND status = 'active' ORDER BY package, published_at, seq`,
            all(VersionRow),
          ).pipe(Effect.flatMap(withDismissals)),
    withheldPackageText: () =>
      run(
        "withheldPackageText",
        sql`SELECT package, status, status_at, published_at, seq, manifest->'description' AS description, manifest->'keywords' AS keywords
            FROM versions
            WHERE package IN (SELECT package FROM versions WHERE status IN ('revoke-pending', 'revoked'))
            ORDER BY package, published_at, seq`,
        all(TextSourceRow),
      ).pipe(
        Effect.map((rows) => {
          const out = new Map<string, VersionText[]>();

          for (const { package: name, ...v } of rows) out.set(name, [...(out.get(name) ?? []), v]);

          return out;
        }),
      ),
    getVersion: (name, version) =>
      run("getVersion", sql`SELECT * FROM versions WHERE package = ${name} AND version = ${version}`, one(VersionRow)).pipe(
        Effect.flatMap((v) => (v === null ? Effect.succeed(null) : Effect.map(withDismissals([v]), (got) => got[0] ?? null))),
      ),
    insertVersion: (v) =>
      run(
        "insertVersion",
        sql`INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, score)
            VALUES (${v.package}, ${v.version}, ${JSON.stringify(v.manifest)}::jsonb, ${v.shasum}, ${v.integrity}, ${v.size}, ${v.tarball_key},
                    ${v.published_at}, ${v.published_by}, ${v.score === null || v.score === undefined ? null : storableJson(JSON.stringify(v.score))}::jsonb)
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

    // upstreamAnalysesOf for one package: each analysis a row of its own. One row holding every analysis as a jsonb_agg
    // value was next's whole history (61 analyses, about 16 MB), which production's connection dropped, so the ~safe
    // and full packuments of next answered 503 (2026-11-26)
    upstreamAnalyses: (name) => Effect.map(api.upstreamAnalysesOf([name]), (got) => got.get(name) ?? { scores: new Map(), unscorable: new Map() }),
    // getPackage, listVersions and owners, or keptPackage and upstreamAnalyses, as one statement: a package page's
    // answer waited on four round trips in a row before (each about 75 ms from production's Workers to Neon). The
    // local columns are read only when the package row is there, the upstream ones only when it is not, and the kept
    // row's asked-about mark is written as keptPackage writes it. Rows travel as jsonb (to_jsonb keeps every column;
    // an int8 arrives as a JSON number, which Int reads as the driver's bigint).
    pageRead: ({ name, at, scores }) =>
      Effect.gen(function* () {
        const row = yield* pageRow({ name, at, scores, local: "versions" });

        if (row.pkg !== null) return { kind: "local", pkg: row.pkg, versions: dismissedFrom(row.versions, row.dismissals), owners: row.owners } satisfies PageRow;

        return { kind: "upstream", kept: row.kept, analyses: analysesOf(row.analyses, row.dismissals, row.unscorable), whole: new Set(row.shown) } satisfies PageRow;
      }),
    // pageRead's statement without a local package's versions and owners: a file view reads its one version on its own
    fileRead: ({ name, at, scores }) =>
      Effect.gen(function* () {
        const row = yield* pageRow({ name, at, scores, local: "none" });

        if (row.pkg !== null) return { kind: "local" } satisfies FileRow;

        return { kind: "upstream", kept: row.kept, analyses: analysesOf(row.analyses, row.dismissals, row.unscorable), whole: new Set(row.shown) } satisfies FileRow;
      }),
    latestScores: ({ names, at }) =>
      run(
        "latestScores",
        // the CTE's update runs whether or not the select reads it; the select sees the rows as they were
        sql`WITH asked AS (
              UPDATE latest_scores SET asked_at = ${at} WHERE package = ANY(${[...names]}) AND asked_at < ${at - LATEST_SCORE_ASKED_MARK_MS}
            )
            SELECT l.package, l.version, l.score, l.grade, l.computed_at FROM latest_scores l
             WHERE l.package = ANY(${[...names]}) AND NOT EXISTS (SELECT 1 FROM packages p WHERE p.name = l.package)`,
        all(KeptLatestScoreRow),
      ),
    keepLatestScore: ({ score, at, capacity }) =>
      Effect.gen(function* () {
        const replaced = yield* run(
          "keepLatestScore: replace",
          sql`UPDATE latest_scores SET version = ${score.version}, score = ${score.score}, grade = ${score.grade}, computed_at = ${at}, asked_at = ${at}
               WHERE package = ${score.name} RETURNING 1`,
          changed,
        );

        // anyone can name any package: a new row only while there is room. New rows queue behind each other, so two
        // at once cannot both count the last free place (review of d7ac98c).
        if (replaced) return;

        yield* api.tx(
          Effect.gen(function* () {
            yield* run("keepLatestScore: lock", sql`SELECT pg_advisory_xact_lock(${LATEST_SCORE_INSERT_LOCK})`, none);
            yield* run(
              "keepLatestScore: add",
              sql`INSERT INTO latest_scores (package, version, score, grade, computed_at, asked_at)
                  SELECT ${score.name}, ${score.version}, ${score.score}, ${score.grade}, ${at}, ${at}
                   WHERE (SELECT count(*) FROM latest_scores) < ${capacity}
                  ON CONFLICT (package) DO NOTHING`,
              none,
            );
          }),
        );
      }),
    refreshLatestScore: ({ score, at }) =>
      run(
        "refreshLatestScore",
        sql`UPDATE latest_scores SET version = ${score.version}, score = ${score.score}, grade = ${score.grade}, computed_at = ${at} WHERE package = ${score.name}`,
        none,
      ),
    latestScoresToRefresh: ({ askedSince, computedBefore, limit }) =>
      run(
        "latestScoresToRefresh",
        sql`SELECT package, version, score, grade, computed_at FROM latest_scores WHERE asked_at >= ${askedSince} AND computed_at < ${computedBefore} ORDER BY computed_at, package LIMIT ${limit}`,
        all(KeptLatestScoreRow),
      ),
    dropLatestScores: (which) =>
      which.kind === "name"
        ? run("dropLatestScores", sql`DELETE FROM latest_scores WHERE package = ${which.name}`, none)
        : run("dropLatestScores", sql`DELETE FROM latest_scores WHERE asked_at < ${which.askedBefore}`, none),
    keptPackage: ({ name, at }) =>
      run(
        "keptPackage",
        // the CTE's update runs whether or not the select reads it; the select sees the row as it was
        sql`WITH asked AS (
              UPDATE kept_packages SET asked_at = ${at} WHERE package = ${name} AND asked_at < ${at - LATEST_SCORE_ASKED_MARK_MS}
            )
            SELECT k.summary, k.computed_at FROM kept_packages k
             WHERE k.package = ${name} AND NOT EXISTS (SELECT 1 FROM packages p WHERE p.name = k.package)`,
        one(KeptPackageRow),
      ),
    keepPackage: ({ name, summary, at, capacity }) =>
      Effect.gen(function* () {
        const json = storableJson(JSON.stringify(summary));

        const replaced = yield* run(
          "keepPackage: replace",
          sql`UPDATE kept_packages SET summary = ${json}::jsonb, computed_at = ${at}, asked_at = ${at}, failures = 0, next_attempt_at = NULL WHERE package = ${name} RETURNING 1`,
          changed,
        );

        // anyone can name any package: a new row only while there is room, one new row at a time (as keepLatestScore)
        if (replaced) return;

        yield* api.tx(
          Effect.gen(function* () {
            yield* run("keepPackage: lock", sql`SELECT pg_advisory_xact_lock(${KEPT_PACKAGE_INSERT_LOCK})`, none);
            yield* run(
              "keepPackage: add",
              sql`INSERT INTO kept_packages (package, summary, computed_at, asked_at)
                  SELECT ${name}, ${json}::jsonb, ${at}, ${at}
                   WHERE (SELECT count(*) FROM kept_packages) < ${capacity}
                  ON CONFLICT (package) DO NOTHING`,
              none,
            );
          }),
        );
      }),
    refreshKeptPackage: ({ name, summary, at }) =>
      run(
        "refreshKeptPackage",
        sql`UPDATE kept_packages SET summary = ${storableJson(JSON.stringify(summary))}::jsonb, computed_at = ${at}, failures = 0, next_attempt_at = NULL WHERE package = ${name}`,
        none,
      ),
    claimKeptRefresh: ({ name, at, computedBefore, claimedBefore }) =>
      run(
        "claimKeptRefresh",
        sql`UPDATE kept_packages SET claimed_at = ${at}
             WHERE package = ${name} AND computed_at < ${computedBefore} AND (claimed_at IS NULL OR claimed_at < ${claimedBefore})
            RETURNING summary->>'etag' AS etag`,
        one(z.object({ etag: z.string().nullable() })),
      ),
    touchKeptPackage: ({ name, at, etag }) =>
      run(
        "touchKeptPackage",
        sql`UPDATE kept_packages SET computed_at = ${at}, failures = 0, next_attempt_at = NULL
             WHERE package = ${name} AND summary->>'etag' = ${etag} AND computed_at < ${at}`,
        none,
      ),
    failKeptRefresh: ({ name, at, retryMs, maxRetryMs }) =>
      run(
        "failKeptRefresh",
        sql`UPDATE kept_packages
               SET next_attempt_at = ${at} + LEAST(${retryMs}::bigint * (1::bigint << LEAST(failures, 20)), ${maxRetryMs}::bigint), failures = failures + 1
             WHERE package = ${name}`,
        none,
      ),
    keptPackagesToSeed: ({ askedSince, seededBefore, at, limit }) =>
      run(
        "keptPackagesToSeed",
        sql`WITH picked AS (
              SELECT package FROM kept_packages
              WHERE asked_at >= ${askedSince} AND (seeded_at IS NULL OR seeded_at < ${seededBefore})
              ORDER BY seeded_at NULLS FIRST, asked_at DESC LIMIT ${limit}
              FOR UPDATE SKIP LOCKED
            )
            UPDATE kept_packages k SET seeded_at = ${at} FROM picked WHERE k.package = picked.package
            RETURNING k.package AS name, k.summary`,
        all(z.object({ name: z.string(), summary: z.unknown() })),
      ),
    keptPackagesToRefresh: ({ askedSince, computedBefore, at, limit }) =>
      run(
        "keptPackagesToRefresh",
        sql`SELECT package FROM kept_packages
             WHERE asked_at >= ${askedSince} AND computed_at < ${computedBefore} AND (next_attempt_at IS NULL OR next_attempt_at <= ${at})
             ORDER BY computed_at, package LIMIT ${limit}`,
        all(z.object({ package: z.string() }).transform((r) => r.package)),
      ),
    dropKeptPackages: (which) =>
      which.kind === "name"
        ? run("dropKeptPackages", sql`DELETE FROM kept_packages WHERE package = ${which.name}`, none)
        : run("dropKeptPackages", sql`DELETE FROM kept_packages WHERE asked_at < ${which.askedBefore}`, none),

    keptChoicesOf: ({ documents, allowance, weights, at }) =>
      documents.length === 0
        ? Effect.succeed([])
        : run(
            "keptChoicesOf",
            // the CTE's update runs whether or not the select reads it; the select sees the rows as they were
            sql`WITH asked AS (
                  UPDATE upstream_choices SET asked_at = ${at} WHERE document = ANY(${[...documents]}) AND asked_at < ${at - KEPT_CHOICES_ASKED_MARK_MS}
                ),
                sized AS (
                  SELECT document, etag, fetched_at, kept,
                         octet_length(t)::int AS octets,
                         (octet_length(t) - octet_length(translate(t, ':,[', '')))::int AS separators,
                         (octet_length(t) - octet_length(replace(t, '{', '')))::int AS objects
                  FROM (SELECT document, etag, fetched_at, kept, kept::text AS t FROM upstream_choices WHERE document = ANY(${[...documents]})) AS c
                ),
                weighed AS (
                  SELECT *, sum(${weights.octet}::bigint * octets + ${weights.node}::bigint * (1 + separators) + ${weights.object}::bigint * objects) OVER (ORDER BY document) AS running FROM sized
                )
                SELECT document, etag, fetched_at, kept, octets, separators, objects FROM weighed WHERE running <= ${allowance}`,
            all(KeptChoicesOut),
          ),
    writeChoices: ({ at, capacity, maxBytes, maxChoices, maxAgeMs }, write) =>
      // anyone can name any package: a new row only while there is room, one writer at a time (a busy lock skips
      // the write, never waits); a row past maxBytes as stored is never kept (review of 3aacc2a, finding 6)
      api.tx(
        Effect.gen(function* () {
          const got = yield* run("keepChoices: lock", sql`SELECT pg_try_advisory_xact_lock(${KEPT_CHOICES_INSERT_LOCK}) AS got`, one(z.object({ got: z.boolean() })));

          if (got?.got !== true) return;

          // the merge (re-check of 51fc813): a row kept for the same document and the same strong ETag (non-empty, not
          // W/) keeps its choices this write does not make while each holds (younger than maxAgeMs, every version's
          // record there), newest first, up to maxChoices in all with this write's, with their records; this write's
          // choices and records win. Merged past maxBytes, only this write's choices are kept. Another ETag, or a weak
          // or empty one: the row is replaced.
          yield* write((r) =>
            run(
              "keepChoices: upsert",
              sql`WITH incoming AS (SELECT ${r.text}::jsonb AS kept),
                  -- merged only under a strong, non-empty ETag (RFC 9110, 8.8.1): a weak or empty one replaces the row, whatever
                  -- the Worker checked (review of acdb8eb, finding 3)
                  old AS (SELECT u.kept FROM upstream_choices u WHERE u.document = ${r.document} AND u.etag = ${r.etag} AND ${r.etag} <> '' AND left(${r.etag}, 2) <> 'W/'),
                  older AS (
                    SELECT l.key, l.value
                      FROM old, jsonb_each(old.kept->'lists') AS l, incoming
                     WHERE NOT (incoming.kept->'lists' ? l.key)
                       AND (l.value->>'at')::bigint > ${at - maxAgeMs}
                       AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(l.value->'versions') AS v(version) WHERE NOT (old.kept->'records' ? v.version))
                     ORDER BY (l.value->>'at')::bigint DESC, l.key
                     LIMIT greatest(0, ${maxChoices} - (SELECT count(*) FROM incoming, jsonb_object_keys(incoming.kept->'lists')))
                  ),
                  older_records AS (
                    SELECT DISTINCT v.version, old.kept->'records'->v.version AS record
                      FROM older, old, jsonb_array_elements_text(older.value->'versions') AS v(version)
                  ),
                  merged AS (
                    SELECT jsonb_build_object(
                             'distTags', incoming.kept->'distTags',
                             'lists', coalesce((SELECT jsonb_object_agg(key, value) FROM older), '{}'::jsonb) || (incoming.kept->'lists'),
                             'records', coalesce((SELECT jsonb_object_agg(version, record) FROM older_records), '{}'::jsonb) || (incoming.kept->'records')
                           ) AS kept
                      FROM incoming
                  ),
                  kept AS (
                    SELECT CASE WHEN octet_length(merged.kept::text) <= ${maxBytes} THEN merged.kept ELSE incoming.kept END AS kept FROM merged, incoming
                  )
                  INSERT INTO upstream_choices (document, etag, kept, fetched_at, asked_at)
                  SELECT ${r.document}, ${r.etag}, kept.kept, ${at}, ${at}
                    FROM kept
                   WHERE octet_length(kept.kept::text) <= ${maxBytes}
                     AND (EXISTS (SELECT 1 FROM upstream_choices WHERE document = ${r.document}) OR (SELECT count(*) FROM upstream_choices) < ${capacity})
                  ON CONFLICT (document) DO UPDATE SET etag = EXCLUDED.etag, kept = EXCLUDED.kept, fetched_at = EXCLUDED.fetched_at, asked_at = EXCLUDED.asked_at`,
              none,
            ),
          );
        }),
      ),
    keepChoices: ({ rows, at, capacity, maxBytes, maxChoices, maxAgeMs }) => api.writeChoices({ at, capacity, maxBytes, maxChoices, maxAgeMs }, (put) => Effect.forEach(rows, put, { discard: true })),
    dropKeptChoices: ({ askedBefore }) => run("dropKeptChoices", sql`DELETE FROM upstream_choices WHERE asked_at < ${askedBefore}`, none),

    upstreamAnalysesOf: (names) =>
      Effect.gen(function* () {
        if (names.length === 0) return new Map<string, UpstreamAnalyses>();
        const wanted = [...new Set(names)];

        // the analyses, the decided outcomes and the live dismissals in one statement, so from one snapshot: the walk
        // reads them once a level, upstreamAnalyses for one package. Each is a row of its own, so a
        // row holds one analysis at most: every stored analysis of next as one jsonb_agg value was tens of MB, which the
        // connection dropped (production, 2026-11-25)
        const items = yield* run(
          "upstreamAnalysesOf",
          sql`SELECT 'analysis' AS kind, u.package, u.version, u.digest, row_number() OVER (ORDER BY u.scorer) AS seq, u.analysis AS payload
                FROM upstream_analysis u WHERE u.package = ANY(${wanted}) AND (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis)))
              UNION ALL
              SELECT 'decided', o.package, o.version, o.digest, row_number() OVER (ORDER BY o.scorer), jsonb_build_object('outcome', o.outcome, 'detail', o.detail)
                FROM analysis_outcomes o WHERE o.package = ANY(${wanted}) AND (o.scorer = ${SCORER} OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))) AND o.outcome IS NOT NULL
              UNION ALL
              SELECT 'dismissal', e.package, e.version, e.digest, row_number() OVER (ORDER BY e.dismissed_at, e.id), to_jsonb(e)
                FROM evidence_dismissals e WHERE e.package = ANY(${wanted}) AND e.restored_at IS NULL
              ORDER BY seq`,
          all(AnalysisItem),
        );

        return analysesByPackage(items);
      }),
    upstreamAnalysesFor: (keys) =>
      Effect.gen(function* () {
        if (keys.length === 0) return new Map<string, UpstreamAnalyses>();
        const byKey = new Map<string, AnalysisKey>();

        // each key once, whole when any reader of it asked for it whole
        for (const k of keys) {
          const id = JSON.stringify([k.package, k.version, k.digest]);

          byKey.set(id, { ...k, trimmed: (k.trimmed ?? false) && (byKey.get(id)?.trimmed ?? true) });
        }

        // as JSON: a column of digests can be all nulls, which the driver cannot type as text[]
        const asked = [...byKey.values()];

        // upstreamAnalysesOf's statement for only these versions: their analyses (whole, or trimmed as pageRead trims
        // the versions a page does not show) and the dismissals for their bytes, and the outcomes decided for them by
        // version, whatever their digest, as upstreamAnalysesOf reads them (scoredPackage reads one only for a version
        // with no score; one with no checksum has only its outcome)
        const items = yield* run(
          "upstreamAnalysesFor",
          sql`WITH k AS (SELECT * FROM jsonb_to_recordset(${JSON.stringify(asked.map((k) => ({ package: k.package, version: k.version, digest: k.digest, trimmed: k.trimmed ?? false })))}::jsonb) AS k(package text, version text, digest text, trimmed boolean))
              SELECT 'analysis' AS kind, u.package, u.version, u.digest, row_number() OVER (ORDER BY u.scorer) AS seq, CASE WHEN k.trimmed THEN u.analysis - ${[...PAGE_TRIMMED]}::text[] ELSE u.analysis END AS payload
                FROM upstream_analysis u JOIN k ON u.package = k.package AND u.version = k.version AND u.digest = k.digest WHERE (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis)))
              UNION ALL
              SELECT 'decided', o.package, o.version, o.digest, row_number() OVER (ORDER BY o.scorer), jsonb_build_object('outcome', o.outcome, 'detail', o.detail)
                FROM analysis_outcomes o WHERE (o.package, o.version) IN (SELECT package, version FROM k) AND (o.scorer = ${SCORER} OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))) AND o.outcome IS NOT NULL
              UNION ALL
              SELECT 'dismissal', e.package, e.version, e.digest, row_number() OVER (ORDER BY e.dismissed_at, e.id), to_jsonb(e)
                FROM evidence_dismissals e WHERE (e.package, e.version, e.digest) IN (SELECT package, version, digest FROM k) AND e.restored_at IS NULL
              ORDER BY seq`,
          all(AnalysisItem),
        );

        return analysesByPackage(items);
      }),
    upstreamScored: (name) =>
      run(
        "upstreamScored",
        sql`SELECT EXISTS (SELECT 1 FROM upstream_analysis u WHERE u.package = ${name} AND (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis)))) AS scored`,
        z.tuple([z.object({ scored: z.boolean() })]).transform(([r]) => r.scored),
      ),
    upstreamAdmitted: ({ keys, outcomes }) =>
      keys.length === 0
        ? Effect.succeed(false)
        : run(
            "upstreamAdmitted",
            sql`WITH k AS (SELECT * FROM jsonb_to_recordset(${JSON.stringify(keys.map((k) => ({ package: k.package, version: k.version, digest: k.digest })))}::jsonb) AS k(package text, version text, digest text))
                SELECT EXISTS (SELECT 1 FROM upstream_analysis u JOIN k ON u.package = k.package AND u.version = k.version AND u.digest = k.digest WHERE u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis)))
                  OR (${outcomes} AND EXISTS (SELECT 1 FROM analysis_outcomes o WHERE (o.package, o.version) IN (SELECT package, version FROM k) AND (o.scorer = ${SCORER} OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))) AND o.outcome IS NOT NULL)) AS admitted`,
            z.tuple([z.object({ admitted: z.boolean() })]).transform(([r]) => r.admitted),
          ),
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
              WHERE (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis)))
              ORDER BY u.package, u.version, u.scorer = ${SCORER} DESC, u.analyzed_at DESC`,
          all(z.object({ package: z.string(), version: z.string(), digest: z.string(), analysis: z.unknown() })),
        );

        const dismissals = yield* dismissalsOf([...new Set(rows.map((r) => r.package))]);

        return new Map(rows.flatMap((r) => currentScore(r.analysis, dismissalsFor(dismissals.filter((d) => d.package === r.package), r.version, r.digest)).map((score) => [`${r.package} ${r.version}`, score] as const)));
      }),
    setUpstreamAnalysis: (input) =>
      run(
        "setUpstreamAnalysis",
        sql`INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at)
            VALUES (${input.name}, ${input.version}, ${input.digest}, ${SCORER}, ${storableJson(JSON.stringify(input.analysis))}::jsonb, ${input.at})
            ON CONFLICT (package, version, digest, scorer) DO UPDATE SET analysis = EXCLUDED.analysis, analyzed_at = EXCLUDED.analyzed_at`,
        none,
      ),
    claimAnalysisJob: (name, version, now, staleMs) =>
      run(
        "claimAnalysisJob",
        sql`INSERT INTO analysis_jobs (package, version, queued_at, scorer) VALUES (${name}, ${version}, ${now}, ${SCORER})
            ON CONFLICT (package, version) DO UPDATE SET queued_at = EXCLUDED.queued_at, scorer = EXCLUDED.scorer
            WHERE analysis_jobs.queued_at <= ${now - staleMs}
            RETURNING package`,
        changed,
      ),

    claimAnalysisJobs: ({ name, versions, now, staleMs }) =>
      versions.length === 0
        ? Effect.succeed([])
        : run(
            "claimAnalysisJobs",
            sql`INSERT INTO analysis_jobs (package, version, queued_at, scorer)
                SELECT ${name}, w.version, ${now}, ${SCORER} FROM unnest(${[...new Set(versions)]}::text[]) AS w(version)
                ON CONFLICT (package, version) DO UPDATE SET queued_at = EXCLUDED.queued_at, scorer = EXCLUDED.scorer
                WHERE analysis_jobs.queued_at <= ${now - staleMs}
                RETURNING version`,
            all(z.object({ version: z.string() })),
          ).pipe(Effect.map((rows) => rows.map((r) => r.version))),

    admitSeedJobs: ({ name, versions, now, staleMs, since, max }) =>
      versions.length === 0
        ? Effect.succeed([])
        : api.tx(
            Effect.gen(function* () {
              // one admission at a time: the lock is held to the end of the transaction, past the insert's commit
              yield* run("admitSeedJobs: lock", sql`SELECT pg_advisory_xact_lock(${SEED_ADMISSION_LOCK})`, none);
              // a statement of its own after the lock, so its snapshot sees every admission that held it before
              const counted = yield* run("admitSeedJobs: count", sql`SELECT count(*) AS n FROM analysis_jobs WHERE queued_at > ${since}`, one(z.object({ n: Int })));
              const room = Math.max(0, max - (counted?.n ?? max));

              if (room === 0) return [];

              const rows = yield* run(
                "admitSeedJobs: claim",
                // the intake count reads analysis_jobs_queued (migration 0014)
                sql`INSERT INTO analysis_jobs (package, version, queued_at, scorer)
                    SELECT ${name}, w.version, ${now}, ${SCORER} FROM unnest(${[...new Set(versions)].slice(0, room)}::text[]) AS w(version)
                    ON CONFLICT (package, version) DO UPDATE SET queued_at = EXCLUDED.queued_at, scorer = EXCLUDED.scorer
                    WHERE analysis_jobs.queued_at <= ${now - staleMs}
                    RETURNING version`,
                all(z.object({ version: z.string() })),
              );

              return rows.map((r) => r.version);
            }),
          ),

    releaseAnalysisJob: (name, version, claimedAt) =>
      run("releaseAnalysisJob", sql`DELETE FROM analysis_jobs WHERE package = ${name} AND version = ${version} AND queued_at = ${claimedAt}`, none),

    setUnscorable: ({ name, version, unscorable, digest, at }) =>
      run(
        "setUnscorable",
        sql`INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES (${name}, ${version}, ${SCORER}, ${unscorable.reason}, ${unscorable.detail}, ${digest}, ${at})
            ON CONFLICT (package, version, scorer) DO UPDATE SET outcome = EXCLUDED.outcome, detail = EXCLUDED.detail, digest = EXCLUDED.digest, decided_at = EXCLUDED.decided_at`,
        none,
      ),
    startAnalysis: ({ name, version, now, runMs }) =>
      Effect.gen(function* () {
        const started = yield* run(
          "startAnalysis",
          // nothing is started for a version whose apm-score-v10 result the current scorer takes as its own
          sql`INSERT INTO analysis_outcomes (package, version, scorer, starts, started_at)
              SELECT ${name}, ${version}, ${SCORER}, 1, ${now}
              WHERE NOT EXISTS (SELECT 1 FROM upstream_analysis u WHERE u.package = ${name} AND u.version = ${version} AND u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis))
                AND NOT EXISTS (SELECT 1 FROM analysis_outcomes o WHERE o.package = ${name} AND o.version = ${version} AND o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))
              ON CONFLICT (package, version, scorer) DO UPDATE SET starts = analysis_outcomes.starts + 1, started_at = EXCLUDED.started_at
              WHERE analysis_outcomes.outcome IS NULL AND (analysis_outcomes.started_at IS NULL OR analysis_outcomes.started_at <= ${now - runMs})
              RETURNING starts, fetch_failures, fetch_failed_since, failures, reported_start`,
          one(z.object({ starts: Int, fetch_failures: Int, fetch_failed_since: z.coerce.number().nullable(), failures: Int, reported_start: Int.nullable() })),
        );

        if (started) {
          return {
            kind: "started",
            starts: started.starts,
            fetchFailures: started.fetch_failures,
            fetchFailedSince: started.fetch_failed_since,
            failures: started.failures,
            reportedStart: started.reported_start,
          } satisfies AnalysisStart;
        }

        // not started: an outcome decided it (the current scorer's, or a v10 one it keeps), the current scorer reads
        // a v10 analysis as its own, or a run began inside the window
        const decided = yield* run(
          "startAnalysisOutcome",
          sql`SELECT 1 AS decided
              WHERE EXISTS (SELECT 1 FROM analysis_outcomes o WHERE o.package = ${name} AND o.version = ${version} AND (o.scorer = ${SCORER} OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))) AND o.outcome IS NOT NULL)
                 OR EXISTS (SELECT 1 FROM upstream_analysis u WHERE u.package = ${name} AND u.version = ${version} AND u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis))`,
          one(z.object({ decided: Int })),
        );

        return decided ? ({ kind: "decided" } satisfies AnalysisStart) : ({ kind: "running" } satisfies AnalysisStart);
      }),
    failFetch: ({ name, version, errorClass, now, runMs }) =>
      run(
        "failFetch",
        sql`UPDATE analysis_outcomes SET fetch_failures = fetch_failures + 1, last_error = ${errorClass.slice(0, 200)}, started_at = ${now - runMs},
              fetch_failed_since = COALESCE(fetch_failed_since, ${now}), reported_start = starts
            WHERE package = ${name} AND version = ${version} AND scorer = ${SCORER} AND outcome IS NULL
            RETURNING fetch_failures`,
        one(z.object({ fetch_failures: Int })).transform((row) => row?.fetch_failures ?? null),
      ),
    failAnalysis: ({ name, version, errorClass, now, runMs }) =>
      run(
        "failAnalysis",
        sql`UPDATE analysis_outcomes SET failures = failures + 1, last_error = ${errorClass.slice(0, 200)}, started_at = ${now - runMs}, reported_start = starts
            WHERE package = ${name} AND version = ${version} AND scorer = ${SCORER} AND outcome IS NULL
            RETURNING failures`,
        one(z.object({ failures: Int })).transform((row) => row?.failures ?? null),
      ),
    confirmedReviews: (name) =>
      run("confirmedReviews", sql`SELECT version, digest FROM reviews WHERE package = ${name} AND human_state = 'confirmed'`, all(z.object({ version: z.string(), digest: z.string() }))),
    installRead: (name) =>
      run(
        "installRead",
        sql`SELECT EXISTS (SELECT 1 FROM packages WHERE name = ${name}) AS local,
                   coalesce((SELECT jsonb_agg(jsonb_build_object('version', version, 'digest', digest) ORDER BY version, digest)
                             FROM reviews WHERE package = ${name} AND human_state = 'confirmed'), '[]'::jsonb) AS confirmed`,
        one(z.object({ local: z.boolean(), confirmed: z.array(z.object({ version: z.string(), digest: z.string() })) })),
      ).pipe(Effect.map((row) => row ?? { local: false, confirmed: [] })),
    tarballRead: ({ name, version, queuedSince }) =>
      run(
        "tarballRead",
        sql`SELECT EXISTS (SELECT 1 FROM packages WHERE name = ${name}) AS local,
                   coalesce((SELECT jsonb_agg(digest ORDER BY digest) FROM reviews
                             WHERE package = ${name} AND version = ${version} AND human_state = 'confirmed'), '[]'::jsonb) AS confirmed,
                   (EXISTS (SELECT 1 FROM upstream_analysis u WHERE u.package = ${name} AND u.version = ${version}
                              AND (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis))))
                    OR EXISTS (SELECT 1 FROM analysis_outcomes o WHERE o.package = ${name} AND o.version = ${version}
                              AND (o.scorer = ${SCORER} OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))) AND o.outcome IS NOT NULL)) AS decided,
                   EXISTS (SELECT 1 FROM analysis_jobs WHERE package = ${name} AND version = ${version} AND queued_at > ${queuedSince}) AS queued`,
        one(TarballReadRow),
      ).pipe(Effect.map((row): TarballRead => row ?? { local: false, confirmed: [], decided: false, queued: false })),
    decidedAnalyses: (versions) =>
      versions.length === 0
        ? Effect.succeed(new Set<string>())
        : run(
            "decidedAnalyses",
            sql`WITH wanted AS (SELECT * FROM unnest(${versions.map((v) => v.name)}::text[], ${versions.map((v) => v.version)}::text[]) AS w(package, version))
                SELECT w.package, w.version FROM wanted w
                WHERE EXISTS (SELECT 1 FROM upstream_analysis u WHERE u.package = w.package AND u.version = w.version AND (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis))))
                   OR EXISTS (SELECT 1 FROM analysis_outcomes o WHERE o.package = w.package AND o.version = w.version AND (o.scorer = ${SCORER} OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))) AND o.outcome IS NOT NULL)`,
            all(z.object({ package: z.string(), version: z.string() })),
          ).pipe(Effect.map((rows) => new Set(rows.map((r) => `${r.package} ${r.version}`)))),
    unfinishedAnalyses: ({ before, limit, now }) =>
      run(
        "unfinishedAnalyses",
        sql`WITH picked AS (
              SELECT o.package, o.version FROM analysis_outcomes o
              WHERE o.scorer = ${SCORER} AND o.outcome IS NULL AND o.started_at IS NOT NULL AND o.started_at <= ${before}
                AND NOT EXISTS (SELECT 1 FROM upstream_analysis u WHERE u.package = o.package AND u.version = o.version AND (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis))))
              ORDER BY o.swept_at NULLS FIRST, o.started_at LIMIT ${limit}
              FOR UPDATE SKIP LOCKED
            )
            UPDATE analysis_outcomes o SET swept_at = ${now} FROM picked
            WHERE o.package = picked.package AND o.version = picked.version AND o.scorer = ${SCORER}
            RETURNING o.package AS name, o.version`,
        all(z.object({ name: z.string(), version: z.string() })),
      ),

    acceptedAnalyses: ({ before, limit }) =>
      run(
        "acceptedAnalyses",
        // a reservation made for the current scorer, or one from before the scorer was recorded (an older Worker's) for
        // a version that never got a result or began a run under any scorer: genuinely pending, not one already analysed
        sql`SELECT j.package AS name, j.version FROM analysis_jobs j
            WHERE j.queued_at <= ${before}
              AND (j.scorer = ${SCORER}
                   OR (j.scorer IS NULL
                       AND NOT EXISTS (SELECT 1 FROM upstream_analysis a WHERE a.package = j.package AND a.version = j.version)
                       AND NOT EXISTS (SELECT 1 FROM analysis_outcomes p WHERE p.package = j.package AND p.version = j.version AND (p.outcome IS NOT NULL OR p.started_at IS NOT NULL))))
              AND NOT EXISTS (SELECT 1 FROM upstream_analysis u WHERE u.package = j.package AND u.version = j.version AND (u.scorer = ${SCORER} OR (u.scorer = ${PREVIOUS_SCORER} AND apm_v10_reusable(u.analysis))))
              AND NOT EXISTS (SELECT 1 FROM analysis_outcomes o WHERE o.package = j.package AND o.version = j.version
                                AND ((o.scorer = ${SCORER} AND (o.outcome IS NOT NULL OR o.started_at IS NOT NULL)) OR (o.scorer = ${PREVIOUS_SCORER} AND apm_v10_outcome_reusable(o.outcome))))
            ORDER BY j.queued_at LIMIT ${limit}`,
        all(z.object({ name: z.string(), version: z.string() })),
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
    existingPackages: (names) =>
      names.length === 0
        ? Effect.succeed(new Set<string>())
        : Effect.map(
            run("existingPackages", sql`SELECT name FROM packages WHERE name = ANY(${names})`, all(z.object({ name: z.string() }))),
            (rows) => new Set(rows.map((r) => r.name)),
          ),
    advisoriesForPackages: (names) =>
      names.length === 0
        ? Effect.succeed([])
        : run("advisoriesForPackages", sql`SELECT * FROM advisories WHERE package = ANY(${names}) ORDER BY package, id`, all(AdvisoryRow)),

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
    // the inner LIMIT walks the analyzed_at index (migration 0009); grouping only that window keeps it cheap
    recentlyScored: (limit) =>
      run(
        "recentlyScored",
        sql`SELECT package, max(analyzed_at) AS at FROM (SELECT package, analyzed_at FROM upstream_analysis ORDER BY analyzed_at DESC LIMIT ${limit * 10}) recent GROUP BY package ORDER BY at DESC LIMIT ${limit}`,
        all(z.object({ package: z.string(), at: Int })),
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
      guard.transaction(
        "enableTwoFactor",
        sql.withTransaction(
          Effect.all(
            [
              run("enableTwoFactor", sql`UPDATE "twoFactor" SET verified = true WHERE "userId" = ${authUserId}`, none),
              run("enableTwoFactor", sql`UPDATE "user" SET "twoFactorEnabled" = true WHERE id = ${authUserId}`, none),
            ],
            { discard: true },
          ),
        )),
    swapBackupCodes: (input) =>
      run(
        "swapBackupCodes",
        sql`UPDATE "twoFactor" SET "backupCodes" = ${input.next} WHERE "userId" = ${input.authUserId} AND "backupCodes" = ${input.expected} RETURNING id`,
        changed,
      ),
    takeSession: (token) => run("takeSession", sql`DELETE FROM session WHERE token = ${token} RETURNING "userId"`, one(z.object({ userId: z.string() }).transform((r) => r.userId))),

    reserveAttempt: (input) =>
      guard.transaction(
        "reserveAttempt",
        sql.withTransaction(
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
        )),
    settleAttempt: (input) =>
      guard.transaction(
        "settleAttempt",
        sql.withTransaction(
          Effect.gen(function* () {
            yield* run("settleAttempt", sql`UPDATE factor_attempts SET outcome = ${input.ok ? "ok" : "bad"} WHERE id = ${input.id}`, none);

            if (input.ok) yield* run("settleAttempt: clear", sql`DELETE FROM factor_attempts WHERE auth_user_id = ${input.authUserId} AND outcome = 'bad'`, none);
          }),
        )),
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
    passkeyList: (authUserId) =>
      run(
        "passkeyList",
        sql`SELECT p.id, p.name, p.aaguid, (extract(epoch FROM p."createdAt") * 1000)::bigint AS created_at, u.last_used_at
            FROM passkey p LEFT JOIN passkey_uses u ON u.passkey_id = p.id
            WHERE p."userId" = ${authUserId} ORDER BY p."createdAt", p.id`,
        all(PasskeyListRow.transform((row) => ({ id: row.id, name: row.name, aaguid: row.aaguid, createdAt: row.created_at, lastUsedAt: row.last_used_at }))),
      ),
    notePasskeyUse: (input) =>
      run(
        "notePasskeyUse",
        sql`INSERT INTO passkey_uses (passkey_id, last_used_at)
            SELECT id, ${input.at} FROM passkey WHERE "credentialID" = ${input.credentialID} AND "userId" = ${input.authUserId}
            ON CONFLICT (passkey_id) DO UPDATE SET last_used_at = GREATEST(passkey_uses.last_used_at, EXCLUDED.last_used_at)`,
        none,
      ).pipe(Effect.timeoutOption(Duration.millis(PASSKEY_USE_WAIT_MS)), Effect.asVoid),
    removePasskey: (input) =>
      guard.transaction(
        "removePasskey",
        sql.withTransaction(
          Effect.gen(function* () {
            // one account's removals queue behind each other, so two cannot each see the other's passkey and both go
            yield* run("removePasskey: lock", sql`SELECT pg_advisory_xact_lock(hashtextextended(${`passkey:${input.authUserId}`}, 0)) IS NULL AS locked`, none);

            const ways = yield* run(
              "removePasskey: ways in",
              sql`SELECT EXISTS (SELECT 1 FROM passkey WHERE id = ${input.id} AND "userId" = ${input.authUserId}) AS mine,
                         (SELECT count(*) FROM passkey WHERE "userId" = ${input.authUserId}) AS passkeys,
                         (SELECT count(*) FROM account WHERE "userId" = ${input.authUserId} AND "providerId" = ANY(${[...input.providers]})) AS linked`,
              z.tuple([z.object({ mine: z.boolean(), passkeys: Int, linked: Int })]).transform(([row]) => row),
            );

            if (!ways.mine) return "missing" satisfies PasskeyRemoval;

            if (ways.linked === 0 && ways.passkeys <= 1) return "last-way-in" satisfies PasskeyRemoval;
            yield* run("removePasskey", sql`DELETE FROM passkey WHERE id = ${input.id} AND "userId" = ${input.authUserId}`, none);

            return "removed" satisfies PasskeyRemoval;
          }),
        ),
      ),
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
