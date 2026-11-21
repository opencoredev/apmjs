// AI release review, registry side: the review-job queue, the reviewer's service-token routes, stored
// results, the public and maintainer views, "Request AI review", and the owner-only queue where a
// person confirms or dismisses a flag. The model never runs here: a separate reviewer process
// (apps/reviewer) leases jobs over HTTP and posts results back. See docs/AI-REVIEW.md.
import { pageListing } from "./kept-package.ts";
import { RequestMemory } from "./memory.ts";
import { createHash, timingSafeEqual } from "node:crypto";
import { Context, Effect, Option } from "effect";
import type { SqlError } from "effect/sql/SqlError";
import * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { ReleaseBody, ResultBody, ReviewResult, type EnqueueReason, type ReviewJob, type WireFinding } from "@apm/ai-review";
import { isValidPackageName, redactSecrets } from "@apm/core";
import { ReviewDecision, type SessionAction } from "./actions.ts";
import { Auth, type SignedIn } from "./auth.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig } from "./config.ts";
import { Store, storableJson, type User, type VersionRecord } from "./db.ts";
import { refuse, StoreError, type AuthError, type HttpFailure } from "./errors.ts";
import { randomId } from "./hash.ts";
import { fail, json, parseBody } from "./http.ts";
import { requireSiteOrigin } from "./origin.ts";
import { order } from "./semver.ts";
import { splitPath, tagTarget, tarballUrl, type Caller } from "./server.ts";
import { ProofFields, secondFactor, type ProofInput } from "./step-up.ts";
import { digestLabel, digestOf, Upstream, type UpstreamPackage } from "./upstream.ts";
import { timed, timingOrNull } from "./timing.ts";
import { Guard } from "./db-health.ts";
import { blockBeforeCommit } from "./blocklist.ts";
import { fileReferences, INVALID_DEPENDENCY, isWithheld, WITHHELD_ISSUE } from "./withheld.ts";
import { publicFindings } from "./public-finding.ts";

export type ReviewSettings = {
  /** sha256 (hex) of the reviewer's service token. The token itself stays with the reviewer. */
  readonly serviceTokenHash: string;
  /** GitHub logins that may confirm or dismiss flagged reviews. */
  readonly admins: readonly string[];
  /** Upstream versions are reviewed when their package has at least this many weekly downloads. */
  readonly popularWeekly: number;
  /** npm's download-count API, ending in "/". */
  readonly downloadsUrl: string;
  /** How long a leased job stays with one reviewer before it returns to the queue. */
  readonly leaseMs: number;
  /** "Request AI review" presses per user per hour. */
  readonly requestsPerHour: number;
  /** Leases a job may take before it is marked failed. */
  readonly maxAttempts: number;
  /**
   * Whether an AI flag a person has not decided holds installs when no reviewer has set the switch yet
   * (APM_AI_FLAGS_HOLD). The stored switch (review_switch) wins, read on every request.
   */
  readonly flagsHoldDefault: boolean;
};

export const REVIEW_DEFAULTS = {
  popularWeekly: 10_000,
  downloadsUrl: "https://api.npmjs.org/downloads/point/last-week/",
  leaseMs: 15 * 60_000,
  requestsPerHour: 5,
  maxAttempts: 5,
  flagsHoldDefault: true,
} as const;

/** The AI review is on when this service is provided (worker.ts does when the service token hash is set). */
export class ReviewConfig extends Context.Service<ReviewConfig, ReviewSettings>()("@apm/registry/ReviewConfig") {}

/** The sha256 hex of a service token, as APM_REVIEW_TOKEN_HASH takes it. */
export function serviceTokenHashOf(token: string): string {
  return createHash("sha256").update(token.trim()).digest("hex");
}

const HOUR = 3_600_000;
const DOWNLOADS_TTL_MS = 24 * HOUR;
const DOWNLOADS_FAILURE_TTL_MS = HOUR;
const MAX_LEASE_BATCH = 16;
const MAX_REVIEW_BODY_BYTES = 2 * 1024 * 1024;

type Source = "local" | "upstream";

type JobState = "queued" | "leased" | "done" | "failed";

/** none: nothing for a person to do (benign). pending: waits in the owner queue. */
type HumanState = "none" | "pending" | "confirmed" | "dismissed";

const Int = z.union([z.bigint(), z.number()]).transform((n) => Number(n));

const Reasons = z.array(z.enum(["publish", "first-publish", "install-script", "popular", "requested"]));

const JobRow = z.object({
  id: z.string(),
  package: z.string(),
  version: z.string(),
  digest: z.string(),
  source: z.enum(["local", "upstream"]),
  reasons: Reasons,
  priority: Int,
  state: z.enum(["queued", "leased", "done", "failed"]),
  lease_id: z.string().nullable(),
  lease_expires_at: Int.nullable(),
  attempts: Int,
  last_error: z.string().nullable(),
  enqueued_at: Int,
  updated_at: Int,
});

type JobRow = z.infer<typeof JobRow>;

// A model quotes what it read, and a package can ship a live key or a connection string with its password. Every review
// row is redacted as it is parsed (redactSecrets, @apm/core: the secret scan's rules and a few more shapes), so no view
// built in this module, public, maintainer's or reviewer's, can hand one out: only the first and last few characters
// and the length stay. The stored result keeps the text as the reviewer sent it.

const redactFinding = (f: WireFinding): WireFinding => ({ ...f, file: redactSecrets(f.file), quote: redactSecrets(f.quote), excerpt: redactSecrets(f.excerpt), issue: redactSecrets(f.issue) });

/**
 * A review result with every string that came from the publisher or the model redacted: the summaries, every finding's
 * file, quote, excerpt and sentence (the second opinion's too), the paths it read, the paths and dependency names it did
 * not, and the previous version it diffed against (independent review of 17be3f6, finding 3: a key in a file name was
 * handed out through `read`). Left as they are: the model and reviewer ids and every enum, number and time, which are
 * apm's own.
 */
export function redactedResult(res: ReviewResult): ReviewResult {
  const so = res.secondOpinion;

  const shared = {
    summary: redactSecrets(res.summary),
    coverage: { ...res.coverage, previousVersion: res.coverage.previousVersion === null ? null : redactSecrets(res.coverage.previousVersion) },
    read: res.read.map(redactSecrets),
    notRead: res.notRead.map((n) => (n.kind === "file" ? { ...n, path: redactSecrets(n.path) } : { ...n, name: redactSecrets(n.name) })),
    secondOpinion: so ? { ...so, summary: redactSecrets(so.summary), findings: so.findings.map(redactFinding) } : null,
  };

  switch (res.outcome) {
    case "benign":
      return { ...res, ...shared };
    case "flagged":
      return { ...res, ...shared, findings: res.findings.map(redactFinding) };
    case "no-answer":
      return { ...res, ...shared, findings: res.findings.map(redactFinding) };
    default: {
      const _exhaustive: never = res;

      return _exhaustive;
    }
  }
}

export const ReviewRow = z
  .object({
    package: z.string(),
    version: z.string(),
    digest: z.string(),
    outcome: z.enum(["benign", "flagged", "no-answer"]),
    result: ReviewResult,
    reviewed_at: Int,
    human_state: z.enum(["none", "pending", "confirmed", "dismissed"]),
    human_by: z.string().nullable(),
    human_at: Int.nullable(),
    human_note: z.string().nullable(),
  })
  .transform((r) => ({ ...r, result: redactedResult(r.result), human_note: r.human_note === null ? null : redactSecrets(r.human_note) }));

export type StoredReview = z.infer<typeof ReviewRow>;

const one = <S extends z.ZodType>(row: S) => z.array(row).transform((rows) => rows[0] ?? null);
const all = <S extends z.ZodType>(row: S) => z.array(row);
const none = z.array(z.unknown()).transform(() => undefined);

/** Lower runs first. */
const PRIORITY: Record<EnqueueReason, number> = { requested: 0, publish: 1, "first-publish": 2, "install-script": 2, popular: 3 };

function priorityOf(reasons: readonly EnqueueReason[]): number {
  return Math.min(...reasons.map((r) => PRIORITY[r]), 9);
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

const INSTALL_KEYS = ["preinstall", "install", "postinstall"] as const;
const ScriptsOf = z.object({ scripts: z.record(z.string(), z.unknown()).catch({}).default({}), hasInstallScript: z.boolean().catch(false).default(false) });

/** Whether the version's manifest declares an install-time lifecycle script. */
function hasInstallScript(v: VersionRecord): boolean {
  const m = ScriptsOf.parse(v.manifest);

  return m.hasInstallScript || INSTALL_KEYS.some((k) => z.string().min(1).safeParse(m.scripts[k]).success);
}

function isPrerelease(version: string): boolean {
  return version.includes("-");
}

/** The version a release is diffed against: the highest lower one still served, stable unless this is a prerelease. */
export function previousVersionOf(versions: readonly VersionRecord[], version: string): VersionRecord | null {
  let best: VersionRecord | null = null;

  for (const v of versions) {
    if (v.version === version || v.status === "revoked") continue;

    if (!isPrerelease(version) && isPrerelease(v.version)) continue;

    if (order(v.version, version) >= 0) continue;

    if (best === null || order(v.version, best.version) > 0) best = v;
  }

  return best;
}

function labelOf(v: Pick<VersionRecord, "integrity" | "shasum">): string | null {
  const d = digestOf(v);

  return d ? digestLabel(d) : null;
}

/** Path of a tarball relative to the registry root, as the reviewer requests it. */
function tarballPath(name: string, version: string): string {
  return tarballUrl("", name, version);
}

const DownloadsAnswer = z.object({ downloads: z.number() });

// ---------- storage ----------
const query = <S extends z.ZodType>(operation: string, effect: Effect.Effect<ReadonlyArray<unknown>, SqlError>, schema: S): Effect.Effect<z.output<S>, StoreError> =>
  Effect.flatMap(Effect.all([timingOrNull, Effect.serviceOption(Guard)]), ([timing, guard]) => {
    const timedEffect = timed(timing, "db")(effect);

    // bounded like the Store's own statements (db-health.ts) wherever the request's database came with its guard
    return Option.isSome(guard) ? guard.value.statement(`review.${operation}`, timedEffect) : timedEffect.pipe(Effect.mapError((cause) => new StoreError({ operation: `review.${operation}`, cause })));
  }).pipe(
    Effect.flatMap((rows) => {
      const parsed = schema.safeParse(rows);

      return parsed.success ? Effect.succeed(parsed.data) : Effect.fail(new StoreError({ operation: `review.${operation}: parse`, cause: parsed.error }));
    }),
  );

const jobByKey = (name: string, version: string, digest: string) =>
  Effect.flatMap(SqlClient.SqlClient, (sql) =>
    query("jobByKey", sql`SELECT * FROM review_jobs WHERE package = ${name} AND version = ${version} AND digest = ${digest}`, one(JobRow)),
  );

const jobById = (id: string, lock: boolean) =>
  Effect.flatMap(SqlClient.SqlClient, (sql) =>
    query("jobById", lock ? sql`SELECT * FROM review_jobs WHERE id = ${id} FOR UPDATE` : sql`SELECT * FROM review_jobs WHERE id = ${id}`, one(JobRow)),
  );

const reviewFor = (name: string, version: string, digest: string) =>
  Effect.flatMap(SqlClient.SqlClient, (sql) =>
    query("reviewFor", sql`SELECT * FROM reviews WHERE package = ${name} AND version = ${version} AND digest = ${digest}`, one(ReviewRow)),
  );

const StoredAndJob = z.object({ review: ReviewRow.nullable(), job: JobRow.nullable() });

/** The stored review and the job of one version's bytes, in one round trip (the review answer reads both). */
const reviewAndJob = (name: string, version: string, digest: string) =>
  Effect.flatMap(SqlClient.SqlClient, (sql) =>
    query(
      "reviewAndJob",
      sql`SELECT (SELECT to_jsonb(r) FROM reviews r WHERE r.package = ${name} AND r.version = ${version} AND r.digest = ${digest}) AS review,
                 (SELECT to_jsonb(j) FROM review_jobs j WHERE j.package = ${name} AND j.version = ${version} AND j.digest = ${digest}) AS job`,
      one(StoredAndJob),
    ),
  );

/** Where the AI review of one version stands: its public result, or the state of its job, or not picked for review. */
export type ReviewStanding = PublicState | "queued" | "leased" | "failed" | "not-reviewed";

/**
 * The review standing of each name@version (keyed `name@version`), for the resolve route's dependency walk. One
 * query per table, whatever the tree's size. A version whose tarball digest is unknown has no review: not-reviewed.
 */
export const reviewStandings = (items: readonly { name: string; version: string; digest: string | null }[]) =>
  Effect.gen(function* () {
    const out = new Map<string, ReviewStanding>();
    const keyed = items.filter((i): i is { name: string; version: string; digest: string } => i.digest !== null);

    for (const i of items) out.set(`${i.name}@${i.version}`, "not-reviewed");

    if (keyed.length === 0) return out;
    const sql = yield* SqlClient.SqlClient;
    const names = [...new Set(keyed.map((i) => i.name))];
    const versions = [...new Set(keyed.map((i) => i.version))];
    const wanted = new Set(keyed.map((i) => `${i.name}@${i.version}@${i.digest}`));
    const reviews = yield* query("reviewStandings", sql`SELECT * FROM reviews WHERE package = ANY(${names}) AND version = ANY(${versions})`, all(ReviewRow));
    const jobs = yield* query("jobStandings", sql`SELECT * FROM review_jobs WHERE package = ANY(${names}) AND version = ANY(${versions})`, all(JobRow));

    for (const j of jobs) {
      if (!wanted.has(`${j.package}@${j.version}@${j.digest}`)) continue;

      if (j.state === "queued" || j.state === "leased" || j.state === "failed") out.set(`${j.package}@${j.version}`, j.state);
    }

    // a stored result wins over its job's state, as on the review route
    for (const r of reviews) if (wanted.has(`${r.package}@${r.version}@${r.digest}`)) out.set(`${r.package}@${r.version}`, publicState(r));

    return yield* withSwitch(out);
  });

/**
 * Standings as the switch has them now: with "AI flags hold installs" off, an open flag is "flagged" (a note) instead
 * of "under-review" (a hold). The switch is read only when some standing is an open flag.
 */
const withSwitch = (standings: Map<string, ReviewStanding>) =>
  Effect.gen(function* () {
    if (![...standings.values()].includes("under-review")) return standings;

    if (yield* flagsHold) return standings;

    return new Map([...standings].map(([key, s]) => [key, heldState(s, false)] as const));
  });

/** Adds a job, or merges reasons into the waiting one. A finished job is reopened only for a request after no answer. */
const enqueue = (job: { name: string; version: string; digest: string; source: Source; reasons: EnqueueReason[] }) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const store = yield* Store;
    const at = yield* (yield* Clock).now;

    return yield* store.tx(
      Effect.gen(function* () {
        const inserted = yield* query(
          "enqueue: insert",
          sql`INSERT INTO review_jobs (id, package, version, digest, source, reasons, priority, state, enqueued_at, updated_at)
              VALUES (${randomId(12)}, ${job.name}, ${job.version}, ${job.digest}, ${job.source}, ${JSON.stringify(job.reasons)}::jsonb,
                      ${priorityOf(job.reasons)}, 'queued', ${at}, ${at})
              ON CONFLICT (package, version, digest) DO NOTHING RETURNING id`,
          z.array(z.unknown()),
        );

        if (inserted.length > 0) return "queued" as const;

        const cur = yield* query(
          "enqueue: lock",
          sql`SELECT * FROM review_jobs WHERE package = ${job.name} AND version = ${job.version} AND digest = ${job.digest} FOR UPDATE`,
          one(JobRow),
        );

        if (!cur) return "exists" as const;
        const reasons = [...new Set([...cur.reasons, ...job.reasons])];
        const reopen = job.reasons.includes("requested") && (cur.state === "failed" || (yield* reviewFor(job.name, job.version, job.digest))?.outcome === "no-answer");

        if (cur.state !== "queued" && cur.state !== "leased" && !reopen) return "exists" as const;
        const state: JobState = reopen ? "queued" : cur.state;
        yield* query(
          "enqueue: merge",
          sql`UPDATE review_jobs SET reasons = ${JSON.stringify(reasons)}::jsonb, priority = ${Math.min(cur.priority, priorityOf(job.reasons))},
                  state = ${state}, attempts = ${reopen ? 0 : cur.attempts}, updated_at = ${at} WHERE id = ${cur.id}`,
          none,
        );

        return reopen ? ("queued" as const) : ("exists" as const);
      }),
    );
  });

const setJobState = (id: string, state: JobState, error: string | null) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const at = yield* (yield* Clock).now;
    yield* query(
      "setJobState",
      sql`UPDATE review_jobs SET state = ${state}, lease_id = NULL, lease_expires_at = NULL, last_error = ${error}, updated_at = ${at} WHERE id = ${id}`,
      none,
    );
  });

/** Takes up to `max` ready jobs; expired leases count as ready again. Concurrent reviewers never get the same job. */
const takeJobs = (max: number, settings: ReviewSettings) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const store = yield* Store;
    const now = yield* (yield* Clock).now;

    const rows = yield* store.tx(
      Effect.gen(function* () {
        yield* query(
          "takeJobs: expire",
          sql`UPDATE review_jobs SET state = 'queued', lease_id = NULL, lease_expires_at = NULL, updated_at = ${now} WHERE state = 'leased' AND lease_expires_at <= ${now}`,
          none,
        );
        yield* query(
          "takeJobs: give up",
          sql`UPDATE review_jobs SET state = 'failed', last_error = 'too many attempts', updated_at = ${now} WHERE state = 'queued' AND attempts >= ${settings.maxAttempts}`,
          none,
        );

        return yield* query(
          "takeJobs: lease",
          sql`UPDATE review_jobs SET state = 'leased', lease_id = replace(gen_random_uuid()::text, '-', ''), lease_expires_at = ${now + settings.leaseMs},
                  attempts = attempts + 1, updated_at = ${now}
              WHERE id IN (SELECT id FROM review_jobs WHERE state = 'queued' ORDER BY priority, enqueued_at LIMIT ${max} FOR UPDATE SKIP LOCKED)
              RETURNING *`,
          all(JobRow),
        );
      }),
    );

    return rows.toSorted((a, b) => a.priority - b.priority || a.enqueued_at - b.enqueued_at);
  });

// ---------- catalog ----------
/** A version as a catalog lists it: the listing (catalogListing) carries no score. */
type Listed = Omit<VersionRecord, "score">;

type Catalog<V extends Listed = VersionRecord> =
  | { kind: "ok"; source: Source; distTags: Record<string, string>; versions: readonly V[] }
  | { kind: "absent" }
  | { kind: "unavailable" };

/** An upstream answer as a catalog. */
function upstreamCatalog<V extends Listed>(probe: { kind: "found"; pkg: { distTags: Record<string, string>; versions: readonly V[] } } | { kind: "absent" } | { kind: "unknown" }): Catalog<V> {
  switch (probe.kind) {
    case "found":
      return { kind: "ok", source: "upstream", distTags: probe.pkg.distTags, versions: probe.pkg.versions };
    case "absent":
      return { kind: "absent" };
    case "unknown":
      return { kind: "unavailable" };
    default: {
      const _exhaustive: never = probe;

      return _exhaustive;
    }
  }
}

/** A package's versions with their scores (evidence checks and the reviewer's job read them). */
const catalog = (name: string) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const pkg = yield* store.getPackage(name);

    if (pkg) return { kind: "ok", source: "local", distTags: pkg.distTags, versions: yield* store.listVersions(name) } satisfies Catalog;
    const upstream = yield* Effect.serviceOption(Upstream);

    if (Option.isNone(upstream)) return { kind: "absent" } satisfies Catalog;

    return upstreamCatalog(yield* upstream.value.probe(name, yield* RequestMemory));
  });

/**
 * A package's versions, statuses and checksums, for the review answer of `spec`: an upstream package's come from its
 * kept summary when it holds `spec` (kept-package.ts), else from the listing; neither reads scores. A local version's
 * status is read from the database on every call.
 */
const catalogListing = (name: string, spec: string) =>
  Effect.gen(function* () {
    // the package row, a local package's versions, or an upstream one's kept row, in one round trip (Store.pageRead)
    const row = yield* (yield* Store).pageRead({ name, at: yield* (yield* Clock).now, scores: { kind: "none" } });

    if (row.kind === "local") return { kind: "ok", source: "local", distTags: row.pkg.distTags, versions: row.versions } satisfies Catalog<Listed>;
    const upstream = yield* Effect.serviceOption(Upstream);

    if (Option.isNone(upstream)) return { kind: "absent" } satisfies Catalog<Listed>;

    return upstreamCatalog(yield* pageListing({ upstream: upstream.value, name, need: { kind: "spec", spec }, lease: yield* RequestMemory, first: { kind: "read", kept: row.kept, analyses: row.analyses, whole: row.whole } }));
  });

type Payload = { kind: "ok"; job: ReviewJob } | { kind: "gone"; why: string } | { kind: "later"; why: string };

/** The job as the reviewer sees it, or why it cannot be built. */
const jobPayload = (row: JobRow) =>
  Effect.gen(function* () {
    const cat: Catalog = yield* catalog(row.package);

    if (cat.kind === "unavailable") return { kind: "later", why: "the upstream registry could not be reached" } satisfies Payload;

    if (cat.kind === "absent") return { kind: "gone", why: "the package is no longer published" } satisfies Payload;
    const v = cat.versions.find((x) => x.version === row.version);

    if (!v || v.status === "revoked") return { kind: "gone", why: "the version is no longer served" } satisfies Payload;

    if (labelOf(v) !== row.digest) return { kind: "gone", why: "the version's tarball checksum changed" } satisfies Payload;
    const prev = previousVersionOf(cat.versions, row.version);
    const prevDigest = prev ? labelOf(prev) : null;
    const now = yield* (yield* Clock).now;

    return {
      kind: "ok",
      job: {
        id: row.id,
        leaseId: row.lease_id ?? "",
        leaseExpiresAt: iso(row.lease_expires_at ?? now),
        name: row.package,
        version: row.version,
        digest: row.digest,
        tarballPath: tarballPath(row.package, row.version),
        previous: prev && prevDigest ? { version: prev.version, digest: prevDigest, tarballPath: tarballPath(row.package, prev.version) } : null,
        reasons: row.reasons,
      },
    } satisfies Payload;
  });

// ---------- enqueue policy ----------
const weeklyDownloads = (name: string, settings: ReviewSettings) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const now = yield* (yield* Clock).now;

    const hit = yield* query(
      "weeklyDownloads: read",
      sql`SELECT weekly, fetched_at FROM review_downloads WHERE package = ${name}`,
      one(z.object({ weekly: Int.nullable(), fetched_at: Int })),
    );

    if (hit && now - hit.fetched_at < (hit.weekly === null ? DOWNLOADS_FAILURE_TTL_MS : DOWNLOADS_TTL_MS)) return hit.weekly;

    const weekly = yield* Effect.promise(async (): Promise<number | null> => {
      try {
        const res = await fetch(`${settings.downloadsUrl}${name}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000) });

        if (!res.ok) {
          await res.body?.cancel();

          return null;
        }

        const parsed = DownloadsAnswer.safeParse(await res.json());

        return parsed.success ? parsed.data.downloads : null;
      } catch {
        return null;
      }
    });

    yield* query(
      "weeklyDownloads: write",
      sql`INSERT INTO review_downloads (package, weekly, fetched_at) VALUES (${name}, ${weekly}, ${now})
          ON CONFLICT (package) DO UPDATE SET weekly = EXCLUDED.weekly, fetched_at = EXCLUDED.fetched_at`,
      none,
    );

    return weekly;
  });

/** Queues a review of a version that just went live here. Does nothing while the AI review is off. */
export const reviewLocalCommit = (v: { name: string; version: string; firstPublish: boolean }) =>
  Effect.gen(function* () {
    if (Option.isNone(yield* Effect.serviceOption(ReviewConfig))) return;
    const store = yield* Store;
    const rec = yield* store.getVersion(v.name, v.version);
    const digest = rec ? labelOf(rec) : null;

    if (!rec || !digest) return;
    const reasons: EnqueueReason[] = ["publish"];

    if (v.firstPublish) reasons.push("first-publish");
    const prev = previousVersionOf(yield* store.listVersions(v.name), v.version);

    if (hasInstallScript(rec) && (prev === null || !hasInstallScript(prev))) reasons.push("install-script");
    yield* enqueue({ name: v.name, version: v.version, digest, source: "local", reasons });
  });

/**
 * Versions apm sees for the first time: the newest on first sight of a package, then every newer one. The
 * high-water mark and the jobs commit together, so a failed enqueue leaves the versions unseen and the next
 * fetch queues them. The download count (a network call) is read before the transaction.
 */
export const considerUpstream = (pkg: UpstreamPackage) =>
  Effect.gen(function* () {
    const found = yield* Effect.serviceOption(ReviewConfig);

    if (Option.isNone(found)) return;
    const settings = found.value;
    const sql = yield* SqlClient.SqlClient;
    const store = yield* Store;
    const versions = pkg.versions.filter((v) => v.published_at > 0);
    const newest = Math.max(0, ...versions.map((v) => v.published_at));
    const latest = pkg.distTags.latest;
    const freshSince = (seen: number | null) => (seen === null ? versions.filter((v) => v.version === latest) : versions.filter((v) => v.published_at > seen));

    // the mark only moves forward, so when it already covers this packument there is nothing to claim
    const mark = yield* query("considerUpstream: peek", sql`SELECT newest_at FROM review_seen WHERE package = ${pkg.name}`, one(z.object({ newest_at: Int })));

    if (mark !== null && mark.newest_at >= newest) return;

    if (freshSince(mark?.newest_at ?? null).length === 0) return;
    const popular = ((yield* weeklyDownloads(pkg.name, settings)) ?? 0) >= settings.popularWeekly;

    yield* store.tx(
      Effect.gen(function* () {
        // claims the newer versions atomically, so two requests that fetched the same packument queue them once
        const claimed = yield* query(
          "considerUpstream: seen",
          sql`WITH old AS (SELECT newest_at FROM review_seen WHERE package = ${pkg.name} FOR UPDATE)
              INSERT INTO review_seen (package, newest_at) VALUES (${pkg.name}, ${newest})
              ON CONFLICT (package) DO UPDATE SET newest_at = EXCLUDED.newest_at WHERE review_seen.newest_at < EXCLUDED.newest_at
              RETURNING (SELECT newest_at FROM old) AS previous`,
          one(z.object({ previous: Int.nullable() })),
        );

        if (!claimed) return;

        for (const v of freshSince(claimed.previous).slice(-20)) {
          const digest = labelOf(v);

          if (!digest) continue;
          const reasons: EnqueueReason[] = [];

          if (versions.length === 1) reasons.push("first-publish");
          const prev = previousVersionOf(versions, v.version);

          if (hasInstallScript(v) && (prev === null || !hasInstallScript(prev))) reasons.push("install-script");

          if (popular) reasons.push("popular");

          if (reasons.length > 0) yield* enqueue({ name: pkg.name, version: v.version, digest, source: "upstream", reasons });
        }
      }),
    );
  });

// ---------- viewers ----------
/** Who is asking. A website session carries its sign-in, which review decisions check a fresh factor against. */
export type Viewer = { kind: "anon" } | { kind: "user"; user: User; githubLogin: string | null; via: { kind: "token" } | { kind: "session"; session: SignedIn } };

/** A viewer signed in on the website. */
export type SessionViewer = Extract<Viewer, { kind: "user" }> & { via: { kind: "session"; session: SignedIn } };

export const viewerOf = (req: Request, caller: Caller) =>
  Effect.gen(function* () {
    const store = yield* Store;

    if (caller.kind === "user") {
      const user = yield* store.getUser(caller.user);

      return user ? ({ kind: "user", user, githubLogin: user.github_login?.toLowerCase() ?? null, via: { kind: "token" } } satisfies Viewer) : ({ kind: "anon" } satisfies Viewer);
    }

    // a website session is a cookie: without one there is nothing to read, and Better Auth is not built for nothing
    if (!req.headers.has("cookie")) return { kind: "anon" } satisfies Viewer;
    const auth = yield* Auth;
    const s = yield* auth.sessionOf(req);

    if (!s) return { kind: "anon" } satisfies Viewer;
    const user = yield* auth.apmUserOf(s.authUserId);

    if (!user) return { kind: "anon" } satisfies Viewer;
    const login = yield* auth.gitHubNameOf(s.authUserId);

    return { kind: "user", user, githubLogin: login?.toLowerCase() ?? null, via: { kind: "session", session: s } } satisfies Viewer;
  });

function adminsOf(settings: ReviewSettings): ReadonlySet<string> {
  return new Set(settings.admins.map((a) => a.trim().toLowerCase()).filter((a) => a !== ""));
}

/**
 * One of apm's reviewers, signed in on the website. A token never counts, not even the reviewer's own:
 * a stolen `apm login` or CI token must not read the private queue or clear a flag.
 * Entries in `settings.admins` may be GitHub logins or immutable numeric GitHub user IDs prefixed with `id:` (`id:12345`).
 */
function isAdmin(v: Viewer, settings: ReviewSettings): v is SessionViewer {
  if (v.kind !== "user" || v.via.kind !== "session") return false;
  const admins = adminsOf(settings);
  const githubId = v.user.github_id;

  if (githubId !== null && admins.has(`id:${githubId}`)) return true;

  return v.githubLogin !== null && !v.githubLogin.startsWith("id:") && admins.has(v.githubLogin);
}

/**
 * Whether the viewer may see an unconfirmed flag's findings as the package's maintainer: only for a package published
 * on apm (`source` "local", read from apm's packages table), and only for an owner of it in apm's records or the
 * account whose apm scope it is under ("Your packages" lists the same). A package npm serves is nobody's here, whatever
 * its scope: apm has no record of who owns it on npm, so an apm user named alice is not the owner of npm's @alice/x
 * (independent review of 17be3f6, finding 1).
 */
const isMaintainer = (input: { viewer: Viewer; name: string; source: Source }) => {
  const { viewer, name, source } = input;

  if (viewer.kind !== "user" || source !== "local") return Effect.succeed(false);

  return Effect.map(
    Store.use((store) => Effect.all([store.getPackage(name), store.owners(name)])),
    ([pkg, owners]) => pkg !== null && (name.startsWith(`@${viewer.user.name}/`) || owners.includes(viewer.user.name)),
  );
};

/** Cookie-authenticated writes must come from the website (origin.ts); a token's requests are not a browser's. */
export const checkOrigin = (req: Request, v: Viewer) => (v.kind === "user" && v.via.kind === "session" ? requireSiteOrigin(req) : Effect.void);

function isService(req: Request, settings: ReviewSettings): boolean {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.get("authorization") ?? "");
  const expected = Buffer.from(settings.serviceTokenHash, "hex");

  return m?.[1] !== undefined && expected.length === 32 && timingSafeEqual(createHash("sha256").update(m[1].trim()).digest(), expected);
}

// ---------- views ----------
/**
 * under-review: an AI flag a person has not decided, while flags hold installs. flagged: the same flag while they do
 * not (the switch is off): shown and told to agents as a note, never as a hold.
 */
type PublicState = "found-nothing" | "under-review" | "flagged" | "no-answer" | "confirmed" | "cleared";

/** A state as the switch has it: an open flag reads "flagged" while flags do not hold installs. */
function heldState<S extends ReviewStanding>(state: S, hold: boolean): S | "flagged" {
  return state === "under-review" && !hold ? "flagged" : state;
}

function publicState(r: StoredReview): PublicState {
  switch (r.human_state) {
    case "confirmed":
      return "confirmed";
    case "dismissed":
      return "cleared";
    case "none":
    case "pending":
      break;
    default: {
      const _exhaustive: never = r.human_state;

      return _exhaustive;
    }
  }

  switch (r.result.outcome) {
    case "benign":
      return "found-nothing";
    case "flagged":
      return "under-review";
    case "no-answer":
      return r.result.reason === "unsettled" ? "under-review" : "no-answer";
    default: {
      const _exhaustive: never = r.result;

      return _exhaustive;
    }
  }
}

// A withheld version's review (withheld.ts) is rebuilt from allowed fields: line numbers, severities, verdict enums and
// counts. The model's summaries, its finding sentences, and every quote and excerpt are left out, and a field added to
// the wire format later is not sent until it is named here. File paths are publisher text too, so each is replaced by
// a numbered reference ("file 3") that is the same for one path throughout the review.

/** Every path a review result names, sorted, each mapped to "file <n>". */
function fileRefs(res: ReviewResult): (path: string) => string {
  const so = res.secondOpinion;

  const paths = [
    ...res.read,
    ...res.notRead.flatMap((n) => (n.kind === "file" ? [n.path] : [])),
    ...findingsOf(res).map((f) => f.file),
    ...(so ? so.findings.map((f) => f.file) : []),
  ];

  return fileReferences(paths);
}

/** A finding of a withheld version: which file by reference, the line, and how bad; no sentence, quote or excerpt. */
const withheldFinding = (f: WireFinding, ref: (path: string) => string): WireFinding => ({ file: ref(f.file), line: f.line, issue: WITHHELD_ISSUE, severity: f.severity, quote: "", excerpt: "" });

/** The result fields every outcome shares, from allowed fields only. */
function withheldFields(res: ReviewResult, ref: (path: string) => string) {
  const so = res.secondOpinion;

  return {
    model: res.model,
    reviewedAt: res.reviewedAt,
    summary: "",
    coverage: { mode: res.coverage.mode, previousVersion: res.coverage.previousVersion, filesInScope: res.coverage.filesInScope, filesRead: res.coverage.filesRead },
    read: res.read.map(ref),
    // a dependency's manifest key is any text the publisher wrote: one that is not a valid npm name is not repeated
    notRead: res.notRead.map((n) =>
      n.kind === "file" ? { kind: "file" as const, path: ref(n.path), reason: n.reason } : { kind: "dependency" as const, name: isValidPackageName(n.name) ? n.name : INVALID_DEPENDENCY },
    ),
    attempts: res.attempts.map((a) => ({ result: a.result, kept: a.kept, dropped: a.dropped, promptTokens: a.promptTokens, completionTokens: a.completionTokens, latencyMs: a.latencyMs })),
    secondOpinion: so ? { reviewer: so.reviewer, verdict: so.verdict, summary: "", findings: so.findings.map((f) => withheldFinding(f, ref)) } : null,
  };
}

/** A withheld version's review result, built from allowed fields only. */
function withheldResult(res: ReviewResult): ReviewResult {
  const ref = fileRefs(res);
  const fields = withheldFields(res, ref);

  switch (res.outcome) {
    case "benign":
      return { outcome: "benign", ...fields };
    case "flagged":
      return { outcome: "flagged", verdict: res.verdict, findings: res.findings.map((f) => withheldFinding(f, ref)), ...fields };
    case "no-answer":
      return { outcome: "no-answer", reason: res.reason, findings: res.findings.map((f) => withheldFinding(f, ref)), ...fields };
    default: {
      const _exhaustive: never = res;

      return _exhaustive;
    }
  }
}

/** A stored review of a withheld version: its result rebuilt from allowed fields; the person's decision and note stay. */
const withheldReview = (r: StoredReview): StoredReview => ({ ...r, result: withheldResult(r.result) });

function findingsOf(r: ReviewResult): WireFinding[] {
  return r.outcome === "benign" ? [] : r.findings;
}

/**
 * The review as anyone may see it: the state, the model, when, how many files it read and did not, and, once a person
 * confirmed it, each finding as file, line, severity and a label apm chose (public-finding.ts) plus the person's note.
 * Nothing the model or the publisher wrote freely: no sentence, summary, quoted line, excerpt or path list (independent
 * re-checks of 7207ea0 and 70dc3df), so nothing public depends on masking. The owners' and the reviewers' views keep
 * all of it, masked (privateView). Exported for test/public-review.test.ts, which builds it with masking stubbed out.
 */
export function publicView(r: StoredReview, hold: boolean) {
  const state = heldState(publicState(r), hold);
  const notRead = r.result.notRead;

  return {
    state,
    model: r.result.model,
    reviewedAt: r.result.reviewedAt,
    coverage: r.result.coverage,
    // counts only: a path is the publisher's text
    notReadCounts: { files: notRead.filter((n) => n.kind === "file").length, dependencies: notRead.filter((n) => n.kind === "dependency").length },
    findings: state === "confirmed" ? publicFindings(findingsOf(r.result)) : [],
    decidedAt: r.human_at === null ? null : iso(r.human_at),
    // a person at apm wrote it, for the public
    note: state === "confirmed" || state === "cleared" ? r.human_note : null,
  };
}

function privateView(r: StoredReview) {
  return {
    outcome: r.result.outcome,
    verdict: r.result.outcome === "flagged" ? r.result.verdict : null,
    reason: r.result.outcome === "no-answer" ? r.result.reason : null,
    summary: r.result.summary,
    findings: findingsOf(r.result),
    // the paths it read and did not: the publisher's text, masked, for the owners and the reviewers only
    read: r.result.read,
    notRead: r.result.notRead,
    attempts: r.result.attempts,
    secondOpinion: r.result.secondOpinion,
    humanState: r.human_state,
  };
}

/** The version `version` names in `cat`, or the refusal that says why there is none. */
const pickVersion = <V extends Listed>(cat: Catalog<V>, version: string) => {
  if (cat.kind === "unavailable") return Effect.fail(refuse(503, "The upstream registry could not be reached."));

  if (cat.kind === "absent") return Effect.fail(refuse(404, "Not found"));
  const v = cat.versions.find((x) => x.version === version);

  if (!v) return Effect.fail(refuse(404, "No such version"));

  return Effect.succeed({ source: cat.source, version: v, digest: labelOf(v) });
};

export const resolveVersion = (name: string, version: string | undefined) =>
  Effect.gen(function* () {
    if (!version) return yield* Effect.fail(refuse(404, "Name a version."));

    return yield* pickVersion(yield* catalog(name), version);
  });

/**
 * The version a review answer is for: an exact version, else a dist-tag (the website asks for `latest` while it reads
 * the package answer). An exact version wins over a tag of the same name.
 */
const resolveListed = (name: string, spec: string | undefined) =>
  Effect.gen(function* () {
    if (!spec) return yield* Effect.fail(refuse(404, "Name a version."));
    const cat = yield* catalogListing(name, spec);
    const exact = cat.kind === "ok" && cat.versions.some((v) => v.version === spec);

    return yield* pickVersion(cat, cat.kind === "ok" && !exact ? (tagTarget(cat.distTags, spec) ?? spec) : spec);
  });

const reviewResponse = (req: Request, caller: Caller, name: string, version: string | undefined, settings: ReviewSettings) =>
  Effect.gen(function* () {
    const got = yield* resolveListed(name, version);
    const v = got.version;
    const viewer = yield* viewerOf(req, caller);
    let role: "admin" | "maintainer" | "public" = "public";

    if (isAdmin(viewer, settings)) role = "admin";
    else if (yield* isMaintainer({ viewer, name, source: got.source })) role = "maintainer";
    const found = got.digest ? yield* reviewAndJob(name, v.version, got.digest) : null;
    const stored = found?.review ?? null;
    const redacted = isWithheld(v.status);
    const review = stored && redacted ? withheldReview(stored) : stored;
    const job = found?.job ?? null;
    // the switch is read only for an open flag: every other answer is the same either way
    const hold = review !== null && publicState(review) === "under-review" ? yield* flagsHold : true;
    let status: "reviewed" | "queued" | "failed" | "not-reviewed" = "not-reviewed";

    // a waiting job comes first: a retry after no answer is queued while the older result is still stored, and the
    // card keeps polling only while the answer says queued
    if (job?.state === "queued" || job?.state === "leased") status = "queued";
    else if (review) status = "reviewed";
    else if (job?.state === "failed") status = "failed";

    return json(
      {
        name,
        version: v.version,
        status,
        // a withheld version's findings keep their line and severity: the sentence is WITHHELD_ISSUE, each file a reference
        redacted,
        // the version's own state as this answer was made: a version yanked or revoked after a client's resolve read
        // must stop that client from installing it (the install verdict checks this before the review)
        versionStatus: v.status,
        // `status` folds a leased job into "queued"; `job` keeps them apart for clients that act on the difference
        job: job?.state ?? null,
        review: review ? publicView(review, hold) : null,
        viewer: role,
        private: review && role !== "public" ? privateView(review) : null,
        canRequest: viewer.kind === "user" && got.digest !== null && status !== "queued" && (review === null || review.result.outcome === "no-answer"),
      },
      200,
      { "cache-control": "no-store" },
    );
  });

const requestResponse = (req: Request, caller: Caller, name: string, version: string | undefined, settings: ReviewSettings) =>
  Effect.gen(function* () {
    const viewer = yield* viewerOf(req, caller);

    if (viewer.kind !== "user") return fail(401, `Sign in at ${(yield* RegistryConfig).webUrl} to request an AI review.`);
    yield* checkOrigin(req, viewer);
    const got = yield* resolveVersion(name, version);

    if (!got.digest) return fail(422, "This version has no checksum, so its tarball cannot be verified for review.");
    const existing = yield* reviewFor(name, got.version.version, got.digest);

    if (existing && existing.result.outcome !== "no-answer") return fail(409, "This version already has an AI review.");
    const job = yield* jobByKey(name, got.version.version, got.digest);

    if (job && (job.state === "queued" || job.state === "leased")) return json({ status: "queued" });
    const sql = yield* SqlClient.SqlClient;
    const now = yield* (yield* Clock).now;
    const store = yield* Store;

    // the budget check and the press it records are one step, so parallel presses cannot overspend it
    const allowed = yield* store.tx(
      Effect.gen(function* () {
        yield* query("request: lock", sql`SELECT pg_advisory_xact_lock(hashtext(${`review-request ${viewer.user.name}`}))`, none);

        const used = yield* query(
          "request: count",
          sql`SELECT COUNT(*) AS n FROM review_requests WHERE actor = ${viewer.user.name} AND at > ${now - HOUR}`,
          one(z.object({ n: Int })),
        );

        if ((used?.n ?? 0) >= settings.requestsPerHour) return false;
        yield* query(
          "request: record",
          sql`INSERT INTO review_requests (actor, package, version, at) VALUES (${viewer.user.name}, ${name}, ${got.version.version}, ${now})`,
          none,
        );

        return true;
      }),
    );

    if (!allowed) return fail(429, `You can request ${settings.requestsPerHour} AI reviews an hour. Try again later.`, { retryAfterSeconds: 3600 });
    yield* enqueue({ name, version: got.version.version, digest: got.digest, source: got.source, reasons: ["requested"] });

    return json({ status: "queued" }, 202);
  });

// ---------- reviewer (service token) ----------
const leaseResponse = (url: URL, settings: ReviewSettings) =>
  Effect.gen(function* () {
    const max = Math.max(1, Math.min(MAX_LEASE_BATCH, Number(url.searchParams.get("max") ?? "4") || 4));
    const jobs: ReviewJob[] = [];

    for (const row of yield* takeJobs(max, settings)) {
      const p: Payload = yield* jobPayload(row);

      switch (p.kind) {
        case "ok":
          jobs.push(p.job);
          break;
        case "gone":
          yield* setJobState(row.id, "failed", p.why);
          break;
        case "later":
          yield* setJobState(row.id, "queued", p.why);
          break;
        default: {
          const _exhaustive: never = p;

          return _exhaustive;
        }
      }
    }

    return json({ jobs }, 200, { "cache-control": "no-store" });
  });

/** The job, locked, when `leaseId` still holds it. */
const leaseHolder = (id: string, leaseId: string) =>
  Effect.gen(function* () {
    const job = yield* jobById(id, true);

    if (!job) return yield* Effect.fail(refuse(404, "No such job."));

    if (job.state !== "leased" || job.lease_id !== leaseId) return yield* Effect.fail(refuse(409, "This lease is no longer yours; the job went back to the queue or was finished."));

    return job;
  });

const resultResponse = (req: Request, id: string) =>
  Effect.gen(function* () {
    const body = yield* parseBody(req, ResultBody, MAX_REVIEW_BODY_BYTES);
    const sql = yield* SqlClient.SqlClient;
    const store = yield* Store;
    const at = yield* (yield* Clock).now;

    const stored = yield* store.tx(
      Effect.gen(function* () {
        const job = yield* leaseHolder(id, body.leaseId);
        const r = body.result;
        const human: HumanState = r.outcome === "benign" ? "none" : "pending";
        yield* query(
          "result: store",
          sql`INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state, human_by, human_at, human_note)
              VALUES (${job.package}, ${job.version}, ${job.digest}, ${r.outcome}, ${storableJson(JSON.stringify(r))}::jsonb, ${at}, ${human}, NULL, NULL, NULL)
              ON CONFLICT (package, version, digest) DO UPDATE SET outcome = EXCLUDED.outcome, result = EXCLUDED.result, reviewed_at = EXCLUDED.reviewed_at,
                human_state = EXCLUDED.human_state, human_by = NULL, human_at = NULL, human_note = NULL`,
          none,
        );
        yield* setJobState(job.id, "done", null);

        return yield* reviewFor(job.package, job.version, job.digest);
      }),
    );

    return stored ? json({ ok: true, state: publicState(stored) }) : fail(500, "The review was not stored.");
  });

const releaseResponse = (req: Request, id: string) =>
  Effect.gen(function* () {
    const body = yield* parseBody(req, ReleaseBody, MAX_REVIEW_BODY_BYTES);
    const store = yield* Store;
    yield* store.tx(
      Effect.gen(function* () {
        const job = yield* leaseHolder(id, body.leaseId);
        yield* setJobState(job.id, body.retryable ? "queued" : "failed", body.error);
      }),
    );

    return json({ ok: true });
  });

// ---------- second stage: the owner queue ----------
const DecideBody = ReviewDecision.extend(ProofFields);

const VersionStatusRow = z.object({ package: z.string(), version: z.string(), status: z.string() });

/** The queue's local versions that are withheld, as "name@version", in one query; an upstream version has no row. */
const withheldOf = (rows: readonly StoredReview[]) =>
  Effect.gen(function* () {
    if (rows.length === 0) return new Set<string>();
    const sql = yield* SqlClient.SqlClient;
    const names = [...new Set(rows.map((r) => r.package))];
    const versions = [...new Set(rows.map((r) => r.version))];

    const found = yield* query(
      "queue: version status",
      sql`SELECT package, version, status FROM versions WHERE package = ANY(${names}) AND version = ANY(${versions})`,
      all(VersionStatusRow),
    );

    return new Set(found.filter((v) => isWithheld(v.status)).map((v) => `${v.package}@${v.version}`));
  });

/** One line for the triage list: the model's summary to its first sentence, or its first finding's, at most 160 characters. */
export function summaryLine(r: ReviewResult): string {
  const text = (r.summary.trim() || findingsOf(r)[0]?.issue.trim() || "").replace(/\s+/g, " ");
  const first = /^(.+?[.!?])(?:\s|$)/.exec(text)?.[1] ?? text;

  return first.length > 160 ? `${first.slice(0, 159)}…` : first;
}

const PendingRow = z.object({ review: ReviewRow, weekly: Int.nullable() });

const queueResponse = (viewer: SessionViewer, settings: ReviewSettings) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    // most downloaded first: a false hold on a popular package costs the most installs
    const pending = yield* query(
      "queue: pending",
      sql`SELECT to_jsonb(r) AS review, d.weekly FROM reviews r LEFT JOIN review_downloads d ON d.package = r.package
          WHERE r.human_state = 'pending' ORDER BY d.weekly DESC NULLS LAST, r.reviewed_at LIMIT 200`,
      all(PendingRow),
    );

    const decided = yield* query(
      "queue: decided",
      sql`SELECT * FROM reviews WHERE human_state IN ('confirmed', 'dismissed') ORDER BY human_at DESC LIMIT 50`,
      all(ReviewRow),
    );

    // a withheld version's review is rebuilt before any view is: the admin sees where and what, not the source
    const withheld = yield* withheldOf([...pending.map((p) => p.review), ...decided]);
    const hold = yield* flagsHold;
    const until = yield* decisionWindow(viewer);

    const item = (stored: StoredReview, weekly: number | null) => {
      const redacted = withheld.has(`${stored.package}@${stored.version}`);
      const r = redacted ? withheldReview(stored) : stored;

      return {
        name: r.package,
        version: r.version,
        digest: r.digest,
        reviewedAt: iso(r.reviewed_at),
        redacted,
        weeklyDownloads: weekly,
        summaryLine: summaryLine(r.result),
        public: publicView(r, hold),
        private: privateView(r),
        decidedBy: r.human_by,
      };
    };

    return json(
      {
        pending: pending.map((p) => item(p.review, p.weekly)),
        decided: decided.map((d) => item(d, null)),
        // the stronger-model step plugs in at the reviewer (apps/reviewer/src/second-stage.ts); none is configured
        secondStage: null,
        flagsHold: yield* switchState(settings),
        unlockedUntil: until === null ? null : iso(until),
        windowMs: DECISION_WINDOW_MS,
      },
      200,
      { "cache-control": "no-store" },
    );
  });

const decideResponse = (req: Request, viewer: SessionViewer) =>
  Effect.gen(function* () {
    const d = yield* parseBody(req, DecideBody, MAX_REVIEW_BODY_BYTES);
    // a decision changes what the public sees: a code or passkey check for exactly this one, or the window one opened
    yield* decisionAllowed({ viewer, body: d, action: { kind: "review-decision", name: d.name, version: d.version, digest: d.digest, decision: d.decision, note: d.note } });
    const r = yield* reviewFor(d.name, d.version, d.digest);

    if (!r) return fail(404, "No such review.");

    if (r.human_state === "none") return fail(409, "This review found nothing; there is no flag to confirm or dismiss.");
    const sql = yield* SqlClient.SqlClient;
    const at = yield* (yield* Clock).now;
    const note = d.note === "" ? null : d.note;

    // a confirmed version is refused by the install routes while Postgres is down too: it goes on the block list
    // first, and the decision is not written when that fails (blocklist.ts). A dismissal leaves it for the cron's sync.
    if (d.decision === "confirm") {
      yield* blockBeforeCommit({ confirmed: [{ name: d.name, version: d.version, digest: d.digest }] }).pipe(
        Effect.mapError(() => refuse(503, "The registry could not record this decision where the install routes read it during an outage, so nothing changed. Try again.")),
      );
    }

    yield* query(
      "decide",
      sql`UPDATE reviews SET human_state = ${d.decision === "confirm" ? "confirmed" : "dismissed"}, human_by = ${viewer.githubLogin ?? viewer.user.name},
              human_at = ${at}, human_note = ${note}
          WHERE package = ${d.name} AND version = ${d.version} AND digest = ${d.digest}`,
      none,
    );

    return json({ ok: true });
  });

// ---------- a maintainer's flags ----------
/**
 * Every AI flag on `names` (a person's own packages, "Your packages"), newest first: the version, where it stands and
 * the findings, redacted as every review row is. A withheld version's come rebuilt from allowed fields. Empty while
 * the AI review is off.
 */
export const flagsForPackages = (names: readonly string[]) =>
  Effect.gen(function* () {
    const out = new Map<string, { version: string; state: PublicState; reviewedAt: string; verdict: "malicious" | "suspicious" | null; summary: string; findings: WireFinding[]; note: string | null }[]>();

    if (names.length === 0 || Option.isNone(yield* Effect.serviceOption(ReviewConfig))) return out;
    const sql = yield* SqlClient.SqlClient;

    const rows = yield* query(
      "maintainer flags",
      // apm's own packages only, as isMaintainer: a name npm serves is nobody's here
      sql`SELECT r.* FROM reviews r JOIN packages p ON p.name = r.package
          WHERE r.package = ANY(${[...names]}) AND r.human_state <> 'none' ORDER BY r.reviewed_at DESC LIMIT 200`,
      all(ReviewRow),
    );

    const withheld = yield* withheldOf(rows);
    const hold = rows.some((r) => publicState(r) === "under-review") ? yield* flagsHold : true;

    for (const stored of rows) {
      const r = withheld.has(`${stored.package}@${stored.version}`) ? withheldReview(stored) : stored;
      const p = privateView(r);
      const list = out.get(r.package) ?? [];

      list.push({ version: r.version, state: heldState(publicState(r), hold), reviewedAt: iso(r.reviewed_at), verdict: p.verdict, summary: p.summary, findings: p.findings, note: r.human_note });
      out.set(r.package, list);
    }

    return out;
  });

// ---------- the off switch ----------
// "AI flags hold installs": on, an AI flag a person has not decided is review-first for agents (under-review); off, it
// is a note (flagged). Stored in review_switch and read on every request that meets an open flag, so a change counts on
// the next request, with no deploy. Confirmed-malicious decisions, the score and refusals do not read it.

const SwitchRow = z.object({ value: z.boolean(), changed_by: z.string(), changed_at: Int });

const switchRow = Effect.flatMap(SqlClient.SqlClient, (sql) => query("switch: read", sql`SELECT value, changed_by, changed_at FROM review_switch WHERE name = 'flags-hold'`, one(SwitchRow)));

/**
 * Whether an AI flag a person has not decided holds installs right now: the stored switch, else the deploy's default.
 * A read that fails holds, as before the switch existed.
 */
export const flagsHold: Effect.Effect<boolean, never, SqlClient.SqlClient | Clock> = Effect.gen(function* () {
  const found = yield* Effect.serviceOption(ReviewConfig);
  const fallback = Option.isSome(found) ? found.value.flagsHoldDefault : true;
  const row = yield* switchRow;

  return row?.value ?? fallback;
}).pipe(Effect.orElseSucceed(() => true));

const SwitchBody = z.object({ hold: z.boolean(), ...ProofFields });

/** Sets the switch with a fresh factor made for exactly this value; logs who and when beside the review decisions. */
const switchResponse = (req: Request, viewer: SessionViewer) =>
  Effect.gen(function* () {
    const body = yield* parseBody(req, SwitchBody, 4096);
    // never covered by the decision window: a factor for this change, this value, from this session
    yield* secondFactor({ session: viewer.via.session, body, action: { kind: "review-switch", hold: body.hold } });
    const sql = yield* SqlClient.SqlClient;
    const store = yield* Store;
    const at = yield* (yield* Clock).now;
    const by = viewer.githubLogin ?? viewer.user.name;

    yield* store.tx(
      Effect.gen(function* () {
        yield* query(
          "switch: write",
          sql`INSERT INTO review_switch (name, value, changed_by, changed_at) VALUES ('flags-hold', ${body.hold}, ${by}, ${at})
              ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value, changed_by = EXCLUDED.changed_by, changed_at = EXCLUDED.changed_at`,
          none,
        );
        yield* query("switch: log", sql`INSERT INTO review_switch_log (name, value, changed_by, changed_at) VALUES ('flags-hold', ${body.hold}, ${by}, ${at})`, none);
      }),
    );

    return json({ ok: true, hold: body.hold, changedBy: by, changedAt: iso(at) }, 200, { "cache-control": "no-store" });
  });

const SwitchLogRow = z.object({ value: z.boolean(), changed_by: z.string(), changed_at: Int });

/** The switch as the queue shows it: its value, where it comes from, and its recent changes. */
const switchState = (settings: ReviewSettings) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const row = yield* switchRow;
    const log = yield* query("switch: history", sql`SELECT value, changed_by, changed_at FROM review_switch_log WHERE name = 'flags-hold' ORDER BY changed_at DESC, id DESC LIMIT 20`, all(SwitchLogRow));

    return {
      hold: row?.value ?? settings.flagsHoldDefault,
      source: row ? ("set" as const) : ("default" as const),
      defaultHold: settings.flagsHoldDefault,
      changedBy: row?.changed_by ?? null,
      changedAt: row ? iso(row.changed_at) : null,
      history: log.map((l) => ({ hold: l.value, by: l.changed_by, at: iso(l.changed_at) })),
    };
  });

// ---------- the decision window ----------
// One factor (a code, or a passkey check made for "review-unlock") opens decisions for DECISION_WINDOW_MS, for this
// session alone: the window is keyed by the session token's sha256, the account and its scope. Another session, another
// account or another kind of change (the switch) finds no window. It ends when it expires or the reviewer locks it.

/** How long one unlock lets a reviewer confirm and dismiss without another factor. */
export const DECISION_WINDOW_MS = 10 * 60_000;

const DECISION_SCOPE = "review-decisions";

const sessionHash = (s: SignedIn): string => createHash("sha256").update(s.sessionToken).digest("hex");

/** When this session's decision window ends, or null when none is open. */
const decisionWindow = (viewer: SessionViewer) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const now = yield* (yield* Clock).now;

    const row = yield* query(
      "window: read",
      sql`SELECT expires_at FROM step_up_windows
          WHERE session_hash = ${sessionHash(viewer.via.session)} AND auth_user_id = ${viewer.via.session.authUserId} AND scope = ${DECISION_SCOPE}
            AND opened_at <= ${now} AND expires_at > ${now}`,
      one(z.object({ expires_at: Int })),
    );

    return row?.expires_at ?? null;
  });

const UnlockBody = z.object(ProofFields);

const unlockResponse = (req: Request, viewer: SessionViewer) =>
  Effect.gen(function* () {
    const body = yield* parseBody(req, UnlockBody, 4096);
    yield* secondFactor({ session: viewer.via.session, body, action: { kind: "review-unlock" } });
    const sql = yield* SqlClient.SqlClient;
    const at = yield* (yield* Clock).now;
    const until = at + DECISION_WINDOW_MS;

    yield* query("window: purge", sql`DELETE FROM step_up_windows WHERE expires_at <= ${at}`, none);
    yield* query(
      "window: open",
      sql`INSERT INTO step_up_windows (session_hash, auth_user_id, scope, opened_at, expires_at)
          VALUES (${sessionHash(viewer.via.session)}, ${viewer.via.session.authUserId}, ${DECISION_SCOPE}, ${at}, ${until})
          ON CONFLICT (session_hash, scope) DO UPDATE SET auth_user_id = EXCLUDED.auth_user_id, opened_at = EXCLUDED.opened_at, expires_at = EXCLUDED.expires_at`,
      none,
    );

    return json({ ok: true, until: iso(until) }, 200, { "cache-control": "no-store" });
  });

const lockResponse = (viewer: SessionViewer) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    yield* query("window: close", sql`DELETE FROM step_up_windows WHERE session_hash = ${sessionHash(viewer.via.session)} AND scope = ${DECISION_SCOPE}`, none);

    return json({ ok: true }, 200, { "cache-control": "no-store" });
  });

/** A decision goes ahead on a factor sent with it (as before the window) or on this session's open window. */
const decisionAllowed = (input: { viewer: SessionViewer; body: ProofInput; action: SessionAction }) =>
  Effect.gen(function* () {
    if (input.body.code !== undefined || input.body.confirmation !== undefined) return yield* secondFactor({ session: input.viewer.via.session, body: input.body, action: input.action });

    if ((yield* decisionWindow(input.viewer)) === null) return yield* Effect.fail(refuse(401, "Unlock decisions first: confirm it's you with your authenticator code or passkey."));
  });

// ---------- bulk dismiss ----------
const BulkKey = z.object({ name: z.string().min(1).max(214), version: z.string().min(1).max(256), digest: z.string().min(1).max(200) });

const BulkBody = z.object({ items: z.array(BulkKey).min(1).max(100), note: z.string().trim().max(2000).default("") });

/** Dismisses many open flags at once, inside an open window only. A flag already decided is left as it is. */
const bulkDismissResponse = (req: Request, viewer: SessionViewer) =>
  Effect.gen(function* () {
    const body = yield* parseBody(req, BulkBody, MAX_REVIEW_BODY_BYTES);

    if ((yield* decisionWindow(viewer)) === null) return fail(401, "Unlock decisions first: confirm it's you with your authenticator code or passkey.");
    const sql = yield* SqlClient.SqlClient;
    const store = yield* Store;
    const at = yield* (yield* Clock).now;
    const note = body.note === "" ? null : body.note;
    const by = viewer.githubLogin ?? viewer.user.name;

    const dismissed = yield* store.tx(
      Effect.forEach(body.items, (i) =>
        query(
          "bulk dismiss",
          sql`UPDATE reviews SET human_state = 'dismissed', human_by = ${by}, human_at = ${at}, human_note = ${note}
              WHERE package = ${i.name} AND version = ${i.version} AND digest = ${i.digest} AND human_state = 'pending' RETURNING package`,
          z.array(z.unknown()).transform((rows) => rows.length),
        ),
      ),
    );

    return json({ ok: true, dismissed: dismissed.reduce((a, b) => a + b, 0) }, 200, { "cache-control": "no-store" });
  });

// ---------- the public status ----------
const Counts = z.object({ reviewed: Int, flagged: Int, waiting: Int, dismissed: Int, confirmed: Int });

const WaitingRow = z.object({ package: z.string(), version: z.string(), reviewed_at: Int, weekly: Int.nullable() });

/**
 * GET /-/apm/v1/reviews: what the AI review has done, in numbers, and which versions wait for a person. Names,
 * versions and times only: no finding, quote, summary or note of an open flag.
 */
const statusResponse = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  const counts = yield* query(
    "status: counts",
    sql`SELECT COUNT(*) AS reviewed,
               COUNT(*) FILTER (WHERE human_state <> 'none') AS flagged,
               COUNT(*) FILTER (WHERE human_state = 'pending') AS waiting,
               COUNT(*) FILTER (WHERE human_state = 'dismissed') AS dismissed,
               COUNT(*) FILTER (WHERE human_state = 'confirmed') AS confirmed
          FROM reviews`,
    one(Counts),
  );

  const waiting = yield* query(
    "status: waiting",
    sql`SELECT r.package, r.version, r.reviewed_at, d.weekly FROM reviews r LEFT JOIN review_downloads d ON d.package = r.package
        WHERE r.human_state = 'pending' ORDER BY d.weekly DESC NULLS LAST, r.reviewed_at LIMIT 200`,
    all(WaitingRow),
  );

  return json(
    {
      counts: counts ?? { reviewed: 0, flagged: 0, waiting: 0, dismissed: 0, confirmed: 0 },
      flagsHold: yield* flagsHold,
      waiting: waiting.map((w) => ({ name: w.package, version: w.version, since: iso(w.reviewed_at), weeklyDownloads: w.weekly })),
    },
    200,
    { "cache-control": "public, max-age=30" },
  );
});

// ---------- router ----------
export const reviewRoute = (
  req: Request,
  url: URL,
  caller: Caller,
): Effect.Effect<Response | null, HttpFailure | StoreError | AuthError, Store | SqlClient.SqlClient | Clock | RegistryConfig | Auth | RequestMemory> =>
  Effect.gen(function* () {
    const p = url.pathname;

    const isReviewPath =
      p === "/-/apm/v1/review-jobs" || p.startsWith("/-/apm/v1/review-jobs/") || p.startsWith("/-/apm/v1/review-admin/") || p.startsWith("/-/apm/v1/review/") || p === "/-/apm/v1/reviews";

    if (!isReviewPath) return null;
    const found = yield* Effect.serviceOption(ReviewConfig);

    if (Option.isNone(found)) return null;
    const settings = found.value;

    if (p === "/-/apm/v1/reviews") return req.method === "GET" || req.method === "HEAD" ? yield* statusResponse : fail(405, "Method not allowed");

    if (p === "/-/apm/v1/review-jobs" || p.startsWith("/-/apm/v1/review-jobs/")) {
      if (!isService(req, settings)) return fail(401, "This route is for the AI reviewer's service token.");

      if (p === "/-/apm/v1/review-jobs" && req.method === "GET") return yield* leaseResponse(url, settings);
      const m = /^\/-\/apm\/v1\/review-jobs\/([A-Za-z0-9_-]{1,64})\/(result|release)$/.exec(p);

      if (!m?.[1] || req.method !== "POST") return fail(404, "Not found");

      return m[2] === "result" ? yield* resultResponse(req, m[1]) : yield* releaseResponse(req, m[1]);
    }

    if (p.startsWith("/-/apm/v1/review-admin/")) {
      const viewer = yield* viewerOf(req, caller);

      if (viewer.kind !== "user") return fail(401, "Sign in first.");

      if (!isAdmin(viewer, settings)) {
        return fail(
          403,
          viewer.via.kind === "token" ? "The review queue is on the website only: sign in there. Tokens cannot read it or decide." : "Only apm's reviewers can see this queue.",
        );
      }

      if (p === "/-/apm/v1/review-admin/queue" && req.method === "GET") return yield* queueResponse(viewer, settings);

      if (req.method === "POST" && p.startsWith("/-/apm/v1/review-admin/")) {
        const action = p.slice("/-/apm/v1/review-admin/".length);

        if (action === "decide" || action === "dismiss" || action === "unlock" || action === "lock" || action === "switch") {
          // cookie-authenticated writes come from the website only
          yield* checkOrigin(req, viewer);

          switch (action) {
            case "decide":
              return yield* decideResponse(req, viewer);
            case "dismiss":
              return yield* bulkDismissResponse(req, viewer);
            case "unlock":
              return yield* unlockResponse(req, viewer);
            case "lock":
              return yield* lockResponse(viewer);
            case "switch":
              return yield* switchResponse(req, viewer);
            default: {
              const _exhaustive: never = action;

              return _exhaustive;
            }
          }
        }
      }

      return fail(404, "Not found");
    }

    const sp = splitPath(p.slice("/-/apm/v1/review".length));

    if (!sp) return fail(404, "Not found");

    if (req.method === "GET" && sp.rest.length === 1) return yield* reviewResponse(req, caller, sp.name, sp.rest[0], settings);

    if (req.method === "POST" && sp.rest.length === 2 && sp.rest[1] === "request") return yield* requestResponse(req, caller, sp.name, sp.rest[0], settings);

    return fail(404, "Not found");
  });
