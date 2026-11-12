// AI release review, registry side: the review-job queue, the reviewer's service-token routes, stored
// results, the public and maintainer views, "Request AI review", and the owner-only queue where a
// person confirms or dismisses a flag. The model never runs here: a separate reviewer process
// (apps/reviewer) leases jobs over HTTP and posts results back. See docs/AI-REVIEW.md.
import { createHash, timingSafeEqual } from "node:crypto";
import { Context, Effect, Option } from "effect";
import type { SqlError } from "effect/sql/SqlError";
import * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { ReleaseBody, ResultBody, ReviewResult, type EnqueueReason, type ReviewJob, type WireFinding } from "@apm/ai-review";
import { isValidPackageName } from "@apm/core";
import { ReviewDecision } from "./actions.ts";
import { Auth, type SignedIn } from "./auth.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig } from "./config.ts";
import { Store, type User, type VersionRecord } from "./db.ts";
import { refuse, StoreError, type AuthError, type HttpFailure } from "./errors.ts";
import { randomId } from "./hash.ts";
import { fail, json, parseBody } from "./http.ts";
import { requireSiteOrigin } from "./origin.ts";
import { order } from "./semver.ts";
import { splitPath, tagTarget, tarballUrl, type Caller } from "./server.ts";
import { ProofFields, secondFactor } from "./step-up.ts";
import { digestLabel, digestOf, Upstream, type UpstreamPackage } from "./upstream.ts";
import { timed, timingOrNull } from "./timing.ts";
import { fileReferences, INVALID_DEPENDENCY, isWithheld, WITHHELD_ISSUE } from "./withheld.ts";

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
};

export const REVIEW_DEFAULTS = {
  popularWeekly: 10_000,
  downloadsUrl: "https://api.npmjs.org/downloads/point/last-week/",
  leaseMs: 15 * 60_000,
  requestsPerHour: 5,
  maxAttempts: 5,
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

const ReviewRow = z.object({
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
});

type StoredReview = z.infer<typeof ReviewRow>;

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
  Effect.flatMap(timingOrNull, (timing) => timed(timing, "db")(effect)).pipe(
    Effect.mapError((cause) => new StoreError({ operation: `review.${operation}`, cause })),
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

    return out;
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

    return upstreamCatalog(yield* upstream.value.probe(name));
  });

/**
 * A package's versions, statuses and checksums, for the review answer: an upstream package's come from the listing,
 * which reads no scores from the database. A local version's status is read from the database on every call.
 */
const catalogListing = (name: string) =>
  Effect.gen(function* () {
    const store = yield* Store;
    const pkg = yield* store.getPackage(name);

    if (pkg) return { kind: "ok", source: "local", distTags: pkg.distTags, versions: yield* store.listVersions(name) } satisfies Catalog<Listed>;
    const upstream = yield* Effect.serviceOption(Upstream);

    if (Option.isNone(upstream)) return { kind: "absent" } satisfies Catalog<Listed>;

    return upstreamCatalog(yield* upstream.value.listing(name));
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
 */
function isAdmin(v: Viewer, settings: ReviewSettings): v is SessionViewer {
  return v.kind === "user" && v.via.kind === "session" && v.githubLogin !== null && adminsOf(settings).has(v.githubLogin);
}

const isMaintainer = (v: Viewer, name: string) =>
  v.kind === "user" ? Effect.map(Store.use((store) => store.owners(name)), (owners) => owners.includes(v.user.name)) : Effect.succeed(false);

/** Cookie-authenticated writes must come from the website (origin.ts); a token's requests are not a browser's. */
export const checkOrigin = (req: Request, v: Viewer) => (v.kind === "user" && v.via.kind === "session" ? requireSiteOrigin(req) : Effect.void);

function isService(req: Request, settings: ReviewSettings): boolean {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.get("authorization") ?? "");
  const expected = Buffer.from(settings.serviceTokenHash, "hex");

  return m?.[1] !== undefined && expected.length === 32 && timingSafeEqual(createHash("sha256").update(m[1].trim()).digest(), expected);
}

// ---------- views ----------
type PublicState = "found-nothing" | "under-review" | "no-answer" | "confirmed" | "cleared";

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

function publicView(r: StoredReview) {
  const state = publicState(r);

  return {
    state,
    model: r.result.model,
    reviewedAt: r.result.reviewedAt,
    coverage: r.result.coverage,
    read: r.result.read,
    notRead: r.result.notRead,
    // findings go public only after a person confirms them
    findings: state === "confirmed" ? findingsOf(r.result) : [],
    decidedAt: r.human_at === null ? null : iso(r.human_at),
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
    const cat = yield* catalogListing(name);
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
    else if (yield* isMaintainer(viewer, name)) role = "maintainer";
    const found = got.digest ? yield* reviewAndJob(name, v.version, got.digest) : null;
    const stored = found?.review ?? null;
    const redacted = isWithheld(v.status);
    const review = stored && redacted ? withheldReview(stored) : stored;
    const job = found?.job ?? null;
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
        // a revoked version's findings keep their file, line and sentence, not the quoted source
        redacted,
        // `status` folds a leased job into "queued"; `job` keeps them apart for clients that act on the difference
        job: job?.state ?? null,
        review: review ? publicView(review) : null,
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
              VALUES (${job.package}, ${job.version}, ${job.digest}, ${r.outcome}, ${JSON.stringify(r)}::jsonb, ${at}, ${human}, NULL, NULL, NULL)
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

const queueResponse = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  const pending = yield* query("queue: pending", sql`SELECT * FROM reviews WHERE human_state = 'pending' ORDER BY reviewed_at LIMIT 200`, all(ReviewRow));

  const decided = yield* query(
    "queue: decided",
    sql`SELECT * FROM reviews WHERE human_state IN ('confirmed', 'dismissed') ORDER BY human_at DESC LIMIT 50`,
    all(ReviewRow),
  );

  // a withheld version's review is rebuilt before any view is: the admin sees where and what, not the source
  const withheld = yield* withheldOf([...pending, ...decided]);

  const item = (stored: StoredReview) => {
    const redacted = withheld.has(`${stored.package}@${stored.version}`);
    const r = redacted ? withheldReview(stored) : stored;

    return { name: r.package, version: r.version, digest: r.digest, reviewedAt: iso(r.reviewed_at), redacted, public: publicView(r), private: privateView(r), decidedBy: r.human_by };
  };

  return json(
    {
      pending: pending.map(item),
      decided: decided.map(item),
      // the stronger-model step plugs in at the reviewer (apps/reviewer/src/second-stage.ts); none is configured
      secondStage: null,
    },
    200,
    { "cache-control": "no-store" },
  );
});

const decideResponse = (req: Request, viewer: SessionViewer) =>
  Effect.gen(function* () {
    const d = yield* parseBody(req, DecideBody, MAX_REVIEW_BODY_BYTES);
    // a decision changes what the public sees: a fresh code or passkey check for exactly this one
    yield* secondFactor({ session: viewer.via.session, body: d, action: { kind: "review-decision", name: d.name, version: d.version, digest: d.digest, decision: d.decision, note: d.note } });
    const r = yield* reviewFor(d.name, d.version, d.digest);

    if (!r) return fail(404, "No such review.");

    if (r.human_state === "none") return fail(409, "This review found nothing; there is no flag to confirm or dismiss.");
    const sql = yield* SqlClient.SqlClient;
    const at = yield* (yield* Clock).now;
    const note = d.note === "" ? null : d.note;
    yield* query(
      "decide",
      sql`UPDATE reviews SET human_state = ${d.decision === "confirm" ? "confirmed" : "dismissed"}, human_by = ${viewer.githubLogin ?? viewer.user.name},
              human_at = ${at}, human_note = ${note}
          WHERE package = ${d.name} AND version = ${d.version} AND digest = ${d.digest}`,
      none,
    );

    return json({ ok: true });
  });

// ---------- router ----------
export const reviewRoute = (
  req: Request,
  url: URL,
  caller: Caller,
): Effect.Effect<Response | null, HttpFailure | StoreError | AuthError, Store | SqlClient.SqlClient | Clock | RegistryConfig | Auth> =>
  Effect.gen(function* () {
    const p = url.pathname;
    const isReviewPath = p === "/-/apm/v1/review-jobs" || p.startsWith("/-/apm/v1/review-jobs/") || p.startsWith("/-/apm/v1/review-admin/") || p.startsWith("/-/apm/v1/review/");

    if (!isReviewPath) return null;
    const found = yield* Effect.serviceOption(ReviewConfig);

    if (Option.isNone(found)) return null;
    const settings = found.value;

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

      if (p === "/-/apm/v1/review-admin/queue" && req.method === "GET") return yield* queueResponse;

      if (p === "/-/apm/v1/review-admin/decide" && req.method === "POST") {
        yield* checkOrigin(req, viewer);

        return yield* decideResponse(req, viewer);
      }

      return fail(404, "Not found");
    }

    const sp = splitPath(p.slice("/-/apm/v1/review".length));

    if (!sp) return fail(404, "Not found");

    if (req.method === "GET" && sp.rest.length === 1) return yield* reviewResponse(req, caller, sp.name, sp.rest[0], settings);

    if (req.method === "POST" && sp.rest.length === 2 && sp.rest[1] === "request") return yield* requestResponse(req, caller, sp.name, sp.rest[0], settings);

    return fail(404, "Not found");
  });
