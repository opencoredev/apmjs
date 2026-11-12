// AI release review, registry side: the review-job queue, the reviewer's service-token routes, stored
// results, the public and maintainer views, "Request AI review", and the owner-only queue where a
// person confirms or dismisses a flag. The model never runs here: a separate reviewer process
// (apps/reviewer) leases jobs over HTTP and posts results back. See docs/AI-REVIEW.md.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { ReleaseBody, ResultBody, ReviewResult, type EnqueueReason, type ReviewJob, type WireFinding } from "@apm/ai-review";
import type { ApmAuth } from "./auth.ts";
import type { User, VersionRecord } from "./db.ts";
import { fail, json, splitPath, tarballUrl, type Auth, type Ctx } from "./server.ts";
import { digestLabel, digestOf, type Upstream, type UpstreamPackage } from "./upstream.ts";

export type ReviewOptions = {
  /** sha256 (hex) of the reviewer's service token. The token itself lives in a 0600 file. */
  serviceTokenHash: string;
  /** GitHub logins that may confirm or dismiss flagged reviews. */
  admins: readonly string[];
  /** Upstream versions are reviewed when their package has at least this many weekly downloads. */
  popularWeekly?: number;
  /** npm's download-count API, ending in "/". */
  downloadsUrl?: string;
  /** How long a leased job stays with one reviewer before it returns to the queue. */
  leaseMs?: number;
  /** "Request AI review" presses per user per hour. */
  requestsPerHour?: number;
  /** Leases a job may take before it is marked failed. */
  maxAttempts?: number;
};

const DEFAULTS = {
  popularWeekly: 10_000,
  downloadsUrl: "https://api.npmjs.org/downloads/point/last-week/",
  leaseMs: 15 * 60_000,
  requestsPerHour: 5,
  maxAttempts: 5,
} as const;

const HOUR = 3_600_000;
const DOWNLOADS_TTL_MS = 24 * HOUR;
const DOWNLOADS_FAILURE_TTL_MS = HOUR;
const MAX_LEASE_BATCH = 16;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS review_jobs (
  id TEXT PRIMARY KEY,
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  source TEXT NOT NULL,
  reasons TEXT NOT NULL,
  priority INTEGER NOT NULL,
  state TEXT NOT NULL,
  lease_id TEXT,
  lease_expires_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  enqueued_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS review_jobs_key ON review_jobs(package, version, digest);
CREATE INDEX IF NOT EXISTS review_jobs_ready ON review_jobs(state, priority, enqueued_at);
CREATE TABLE IF NOT EXISTS reviews (
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  outcome TEXT NOT NULL,
  result TEXT NOT NULL,
  reviewed_at INTEGER NOT NULL,
  human_state TEXT NOT NULL,
  human_by TEXT,
  human_at INTEGER,
  human_note TEXT,
  PRIMARY KEY (package, version, digest)
);
CREATE INDEX IF NOT EXISTS reviews_human ON reviews(human_state, reviewed_at);
CREATE TABLE IF NOT EXISTS review_seen (
  package TEXT PRIMARY KEY,
  newest_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS review_downloads (
  package TEXT PRIMARY KEY,
  weekly INTEGER,
  fetched_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS review_requests (
  actor TEXT NOT NULL,
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS review_requests_actor ON review_requests(actor, at);
`;

type Source = "local" | "upstream";

type JobState = "queued" | "leased" | "done" | "failed";

/** none: nothing for a person to do (benign). pending: waits in the owner queue. */
type HumanState = "none" | "pending" | "confirmed" | "dismissed";

const Reasons = z.array(z.enum(["publish", "first-publish", "install-script", "popular", "requested"]));

const JobRow = z.object({
  id: z.string(),
  package: z.string(),
  version: z.string(),
  digest: z.string(),
  source: z.enum(["local", "upstream"]),
  reasons: z.string(),
  priority: z.number(),
  state: z.enum(["queued", "leased", "done", "failed"]),
  lease_id: z.string().nullable(),
  lease_expires_at: z.number().nullable(),
  attempts: z.number(),
  last_error: z.string().nullable(),
  enqueued_at: z.number(),
  updated_at: z.number(),
});

type JobRow = z.infer<typeof JobRow>;

const ReviewRow = z.object({
  package: z.string(),
  version: z.string(),
  digest: z.string(),
  outcome: z.enum(["benign", "flagged", "no-answer"]),
  result: z.string(),
  reviewed_at: z.number(),
  human_state: z.enum(["none", "pending", "confirmed", "dismissed"]),
  human_by: z.string().nullable(),
  human_at: z.number().nullable(),
  human_note: z.string().nullable(),
});

type StoredReview = Omit<z.infer<typeof ReviewRow>, "result"> & { result: ReviewResult };

/** Lower runs first. */
const PRIORITY: Record<EnqueueReason, number> = { requested: 0, publish: 1, "first-publish": 2, "install-script": 2, popular: 3 };

function priorityOf(reasons: readonly EnqueueReason[]): number {
  return Math.min(...reasons.map((r) => PRIORITY[r]), 9);
}

function sha256(text: string): Buffer {
  return createHash("sha256").update(text).digest();
}

function newId(): string {
  return randomBytes(12).toString("base64url");
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

    if (Bun.semver.order(v.version, version) >= 0) continue;

    if (best === null || Bun.semver.order(v.version, best.version) > 0) best = v;
  }

  return best;
}

function labelOf(v: VersionRecord): string | null {
  const d = digestOf(v);

  return d ? digestLabel(d) : null;
}

/** Path of a tarball relative to the registry root, as the reviewer requests it. */
function tarballPath(name: string, version: string): string {
  return tarballUrl("", name, version);
}

const DownloadsAnswer = z.object({ downloads: z.number() });

type Viewer = { kind: "anon" } | { kind: "user"; user: User; githubLogin: string | null; via: "token" | "session" };

export type ReviewModule = {
  routes: (req: Request, url: URL, auth: Auth) => Promise<Response | null>;
  /** Called after a local version is committed. */
  onLocalCommit: (v: { name: string; version: string; firstPublish: boolean }) => void;
  /** Called when the upstream packument of a package is fetched (not on cache hits). */
  onUpstreamPackage: (pkg: UpstreamPackage) => void;
  /** Settles background work (download lookups); for tests and shutdown. */
  idle: () => Promise<void>;
};

export function reviewModule(input: { ctx: Ctx; auth: ApmAuth; upstream: Upstream | null; options: ReviewOptions }): ReviewModule {
  const { ctx, auth, upstream } = input;
  const opts = { ...DEFAULTS, ...input.options };
  const admins = new Set(opts.admins.map((a) => a.trim().toLowerCase()).filter((a) => a !== ""));
  const tokenHash = Buffer.from(opts.serviceTokenHash, "hex");
  const db = ctx.store.db;
  const pending = new Set<Promise<void>>();

  if (tokenHash.length !== 32) throw new Error("review.serviceTokenHash must be a sha256 hex digest");
  db.exec(SCHEMA);

  // ---------- storage ----------
  function jobByKey(name: string, version: string, digest: string): JobRow | null {
    const row = db.query("SELECT * FROM review_jobs WHERE package = ? AND version = ? AND digest = ?").get(name, version, digest);

    return row ? JobRow.parse(row) : null;
  }

  function jobById(id: string): JobRow | null {
    const row = db.query("SELECT * FROM review_jobs WHERE id = ?").get(id);

    return row ? JobRow.parse(row) : null;
  }

  function toReview(r: z.infer<typeof ReviewRow>): StoredReview {
    return { ...r, result: ReviewResult.parse(JSON.parse(r.result)) };
  }

  function reviewFor(name: string, version: string, digest: string): StoredReview | null {
    const row = db.query("SELECT * FROM reviews WHERE package = ? AND version = ? AND digest = ?").get(name, version, digest);

    return row ? toReview(ReviewRow.parse(row)) : null;
  }

  /** Adds a job, or merges reasons into the waiting one. A finished job is reopened only for a request after no answer. */
  function enqueue(job: { name: string; version: string; digest: string; source: Source; reasons: EnqueueReason[] }): "queued" | "exists" {
    const at = ctx.now();

    return ctx.store.tx(() => {
      const cur = jobByKey(job.name, job.version, job.digest);

      if (!cur) {
        db.query(
          "INSERT INTO review_jobs (id, package, version, digest, source, reasons, priority, state, enqueued_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)",
        ).run(newId(), job.name, job.version, job.digest, job.source, JSON.stringify(job.reasons), priorityOf(job.reasons), at, at);

        return "queued";
      }

      const reasons = [...new Set([...Reasons.parse(JSON.parse(cur.reasons)), ...job.reasons])];
      const reopen = job.reasons.includes("requested") && (cur.state === "failed" || reviewFor(job.name, job.version, job.digest)?.outcome === "no-answer");

      if (cur.state === "queued" || cur.state === "leased" || reopen) {
        db.query("UPDATE review_jobs SET reasons = ?, priority = ?, state = CASE WHEN ? THEN 'queued' ELSE state END, attempts = CASE WHEN ? THEN 0 ELSE attempts END, updated_at = ? WHERE id = ?").run(
          JSON.stringify(reasons),
          Math.min(cur.priority, priorityOf(job.reasons)),
          reopen ? 1 : 0,
          reopen ? 1 : 0,
          at,
          cur.id,
        );

        return reopen ? "queued" : "exists";
      }

      return "exists";
    });
  }

  function setJobState(id: string, state: JobState, error: string | null): void {
    db.query("UPDATE review_jobs SET state = ?, lease_id = NULL, lease_expires_at = NULL, last_error = ?, updated_at = ? WHERE id = ?").run(state, error, ctx.now(), id);
  }

  /** Takes up to `max` ready jobs; expired leases count as ready again. */
  function takeJobs(max: number): JobRow[] {
    const now = ctx.now();

    return ctx.store.tx(() => {
      db.query("UPDATE review_jobs SET state = 'queued', lease_id = NULL, lease_expires_at = NULL, updated_at = ? WHERE state = 'leased' AND lease_expires_at <= ?").run(now, now);

      db.query("UPDATE review_jobs SET state = 'failed', last_error = 'too many attempts', updated_at = ? WHERE state = 'queued' AND attempts >= ?").run(now, opts.maxAttempts);

      const rows = db
        .query("SELECT * FROM review_jobs WHERE state = 'queued' ORDER BY priority, enqueued_at LIMIT ?")
        .all(max)
        .map((r) => JobRow.parse(r));

      for (const r of rows) {
        db.query("UPDATE review_jobs SET state = 'leased', lease_id = ?, lease_expires_at = ?, attempts = attempts + 1, updated_at = ? WHERE id = ?").run(newId(), now + opts.leaseMs, now, r.id);
      }

      return rows.map((r) => jobById(r.id)).filter((r): r is JobRow => r !== null);
    });
  }

  // ---------- catalog ----------
  type Catalog = { kind: "ok"; source: Source; versions: VersionRecord[] } | { kind: "absent" } | { kind: "unavailable" };

  async function catalog(name: string): Promise<Catalog> {
    if (ctx.store.getPackage(name)) return { kind: "ok", source: "local", versions: ctx.store.listVersions(name) };

    if (!upstream) return { kind: "absent" };
    const probe = await upstream.probe(ctx, name);

    switch (probe.kind) {
      case "found":
        return { kind: "ok", source: "upstream", versions: probe.pkg.versions };
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

  /** The job as the reviewer sees it, or why it cannot be built. */
  async function jobPayload(row: JobRow): Promise<{ kind: "ok"; job: ReviewJob } | { kind: "gone"; why: string } | { kind: "later"; why: string }> {
    const cat = await catalog(row.package);

    if (cat.kind === "unavailable") return { kind: "later", why: "the upstream registry could not be reached" };

    if (cat.kind === "absent") return { kind: "gone", why: "the package is no longer published" };
    const v = cat.versions.find((x) => x.version === row.version);

    if (!v || v.status === "revoked") return { kind: "gone", why: "the version is no longer served" };

    if (labelOf(v) !== row.digest) return { kind: "gone", why: "the version's tarball checksum changed" };
    const prev = previousVersionOf(cat.versions, row.version);
    const prevDigest = prev ? labelOf(prev) : null;

    return {
      kind: "ok",
      job: {
        id: row.id,
        leaseId: row.lease_id ?? "",
        leaseExpiresAt: iso(row.lease_expires_at ?? ctx.now()),
        name: row.package,
        version: row.version,
        digest: row.digest,
        tarballPath: tarballPath(row.package, row.version),
        previous: prev && prevDigest ? { version: prev.version, digest: prevDigest, tarballPath: tarballPath(row.package, prev.version) } : null,
        reasons: Reasons.parse(JSON.parse(row.reasons)),
      },
    };
  }

  // ---------- enqueue policy ----------
  async function weeklyDownloads(name: string): Promise<number | null> {
    const now = ctx.now();
    const cached = db.query("SELECT weekly, fetched_at FROM review_downloads WHERE package = ?").get(name);
    const hit = cached ? z.object({ weekly: z.number().nullable(), fetched_at: z.number() }).parse(cached) : null;

    if (hit && now - hit.fetched_at < (hit.weekly === null ? DOWNLOADS_FAILURE_TTL_MS : DOWNLOADS_TTL_MS)) return hit.weekly;
    let weekly: number | null = null;

    try {
      const res = await fetch(`${opts.downloadsUrl}${name}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000) });

      if (res.ok) {
        const parsed = DownloadsAnswer.safeParse(await res.json());

        weekly = parsed.success ? parsed.data.downloads : null;
      } else {
        await res.body?.cancel();
      }
    } catch {
      weekly = null;
    }

    db.query("INSERT OR REPLACE INTO review_downloads (package, weekly, fetched_at) VALUES (?, ?, ?)").run(name, weekly, now);

    return weekly;
  }

  function background(work: Promise<void>): void {
    const p = work.catch((cause: unknown) => {
      process.stderr.write(`apm review: background work failed: ${cause instanceof Error ? cause.message : String(cause)}\n`);
    });

    pending.add(p);
    void p.finally(() => pending.delete(p));
  }

  /** Versions apm sees for the first time: the newest on first sight of a package, then every newer one. */
  async function considerUpstream(pkg: UpstreamPackage): Promise<void> {
    const versions = pkg.versions.filter((v) => v.published_at > 0);
    const newest = Math.max(0, ...versions.map((v) => v.published_at));
    const seenRow = db.query("SELECT newest_at FROM review_seen WHERE package = ?").get(pkg.name);
    const seen = seenRow ? z.object({ newest_at: z.number() }).parse(seenRow).newest_at : null;

    if (seen !== null && newest <= seen) return;
    db.query("INSERT OR REPLACE INTO review_seen (package, newest_at) VALUES (?, ?)").run(pkg.name, newest);
    const latest = pkg.distTags.latest;
    const fresh = seen === null ? versions.filter((v) => v.version === latest) : versions.filter((v) => v.published_at > seen);

    if (fresh.length === 0) return;
    let popular: boolean | null = null;

    for (const v of fresh.slice(-20)) {
      const digest = labelOf(v);

      if (!digest) continue;
      const reasons: EnqueueReason[] = [];

      if (versions.length === 1) reasons.push("first-publish");
      const prev = previousVersionOf(versions, v.version);

      if (hasInstallScript(v) && (prev === null || !hasInstallScript(prev))) reasons.push("install-script");
      popular ??= ((await weeklyDownloads(pkg.name)) ?? 0) >= opts.popularWeekly;

      if (popular) reasons.push("popular");

      if (reasons.length > 0) enqueue({ name: pkg.name, version: v.version, digest, source: "upstream", reasons });
    }
  }

  // ---------- viewers ----------
  async function viewerOf(req: Request, a: Auth): Promise<Viewer> {
    if (a.kind === "user") {
      const user = ctx.store.getUser(a.user);

      return user ? { kind: "user", user, githubLogin: user.github_login?.toLowerCase() ?? null, via: "token" } : { kind: "anon" };
    }

    const s = await auth.sessionOf(req);

    if (!s) return { kind: "anon" };
    const user = auth.apmUserOf(s.authUserId);

    return user ? { kind: "user", user, githubLogin: auth.gitHubNameOf(s.authUserId), via: "session" } : { kind: "anon" };
  }

  function isAdmin(v: Viewer): boolean {
    return v.kind === "user" && v.githubLogin !== null && admins.has(v.githubLogin);
  }

  function isMaintainer(v: Viewer, name: string): boolean {
    return v.kind === "user" && ctx.store.owners(name).includes(v.user.name);
  }

  /** Cookie-authenticated writes must come from the website or the registry itself. */
  function badOrigin(req: Request, v: Viewer): Response | null {
    const origin = req.headers.get("origin");

    if (v.kind !== "user" || v.via !== "session" || origin === null) return null;
    const allowed = new Set([new URL(ctx.access.webUrl()).origin, new URL(ctx.baseUrl()).origin]);

    return allowed.has(origin) ? null : fail(403, "Cross-site request refused.");
  }

  function isService(req: Request): boolean {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.get("authorization") ?? "");

    return m?.[1] !== undefined && timingSafeEqual(sha256(m[1].trim()), tokenHash);
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

  type Resolved = { kind: "ok"; source: Source; version: VersionRecord; digest: string | null } | { kind: "error"; res: Response };

  async function resolveVersion(name: string, version: string | undefined): Promise<Resolved> {
    if (!version) return { kind: "error", res: fail(404, "Name a version.") };
    const cat = await catalog(name);

    if (cat.kind === "unavailable") return { kind: "error", res: fail(503, "The upstream registry could not be reached.") };

    if (cat.kind === "absent") return { kind: "error", res: fail(404, "Not found") };
    const v = cat.versions.find((x) => x.version === version);

    if (!v) return { kind: "error", res: fail(404, "No such version") };

    return { kind: "ok", source: cat.source, version: v, digest: labelOf(v) };
  }

  async function reviewResponse(req: Request, a: Auth, name: string, version: string | undefined): Promise<Response> {
    const got = await resolveVersion(name, version);

    if (got.kind === "error") return got.res;
    const v = got.version;
    const viewer = await viewerOf(req, a);
    let role: "admin" | "maintainer" | "public" = "public";

    if (isAdmin(viewer)) role = "admin";
    else if (isMaintainer(viewer, name)) role = "maintainer";
    const review = got.digest ? reviewFor(name, v.version, got.digest) : null;
    const job = got.digest ? jobByKey(name, v.version, got.digest) : null;
    let status: "reviewed" | "queued" | "failed" | "not-reviewed" = "not-reviewed";

    if (review) status = "reviewed";
    else if (job?.state === "queued" || job?.state === "leased") status = "queued";
    else if (job?.state === "failed") status = "failed";

    return json(
      {
        name,
        version: v.version,
        status,
        review: review ? publicView(review) : null,
        viewer: role,
        private: review && role !== "public" ? privateView(review) : null,
        canRequest: viewer.kind === "user" && got.digest !== null && status !== "queued" && (review === null || review.result.outcome === "no-answer"),
      },
      200,
      { "cache-control": "no-store" },
    );
  }

  async function requestResponse(req: Request, a: Auth, name: string, version: string | undefined): Promise<Response> {
    const viewer = await viewerOf(req, a);

    if (viewer.kind !== "user") return fail(401, `Sign in at ${ctx.access.webUrl()} to request an AI review.`);
    const bad = badOrigin(req, viewer);

    if (bad) return bad;
    const got = await resolveVersion(name, version);

    if (got.kind === "error") return got.res;

    if (!got.digest) return fail(422, "This version has no checksum, so its tarball cannot be verified for review.");
    const existing = reviewFor(name, got.version.version, got.digest);

    if (existing && existing.result.outcome !== "no-answer") return fail(409, "This version already has an AI review.");
    const job = jobByKey(name, got.version.version, got.digest);

    if (job && (job.state === "queued" || job.state === "leased")) return json({ status: "queued" });
    const since = ctx.now() - HOUR;
    const used = z.object({ n: z.number() }).parse(db.query("SELECT COUNT(*) AS n FROM review_requests WHERE actor = ? AND at > ?").get(viewer.user.name, since)).n;

    if (used >= opts.requestsPerHour) return fail(429, `You can request ${opts.requestsPerHour} AI reviews an hour. Try again later.`, { retryAfterSeconds: 3600 });
    db.query("INSERT INTO review_requests (actor, package, version, at) VALUES (?, ?, ?, ?)").run(viewer.user.name, name, got.version.version, ctx.now());
    enqueue({ name, version: got.version.version, digest: got.digest, source: got.source, reasons: ["requested"] });

    return json({ status: "queued" }, 202);
  }

  // ---------- reviewer (service token) ----------
  async function leaseResponse(url: URL): Promise<Response> {
    const max = Math.max(1, Math.min(MAX_LEASE_BATCH, Number(url.searchParams.get("max") ?? "4") || 4));
    const jobs: ReviewJob[] = [];

    for (const row of takeJobs(max)) {
      const p = await jobPayload(row);

      switch (p.kind) {
        case "ok":
          jobs.push(p.job);
          break;
        case "gone":
          setJobState(row.id, "failed", p.why);
          break;
        case "later":
          setJobState(row.id, "queued", p.why);
          break;
        default: {
          const _exhaustive: never = p;

          return _exhaustive;
        }
      }
    }

    return json({ jobs }, 200, { "cache-control": "no-store" });
  }

  async function readBody<T>(req: Request, schema: z.ZodType<T>): Promise<{ ok: true; value: T } | { ok: false; res: Response }> {
    const text = await req.text();

    if (text.length > 2 * 1024 * 1024) return { ok: false, res: fail(413, "Body too large.") };

    try {
      const parsed = schema.safeParse(JSON.parse(text));

      return parsed.success ? { ok: true, value: parsed.data } : { ok: false, res: fail(400, `Invalid body: ${parsed.error.message.slice(0, 500)}`) };
    } catch {
      return { ok: false, res: fail(400, "Body must be JSON.") };
    }
  }

  function leaseHolder(id: string, leaseId: string): JobRow | Response {
    const job = jobById(id);

    if (!job) return fail(404, "No such job.");

    if (job.state !== "leased" || job.lease_id !== leaseId) return fail(409, "This lease is no longer yours; the job went back to the queue or was finished.");

    return job;
  }

  async function resultResponse(req: Request, id: string): Promise<Response> {
    const body = await readBody(req, ResultBody);

    if (!body.ok) return body.res;
    const at = ctx.now();

    return ctx.store.tx(() => {
      const job = leaseHolder(id, body.value.leaseId);

      if (job instanceof Response) return job;
      const r = body.value.result;
      const human: HumanState = r.outcome === "benign" ? "none" : "pending";

      db.query(
        "INSERT OR REPLACE INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state, human_by, human_at, human_note) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
      ).run(job.package, job.version, job.digest, r.outcome, JSON.stringify(r), at, human);
      setJobState(job.id, "done", null);
      const stored = reviewFor(job.package, job.version, job.digest);

      return stored ? json({ ok: true, state: publicState(stored) }) : fail(500, "The review was not stored.");
    });
  }

  async function releaseResponse(req: Request, id: string): Promise<Response> {
    const body = await readBody(req, ReleaseBody);

    if (!body.ok) return body.res;

    return ctx.store.tx(() => {
      const job = leaseHolder(id, body.value.leaseId);

      if (job instanceof Response) return job;
      setJobState(job.id, body.value.retryable ? "queued" : "failed", body.value.error);

      return json({ ok: true });
    });
  }

  // ---------- second stage: the owner queue ----------
  const DecideBody = z.object({
    name: z.string().min(1).max(214),
    version: z.string().min(1).max(256),
    digest: z.string().min(1).max(200),
    decision: z.enum(["confirm", "dismiss"]),
    note: z.string().max(2000).default(""),
  });

  function queueResponse(): Response {
    const rows = (sql: string): StoredReview[] =>
      db
        .query(sql)
        .all()
        .map((r) => toReview(ReviewRow.parse(r)));

    const item = (r: StoredReview) => ({ name: r.package, version: r.version, digest: r.digest, reviewedAt: iso(r.reviewed_at), public: publicView(r), private: privateView(r), decidedBy: r.human_by });

    return json(
      {
        pending: rows("SELECT * FROM reviews WHERE human_state = 'pending' ORDER BY reviewed_at LIMIT 200").map(item),
        decided: rows("SELECT * FROM reviews WHERE human_state IN ('confirmed', 'dismissed') ORDER BY human_at DESC LIMIT 50").map(item),
        // the stronger-model step plugs in at the reviewer (apps/reviewer/src/second-stage.ts); none is configured
        secondStage: null,
      },
      200,
      { "cache-control": "no-store" },
    );
  }

  async function decideResponse(req: Request, viewer: Viewer): Promise<Response> {
    const body = await readBody(req, DecideBody);

    if (!body.ok) return body.res;
    const d = body.value;
    const r = reviewFor(d.name, d.version, d.digest);

    if (!r) return fail(404, "No such review.");

    if (r.human_state === "none") return fail(409, "This review found nothing; there is no flag to confirm or dismiss.");
    const by = viewer.kind === "user" ? (viewer.githubLogin ?? viewer.user.name) : "unknown";

    db.query("UPDATE reviews SET human_state = ?, human_by = ?, human_at = ?, human_note = ? WHERE package = ? AND version = ? AND digest = ?").run(
      d.decision === "confirm" ? "confirmed" : "dismissed",
      by,
      ctx.now(),
      d.note.trim() === "" ? null : d.note.trim(),
      d.name,
      d.version,
      d.digest,
    );

    return json({ ok: true });
  }

  // ---------- router ----------
  async function routes(req: Request, url: URL, a: Auth): Promise<Response | null> {
    const p = url.pathname;

    if (p === "/-/apm/v1/review-jobs" || p.startsWith("/-/apm/v1/review-jobs/")) {
      if (!isService(req)) return fail(401, "This route is for the AI reviewer's service token.");

      if (p === "/-/apm/v1/review-jobs" && req.method === "GET") return leaseResponse(url);
      const m = /^\/-\/apm\/v1\/review-jobs\/([A-Za-z0-9_-]{1,64})\/(result|release)$/.exec(p);

      if (!m?.[1] || req.method !== "POST") return fail(404, "Not found");

      return m[2] === "result" ? resultResponse(req, m[1]) : releaseResponse(req, m[1]);
    }

    if (p.startsWith("/-/apm/v1/review-admin/")) {
      const viewer = await viewerOf(req, a);

      if (viewer.kind !== "user") return fail(401, "Sign in first.");

      if (!isAdmin(viewer)) return fail(403, "Only apm's reviewers can see this queue.");

      if (p === "/-/apm/v1/review-admin/queue" && req.method === "GET") return queueResponse();

      if (p === "/-/apm/v1/review-admin/decide" && req.method === "POST") return badOrigin(req, viewer) ?? decideResponse(req, viewer);

      return fail(404, "Not found");
    }

    if (p.startsWith("/-/apm/v1/review/")) {
      const sp = splitPath(p.slice("/-/apm/v1/review".length));

      if (!sp) return fail(404, "Not found");

      if (req.method === "GET" && sp.rest.length === 1) return reviewResponse(req, a, sp.name, sp.rest[0]);

      if (req.method === "POST" && sp.rest.length === 2 && sp.rest[1] === "request") return requestResponse(req, a, sp.name, sp.rest[0]);

      return fail(404, "Not found");
    }

    return null;
  }

  return {
    routes,
    onLocalCommit(v) {
      const rec = ctx.store.getVersion(v.name, v.version);
      const digest = rec ? labelOf(rec) : null;

      if (!rec || !digest) return;
      const reasons: EnqueueReason[] = ["publish"];

      if (v.firstPublish) reasons.push("first-publish");
      const prev = previousVersionOf(ctx.store.listVersions(v.name), v.version);

      if (hasInstallScript(rec) && (prev === null || !hasInstallScript(prev))) reasons.push("install-script");
      enqueue({ name: v.name, version: v.version, digest, source: "local", reasons });
    },
    onUpstreamPackage(pkg) {
      background(considerUpstream(pkg));
    },
    async idle() {
      while (pending.size > 0) await Promise.all(pending);
    },
  };
}

/** Reads the service token from its file and returns its sha256, for StartOptions.review. */
export function serviceTokenHashOf(token: string): string {
  return sha256(token.trim()).toString("hex");
}
