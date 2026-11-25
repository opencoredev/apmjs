// GET /-/apm/v1/health, for external monitors (Instatus and the like). One cheap answer that says whether each part the
// registry needs answers right now: Postgres, R2, the analysis queue and npm. HTTP 200 while installs work (with or
// without the database, see degraded.ts), 503 when they do not. It is never cached (`no-store`), carries no secret and
// no address, and checks at most once every MEMO_MS per isolate, so a check every 30 seconds from several places costs
// one `SELECT 1`, two small R2 reads and one npm ping per isolate per check at most.
import { Duration, Effect, Exit } from "effect";
import * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { readFrom, type BlocklistReader } from "./blocklist.ts";
import { Guard } from "./db-health.ts";
import { Store } from "./db.ts";

export const HEALTH_PATH = "/-/apm/v1/health";

/** The object the queue consumer writes when it takes the cron's probe message (worker.ts). */
export const QUEUE_PROBE_KEY = "state/queue-probe.json";

/** A probe message: the cron sends one every run, and the consumer records when it took it. */
export const QueueProbe = z.object({ probe: z.literal("health"), sentAt: z.number() });

export const QueueProbeRecord = z.object({ sentAt: z.number(), receivedAt: z.number() });

/** How long one check may take. */
const CHECK_TIMEOUT_MS = 3_000;

/** How long an isolate reuses its last answer. */
const MEMO_MS = 5_000;

/** A queue whose last probe was consumed longer ago than this is reported down: the cron sends one every 10 minutes. */
const QUEUE_STALE_MS = 25 * 60_000;

export type CheckStatus = "up" | "down" | "unknown";

export type Check = { readonly status: CheckStatus; readonly ms: number | null; readonly detail: string };

export type Health = {
  /** ok: everything answers. degraded: installs work, something does not answer. down: installs do not work. */
  readonly status: "ok" | "degraded" | "down";
  /** working: every install. npm-only: npm's packages install, apm's own do not and scores are unknown. down: none. */
  readonly installs: "working" | "npm-only" | "down";
  readonly checkedAt: string;
  readonly checks: {
    readonly database: Check;
    readonly r2: Check;
    /** The block list the install routes read while the database is down (blocklist.ts). */
    readonly blocklist: Check & { readonly syncedAt: string | null };
    readonly queue: Check & { readonly lastConsumedAt: string | null };
    readonly upstream: Check;
  };
};

export type HealthEnv = {
  readonly databaseUrl: string;
  /** The registry's bucket, as the health check reads it: the block list and the queue probe's record. */
  readonly bucket: BlocklistReader;
  readonly queueBound: boolean;
  /** The upstream registry, or null when the registry proxies none. */
  readonly upstreamUrl: string | null;
};

async function timedCheck(run: () => Promise<Omit<Check, "ms">>): Promise<Check> {
  const start = performance.now();
  const ms = (): number => Math.round(performance.now() - start);

  try {
    const timeout = new Promise<Omit<Check, "ms">>((resolve) => setTimeout(() => resolve({ status: "down", detail: `no answer within ${CHECK_TIMEOUT_MS / 1000} s` }), CHECK_TIMEOUT_MS));
    const got = await Promise.race([run(), timeout]);

    return { ...got, ms: ms() };
  } catch {
    // causes are not sent: a driver's message could name a host
    return { status: "down", detail: "the check failed", ms: ms() };
  }
}

/** The database's status from a check of its own, every time: nothing is kept between requests (db-health.ts). */
async function database(url: string): Promise<Check> {
  return timedCheck(async () => {
    const program = Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;

      return yield* (yield* Guard).statement("health", sql`SELECT 1 AS ok`);
    }).pipe(
      Effect.timeoutOrElse({ duration: Duration.millis(CHECK_TIMEOUT_MS), orElse: () => Effect.fail("timeout" as const) }),
      // the statement's own deadline ends before the check's, so the guard's verdict says what is wrong
      Effect.provide(Store.postgres(url, new Set(), { statementMs: CHECK_TIMEOUT_MS - 200 })),
      Effect.scoped,
    );

    const exit = await Effect.runPromiseExit(program);

    return Exit.isSuccess(exit) ? { status: "up", detail: "answers" } : { status: "down", detail: "does not answer" };
  });
}

/**
 * R2, and the block list read and parsed the way the degraded routes read it (blocklist.ts, readFrom), so the check says
 * the list is usable exactly when they would use it: written, parsed, and synced from the database once.
 */
async function r2(bucket: BlocklistReader): Promise<{ r2: Check; blocklist: Health["checks"]["blocklist"] }> {
  let syncedAt: string | null = null;
  let listed: Omit<Check, "ms"> = { status: "unknown", detail: "not read" };

  const check = await timedCheck(async () => {
    const read = await readFrom(bucket);

    switch (read.kind) {
      case "missing":
        listed = { status: "down", detail: "never written: the cron's sync writes it" };
        break;
      case "unreadable":
        listed = { status: "down", detail: `unreadable (${read.reason}): installs without the database are refused until the cron's sync rewrites it` };
        break;
      case "ok":
        if (read.list.syncedAt === null) listed = { status: "down", detail: "written but never synced from the database: installs without the database are refused" };
        else {
          syncedAt = new Date(read.list.syncedAt).toISOString();
          listed = { status: "up", detail: "synced from the database" };
        }

        break;
      default: {
        const _exhaustive: never = read;

        return _exhaustive;
      }
    }

    return { status: "up", detail: "answers" };
  });

  return { r2: check, blocklist: { ...(check.status === "up" ? listed : { status: "unknown", detail: "R2 does not answer" }), ms: null, syncedAt } };
}

/** The probe record `text` holds, or null when it is not one: text that is not JSON is as unreadable as the wrong form. */
function probeRecord(text: string): z.infer<typeof QueueProbeRecord> | null {
  try {
    const record = QueueProbeRecord.safeParse(JSON.parse(text));

    return record.success ? record.data : null;
  } catch {
    return null;
  }
}

async function queue(bucket: BlocklistReader, bound: boolean, now: number): Promise<Health["checks"]["queue"]> {
  if (!bound) return { status: "unknown", ms: null, detail: "no queue is bound", lastConsumedAt: null };
  let lastConsumedAt: string | null = null;

  const check = await timedCheck(async () => {
    const obj = await bucket.get(QUEUE_PROBE_KEY);

    if (obj === null) return { status: "unknown", detail: "no probe consumed yet: the cron sends one every 10 minutes" };
    const record = probeRecord(await new Response(obj.body).text());

    if (record === null) return { status: "unknown", detail: "the last probe's record is unreadable" };
    lastConsumedAt = new Date(record.receivedAt).toISOString();
    const age = now - record.receivedAt;

    return age <= QUEUE_STALE_MS ? { status: "up", detail: `the cron's probe was consumed ${Math.round(age / 60_000)} min ago` } : { status: "down", detail: `no probe consumed for ${Math.round(age / 60_000)} min: the consumer is stopped or far behind` };
  });

  return { ...check, lastConsumedAt };
}

async function upstream(url: string | null): Promise<Check> {
  if (url === null) return { status: "unknown", ms: null, detail: "this registry proxies no upstream" };

  return timedCheck(async () => {
    const res = await fetch(`${url}-/ping`, { signal: AbortSignal.timeout(CHECK_TIMEOUT_MS), headers: { accept: "application/json" } });
    await res.body?.cancel();

    return res.status === 200 ? { status: "up", detail: "answers" } : { status: "down", detail: `answered ${res.status}` };
  });
}

/**
 * The overall answer from each check. Installs need R2 in every case (apm's tarballs live there, and npm's are looked up and kept there
 * before they are served: a failed R2 read fails the tarball), npm when the registry proxies it, and either the database or the synced block list.
 */
export function summarize(checks: Health["checks"], upstreamProxied: boolean): Pick<Health, "status" | "installs"> {
  const npm = !upstreamProxied || checks.upstream.status === "up";
  const storage = checks.r2.status === "up";
  const installs: Health["installs"] = !npm || !storage ? "down" : checks.database.status === "up" ? "working" : upstreamProxied && checks.blocklist.status === "up" ? "npm-only" : "down";
  const everything = [checks.database, checks.r2, checks.blocklist, checks.queue, checks.upstream].every((c) => c.status !== "down");

  return { installs, status: installs === "down" ? "down" : installs === "working" && everything ? "ok" : "degraded" };
}

export async function checkHealth(env: HealthEnv, now: number = Date.now()): Promise<Health> {
  const [db, storage, q, up] = await Promise.all([database(env.databaseUrl), r2(env.bucket), queue(env.bucket, env.queueBound, now), upstream(env.upstreamUrl)]);
  const checks = { database: db, r2: storage.r2, blocklist: storage.blocklist, queue: q, upstream: up };

  const { status, installs } = summarize(checks, env.upstreamUrl !== null);

  return { status, installs, checkedAt: new Date(now).toISOString(), checks };
}

/**
 * The isolate's last finished answer. The answer itself, never the promise of one: a promise made by one request and
 * awaited by another is not safe in workerd.
 */
let memo: { at: number; health: Health } | null = null;

/** The health answer. Checks run at most once per MEMO_MS in an isolate, except while one is still running. */
export async function healthResponse(req: Request, env: HealthEnv): Promise<Response> {
  const now = Date.now();
  const recent = memo !== null && now - memo.at < MEMO_MS ? memo.health : null;
  const health = recent ?? (await checkHealth(env, now));

  if (recent === null) memo = { at: now, health };
  const status = health.installs === "down" ? 503 : 200;
  const headers = { "content-type": "application/json", "cache-control": "no-store" };

  return new Response(req.method === "HEAD" ? null : `${JSON.stringify(health)}\n`, { status, headers });
}
