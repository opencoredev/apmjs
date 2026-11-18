// The registry Worker: a thin fetch handler over the Effect program, the analysis queue consumer and the cron
// that writes down time-based state changes. Services are built per request from the Worker's bindings.
import { createHash, timingSafeEqual } from "node:crypto";
import { Cause, Effect, Exit, Layer } from "effect";
import * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { Analysis, RUN_WINDOW_MS, type AnalysisJob } from "./analysis.ts";
import { matureRevocations, refreshLatestScores } from "./apm.ts";
import { KeptRefresh, refreshKeptPackages, runRefresh } from "./kept-package.ts";
import { sweepConfirmations, sweepStaged } from "./account.ts";
import { Auth, type AuthOptions } from "./auth.ts";
import { Blobs } from "./blobs.ts";
import { Blocklist, blockTruth } from "./blocklist.ts";
import { DatabaseUnavailable, isDatabaseUnavailable } from "./db-health.ts";
import { reportFailure, type Failure } from "./error-reports.ts";
import { degradedRoute, isInstallRead, unavailable } from "./degraded.ts";
import { EdgeChecks, FIRST_PUBLISH_HOLD_MS, PublishFence, type AskInput, type AskOutcome } from "./edge-checks.ts";
import { queueDownload } from "./fast-tarball.ts";
import { HEALTH_PATH, healthResponse, QUEUE_PROBE_KEY, QueueProbe } from "./health.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig, type RegistrySettings } from "./config.ts";
import { Store, type StoreFault } from "./db.ts";
import type { HttpFailure, InfraError, StoreError } from "./errors.ts";
import { fail, failureResponse, routePath, withPrivacyHeaders, withServerTiming, withSlash } from "./http.ts";
import { ChoicesWriter, dropStaleChoices } from "./kept-choices.ts";
import { route } from "./router.ts";
import { ISOLATE_POOL, RequestMemory } from "./memory.ts";
import { legacyAuthRefusal } from "./startup.ts";
import { ReleaseHooks } from "./hooks.ts";
import { considerUpstream, REVIEW_DEFAULTS, ReviewConfig, reviewLocalCommit, type ReviewSettings } from "./review.ts";
import { Timing, type TimingApi, type TimingDetail } from "./timing.ts";
import { Upstream } from "./upstream.ts";

const Method = z.instanceof(Function);

/** A binding is checked by the methods apm calls on it; Cloudflare's own objects carry the rest. */
const binding = <T>(methods: readonly string[], message: string) => {
  const required = z.object(Object.fromEntries(methods.map((m) => [m, Method])));

  return z.custom<T>((v) => required.safeParse(v).success, message);
};

const Flag = z
  .string()
  .optional()
  .transform((v) => v === "1" || v === "true" || v === "on");

const OptionalText = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === "" ? undefined : v.trim()));

const GitHubEndpoints = z.object({ authorize: z.string(), token: z.string(), user: z.string(), emails: z.string() });

/** The Worker's environment: bindings declared in packages/infra, vars and secrets. Parsed once per request. */
const WorkerEnv = z.object({
  HYPERDRIVE: z.object({ connectionString: z.string().min(1) }, "HYPERDRIVE must be a Hyperdrive binding"),
  BLOBS: binding<R2Bucket>(["get", "put", "head", "delete", "list"], "BLOBS must be an R2 bucket binding"),
  ANALYSIS_QUEUE: binding<Queue<AnalysisJob>>(["send"], "ANALYSIS_QUEUE must be a Queue binding").optional(),
  /** The registry's public URL (tarball links). Defaults to the request's origin. */
  APM_REGISTRY_URL: OptionalText,
  /** The website's public URL (sign-in, approval links, the device page). Defaults to the registry URL. */
  APM_PUBLIC_URL: OptionalText,
  /** Public registry to proxy, or "off". */
  APM_UPSTREAM: OptionalText,
  /** How long an upstream answer is trusted, in milliseconds. Default 60000. */
  APM_UPSTREAM_TTL_MS: z.coerce.number().int().min(0).optional(),
  /** "upstream" lets a checked tarball request be redirected to the configured upstream (tests, the bench); default npm's own URL only. */
  APM_TARBALL_REDIRECTS: z.enum(["npm", "upstream"]).optional(),
  APM_LEGACY_AUTH: Flag,
  /** Lets legacy password auth run on a public https address. Without it the registry refuses to serve. */
  APM_ALLOW_LEGACY_IN_PROD: OptionalText,
  APM_NAME_POLICY: z.enum(["scoped", "open"]).optional(),
  APM_AUTH_SECRET: z.string().min(32, "APM_AUTH_SECRET must be at least 32 characters"),
  APM_GITHUB_CLIENT_ID: OptionalText,
  APM_GITHUB_CLIENT_SECRET: OptionalText,
  /** Overrides GitHub's OAuth endpoints (JSON). For tests against a fake GitHub. */
  APM_GITHUB_ENDPOINTS: OptionalText,
  APM_VERCEL_CLIENT_ID: OptionalText,
  APM_VERCEL_CLIENT_SECRET: OptionalText,
  /** sha256 (hex) of the AI reviewer's service token. The AI review is on when it is set. See docs/AI-REVIEW.md. */
  APM_REVIEW_TOKEN_HASH: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, "APM_REVIEW_TOKEN_HASH must be a sha256 hex digest")
    .optional(),
  /** Comma-separated GitHub logins of apm's reviewers: they confirm or dismiss flagged reviews and dismiss score evidence. */
  APM_ADMINS: OptionalText,
  APM_REVIEW_POPULAR_WEEKLY: z.coerce.number().int().min(0).optional(),
  APM_NPM_DOWNLOADS_URL: OptionalText,
  APM_REVIEW_LEASE_MS: z.coerce.number().int().min(1).optional(),
  APM_REVIEW_REQUESTS_PER_HOUR: z.coerce.number().int().min(0).optional(),
  APM_REVIEW_MAX_ATTEMPTS: z.coerce.number().int().min(1).optional(),
  /** How long an isolate takes the database as down after it failed to answer (db-health.ts). For tests; production keeps the default. */
  /** sha256 (hex) of the operator's debug token: a request whose x-apm-debug header is that token gets the full Server-Timing (timing.ts). */
  APM_DEBUG_TOKEN_HASH: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, "APM_DEBUG_TOKEN_HASH must be a sha256 hex digest")
    .optional(),
  /** The deploy run that uploaded this version (packages/infra/deploy.ts): /-/ping answers with it in BUILD_HEADER. */
  APM_BUILD: OptionalText,
  /** Databuddy's public client id: unhandled 500s are reported to it (error-reports.ts). Production alone has one. */
  APM_DATABUDDY_CLIENT_ID: OptionalText,
  /**
   * What the install document and tarball redirect of a package only npm has check before their answer: "database"
   * (the default), one statement on every request; "edge", this isolate's read of the install block list, at most 4 s
   * old when the answer is made, with no database statement (edge-checks.ts). Every first publish waits 8 s for edge
   * views either way (PublishFence).
   */
  APM_INSTALL_CHECKS: z.enum(["database", "edge"]).optional(),
});

const DebugEnv = WorkerEnv.pick({ APM_DEBUG_TOKEN_HASH: true });

const BuildEnv = WorkerEnv.pick({ APM_BUILD: true });

/** "full" only when the request's x-apm-debug header hashes to APM_DEBUG_TOKEN_HASH; anyone else gets "none". */
export function timingDetail(req: Request, rawEnv: RawEnv): TimingDetail {
  const parsed = DebugEnv.safeParse(rawEnv);
  const token = req.headers.get("x-apm-debug");

  if (!parsed.success || parsed.data.APM_DEBUG_TOKEN_HASH === undefined || token === null || token.trim() === "") return "none";
  const expected = Buffer.from(parsed.data.APM_DEBUG_TOKEN_HASH, "hex");

  return timingSafeEqual(createHash("sha256").update(token.trim()).digest(), expected) ? "full" : "none";
}

/** What the Workers runtime hands the entry: the bindings and vars as declared, before they are checked. */
export type RawEnv = z.input<typeof WorkerEnv>;

export type WorkerEnv = z.output<typeof WorkerEnv>;

export function parseEnv(raw: RawEnv): WorkerEnv {
  return WorkerEnv.parse(raw);
}

function settingsOf(env: WorkerEnv, requestUrl: string): RegistrySettings {
  const baseUrl = withSlash(env.APM_REGISTRY_URL ?? new URL(requestUrl).origin);
  const upstream = env.APM_UPSTREAM ?? "https://registry.npmjs.org/";

  return {
    baseUrl,
    webUrl: withSlash(env.APM_PUBLIC_URL ?? baseUrl),
    upstreamUrl: upstream === "off" ? null : withSlash(upstream),
    legacyAuth: env.APM_LEGACY_AUTH,
    namePolicy: env.APM_NAME_POLICY ?? "scoped",
    admins: (env.APM_ADMINS ?? "").split(","),
    tarballRedirects: env.APM_TARBALL_REDIRECTS ?? "npm",
  };
}

function authOptions(env: WorkerEnv): AuthOptions {
  const options: AuthOptions = { secret: env.APM_AUTH_SECRET };

  if (env.APM_GITHUB_CLIENT_ID && env.APM_GITHUB_CLIENT_SECRET) {
    const github: NonNullable<AuthOptions["github"]> = { clientId: env.APM_GITHUB_CLIENT_ID, clientSecret: env.APM_GITHUB_CLIENT_SECRET };

    if (env.APM_GITHUB_ENDPOINTS !== undefined) github.endpoints = GitHubEndpoints.parse(JSON.parse(env.APM_GITHUB_ENDPOINTS));
    options.github = github;
  }

  if (env.APM_VERCEL_CLIENT_ID && env.APM_VERCEL_CLIENT_SECRET) options.vercel = { clientId: env.APM_VERCEL_CLIENT_ID, clientSecret: env.APM_VERCEL_CLIENT_SECRET };

  return options;
}

function reviewSettings(env: WorkerEnv): ReviewSettings | null {
  if (env.APM_REVIEW_TOKEN_HASH === undefined) return null;

  return {
    serviceTokenHash: env.APM_REVIEW_TOKEN_HASH.toLowerCase(),
    admins: (env.APM_ADMINS ?? "").split(","),
    popularWeekly: env.APM_REVIEW_POPULAR_WEEKLY ?? REVIEW_DEFAULTS.popularWeekly,
    downloadsUrl: withSlash(env.APM_NPM_DOWNLOADS_URL ?? REVIEW_DEFAULTS.downloadsUrl),
    leaseMs: env.APM_REVIEW_LEASE_MS ?? REVIEW_DEFAULTS.leaseMs,
    requestsPerHour: env.APM_REVIEW_REQUESTS_PER_HOUR ?? REVIEW_DEFAULTS.requestsPerHour,
    maxAttempts: env.APM_REVIEW_MAX_ATTEMPTS ?? REVIEW_DEFAULTS.maxAttempts,
  };
}

/** Hands work to the runtime to finish after the response (ExecutionContext.waitUntil), or null outside a request. */
export type Background = ((work: Promise<void>) => void) | null;

/**
 * The AI review's listeners, when it is on. A commit is queued for review inline, on the request's connection,
 * once the publish transaction is over. An upstream packument is considered after the response, on its own
 * connection: the request's connection closes with the request.
 */
function reviewHooks(env: WorkerEnv, review: ReviewSettings, clock: Layer.Layer<Clock>, background: Background) {
  const fresh = Layer.mergeAll(Store.postgres(env.HYPERDRIVE.connectionString), clock, Layer.succeed(ReviewConfig, review));

  return Layer.effect(
    ReleaseHooks,
    Effect.gen(function* () {
      const context = yield* Effect.context<Store | SqlClient.SqlClient | Clock | ReviewConfig>();

      return ReleaseHooks.of({
        afterCommit: (v) =>
          reviewLocalCommit(v).pipe(
            Effect.provide(context),
            Effect.catch((e) => Effect.sync(() => logFailure("review", { name: v.name, version: v.version }, String(e.cause)))),
          ),
        upstreamFetched: (pkg, held) =>
          Effect.sync(() => {
            if (background === null) {
              held.release();

              return;
            }

            background(
              // interrupted at the lease's deadline: the run settles once its finalizers have, and only then is the
              // package given back to the isolate's memory pool
              Effect.runPromiseExit(considerUpstream(pkg).pipe(Effect.provide(fresh), Effect.scoped), { signal: held.signal })
                .then((exit) => {
                  if (Exit.isFailure(exit)) logFailure("review", { name: pkg.name }, Cause.pretty(exit.cause));
                })
                .finally(() => held.release()),
            );
          }),
      });
    }),
  );
}

export type RequestServices = Store | Blobs | Clock | RegistryConfig | Analysis | Auth;

/**
 * Every service a request uses, over this Worker's bindings. The Postgres connection and the request's memory lease
 * (memory.ts) live as long as the request.
 */
export function servicesFor(env: WorkerEnv, settings: RegistrySettings, clock: Layer.Layer<Clock>, background: Background = null, controls: TestControls = PRODUCTION) {
  const run = runServices(env, settings, clock, background, controls);

  return background === null || settings.upstreamUrl === null ? run : Layer.mergeAll(run, keptRefresh(env, settings, clock, background, controls), choicesWriter(env, settings, clock, background, controls));
}

/** servicesFor without KeptRefresh: what a refresh after the response runs on. */
function runServices(env: WorkerEnv, settings: RegistrySettings, clock: Layer.Layer<Clock>, background: Background, controls: TestControls) {
  const databaseUrl = env.HYPERDRIVE.connectionString;
  const review = reviewSettings(env);

  const core = Layer.mergeAll(
    Store.postgres(databaseUrl, controls.faults),
    Blobs.r2(env.BLOBS),
    Blocklist.r2(env.BLOBS),
    clock,
    Layer.succeed(RegistryConfig, settings),
    // every first publish waits for edge views whatever this Worker's read mode, so a build that reads them can go live
    // once no build without the fence is left (docs/DEPLOY.md)
    PublishFence.layer(controls.publishFenceMs),
    edgeChecks(env, settings, clock, background, controls),
  );

  const base = review === null ? core : Layer.provideMerge(Layer.provideMerge(reviewHooks(env, review, clock, background), Layer.succeed(ReviewConfig, review)), core);
  const analysisQueue = env.ANALYSIS_QUEUE ?? null;

  const withScoring =
    settings.upstreamUrl === null
      ? Layer.provideMerge(Analysis.none, base)
      : Layer.provideMerge(Analysis.layer(analysisQueue), Layer.provideMerge(Upstream.layer(settings.upstreamUrl, env.APM_UPSTREAM_TTL_MS, background), base));

  // one lease of the isolate's memory pool for the run (a request, a queue job, the sweep): every read of npm's
  // package metadata it makes takes from it, and a streamed answer keeps it until the last byte is sent
  return Layer.mergeAll(Layer.provideMerge(Auth.layer({ databaseUrl, options: authOptions(env), baseURL: settings.webUrl }), withScoring), RequestMemory.layer(ISOLATE_POOL));
}

/**
 * A kept package summary worked out again after the response (kept-package.ts), on services of its own: the request's
 * connection and memory lease close with the request.
 */
function keptRefresh(env: WorkerEnv, settings: RegistrySettings, clock: Layer.Layer<Clock>, background: (work: Promise<void>) => void, controls: TestControls) {
  return Layer.succeed(
    KeptRefresh,
    KeptRefresh.of({
      later: (name) =>
        Effect.sync(() =>
          background(
            // with the request's background, so the AI review still looks at the packument npm sent (reviewHooks), as
            // it does after a view that read it; without KeptRefresh, so a refresh starts no other
            Effect.runPromiseExit(runRefresh(name).pipe(Effect.provide(runServices(env, settings, clock, background, { ...controls, faults: new Set() })), Effect.scoped)).then((exit) => {
              if (Exit.isFailure(exit)) logFailure("kept-package-refresh", { name }, Cause.pretty(exit.cause));
            }),
          ),
        ),
      // one UPDATE on a connection of its own: the answer npm's 304 let through does not wait on it
      touch: (input) =>
        Effect.sync(() =>
          background(
            Effect.runPromiseExit(Effect.flatMap(Store, (s) => s.touchKeptPackage(input)).pipe(Effect.provide(Store.postgres(env.HYPERDRIVE.connectionString)), Effect.scoped)).then((exit) => {
              if (Exit.isFailure(exit)) logFailure("kept-package-touch", { name: input.name }, Cause.pretty(exit.cause));
            }),
          ),
        ),
    }),
  );
}

/**
 * A resolve's kept choices written after the response (kept-choices.ts), on services of its own: the request's
 * connection and memory lease close with the request, and the answer never waits on the write.
 */
function choicesWriter(env: WorkerEnv, settings: RegistrySettings, clock: Layer.Layer<Clock>, background: (work: Promise<void>) => void, controls: TestControls) {
  return Layer.succeed(
    ChoicesWriter,
    ChoicesWriter.of({
      later: (write) =>
        Effect.sync(() =>
          background(
            Effect.runPromiseExit(write.pipe(Effect.provide(runServices(env, settings, clock, background, { ...controls, faults: new Set() })), Effect.scoped)).then((exit) => {
              if (Exit.isFailure(exit)) logFailure("kept-choices-write", {}, Cause.pretty(exit.cause));
            }),
          ),
        ),
    }),
  );
}

/**
 * The edge views (edge-checks.ts) when APM_INSTALL_CHECKS is "edge": shared by every request in the isolate, the data
 * center's copy in the Cache API, and a download answered from one queued for analysis after the response, on services
 * of its own (the request's connection closes with the request). Nothing otherwise.
 */
function edgeChecks(env: WorkerEnv, settings: RegistrySettings, clock: Layer.Layer<Clock>, background: Background, controls: TestControls) {
  if (env.APM_INSTALL_CHECKS !== "edge" || settings.upstreamUrl === null) return Layer.empty;

  // the edge aborts an ask past its deadline: the signal interrupts it, closing its connection, and nothing is logged
  // for it here (the edge counts it as a timeout)
  const queue = ({ name, version, signal }: AskInput): Promise<AskOutcome> =>
    Effect.runPromiseExit(queueDownload({ name, version }).pipe(Effect.provide(runServices(env, settings, clock, background, { ...controls, faults: new Set() })), Effect.scoped), { signal }).then(
      (exit): AskOutcome => {
        if (Exit.isSuccess(exit)) return exit.value;

        if (!signal.aborted) logFailure("download-queue", { name, version }, Cause.pretty(exit.cause));

        return "failed";
      },
    );

  return EdgeChecks.layer(
    {
      bucket: env.BLOBS,
      // `background` is set only inside a Worker request, where `caches` always exists
      cache: background === null ? null : caches.default,
      cacheKey: `${settings.baseUrl}-/apm/internal/edge-view`,
      now: Date.now,
      background,
      // once a minute per isolate: what its views decided, its R2 reads and how many requests fell back
      report: (counts) => console.log(JSON.stringify({ level: "info", event: "edge-checks", ...counts })),
    },
    queue,
  );
}

/**
 * What only the test entry (worker-test.ts) changes: store faults it switches on, and how long a first publish waits
 * for edge views (FIRST_PUBLISH_HOLD_MS in production; the acceptance suite's publishes skip it unless a test asks).
 */
export type TestControls = { readonly faults: ReadonlySet<StoreFault>; readonly publishFenceMs: number };

const PRODUCTION: TestControls = { faults: new Set(), publishFenceMs: FIRST_PUBLISH_HOLD_MS };

type LogFields = Readonly<Record<string, string | number | boolean | null>>;

/** One JSON line per failure, for Workers Logs. Causes are database, R2 and parse errors, never secrets. */
function logFailure(event: string, fields: LogFields, error: string): void {
  console.error(JSON.stringify({ level: "error", event, ...fields, error }));
}

/** One line per request answered without the database: a warning, since the answer was still made. */
function logDegraded(fields: LogFields, cause: unknown): void {
  const reason = cause instanceof DatabaseUnavailable ? cause.reason : String(cause);

  console.warn(JSON.stringify({ level: "warn", event: "degraded", ...fields, reason }));
}

/**
 * Runs the router for one request. `clock` is the system clock in production, and `controls` are production's there:
 * only the test entry (worker-test.ts) switches a fault on or shortens the publish fence. Per-user answers are marked private, whichever route made them.
 */
export async function handle(
  req: Request,
  rawEnv: RawEnv,
  clock: Layer.Layer<Clock> = Clock.system,
  ctx: ExecutionContext | null = null,
  controls: TestControls = PRODUCTION,
): Promise<Response> {
  const start = performance.now();
  const timing = Timing.make();
  const res = await respond({ req, rawEnv, clock, ctx, controls, timing });
  // an answer a route marked public carries its phases to anyone (timing.ts); any other only to the debug token
  const exposed = timing.exposed();
  const detail: TimingDetail = exposed ? "full" : timingDetail(req, rawEnv);

  return withBuild(req, withServerTiming(req, withPrivacyHeaders(req, res), timing.header({ total: performance.now() - start, detail }), exposed), rawEnv);
}

/** The header /-/ping carries this version's build id in (APM_BUILD), for the deploy's smoke check (packages/infra/smoke-identity.ts). */
export const BUILD_HEADER = "x-apm-build";

/** /-/ping's answer with the version's build id, never cached; every other answer unchanged. */
function withBuild(req: Request, res: Response, rawEnv: RawEnv): Response {
  const parsed = BuildEnv.safeParse(rawEnv);
  const build = parsed.success ? (parsed.data.APM_BUILD ?? "") : "";

  if (build === "" || routePath(new URL(req.url).pathname).path !== "/-/ping") return res;
  const stamped = new Response(res.body, res);

  stamped.headers.set(BUILD_HEADER, build);
  stamped.headers.set("cache-control", "no-store");

  return stamped;
}

type Respond = { req: Request; rawEnv: RawEnv; clock: Layer.Layer<Clock>; ctx: ExecutionContext | null; controls: TestControls; timing: TimingApi };

async function respond({ req, rawEnv, clock, ctx, controls, timing }: Respond): Promise<Response> {
  const parsed = WorkerEnv.safeParse(rawEnv);

  // an unhandled 500 is reported to Databuddy after the answer (error-reports.ts), on production alone: a fixed code
  // and the route's label, read inside the reporter's guard
  const report = (failure: Failure): void => reportFailure({ req, env: rawEnv, waitUntil: ctx === null ? null : (work) => ctx.waitUntil(work), failure });

  if (!parsed.success) {
    logFailure("config", {}, parsed.error.message);
    report({ kind: "misconfigured" });

    return fail(500, "The registry is misconfigured.");
  }

  const env = parsed.data;
  const settings = settingsOf(env, req.url);

  const refusal = legacyAuthRefusal({
    APM_LEGACY_AUTH: env.APM_LEGACY_AUTH ? "1" : "0",
    APM_PUBLIC_URL: settings.webUrl,
    APM_ALLOW_LEGACY_IN_PROD: env.APM_ALLOW_LEGACY_IN_PROD,
  });

  if (refusal !== null) {
    logFailure("config", {}, refusal);

    return fail(503, `The registry refuses to serve: ${refusal}`);
  }

  const path = new URL(req.url).pathname;

  // before the router: it answers whatever else is down, and reads nothing a request's services would
  if ((req.method === "GET" || req.method === "HEAD") && routePath(path).path === HEALTH_PATH) {
    return healthResponse(req, { databaseUrl: env.HYPERDRIVE.connectionString, bucket: env.BLOBS, queueBound: env.ANALYSIS_QUEUE !== undefined, upstreamUrl: settings.upstreamUrl });
  }

  const program = route(req).pipe(
    Effect.catchTag("HttpFailure", (f: HttpFailure) => Effect.succeed(failureResponse(f))),
    // an install read that could not use the database is answered without it, from npm and the block list
    // (degraded.ts); anything else that needs a database it cannot reach says so, rather than "Internal error"
    Effect.catchTag("StoreError", (e: StoreError) => {
      // only a database that cannot be reached: a statement that failed on a database that answers is a bug or a bad
      // row, and answering around it would hide it (and skip what the database would have refused)
      if (!isDatabaseUnavailable(e)) return Effect.fail(e);
      const answer = isInstallRead(req) ? degradedRoute(req) : Effect.succeed(unavailable("this request needs it"));

      return Effect.andThen(Effect.sync(() => logDegraded({ method: req.method, path, operation: e.operation }, e.cause)), answer);
    }),
    Effect.catch((e: InfraError) =>
      Effect.sync(() => {
        logFailure("request", { method: req.method, path, tag: e._tag, operation: e.operation }, String(e.cause));
        report({ kind: "infra", error: e });

        return fail(500, "Internal error");
      }),
    ),
    Effect.provide(servicesFor(env, settings, clock, ctx === null ? null : (work) => ctx.waitUntil(work), controls)),
    Effect.scoped,
    // outside servicesFor, so the Store and Upstream layers find it while they are built
    Effect.provideService(Timing, timing),
  );

  const exit = await Effect.runPromiseExit(program);

  if (Exit.isSuccess(exit)) return exit.value;
  logFailure("defect", { method: req.method, path }, Cause.pretty(exit.cause));
  report({ kind: "defect", cause: exit.cause });

  return fail(500, "Internal error");
}

const Job = z.object({ name: z.string(), version: z.string() });

/**
 * Scores queued upstream versions, one message per invocation (the consumer's batch size is 1, so one analysis has the
 * whole CPU limit). A failed job, or one whose upstream may answer later, is retried by the queue; one another run may
 * still be working on comes back once that run must have ended.
 */
export async function consume(batch: MessageBatch<unknown>, rawEnv: RawEnv): Promise<void> {
  const env = parseEnv(rawEnv);
  const settings = settingsOf(env, env.APM_REGISTRY_URL ?? "http://localhost/");

  for (const message of batch.messages) {
    const probe = QueueProbe.safeParse(message.body);

    // the cron's probe (health.ts): the queue delivered it, which is all the health check needs to know
    if (probe.success) {
      await recordProbe(env.BLOBS, probe.data.sentAt);
      message.ack();
      continue;
    }

    const job = Job.safeParse(message.body);

    if (!job.success) {
      message.ack();
      continue;
    }

    const exit = await Effect.runPromiseExit(
      Effect.flatMap(Analysis, (a) => a.runJob(job.data)).pipe(Effect.provide(servicesFor(env, settings, Clock.system)), Effect.scoped),
    );

    if (Exit.isFailure(exit)) {
      logFailure("analysis", { name: job.data.name, version: job.data.version }, Cause.pretty(exit.cause));
      message.retry();
    } else if (exit.value === "retry") message.retry();
    else if (exit.value === "busy") message.retry({ delaySeconds: RUN_WINDOW_MS / 1000 });
    else message.ack();
  }
}

/** Records that the queue delivered the cron's probe sent at `sentAt`. A failed write is logged: the health check then reports the queue stale. */
async function recordProbe(bucket: R2Bucket, sentAt: number): Promise<void> {
  try {
    await bucket.put(QUEUE_PROBE_KEY, JSON.stringify({ sentAt, receivedAt: Date.now() }), { httpMetadata: { contentType: "application/json" } });
  } catch (e) {
    logFailure("queue-probe", {}, String(e));
  }
}

/** Sends the health check's queue probe (health.ts). Runs first in the sweep and never stops it. */
async function sendProbe(queue: Queue<AnalysisJob> | undefined): Promise<void> {
  if (queue === undefined) return;

  try {
    // the queue carries analysis jobs; the consumer tells a probe apart by its shape (QueueProbe)
    const any: Queue<unknown> = queue;
    await any.send({ probe: "health", sentAt: Date.now() });
  } catch (e) {
    logFailure("queue-probe", {}, String(e));
  }
}

/**
 * Rewrites the install routes' block list from the database (blocklist.ts): the safety net under the writes that add
 * to it. It runs before the rest of the sweep, and a failure is logged without stopping the rest.
 */
const syncBlocklist = Effect.gen(function* () {
  const truth = yield* blockTruth(yield* SqlClient.SqlClient);
  const list = yield* (yield* Blocklist).sync(truth);

  console.log(JSON.stringify({ level: "info", event: "blocklist-sync", local: list.local.length, confirmed: list.confirmed.length }));
}).pipe(Effect.catch((e) => Effect.sync(() => logFailure("blocklist-sync", {}, String(e)))));

/** Requeues analyses the platform stopped: every run that began and never stored anything (analysis.ts, `recover`). */
const recoverAnalyses = Effect.flatMap(Analysis, (a) => a.recover).pipe(
  Effect.tap((n) => (n > 0 ? Effect.sync(() => console.log(JSON.stringify({ level: "info", event: "analysis-recover", requeued: n }))) : Effect.void)),
);

/** Works the kept package summaries out again (kept-package.ts): it reads whole packuments, so it runs late. */
const refreshPages = refreshKeptPackages.pipe(
  Effect.tap((n) => (n > 0 ? Effect.sync(() => console.log(JSON.stringify({ level: "info", event: "kept-package-refresh", refreshed: n }))) : Effect.void)),
);

/**
 * Works the kept popular-scores answers out again (apm.ts), last: it reads whole packuments, the slowest part. A
 * package refreshPages just read is in the isolate's cache.
 */
const refreshPopular = refreshLatestScores.pipe(
  Effect.tap((n) => (n > 0 ? Effect.sync(() => console.log(JSON.stringify({ level: "info", event: "latest-score-refresh", refreshed: n }))) : Effect.void)),
);

/** Writes down what time already decided: pending revokes past 24h, staged versions past their deadline, and drops spent factor challenges and confirmations and kept upstream choices nobody asked about for a week. Requeues analyses the platform stopped, then refreshes popular-scores' kept answers. */
export async function sweep(rawEnv: RawEnv, clock: Layer.Layer<Clock> = Clock.system): Promise<void> {
  const env = parseEnv(rawEnv);
  const settings = settingsOf(env, env.APM_REGISTRY_URL ?? "http://localhost/");

  await sendProbe(env.ANALYSIS_QUEUE);

  const exit = await Effect.runPromiseExit(
    Effect.all([syncBlocklist, matureRevocations, sweepStaged, sweepConfirmations, dropStaleChoices, recoverAnalyses, refreshPages, refreshPopular], { discard: true }).pipe(Effect.provide(servicesFor(env, settings, clock)), Effect.scoped),
  );

  if (Exit.isFailure(exit)) logFailure("sweep", {}, Cause.pretty(exit.cause));
}

export default {
  fetch: (req: Request, env: RawEnv, ctx: ExecutionContext): Promise<Response> => handle(req, env, Clock.system, ctx),
  queue: (batch: MessageBatch<unknown>, env: RawEnv): Promise<void> => consume(batch, env),
  scheduled: (_controller: ScheduledController, env: RawEnv, ctx: ExecutionContext): void => {
    ctx.waitUntil(sweep(env));
  },
};
