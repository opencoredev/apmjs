// The registry Worker: a thin fetch handler over the Effect program, the analysis queue consumer and the cron
// that writes down time-based state changes. Services are built per request from the Worker's bindings.
import { createHash, timingSafeEqual } from "node:crypto";
import { Cause, Effect, Exit, Layer } from "effect";
import type * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { Analysis, RUN_WINDOW_MS, type AnalysisJob } from "./analysis.ts";
import { matureRevocations } from "./apm.ts";
import { sweepConfirmations, sweepStaged } from "./account.ts";
import { Auth, type AuthOptions } from "./auth.ts";
import { Blobs } from "./blobs.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig, type RegistrySettings } from "./config.ts";
import { Store, type StoreFault } from "./db.ts";
import type { HttpFailure, InfraError } from "./errors.ts";
import { fail, failureResponse, withPrivacyHeaders, withServerTiming, withSlash } from "./http.ts";
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
  /** sha256 (hex) of the operator's debug token: a request whose x-apm-debug header is that token gets the full Server-Timing (timing.ts). */
  APM_DEBUG_TOKEN_HASH: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, "APM_DEBUG_TOKEN_HASH must be a sha256 hex digest")
    .optional(),
});

const DebugEnv = WorkerEnv.pick({ APM_DEBUG_TOKEN_HASH: true });

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
              Effect.runPromiseExit(considerUpstream(pkg).pipe(Effect.provide(fresh), Effect.scoped))
                .then((exit) => {
                  if (Exit.isFailure(exit)) logFailure("review", { name: pkg.name }, Cause.pretty(exit.cause));
                })
                // the package stays charged to the isolate's memory pool until the look at it is over
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
export function servicesFor(env: WorkerEnv, settings: RegistrySettings, clock: Layer.Layer<Clock>, background: Background = null, faults: ReadonlySet<StoreFault> = new Set()) {
  const databaseUrl = env.HYPERDRIVE.connectionString;
  const review = reviewSettings(env);
  const core = Layer.mergeAll(Store.postgres(databaseUrl, faults), Blobs.r2(env.BLOBS), clock, Layer.succeed(RegistryConfig, settings));
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

type LogFields = Readonly<Record<string, string | number | boolean | null>>;

/** One JSON line per failure, for Workers Logs. Causes are database, R2 and parse errors, never secrets. */
function logFailure(event: string, fields: LogFields, error: string): void {
  console.error(JSON.stringify({ level: "error", event, ...fields, error }));
}

/**
 * Runs the router for one request. `clock` is the system clock in production, and `faults` is empty there: only the
 * test entry (worker-test.ts) switches one on. Per-user answers are marked private, whichever route made them.
 */
export async function handle(
  req: Request,
  rawEnv: RawEnv,
  clock: Layer.Layer<Clock> = Clock.system,
  ctx: ExecutionContext | null = null,
  faults: ReadonlySet<StoreFault> = new Set(),
): Promise<Response> {
  const start = performance.now();
  const timing = Timing.make();
  const res = await respond({ req, rawEnv, clock, ctx, faults, timing });

  return withServerTiming(req, withPrivacyHeaders(req, res), timing.header({ total: performance.now() - start, detail: timingDetail(req, rawEnv) }));
}

type Respond = { req: Request; rawEnv: RawEnv; clock: Layer.Layer<Clock>; ctx: ExecutionContext | null; faults: ReadonlySet<StoreFault>; timing: TimingApi };

async function respond({ req, rawEnv, clock, ctx, faults, timing }: Respond): Promise<Response> {
  const parsed = WorkerEnv.safeParse(rawEnv);

  if (!parsed.success) {
    logFailure("config", {}, parsed.error.message);

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

  const program = route(req).pipe(
    Effect.catchTag("HttpFailure", (f: HttpFailure) => Effect.succeed(failureResponse(f))),
    Effect.catch((e: InfraError) =>
      Effect.sync(() => {
        logFailure("request", { method: req.method, path, tag: e._tag, operation: e.operation }, String(e.cause));

        return fail(500, "Internal error");
      }),
    ),
    Effect.provide(servicesFor(env, settings, clock, ctx === null ? null : (work) => ctx.waitUntil(work), faults)),
    Effect.scoped,
    // outside servicesFor, so the Store and Upstream layers find it while they are built
    Effect.provideService(Timing, timing),
  );

  const exit = await Effect.runPromiseExit(program);

  if (Exit.isSuccess(exit)) return exit.value;
  logFailure("defect", { method: req.method, path }, Cause.pretty(exit.cause));

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

/** Requeues analyses the platform stopped: every run that began and never stored anything (analysis.ts, `recover`). */
const recoverAnalyses = Effect.flatMap(Analysis, (a) => a.recover).pipe(
  Effect.tap((n) => (n > 0 ? Effect.sync(() => console.log(JSON.stringify({ level: "info", event: "analysis-recover", requeued: n }))) : Effect.void)),
);

/** Writes down what time already decided: pending revokes past 24h, staged versions past their deadline, and drops spent factor challenges and confirmations. Requeues analyses the platform stopped. */
export async function sweep(rawEnv: RawEnv, clock: Layer.Layer<Clock> = Clock.system): Promise<void> {
  const env = parseEnv(rawEnv);
  const settings = settingsOf(env, env.APM_REGISTRY_URL ?? "http://localhost/");

  const exit = await Effect.runPromiseExit(
    Effect.all([matureRevocations, sweepStaged, sweepConfirmations, recoverAnalyses], { discard: true }).pipe(Effect.provide(servicesFor(env, settings, clock)), Effect.scoped),
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
