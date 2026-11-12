// The acceptance suite's entry: the production Worker plus test-only controls, never deployed.
// x-apm-test-now sets the registry clock for one request and x-apm-test-totp-now the wall clock authenticator
// codes are checked against; POST /__test/mint issues a token without a login flow.
// /__test/blobs lists the blob store's keys (GET) and overwrites one (PUT /__test/blobs/<key>), so tests can
// tamper with stored bytes. POST /__test/upstream-cache puts a packument in the shared cache as another isolate would
// have, with the fetch time the test names. POST /__test/sweep runs the cron's sweep at the test clock. POST /__test/analysis-job runs
// the queue consumer on one job and says whether it acked the message or asked for a retry. x-apm-test-queue: fail
// makes the analysis queue refuse every send for that request, and x-apm-test-fault: event-insert makes every
// public-log insert fail inside Postgres for that request. All of it answers only to a caller holding
// TEST_CONTROL_SECRET, a binding the deployed Worker does not have.
import { Effect } from "effect";
import { z } from "zod";
import { Clock } from "./clock.ts";
import { Store, type StoreFault } from "./db.ts";
import { fail, json } from "./http.ts";
import { issueToken } from "./server.ts";
import { FETCHED_AT_HEADER, packumentKey } from "./upstream.ts";
import worker, { consume, handle, parseEnv, servicesFor, sweep, type RawEnv } from "./worker.ts";

/** A positive millisecond time from a test header, or null. */
function timeHeader(req: Request, name: string): number | null {
  const at = Number(req.headers.get(name));

  return Number.isFinite(at) && at > 0 ? at : null;
}

function testClock(req: Request): ReturnType<typeof Clock.fixed> {
  const now = timeHeader(req, "x-apm-test-now");

  return now === null ? Clock.system : Clock.fixed({ now, wallNow: timeHeader(req, "x-apm-test-totp-now") });
}

const MintBody = z.object({ user: z.string().min(1), scope: z.enum(["publish", "stage"]) });

/** The test Worker's env: the production bindings plus the control secret the harness holds. */
type TestEnv = RawEnv & { readonly TEST_CONTROL_SECRET?: string };

const ControlSecret = z.object({ TEST_CONTROL_SECRET: z.string().min(16) });

function controlSecret(env: TestEnv): string | null {
  const parsed = ControlSecret.safeParse(env);

  return parsed.success ? parsed.data.TEST_CONTROL_SECRET : null;
}

async function mint(req: Request, env: TestEnv, clock: ReturnType<typeof Clock.fixed>): Promise<Response> {
  const body = MintBody.safeParse(await req.json());

  if (!body.success) return fail(400, body.error.message);
  const parsed = parseEnv(env);
  const settings = { baseUrl: "http://localhost/", webUrl: "http://localhost/", upstreamUrl: null, legacyAuth: false, namePolicy: "open" as const, admins: [] };
  const { user, scope } = body.data;

  const program = Effect.gen(function* () {
    const store = yield* Store;
    const now = yield* (yield* Clock).now;

    if (!(yield* store.getUser(user))) yield* store.createUser({ name: user, password_hash: "", email: "", created_at: now });

    return yield* issueToken({ user, label: scope === "publish" ? "direct publish (minted)" : "staging (minted)", scope });
  }).pipe(Effect.provide(servicesFor(parsed, settings, clock)), Effect.scoped);

  return json({ token: await Effect.runPromise(program) });
}

async function blobControl(req: Request, env: TestEnv, path: string): Promise<Response> {
  const bucket = parseEnv(env).BLOBS;

  if (req.method === "GET" && path === "/__test/blobs") {
    const keys: string[] = [];
    let cursor: string | undefined;

    do {
      const page = await bucket.list(cursor === undefined ? {} : { cursor });
      keys.push(...page.objects.map((o) => o.key));
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor !== undefined);

    return json({ keys });
  }

  if (req.method === "PUT") {
    await bucket.put(decodeURIComponent(path.slice("/__test/blobs/".length)), await req.arrayBuffer());

    return json({ ok: true });
  }

  return fail(405, "Method not allowed");
}

const SeedBody = z.object({ url: z.string().url(), packument: z.string(), fetchedAt: z.number().nullable() });

/** Puts npm's answer for `url` in the data center's cache, sent at `fetchedAt` (null: a copy from before copies carried a time). */
async function seedUpstreamCache(req: Request): Promise<Response> {
  const body = SeedBody.safeParse(await req.json());

  if (!body.success) return fail(400, body.error.message);
  const headers = new Headers({ "content-type": "application/json", "cache-control": "public, max-age=600" });

  if (body.data.fetchedAt !== null) headers.set(FETCHED_AT_HEADER, String(body.data.fetchedAt));
  await caches.default.put(packumentKey(body.data.url), new Response(body.data.packument, { headers }));

  return json({ ok: true });
}

const JobBody = z.object({ name: z.string().min(1), version: z.string().min(1) });

/** Runs the consumer on a one-message batch, the way the queue delivers it, and reports what it did with the message. */
async function analysisJob(req: Request, env: TestEnv): Promise<Response> {
  const job = JobBody.safeParse(await req.json());

  if (!job.success) return fail(400, job.error.message);
  let outcome: "ack" | "retry" | "none" = "none";

  const message = {
    id: "test",
    timestamp: new Date(),
    body: job.data,
    attempts: 1,
    ack: () => {
      outcome = "ack";
    },
    retry: () => {
      outcome = "retry";
    },
  } satisfies Message<unknown>;

  const batch = {
    queue: "test",
    messages: [message],
    metadata: { metrics: { backlogCount: 0, backlogBytes: 0 } },
    ackAll: () => message.ack(),
    retryAll: () => message.retry(),
  } satisfies MessageBatch<unknown>;

  await consume(batch, env);

  return json({ outcome });
}

/** The env for one request: with x-apm-test-queue: fail, an analysis queue whose every send fails. */
function envFor(req: Request, env: TestEnv): TestEnv {
  if (req.headers.get("x-apm-test-queue") !== "fail") return env;

  const refuse = (): Promise<never> => Promise.reject(new Error("test: the queue refused the message"));

  return { ...env, ANALYSIS_QUEUE: { send: refuse, sendBatch: refuse, metrics: () => Promise.resolve({ backlogCount: 0, backlogBytes: 0 }) } };
}

/** The store faults a trusted request asked for with x-apm-test-fault. */
function faultsFor(req: Request): ReadonlySet<StoreFault> {
  return req.headers.get("x-apm-test-fault") === "event-insert" ? new Set(["event-insert"]) : new Set();
}

export default {
  async fetch(req: Request, env: TestEnv, ctx: ExecutionContext): Promise<Response> {
    const secret = controlSecret(env);
    const trusted = secret !== null && req.headers.get("x-apm-test-control") === secret;
    const clock = trusted ? testClock(req) : Clock.system;
    const path = new URL(req.url).pathname;

    if (path === "/__test/mint") return trusted ? mint(req, env, clock) : fail(404, "Not found");

    if (path === "/__test/blobs" || path.startsWith("/__test/blobs/")) return trusted ? blobControl(req, env, path) : fail(404, "Not found");

    if (path === "/__test/upstream-cache") return trusted && req.method === "POST" ? seedUpstreamCache(req) : fail(404, "Not found");

    if (path === "/__test/analysis-job") return trusted && req.method === "POST" ? analysisJob(req, env) : fail(404, "Not found");

    if (path === "/__test/sweep") return trusted && req.method === "POST" ? sweep(env, clock).then(() => json({ ok: true })) : fail(404, "Not found");

    if (!trusted) return handle(req, env, clock, ctx);
    const headers = new Headers(req.headers);
    headers.delete("x-apm-test-control");
    headers.delete("x-apm-test-now");
    headers.delete("x-apm-test-totp-now");
    headers.delete("x-apm-test-queue");
    headers.delete("x-apm-test-fault");

    return handle(new Request(req, { headers }), envFor(req, env), clock, ctx, faultsFor(req));
  },
  queue: worker.queue,
  scheduled: worker.scheduled,
};
