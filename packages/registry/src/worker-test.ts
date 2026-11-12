// The acceptance suite's entry: the production Worker plus test-only controls, never deployed.
// x-apm-test-now sets the registry clock for one request and x-apm-test-totp-now the wall clock authenticator
// codes are checked against; POST /__test/mint issues a token without a login flow.
// /__test/blobs lists the blob store's keys (GET) and overwrites one (PUT /__test/blobs/<key>), so tests can
// tamper with stored bytes. POST /__test/sweep runs the cron's sweep at the test clock. All of it answers only to a caller holding TEST_CONTROL_SECRET, a binding the
// deployed Worker does not have.
import { Effect } from "effect";
import { z } from "zod";
import { Clock } from "./clock.ts";
import { Store } from "./db.ts";
import { fail, json } from "./http.ts";
import { issueToken } from "./server.ts";
import worker, { handle, parseEnv, servicesFor, sweep, type RawEnv } from "./worker.ts";

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
  const settings = { baseUrl: "http://localhost/", webUrl: "http://localhost/", upstreamUrl: null, legacyAuth: false, namePolicy: "open" as const };
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

export default {
  async fetch(req: Request, env: TestEnv, ctx: ExecutionContext): Promise<Response> {
    const secret = controlSecret(env);
    const trusted = secret !== null && req.headers.get("x-apm-test-control") === secret;
    const clock = trusted ? testClock(req) : Clock.system;
    const path = new URL(req.url).pathname;

    if (path === "/__test/mint") return trusted ? mint(req, env, clock) : fail(404, "Not found");

    if (path === "/__test/blobs" || path.startsWith("/__test/blobs/")) return trusted ? blobControl(req, env, path) : fail(404, "Not found");

    if (path === "/__test/sweep") return trusted && req.method === "POST" ? sweep(env, clock).then(() => json({ ok: true })) : fail(404, "Not found");

    if (!trusted) return handle(req, env, clock, ctx);
    const headers = new Headers(req.headers);
    headers.delete("x-apm-test-control");
    headers.delete("x-apm-test-now");
    headers.delete("x-apm-test-totp-now");

    return handle(new Request(req, { headers }), env, clock, ctx);
  },
  queue: worker.queue,
  scheduled: worker.scheduled,
};
