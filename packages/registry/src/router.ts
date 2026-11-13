// One request in, one Response out. Picks the route; everything else lives in the route modules. A GET or HEAD is
// answered only on a path the GET table (routes.ts) lists.
import { Effect } from "effect";
import { accountRoute } from "./account.ts";
import { Analysis } from "./analysis.ts";
import { apmExtensions, apmRoute, safeView, sessionUser, upstreamRoute } from "./apm.ts";
import { Auth } from "./auth.ts";
import { Clock } from "./clock.ts";
import { evidenceRoute } from "./evidence.ts";
import { fileRoute } from "./files.ts";
import { fail, routePath } from "./http.ts";
import { reviewRoute } from "./review.ts";
import { AUTH_PREFIX, getRouteOf, NO_GET_ROUTE } from "./routes.ts";
import { callerOf, protocolRoute, type PackumentView } from "./server.ts";

export const route = (req: Request) =>
  Effect.gen(function* () {
    const url = new URL(req.url);
    const isAuth = url.pathname.startsWith(AUTH_PREFIX);
    const { path, viaSafe } = routePath(url.pathname);

    // a read the GET table (routes.ts) does not list is answered here, before any module could answer it
    if ((req.method === "GET" || req.method === "HEAD") && getRouteOf(url.pathname) === null) return fail(404, NO_GET_ROUTE);

    if (isAuth) return yield* (yield* Auth).handler(req);

    const caller = yield* callerOf(req);
    // an anonymous request never analyses anything: a version with no stored analysis is queued. A token caller, or a
    // website session (looked up only once an analysis would run), may have a few analysed inline.
    const auth = yield* Effect.context<Auth>();

    const signedIn: Effect.Effect<boolean> =
      caller.kind === "user"
        ? Effect.succeed(true)
        : !req.headers.has("cookie")
          ? Effect.succeed(false)
          : sessionUser(req).pipe(
              Effect.map((user) => user !== null),
              Effect.catch(() => Effect.succeed(false)),
              Effect.provide(auth),
            );

    yield* (yield* Analysis).allowInline(signedIn);
    let view: PackumentView | undefined;

    if (viaSafe) {
      url.pathname = path;
      view = safeView(yield* (yield* Clock).now);
    }

    const review = yield* reviewRoute(req, url, caller);

    if (review) return review;
    const evidence = yield* evidenceRoute(req, url, caller);

    if (evidence) return evidence;
    const account = yield* accountRoute(req, url);

    if (account) return account;
    const file = yield* fileRoute(req, url);

    if (file) return file;
    const apm = yield* apmRoute(req, url, caller);

    if (apm) return apm;

    if (!path.startsWith("/-/apm/v1/")) {
      const up = yield* upstreamRoute(req, url, viaSafe);

      if (up) return up;
    }

    return yield* protocolRoute(req, url, path, caller, apmExtensions, view);
  });
