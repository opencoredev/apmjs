// One request in, one Response out. Picks the route; everything else lives in the route modules.
import { Effect } from "effect";
import { accountRoute } from "./account.ts";
import { apmExtensions, apmRoute, safeView, upstreamRoute } from "./apm.ts";
import { Auth } from "./auth.ts";
import { Clock } from "./clock.ts";
import { evidenceRoute } from "./evidence.ts";
import { fileRoute } from "./files.ts";
import { routePath } from "./http.ts";
import { reviewRoute } from "./review.ts";
import { callerOf, protocolRoute, type PackumentView } from "./server.ts";

export const route = (req: Request) =>
  Effect.gen(function* () {
    const url = new URL(req.url);

    if (url.pathname.startsWith("/api/auth/")) return yield* (yield* Auth).handler(req);

    const caller = yield* callerOf(req);
    const { path, viaSafe } = routePath(url.pathname);
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
