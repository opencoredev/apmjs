// One request in, one Response out. Picks the route; everything else lives in the route modules.
import { Effect } from "effect";
import { accountRoute } from "./account.ts";
import { apmExtensions, apmRoute, safeView, upstreamRoute } from "./apm.ts";
import { Auth } from "./auth.ts";
import { Clock } from "./clock.ts";
import { reviewRoute } from "./review.ts";
import { callerOf, protocolRoute, type PackumentView } from "./server.ts";

export const route = (req: Request) =>
  Effect.gen(function* () {
    const url = new URL(req.url);

    if (url.pathname.startsWith("/api/auth/")) return yield* (yield* Auth).handler(req);

    const caller = yield* callerOf(req);
    let path = url.pathname;
    let view: PackumentView | undefined;
    const viaSafe = path === "/~safe" || path.startsWith("/~safe/");

    if (viaSafe) {
      path = path.slice("/~safe".length) || "/";
      url.pathname = path;
      view = safeView(yield* (yield* Clock).now);
    }

    const review = yield* reviewRoute(req, url, caller);

    if (review) return review;
    const account = yield* accountRoute(req, url);

    if (account) return account;
    const apm = yield* apmRoute(req, url, caller);

    if (apm) return apm;

    if (!path.startsWith("/-/apm/v1/")) {
      const up = yield* upstreamRoute(req, url, viaSafe);

      if (up) return up;
    }

    return yield* protocolRoute(req, url, path, caller, apmExtensions, view);
  });
