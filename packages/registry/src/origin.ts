// Website-only writes (account and approval actions, factor confirmations, review decisions, evidence dismissals)
// ride on the session cookie, so they must come from the website itself. Browsers send Origin on every POST, so a
// request with none, with "null", or with another site's is refused before anything is read or spent. Routes that
// take a CLI or CI token (Authorization) never call this: a token is not sent by a browser on its own.
import { Effect } from "effect";
import { RegistryConfig } from "./config.ts";
import { refuse } from "./errors.ts";

/** The origins a website write may come from: the website, and the registry's own origin (the same one when not split). */
export const siteOrigins = Effect.gen(function* () {
  const { webUrl, baseUrl } = yield* RegistryConfig;

  return new Set([new URL(webUrl).origin, new URL(baseUrl).origin]) satisfies ReadonlySet<string>;
});

/** Fails with 403 unless the request's Origin is the website's. */
export const requireSiteOrigin = (req: Request) =>
  Effect.gen(function* () {
    const origin = req.headers.get("origin");

    if (origin === null) return yield* Effect.fail(refuse(403, "This request has no Origin header. Make this change from the website."));

    if (!(yield* siteOrigins).has(origin)) return yield* Effect.fail(refuse(403, "Cross-site request refused."));
  });
