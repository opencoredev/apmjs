// Every GET route the registry answers, in one table. router.ts refuses a GET or HEAD whose path matches no entry
// before any route module sees it, so a GET handler added to a module answers nothing until it is listed here, and
// tests/acceptance/revoke-sweep.test.ts sends a request to every entry (and fails on an entry it does not probe).
// Paths are matched after a /~safe prefix is removed, except Better Auth's, which never take one.
//
// The table matches a path in the form the route modules read it (routeKey), so every spelling a module answered
// before the table existed still reaches it: tests/acceptance/route-compat.test.ts compares each one with 19a99eb.

import { routePath } from "./http.ts";

/** A scope's segment with no slash in it: a scoped name's first of two segments, as splitPath reads them. */
const SCOPE = String.raw`@(?:(?!%2F)[^/])*`;

/**
 * A package name, as splitPath reads it: a scope and name in one segment (its slash was encoded), a scope then a name,
 * or a bare name.
 */
const NAME = String.raw`(?:@[^/]*%2F[^/]*|${SCOPE}/[^/]+|[^/@~-][^/]*)`;

/** One segment that is not empty. */
const SEG = String.raw`[^/]+`;

/** Segments after the ones a route reads: its module ignores them, as it did before the table. Any character, line
 * terminators included: a decoded %0a or U+2028 in an ignored segment answered before the table too. */
const TAIL = String.raw`(?:/[\s\S]*)?`;

const path = (body: string): RegExp => new RegExp(`^${body}$`);

/** A GET route: a stable name (the sweep's probes name the route they exercise) and the paths it answers. */
export type GetRoute = { readonly name: string; readonly pattern: RegExp };

/** The paths router.ts hands to Better Auth (auth.ts), as is: they never take a /~safe prefix. */
export const AUTH_PREFIX = "/api/auth/";

/** The registry's own GET routes: every path outside AUTH_PREFIX, after a /~safe prefix is removed. */
const REGISTRY_ROUTES = [
  // the npm protocol (server.ts), and npm's packages through upstreamRoute (apm.ts)
  // a lone scope names no package: the protocol route answers it as the root
  { name: "root", pattern: path(`/(?:${SCOPE})?`) },
  { name: "ping", pattern: path("/-/ping") },
  { name: "whoami", pattern: path("/-/whoami") },
  { name: "user", pattern: path(String.raw`/-/user/org\.couchdb\.user:.*`) },
  { name: "search", pattern: path("/-/v1/search") },
  // a GET reads the whole map, so a tag after it is read past
  { name: "dist-tags", pattern: path(`/-/package/${NAME}/dist-tags${TAIL}`) },
  { name: "packument", pattern: path(`/${NAME}`) },
  { name: "version", pattern: path(`/${NAME}/[^/-][^/]*${TAIL}`) },
  { name: "tarball", pattern: path(String.raw`/${NAME}/-/${SEG}\.tgz${TAIL}`) },
  // apm's API (apm.ts)
  { name: "names", pattern: path("/-/apm/v1/names") },
  { name: "recent", pattern: path("/-/apm/v1/recent") },
  { name: "resolve", pattern: path("/-/apm/v1/resolve") },
  { name: "me", pattern: path("/-/apm/v1/me") },
  { name: "score", pattern: path(`/-/apm/v1/score/${NAME}${TAIL}`) },
  { name: "package", pattern: path(`/-/apm/v1/packages/${NAME}`) },
  { name: "events", pattern: path(`/-/apm/v1/packages/${NAME}/events${TAIL}`) },
  // a version's files and readme (files.ts)
  { name: "file", pattern: path(`/-/apm/v1/file/${NAME}/${SEG}`) },
  { name: "readme", pattern: path(`/-/apm/v1/readme/${NAME}/${SEG}`) },
  // the AI review (review.ts) and evidence dismissals (evidence.ts)
  { name: "review", pattern: path(`/-/apm/v1/review/${NAME}/${SEG}`) },
  { name: "review queue", pattern: path("/-/apm/v1/review-admin/queue") },
  { name: "review lease", pattern: path("/-/apm/v1/review-jobs") },
  { name: "reviewer", pattern: path("/-/apm/v1/evidence-admin/me") },
  // the account (account.ts)
  { name: "auth config", pattern: path("/-/apm/v1/auth/config") },
  { name: "account", pattern: path("/-/apm/v1/account") },
  { name: "staged list", pattern: path("/-/apm/v1/staged") },
  { name: "staged detail", pattern: path("/-/apm/v1/staged/[A-Za-z0-9_-]+") },
  { name: "staged file", pattern: path("/-/apm/v1/staged/[A-Za-z0-9_-]+/file") },
] as const satisfies readonly GetRoute[];

/**
 * Better Auth's GET routes (auth.ts lets only its ROUTES through, and these are their GETs). A path under AUTH_PREFIX
 * is matched against these alone: the registry's routes would read it as a package named "api".
 */
const AUTH_ROUTES = [
  { name: "auth get-session", pattern: path("/api/auth/get-session") },
  { name: "auth error", pattern: path("/api/auth/error") },
  { name: "auth ok", pattern: path("/api/auth/ok") },
  { name: "auth passkey register options", pattern: path("/api/auth/passkey/generate-register-options") },
  { name: "auth passkey sign-in options", pattern: path("/api/auth/passkey/generate-authenticate-options") },
  { name: "auth device", pattern: path("/api/auth/device") },
  // auth.ts hands Better Auth every path under a callback prefix
  { name: "auth callback", pattern: path(`/api/auth/callback${TAIL}`) },
  { name: "auth oauth2 callback", pattern: path(`/api/auth/oauth2/callback${TAIL}`) },
] as const satisfies readonly GetRoute[];

export const GET_ROUTES = [...REGISTRY_ROUTES, ...AUTH_ROUTES] as const;

export type GetRouteName = (typeof GET_ROUTES)[number]["name"];

/** A segment percent-decoded, or as is when it does not decode (splitPath in server.ts does the same). */
function decodeSegment(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * A path as the route modules read it: empty segments dropped (a trailing or doubled slash), and each segment
 * percent-decoded (`%40` is `@`), as splitPath does. A slash that decoding produced is written back as %2F, so it stays
 * inside its segment the way a scoped name's `@scope%2fname` does, and a percent sign as %25, so %2F means only that.
 * A module that compares the raw path exactly still refuses a spelling this accepts, as it did before the table.
 */
export function routeKey(pathname: string): string {
  const segs = pathname
    .split("/")
    .filter((s) => s.length > 0)
    .map((s) => decodeSegment(s).replaceAll("%", "%25").replaceAll("/", "%2F"));

  return `/${segs.join("/")}`;
}

/** The first route of a table that answers a path in routeKey form. */
function routeIn<R extends GetRoute>(table: readonly R[], key: string): R["name"] | null {
  return table.find((r) => r.pattern.test(key))?.name ?? null;
}

/** The GET route a request's path belongs to (as sent, /~safe and all), or null when the registry has none for it. */
export function getRouteOf(pathname: string): GetRouteName | null {
  if (pathname.startsWith(AUTH_PREFIX)) return routeIn(AUTH_ROUTES, routeKey(pathname));

  return routeIn(REGISTRY_ROUTES, routeKey(routePath(pathname).path));
}

/** What a GET or HEAD of a path in no route answers. */
export const NO_GET_ROUTE = "Not found: the registry has no GET route for this path.";
