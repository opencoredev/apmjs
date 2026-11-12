// Every GET route the registry answers, in one table. router.ts refuses a GET or HEAD whose path matches no entry
// before any route module sees it, so a GET handler added to a module answers nothing until it is listed here, and
// tests/acceptance/revoke-sweep.test.ts sends a request to every entry (and fails on an entry it does not probe).
// Paths are matched after a /~safe prefix is removed, except Better Auth's, which never take one.

/** One path segment of a package name: a bare name, or a scope and name with the slash as is or encoded. */
const NAME = String.raw`(?:@[^/]+(?:/|%2[fF])[^/]+|[^/@~-][^/]*)`;

/** One segment that is not empty. */
const SEG = String.raw`[^/]+`;

const path = (body: string): RegExp => new RegExp(`^${body}$`);

/** A GET route: a stable name (the sweep's probes name the route they exercise) and the paths it answers. */
export type GetRoute = { readonly name: string; readonly pattern: RegExp };

export const GET_ROUTES = [
  // the npm protocol (server.ts), and npm's packages through upstreamRoute (apm.ts)
  { name: "root", pattern: path("/") },
  { name: "ping", pattern: path("/-/ping") },
  { name: "whoami", pattern: path("/-/whoami") },
  { name: "user", pattern: path(String.raw`/-/user/org\.couchdb\.user:${SEG}`) },
  { name: "search", pattern: path("/-/v1/search") },
  { name: "dist-tags", pattern: path(`/-/package/${NAME}/dist-tags`) },
  { name: "packument", pattern: path(`/${NAME}`) },
  { name: "version", pattern: path(`/${NAME}/[^/-][^/]*`) },
  { name: "tarball", pattern: path(String.raw`/${NAME}/-/${SEG}\.tgz`) },
  // apm's API (apm.ts)
  { name: "names", pattern: path("/-/apm/v1/names") },
  { name: "recent", pattern: path("/-/apm/v1/recent") },
  { name: "resolve", pattern: path("/-/apm/v1/resolve") },
  { name: "me", pattern: path("/-/apm/v1/me") },
  { name: "score", pattern: path(`/-/apm/v1/score/${NAME}(?:/${SEG})?`) },
  { name: "package", pattern: path(`/-/apm/v1/packages/${NAME}`) },
  { name: "events", pattern: path(`/-/apm/v1/packages/${NAME}/events`) },
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
  // Better Auth (auth.ts lets only its ROUTES through, and these are their GETs)
  { name: "auth get-session", pattern: path("/api/auth/get-session") },
  { name: "auth error", pattern: path("/api/auth/error") },
  { name: "auth ok", pattern: path("/api/auth/ok") },
  { name: "auth passkey register options", pattern: path("/api/auth/passkey/generate-register-options") },
  { name: "auth passkey sign-in options", pattern: path("/api/auth/passkey/generate-authenticate-options") },
  { name: "auth device", pattern: path("/api/auth/device") },
  { name: "auth callback", pattern: path(`/api/auth/callback/${SEG}`) },
  { name: "auth oauth2 callback", pattern: path(`/api/auth/oauth2/callback/${SEG}`) },
] as const satisfies readonly GetRoute[];

export type GetRouteName = (typeof GET_ROUTES)[number]["name"];

/** The GET route a path belongs to, or null when the registry has none for it. */
export function getRouteOf(pathname: string): GetRouteName | null {
  return GET_ROUTES.find((r) => r.pattern.test(pathname))?.name ?? null;
}

/** What a GET or HEAD of a path in no route answers. */
export const NO_GET_ROUTE = "Not found: the registry has no GET route for this path.";
