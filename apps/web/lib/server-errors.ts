// The website's unhandled server errors, sent to Databuddy (packages/core/src/error-report.ts) from instrumentation.ts's
// onRequestError. On only when the Worker has APM_DATABUDDY_CLIENT_ID, which packages/infra binds on production alone.
//
// A report carries a fixed code ("internal" for an Error, "unknown" for anything else thrown), the route's label from
// WEB_ROUTES (Next.js names the route's file, such as /package/[...name]/page, never the path a visitor sent; a route
// missing from the table is "unknown"), no status (status=-: the answer's is not known yet, and is 200 when the error
// was in a streamed part, as a home page score badge's was on 2026-11-25), the build id and the colo. Never the error's message, name,
// digest or stack: Workers Logs keeps what Next.js logs.
import { errorReporter, type ErrorCode, type ErrorReporter, type WaitUntil } from "@apm/core/error-report";

/** Every route file in app/, as Next.js names it (without /page or /route), and its label in a report. */
export const WEB_ROUTES = {
  "/": "home",
  "/account": "account",
  "/account/packages": "account packages",
  "/admin/reviews": "admin reviews",
  "/approve/[id]": "approve",
  "/compare": "compare",
  "/device": "device",
  "/docs": "docs",
  "/package/[...name]": "package",
  "/privacy": "privacy",
  "/publish": "publish",
  "/reviews": "reviews",
  "/signin": "signin",
  "/terms": "terms",
  "/_not-found": "not-found",
  "/_global-error": "global-error",
  "/api/build": "api build",
  "/api/explain": "api explain",
  "/api/names": "api names",
  "/api/package-md/[...name]": "api package-md",
  "/api/readme": "api readme",
  "/api/search": "api search",
  "/llms-full.txt": "llms-full",
  "/llms.txt": "llms",
  "/mcp": "mcp",
  "/og/[[...name]]": "og",
  "/openapi.json": "openapi",
  "/.well-known/agent-card.json": "agent-card",
  "/robots.txt": "robots",
  "/sitemap.xml": "sitemap",
  "/icon.svg": "icon",
  "/apple-icon.png": "apple-icon",
  "/favicon.ico": "favicon",
} as const satisfies Readonly<Record<string, string>>;

type WebRoute = keyof typeof WEB_ROUTES;

const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const;

const ROUTE_TYPES = ["render", "route", "action", "proxy"] as const;

/** A report's route label: method, kind and route from the tables above, or "unknown". */
export type WebRouteLabel = `${(typeof METHODS)[number]} ${"render" | "route" | "action"} ${(typeof WEB_ROUTES)[WebRoute]}` | `${(typeof METHODS)[number]} proxy` | "unknown";

/** What onRequestError is given, in the parts a report reads (Instrumentation.onRequestError's parameters). */
export type RequestErrorInput = {
  readonly error: unknown;
  readonly method: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  /** The route's file, such as /package/[...name]/page (Next.js may prefix /app); "" when it names none. */
  readonly routePath: string;
  /** render, route, action or proxy. */
  readonly routeType: string;
};

function isWebRoute(key: string): key is WebRoute {
  return Object.hasOwn(WEB_ROUTES, key);
}

function oneOf<T extends string>(list: readonly T[], value: string): T | null {
  return list.find((v) => v === value) ?? null;
}

/** The route file Next.js names, as a WEB_ROUTES key: no /app prefix, no /page or /route suffix. */
function routeKey(routePath: string): string {
  const bare = routePath.replace(/^\/app(?=\/)/, "").replace(/\/(?:page|route)$/, "");

  return bare === "" ? "/" : bare;
}

/** A failed request's label: built only from the tables' strings, so nothing the visitor sent can be in it. */
export function webRouteLabel(input: Pick<RequestErrorInput, "method" | "routePath" | "routeType">): WebRouteLabel {
  const method = oneOf(METHODS, input.method);
  const kind = oneOf(ROUTE_TYPES, input.routeType);

  if (method === null || kind === null) return "unknown";

  if (kind === "proxy") return `${method} proxy`;

  if (input.routePath === "") return "unknown";
  const key = routeKey(input.routePath);

  return isWebRoute(key) ? `${method} ${kind} ${WEB_ROUTES[key]}` : "unknown";
}

/** The fixed code for what was thrown: by its class, never its text. */
export function webErrorCode(input: Pick<RequestErrorInput, "error">): ErrorCode {
  return input.error instanceof Error ? "internal" : "unknown";
}

/** The location from a cf-ray header ("8f1c2d3e4a5b6c7d-SJC"), or "" without one. */
export function coloOf(ray: string | string[] | undefined): string {
  const value = Array.isArray(ray) ? ray[0] : ray;
  const at = value?.lastIndexOf("-") ?? -1;

  return value !== undefined && at > 0 ? value.slice(at + 1) : "";
}

export type ReportContext = {
  readonly clientId: string;
  readonly build: string;
  readonly waitUntil: WaitUntil;
};

/** One reporter for the isolate, made once: its limit counts every request, whatever hostname it came in on. */
let reporter: ErrorReporter = errorReporter({ fetch: (url, init) => fetch(url, init) });

/** Reports one failed request. Never throws: what it reads is read in the waitUntil task, after the answer. */
export function reportRequestError(input: RequestErrorInput, context: ReportContext): boolean {
  try {
    return reporter.report({
      clientId: context.clientId,
      waitUntil: context.waitUntil,
      error: () => ({
        worker: "web",
        code: webErrorCode(input),
        route: webRouteLabel(input),
        // onRequestError runs before Next.js has picked the status, and an error in a streamed part leaves it 200
        status: null,
        build: context.build,
        colo: coloOf(input.headers["cf-ray"]),
      }),
    });
  } catch {
    return false;
  }
}

/** For tests: a fresh reporter (and limit) for the isolate, optionally with its own fetch and clock. */
export function resetReporter(options?: Parameters<typeof errorReporter>[0]): void {
  reporter = errorReporter(options ?? { fetch: (url, init) => fetch(url, init) });
}
