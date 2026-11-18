// The website's server error reports (lib/server-errors.ts): a fixed code by what was thrown, a static label from the
// route table for every route file in app/, and nothing the visitor sent or the error said.
import { afterEach, describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { coloOf, reportRequestError, resetReporter, WEB_ROUTES, webErrorCode, webRouteLabel, type RequestErrorInput } from "./server-errors";

afterEach(() => resetReporter());

const INPUT: RequestErrorInput = {
  error: new TypeError("Cannot read /device?code=ABCD-1234 for someone@example.com"),
  method: "GET",
  headers: { "cf-ray": "8f1c2d3e4a5b6c7d-SJC", cookie: "better-auth.session_token=abc123def456ghi789jkl", authorization: "Bearer apm_secret_1234567890abcdef" },
  routePath: "/package/[...name]/page",
  routeType: "render",
};

/** Next.js's route name for each page.tsx and route.ts(x) under app/, and the metadata files it serves. */
function appRoutes(): string[] {
  const app = join(import.meta.dir, "..", "app");
  const files = readdirSync(app, { recursive: true, encoding: "utf8" });

  const routes = files.flatMap((f) => {
    const m = /^(.*?)(?:^|\/)(page|route)\.(tsx|ts)$/.exec(f.split(sep).join("/"));

    return m ? [`/${m[1] ?? ""}`] : [];
  });

  const metadata = files.flatMap((f) => {
    const name = relative(".", f);

    if (name === "robots.ts") return ["/robots.txt"];

    if (name === "sitemap.ts") return ["/sitemap.xml"];

    return ["icon.svg", "apple-icon.png", "favicon.ico"].includes(name) ? [`/${name}`] : [];
  });

  return [...routes, ...metadata].map((r) => (r === "/" ? r : r.replace(/\/$/, "")));
}

describe("webRouteLabel", () => {
  test("WEB_ROUTES has every route file in app/, and Next.js's own not-found and global-error", () => {
    const routes = appRoutes();

    expect(routes.length).toBeGreaterThan(20);
    expect([...routes, "/_not-found", "/_global-error"].toSorted()).toEqual(Object.keys(WEB_ROUTES).toSorted());
  });

  test("labels a route by method, kind and the table's name, in every spelling Next.js uses for the file", () => {
    expect(webRouteLabel(INPUT)).toBe("GET render package");
    expect(webRouteLabel({ ...INPUT, routePath: "/package/[...name]" })).toBe("GET render package");
    expect(webRouteLabel({ ...INPUT, routePath: "/app/package/[...name]/page" })).toBe("GET render package");
    expect(webRouteLabel({ method: "GET", routePath: "/page", routeType: "render" })).toBe("GET render home");
    expect(webRouteLabel({ method: "POST", routePath: "/approve/[id]/page", routeType: "action" })).toBe("POST action approve");
    expect(webRouteLabel({ method: "GET", routePath: "/api/package-md/[...name]/route", routeType: "route" })).toBe("GET route api package-md");
    expect(webRouteLabel({ method: "GET", routePath: "/_not-found/page", routeType: "render" })).toBe("GET render not-found");
    expect(webRouteLabel({ method: "GET", routePath: "", routeType: "proxy" })).toBe("GET proxy");
  });

  test("an unrecognized route, kind or method is unknown, never the value Next.js passed", () => {
    expect(webRouteLabel({ ...INPUT, routePath: "/package/react" })).toBe("unknown");
    expect(webRouteLabel({ ...INPUT, routePath: "/approve/stg_AbCdEf123456" })).toBe("unknown");
    expect(webRouteLabel({ ...INPUT, routePath: "/new-route/page" })).toBe("unknown");
    expect(webRouteLabel({ ...INPUT, routePath: "" })).toBe("unknown");
    expect(webRouteLabel({ ...INPUT, routeType: "something" })).toBe("unknown");
    expect(webRouteLabel({ ...INPUT, method: "X-SECRET" })).toBe("unknown");
    expect(webRouteLabel({ ...INPUT, routePath: "toString" })).toBe("unknown");
    expect(webRouteLabel({ ...INPUT, routePath: "/__proto__" })).toBe("unknown");
  });
});

describe("webErrorCode", () => {
  test("is internal for an Error, whatever its name, message or digest, and unknown for anything else", () => {
    expect(webErrorCode({ error: INPUT.error })).toBe("internal");
    expect(webErrorCode({ error: Object.assign(new Error(""), { digest: "custom-digest-with-someone@example.com" }) })).toBe("internal");
    expect(webErrorCode({ error: Object.assign(new Error("x"), { name: "SecretName" }) })).toBe("internal");
    expect(webErrorCode({ error: "a thrown string" })).toBe("unknown");
    expect(webErrorCode({ error: { message: "an object" } })).toBe("unknown");
  });
});

test("coloOf reads the cf-ray suffix", () => {
  expect(coloOf("8f1c2d3e4a5b6c7d-LHR")).toBe("LHR");
  expect(coloOf(["8f1c-AMS", "x-y"])).toBe("AMS");
  expect(coloOf(undefined)).toBe("");
  expect(coloOf("noray")).toBe("");
});

type Sent = { url: string; init: RequestInit };

/** A collector stand-in: what was sent, and the fetch that records it. */
type Collector = { sent: Sent[]; fetch: (url: string, init: RequestInit) => Promise<Response> };

function collector(): Collector {
  const sent: Sent[] = [];

  return {
    sent,
    fetch: async (url, init) => {
      sent.push({ url, init });

      return new Response(null, { status: 204 });
    },
  };
}

describe("reportRequestError", () => {
  test("is off without a client id", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];

    resetReporter({ fetch: c.fetch });
    expect(reportRequestError(INPUT, { clientId: "", build: "", waitUntil: (w) => waited.push(w) })).toBe(false);
    await Promise.all(waited);
    expect(c.sent).toHaveLength(0);
  });

  test("sends the code, the label, the status, the build and the colo, and nothing of the error or the visitor's request", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];

    resetReporter({ fetch: c.fetch, now: () => 9 });
    expect(reportRequestError(INPUT, { clientId: "client-1", build: "b1", waitUntil: (w) => waited.push(w) })).toBe(true);
    await Promise.all(waited);
    expect(c.sent).toHaveLength(1);
    const [s] = c.sent;

    expect(new Headers(s?.init.headers).get("origin")).toBe("https://apmjs.dev");
    expect(JSON.parse(String(s?.init.body))).toEqual([
      {
        timestamp: 9,
        path: "https://apmjs.dev/_server/GET_render_package",
        message: "internal",
        errorType: "internal",
        filename: "web@b1",
        stack: "worker=web code=internal status=500 route=GET_render_package colo=SJC build=b1",
      },
    ]);
  });

  test("never throws, and sends nothing, when the input's getters throw", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];

    resetReporter({ fetch: c.fetch });

    const hostile = Object.defineProperty({ ...INPUT }, "routePath", {
      get() {
        throw new Error("getter");
      },
    });

    // the report is built in the waitUntil task, so it is queued, and the task sends nothing and settles
    expect(reportRequestError(hostile, { clientId: "client-1", build: "b1", waitUntil: (w) => waited.push(w) })).toBe(true);
    expect(await Promise.all(waited)).toEqual([undefined]);
    expect(
      reportRequestError(INPUT, {
        clientId: "client-1",
        build: "",
        waitUntil: () => {
          throw new Error("no context");
        },
      }),
    ).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(c.sent).toHaveLength(0);
  });
});
