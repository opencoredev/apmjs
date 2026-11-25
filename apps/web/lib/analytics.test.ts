// Databuddy's standard tracker on apmjs.dev and docs.apmjs.dev (lib/analytics.ts, components/databuddy.tsx,
// apps/docs/analytics.ts): no static databuddy.js tag, one inline loader per site that adds the tag with the agreed
// settings and skip patterns only at the canonical origin, without Global Privacy Control or Do Not Track, and (on the
// website) off the private routes, and a CSP that lets the tag load and send. The browser check against the real
// databuddy.js, with its endpoint stubbed, is scripts/analytics-browser.ts.
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, sep } from "node:path";
import { DOCS_ORIGIN, docsAnalytics, docsLoaderScript } from "../../docs/analytics";
import { contentSecurityPolicy } from "./security-headers";
import { DATABUDDY_FLAGS_ORIGIN, DATABUDDY_INGEST_ORIGIN, DATABUDDY_SCRIPT_ORIGIN } from "./databuddy-origin";
import { DATABUDDY_LOAD_GLOBAL, DATABUDDY_SCRIPT_URL, databuddyAttributes, databuddyLoaderScript, isPrivatePath, maySend, optedOut, PRIVATE_MASK_PATTERNS, PRIVATE_ROUTES, PRIVATE_SKIP_PATTERNS, SITE_ORIGINS, type BrowserView, type Site } from "./analytics";

const WEB = join(import.meta.dir, "..");
const DOCS = join(WEB, "..", "docs");

/** Every source file of the website, as [path relative to apps/web, text]. */
function sources(): [string, string][] {
  return ["app", "components", "lib"].flatMap((dir) =>
    readdirSync(join(WEB, dir), { recursive: true, encoding: "utf8" })
      .filter((f) => /\.(tsx?|css)$/.test(f) && !/\.test\.tsx?$/.test(f))
      .map((f): [string, string] => [`${dir}/${f.split(sep).join("/")}`, readFileSync(join(WEB, dir, f), "utf8")]),
  );
}

/**
 * Whether databuddy.js skips `path` for `pattern`, as its matcher (Pe in databuddy.js) does for the patterns used
 * here: an exact match, or a trailing "/*" that matches any path under the prefix before the "*".
 */
function skips(path: string, pattern: string): boolean {
  if (path === pattern) return true;
  const star = pattern.indexOf("*");

  return star !== -1 && pattern.slice(star) === "*" && path.startsWith(pattern.slice(0, star));
}

const skipped = (path: string): boolean => PRIVATE_SKIP_PATTERNS.some((p) => skips(path, p));

/**
 * The path databuddy.js reports for `path` under a "/route/**" mask (Mt in databuddy.js): the route, then "*" for
 * anything after it; null when the mask does not apply.
 */
function masked(path: string, pattern: string): string | null {
  const route = pattern.replace(/\/\*\*$/, "");

  if (path === route) return route;

  return path.startsWith(`${route}/`) ? `${route}/*` : null;
}

const maskedPath = (path: string): string => PRIVATE_MASK_PATTERNS.map((p) => masked(path, p)).find((m) => m !== null) ?? path;

describe("the databuddy.js tag", () => {
  test("loads the standard script with the client id, the three trackers and the private skip patterns", () => {
    expect(DATABUDDY_SCRIPT_URL).toBe("https://cdn.databuddy.cc/databuddy.js");
    expect(databuddyAttributes("docs", "client-1")).toEqual({
      "data-client-id": "client-1",
      "data-track-web-vitals": "true",
      "data-track-errors": "true",
      "data-track-outgoing-links": "true",
    });
    expect(databuddyAttributes("web", "client-1")).toEqual({
      "data-client-id": "client-1",
      "data-skip-patterns": '["/account","/account/*","/approve","/approve/*","/admin","/admin/*","/device","/device/*","/signin","/signin/*","/publish","/publish/*"]',
      "data-mask-patterns": '["/account/**","/approve/**","/admin/**","/device/**","/signin/**","/publish/**"]',
      "data-track-web-vitals": "true",
      "data-track-errors": "true",
      "data-track-outgoing-links": "true",
    });
  });

  test("skips every private route, bare and nested, and none of the public ones", () => {
    expect(PRIVATE_ROUTES).toEqual(["/account", "/approve", "/admin", "/device", "/signin", "/publish"]);

    for (const path of ["/account", "/account/tokens", "/approve", "/approve/stg_AbCdEf123456", "/admin", "/admin/reviews", "/device", "/device/confirm", "/signin", "/signin/github", "/publish", "/publish/new"]) {
      expect(skipped(path), path).toBe(true);
      expect(isPrivatePath(path), path).toBe(true);
    }

    for (const path of ["/", "/compare", "/docs", "/package/react", "/package/@scope/name/v/1.0.0/file/package.json", "/reviews", "/privacy", "/accounts-guide", "/devices"]) {
      expect(skipped(path), path).toBe(false);
      expect(isPrivatePath(path), path).toBe(false);
    }

    // "/foo/*" alone would miss the bare route: that is why each is listed twice
    expect(skips("/account", "/account/*")).toBe(false);
  });

  test("masks every private route to the route alone where an exit names it, and leaves public paths as they are", () => {
    // each skipped route has a mask, so an exit from any of them names the route alone
    expect(PRIVATE_MASK_PATTERNS.map((p) => p.replace("/**", "")).toSorted()).toEqual(PRIVATE_SKIP_PATTERNS.filter((p) => !p.endsWith("/*")).toSorted());
    expect(maskedPath("/approve/stg_AbCdEf123456")).toBe("/approve/*");
    expect(maskedPath("/account/tokens/tok_1")).toBe("/account/*");
    expect(maskedPath("/device")).toBe("/device");

    for (const path of ["/", "/compare", "/package/react", "/accounts-guide"]) expect(maskedPath(path)).toBe(path);
  });

  test("is added by one loader, mounted once in the root layout, and no page sends anything of its own", () => {
    const users = sources().filter(([, text]) => text.includes("DATABUDDY_SCRIPT_URL") || text.includes("cdn.databuddy.cc"));

    expect(users.map(([file]) => file).toSorted()).toEqual(["lib/analytics.ts", "lib/databuddy-origin.ts"]);

    const mounts = sources().filter(([, text]) => /<Databuddy\b/.test(text));

    expect(mounts.map(([file]) => file)).toEqual(["app/layout.tsx"]);
    const layout = mounts[0]?.[1] ?? "";

    expect(layout.match(/<Databuddy\b/g)).toHaveLength(1);
    // the loader is the head's own inline script; the client-router half sits at the end of the body
    expect(layout).toMatch(/<head>\s*<Databuddy \/>\s*<\/head>/);
    expect(layout).toMatch(/<\/footer>\s*<DatabuddyNavigation \/>\s*<\/body>/);
    expect(layout.match(/<DatabuddyNavigation\b/g)).toHaveLength(1);

    // custom events and the flag read go through lib/databuddy-client.ts alone, which only asks the tracker already
    // on the page; nothing else sends to Databuddy or reads its tracker
    const readsTracker = /window\??\.(databuddy|db)\b/;

    expect(sources().filter(([, text]) => readsTracker.test(text)).map(([file]) => file)).toEqual(["lib/databuddy-client.ts"]);

    for (const [file, text] of sources()) {
      expect(text.includes("<PageView"), file).toBe(false);
      expect(text.includes(`${DATABUDDY_INGEST_ORIGIN}/`), file).toBe(false);
    }
  });

  test("the component renders the inline loader alone: no static databuddy.js tag React could hoist above it", () => {
    const component = readFileSync(join(WEB, "components", "databuddy.tsx"), "utf8");
    const routeLoader = readFileSync(join(WEB, "components", "databuddy-route-loader.tsx"), "utf8");

    expect(component).toContain('if (CLIENT_ID === "") return null;');
    expect(component).toContain('<script dangerouslySetInnerHTML={{ __html: databuddyLoaderScript("web", CLIENT_ID) }} />');
    expect(component.match(/<script\b/g)).toHaveLength(1);

    // the code alone, comments stripped: no src or async attribute, no URL, no next/script
    for (const text of [component, routeLoader]) {
      const code = text.replace(/^\s*(\/\/|\/\*\*|\*).*$/gm, "");

      expect(code).not.toMatch(/\bsrc\b|\basync\b|DATABUDDY_SCRIPT_URL|next\/script/);
    }

    // the client-router half only calls what the loader left, after the router has committed the new path
    expect(routeLoader.startsWith('"use client";')).toBe(true);
    expect(routeLoader).toContain(`window.${DATABUDDY_LOAD_GLOBAL}?.();`);
    expect(routeLoader).toContain("}, [pathname]);");
  });
});

describe("the opt-out and origin rule", () => {
  const view = (over: Partial<BrowserView>): BrowserView => ({ origin: "https://apmjs.dev", globalPrivacyControl: undefined, doNotTrack: [null, undefined, undefined], ...over });

  test("allows each site's canonical origin when no opt-out is set", () => {
    expect(SITE_ORIGINS).toEqual({ web: "https://apmjs.dev", docs: "https://docs.apmjs.dev" });
    expect(maySend(view({}), "web")).toBe(true);
    expect(maySend(view({ origin: "https://docs.apmjs.dev" }), "docs")).toBe(true);
    expect(maySend(view({ globalPrivacyControl: false, doNotTrack: ["0", "unspecified", "no"] }), "web")).toBe(true);
  });

  test("Global Privacy Control or Do Not Track in any of its places stops it", () => {
    expect(optedOut(view({ globalPrivacyControl: true }))).toBe(true);

    for (const dnt of [["1", null, undefined], [null, "1", undefined], [null, undefined, "1"], ["yes", null, undefined], [null, "yes", undefined]]) {
      expect(optedOut(view({ doNotTrack: dnt }))).toBe(true);
      expect(maySend(view({ doNotTrack: dnt }), "web")).toBe(false);
    }
  });

  test("any other origin is stopped: local, preview, workers.dev, http, the other site, a lookalike", () => {
    for (const origin of ["http://localhost:3000", "http://127.0.0.1:3482", "https://staging.apmjs.dev", "https://apmjs-web-production.example.workers.dev", "http://apmjs.dev", "https://www.apmjs.dev", "https://apmjs.dev.example", "https://docs.apmjs.dev", "null"]) {
      expect(maySend(view({ origin }), "web")).toBe(false);
    }

    expect(maySend(view({ origin: "https://apmjs.dev" }), "docs")).toBe(false);
  });
});

/** A page the loader runs in: where it is, the visitor's signals, and what is already in the head. */
type LoaderPage = {
  origin: string;
  pathname?: string;
  gpc?: unknown;
  dnt?: { navigator?: unknown; window?: unknown; ms?: unknown };
  throws?: boolean;
};

/** A <script> the loader made, as the stand-in document records it. */
type MadeScript = { src: string; async: boolean; crossOrigin: string; attributes: Map<string, string> };

/** The stand-in window: the one opt-out it reads, the flag it sets, history/events, and what it leaves to call. */
type LoaderWindow = {
  doNotTrack?: unknown;
  databuddyDisabled?: unknown;
  __apmLoadDatabuddy?: unknown;
  history: {
    pushState: (state: Record<string, never>, unused: string, url?: string | URL | null) => void;
    replaceState: (state: Record<string, never>, unused: string, url?: string | URL | null) => void;
  };
  addEventListener: (type: string, fn: (e: { stopImmediatePropagation(): void }) => void, capture?: boolean) => void;
};

/** The stand-in browser a loader runs against, and what it did there. */
type LoaderRun = {
  /** The scripts appended to the head. */
  readonly added: MadeScript[];
  readonly window: LoaderWindow;
  /** Native pushState/replaceState calls that were allowed through. */
  readonly historyCalls: { method: "pushState" | "replaceState"; url: string }[];
  /** Full-page navigations triggered by the private-route guard (assign, replace, reload). */
  readonly fullNavs: { method: "assign" | "replace" | "reload"; url?: string }[];
  /** Moves the page to `pathname`, as the client router does, and calls what the loader left, as DatabuddyRouteLoader does. */
  navigate(pathname: string): void;
  /** Fires a popstate event at `pathname` and returns whether immediate propagation was stopped. */
  popstate(pathname: string): boolean;
  /** Runs the loader script again in the same page, as Astro's client router may. */
  rerun(): void;
};

function runLoader(script: string, page: LoaderPage): LoaderRun {
  const added: MadeScript[] = [];
  const historyCalls: { method: "pushState" | "replaceState"; url: string }[] = [];
  const fullNavs: { method: "assign" | "replace" | "reload"; url?: string }[] = [];
  const popListeners: ((e: { stopImmediatePropagation(): void }) => void)[] = [];

  const location = {
    origin: page.origin,
    pathname: page.pathname ?? "/",
    assign: (url: string) => void fullNavs.push({ method: "assign", url }),
    replace: (url: string) => void fullNavs.push({ method: "replace", url }),
    reload: () => void fullNavs.push({ method: "reload" }),
  };

  const window: LoaderWindow = {
    doNotTrack: page.dnt?.window,
    history: {
      pushState: (_state, _unused, url) => {
        if (url != null) {
          const parsed = new URL(String(url), `${location.origin}${location.pathname}`);

          location.pathname = parsed.pathname;
        }

        historyCalls.push({ method: "pushState", url: String(url ?? "") });
      },
      replaceState: (_state, _unused, url) => {
        if (url != null) {
          const parsed = new URL(String(url), `${location.origin}${location.pathname}`);

          location.pathname = parsed.pathname;
        }

        historyCalls.push({ method: "replaceState", url: String(url ?? "") });
      },
    },
    addEventListener: (type, fn) => {
      if (type === "popstate") popListeners.push(fn);
    },
  };

  const document = {
    head: { appendChild: (s: MadeScript) => added.push(s) },
    createElement: (tag: string): MadeScript & { setAttribute(name: string, value: string): void } => {
      expect(tag).toBe("script");
      const attributes = new Map<string, string>();

      return { src: "", async: false, crossOrigin: "", attributes, setAttribute: (name, value) => attributes.set(name, value) };
    },
    querySelector: (selector: string) => (selector === "script[data-apm-databuddy]" ? (added.find((s) => s.attributes.has("data-apm-databuddy")) ?? null) : null),
  };

  const navigator = page.throws
    ? Object.defineProperty({}, "globalPrivacyControl", {
        get: () => {
          throw new Error("blocked");
        },
      })
    : { globalPrivacyControl: page.gpc, doNotTrack: page.dnt?.navigator ?? null, msDoNotTrack: page.dnt?.ms };

  const exec = (): void => new Function("window", "document", "navigator", "location", script)(window, document, navigator, location);

  exec();

  return {
    added,
    window,
    historyCalls,
    fullNavs,
    navigate(pathname) {
      location.pathname = pathname;
      const load = window.__apmLoadDatabuddy;

      if (load instanceof Function) load();
    },
    popstate(pathname) {
      location.pathname = pathname;
      let stopped = false;

      for (const fn of popListeners) fn({ stopImmediatePropagation: () => void (stopped = true) });

      return stopped;
    },
    rerun: exec,
  };
}

/** The tag every site's loader must add, with its exact attributes. */
function expectTag(run: LoaderRun, site: Site): void {
  expect(run.added).toHaveLength(1);
  const [tag] = run.added;

  expect(tag?.src).toBe("https://cdn.databuddy.cc/databuddy.js");
  expect(tag?.async).toBe(true);
  expect(tag?.crossOrigin).toBe("anonymous");
  expect(Object.fromEntries(tag?.attributes ?? [])).toEqual({ "data-apm-databuddy": "", ...databuddyAttributes(site, "client-1") });
  expect(run.window.databuddyDisabled).toBeUndefined();
}

/** The loader each site renders. */
const LOADERS: readonly { site: Site; script: string }[] = [
  { site: "web", script: databuddyLoaderScript("web", "client-1") },
  { site: "docs", script: docsLoaderScript("client-1") },
];

describe("the inline loader", () => {
  test("the docs' copy is the website's loader for the docs origin", () => {
    expect(DOCS_ORIGIN).toBe(SITE_ORIGINS.docs);
    expect(docsLoaderScript("client-1")).toBe(databuddyLoaderScript("docs", "client-1"));
    expect(DATABUDDY_LOAD_GLOBAL).toBe("__apmLoadDatabuddy");
  });

  for (const { site, script } of LOADERS) {
    const home = SITE_ORIGINS[site];

    test(`${site}: adds one databuddy.js tag with the exact attributes at ${home} with no opt-out`, () => {
      expectTag(runLoader(script, { origin: home }), site);
      expectTag(runLoader(script, { origin: home, pathname: "/compare", gpc: false, dnt: { navigator: "0", window: "unspecified", ms: "0" } }), site);
    });

    test(`${site}: adds it once, however often it runs or the page moves`, () => {
      const run = runLoader(script, { origin: home });

      run.rerun();
      run.navigate("/compare");
      run.navigate("/");
      run.rerun();
      expectTag(run, site);
    });

    test(`${site}: under Global Privacy Control or Do Not Track anywhere browsers put it, adds nothing and leaves nothing to call`, () => {
      const pages: LoaderPage[] = [{ origin: home, gpc: true }, ...[{ navigator: "1" }, { navigator: "yes" }, { window: "1" }, { window: "yes" }, { ms: "1" }, { ms: "yes" }].map((dnt) => ({ origin: home, dnt }))];

      for (const page of pages) {
        const run = runLoader(script, page);

        run.navigate("/compare");
        expect(run.added, JSON.stringify(page)).toEqual([]);
        expect(run.window.databuddyDisabled).toBe(true);
        expect(run.window.__apmLoadDatabuddy).toBeUndefined();
      }
    });

    test(`${site}: away from ${home}, and when reading the signals throws, adds nothing`, () => {
      for (const origin of ["http://localhost:3000", "http://127.0.0.1:4321", "https://staging.apmjs.dev", "https://apmjs-web-production.example.workers.dev", `http://${new URL(home).host}`, "https://apmjs.dev.example", SITE_ORIGINS[site === "web" ? "docs" : "web"], "null"]) {
        const run = runLoader(script, { origin });

        run.navigate("/compare");
        expect(run.added, origin).toEqual([]);
        expect(run.window.databuddyDisabled, origin).toBe(true);
      }

      const thrown = runLoader(script, { origin: home, throws: true });

      expect(thrown.added).toEqual([]);
      expect(thrown.window.databuddyDisabled).toBe(true);
    });

    test(`${site}: agrees with maySend`, () => {
      const cases: LoaderPage[] = [{ origin: home }, { origin: "http://localhost:3000" }, { origin: home, gpc: true }, { origin: home, dnt: { window: "yes" } }, { origin: home, gpc: "true" }, { origin: home, dnt: { navigator: 1 } }];

      for (const page of cases) {
        const allowed = maySend({ origin: page.origin, globalPrivacyControl: page.gpc, doNotTrack: [page.dnt?.navigator ?? null, page.dnt?.window, page.dnt?.ms] }, site);

        expect(runLoader(script, page).added.length, JSON.stringify(page)).toBe(allowed ? 1 : 0);
      }
    });

    test(`${site}: reads no query, hash, title, referrer, cookie or storage`, () => {
      expect(script).not.toMatch(/document\.(referrer|cookie|title|URL|location)|location\.(search|href|hash)|Storage|cookie/);
    });
  }

  test("web: on a private page adds nothing, then adds the tag once the client router reaches a public page", () => {
    const script = databuddyLoaderScript("web", "client-1");

    for (const path of ["/account", "/account/tokens", "/approve", "/approve/stg_AbCdEf123456", "/admin/reviews", "/device", "/signin", "/publish/new"]) {
      const run = runLoader(script, { origin: SITE_ORIGINS.web, pathname: path });

      expect(run.added, path).toEqual([]);
      // not an opt-out: the tracker may still load on a public page
      expect(run.window.databuddyDisabled, path).toBeUndefined();
      run.navigate("/signin");
      expect(run.added, path).toEqual([]);
      run.navigate("/");
      expectTag(run, "web");
    }

    // a public route that only starts like a private one loads at once
    expectTag(runLoader(script, { origin: SITE_ORIGINS.web, pathname: "/accounts-guide" }), "web");
  });

  test("web: once tracked, client-router navigations into private routes trigger a full page load instead of pushState/replaceState", () => {
    const run = runLoader(databuddyLoaderScript("web", "client-1"), { origin: SITE_ORIGINS.web, pathname: "/" });

    expectTag(run, "web");
    // public client navigation passes through normally
    run.window.history.pushState({}, "", "/compare?tab=1");
    expect(run.historyCalls).toEqual([{ method: "pushState", url: "/compare?tab=1" }]);
    expect(run.fullNavs).toEqual([]);

    // private pushState is converted to location.assign without mutating history
    run.window.history.pushState({}, "", "/approve/stg_123?gclid=G123");
    expect(run.historyCalls).toHaveLength(1);
    expect(run.fullNavs).toEqual([{ method: "assign", url: "/approve/stg_123?gclid=G123" }]);

    // private replaceState is converted to location.replace without mutating history
    run.window.history.replaceState({}, "", "/signin?next=%2Faccount#top");
    expect(run.historyCalls).toHaveLength(1);
    expect(run.fullNavs).toEqual([
      { method: "assign", url: "/approve/stg_123?gclid=G123" },
      { method: "replace", url: "/signin?next=%2Faccount#top" },
    ]);

    // popstate onto a private route disables databuddy, stops propagation, and reloads
    expect(run.popstate("/account/packages")).toBe(true);
    expect(run.window.databuddyDisabled).toBe(true);
    expect(run.fullNavs.at(-1)).toEqual({ method: "reload" });
  });

  test("web: an untracked private document leaves client-router navigation between private pages alone until it enters a public page", () => {
    const run = runLoader(databuddyLoaderScript("web", "client-1"), { origin: SITE_ORIGINS.web, pathname: "/account" });

    expect(run.added).toEqual([]);
    run.window.history.pushState({}, "", "/publish");
    expect(run.historyCalls).toEqual([{ method: "pushState", url: "/publish" }]);
    expect(run.fullNavs).toEqual([]);

    // once it reaches a public route, the tracker loads and the guard activates
    run.navigate("/");
    expectTag(run, "web");
    run.window.history.pushState({}, "", "/approve/stg_456?gclid=G456");
    expect(run.fullNavs).toEqual([{ method: "assign", url: "/approve/stg_456?gclid=G456" }]);
  });

  test("docs: no route is private", () => {
    expectTag(runLoader(docsLoaderScript("client-1"), { origin: SITE_ORIGINS.docs, pathname: "/account" }), "docs");
  });
});

describe("the docs site's Blume config", () => {
  test("adds nothing without a client id, and with one the inline loader alone, no databuddy.js tag", () => {
    expect(docsAnalytics("")).toEqual([]);
    expect(docsAnalytics("client-1")).toEqual([{ kind: "script", options: { content: docsLoaderScript("client-1") }, requiredSecrets: [], runtimeDeps: [] }]);
  });

  test("blume.config.ts uses docsAnalytics with the build's client id and keeps search queries out", () => {
    const config = readFileSync(join(DOCS, "blume.config.ts"), "utf8");

    expect(config).toContain('const databuddyClientId = process.env.NEXT_PUBLIC_DATABUDDY_CLIENT_ID?.trim() ?? "";');
    expect(config).toContain("analytics: docsAnalytics(databuddyClientId),");
    expect(config).toContain("search: { analytics: { queries: false } }");
    expect(readFileSync(join(DOCS, "analytics.ts"), "utf8")).not.toMatch(/\bdatabuddy\(/);
  });
});

describe("the CSP", () => {
  test("loads scripts from the site and Databuddy's CDN, and lets fetches reach Databuddy's event and flag endpoints, nothing else of theirs", () => {
    const csp = contentSecurityPolicy(false);

    expect(DATABUDDY_SCRIPT_ORIGIN).toBe("https://cdn.databuddy.cc");
    expect(DATABUDDY_INGEST_ORIGIN).toBe("https://basket.databuddy.cc");
    expect(DATABUDDY_FLAGS_ORIGIN).toBe("https://api.databuddy.cc");
    expect(csp).toContain(`script-src 'self' 'unsafe-inline' ${DATABUDDY_SCRIPT_ORIGIN};`);
    expect(csp).toContain(`connect-src 'self' ${DATABUDDY_INGEST_ORIGIN} ${DATABUDDY_FLAGS_ORIGIN};`);
    expect(csp.match(/databuddy/g)).toHaveLength(3);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });
});
