// Page views on apmjs.dev and docs.apmjs.dev (lib/analytics.ts, apps/docs/analytics.ts): one event with a label and
// nothing else, only from the pages that render <PageView> (the docs: that carry Blume's label), only at the site's
// canonical origin, never with Global Privacy Control or Do Not Track, and no Databuddy script anywhere. The browser check that
// navigation between public and private pages sends nothing about the private one is scripts/analytics-browser.ts.
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, sep } from "node:path";
import { DOCS_ORIGIN, DOCS_TRACKER, docsTracker, PAGE_VIEW_ATTRIBUTE } from "../../docs/analytics";
import { contentSecurityPolicy } from "./security-headers";
import { DATABUDDY_INGEST_ORIGIN } from "./databuddy-origin";
import { maySend, optedOut, PAGE_LABELS, pageViewRequest, SITE_ORIGINS, type BrowserView } from "./analytics";

const WEB = join(import.meta.dir, "..");

/** Every source file of the website, as [path relative to apps/web, text]. */
function sources(): [string, string][] {
  return ["app", "components", "lib"].flatMap((dir) =>
    readdirSync(join(WEB, dir), { recursive: true, encoding: "utf8" })
      .filter((f) => /\.(tsx?|css)$/.test(f) && !/\.test\.tsx?$/.test(f))
      .map((f): [string, string] => [`${dir}/${f.split(sep).join("/")}`, readFileSync(join(WEB, dir, f), "utf8")]),
  );
}

describe("a page view", () => {
  test("is one event with the site and the label, posted with no credentials, no referrer and no redirects", () => {
    const { url, init } = pageViewRequest({ clientId: "client-1", site: "web", route: "package" });

    expect(url).toBe("https://basket.databuddy.cc/track?website_id=client-1");
    expect(JSON.parse(String(init.body))).toEqual({ name: "page_view", properties: { site: "web", route: "package" } });
    expect(init).toMatchObject({ method: "POST", credentials: "omit", referrerPolicy: "no-referrer", redirect: "error", cache: "no-store" });
    expect(init.headers).toEqual({ "content-type": "application/json" });
  });

  test("is sent only by the public pages, each with its own label, and the package page's never names the package", () => {
    const users = sources().filter(([, text]) => text.includes("<PageView"));
    const labels = users.flatMap(([file, text]) => [...text.matchAll(/<PageView\b[^>]*\blabel="([a-z-]+)"/g)].map((m) => `${file} ${m[1] ?? ""}`));

    expect(labels.toSorted()).toEqual(["app/compare/page.tsx compare", "app/docs/page.tsx docs", "app/package/[...name]/page.tsx package", "app/page.tsx home"]);
    expect(labels.map((l) => l.split(" ")[1]).toSorted()).toEqual([...PAGE_LABELS].toSorted());

    // a private page, a file view or an error page renders none
    for (const [file] of users) expect(file).not.toMatch(/account|approve|admin|device|signin|publish|file-view|not-found|error/);
  });

  test("no Databuddy script, tracker attribute or error capture is left on the website", () => {
    for (const [file, text] of sources()) {
      expect(text.includes("cdn.databuddy.cc"), file).toBe(false);
      expect(/data-(client-id|track-|skip-patterns)/.test(text), file).toBe(false);
      expect(/window\.(databuddy|db)\b/.test(text), file).toBe(false);
    }
  });
});

describe("the privacy and origin gates", () => {
  const view = (over: Partial<BrowserView>): BrowserView => ({ origin: "https://apmjs.dev", globalPrivacyControl: undefined, doNotTrack: [null, undefined, undefined], ...over });

  test("a view is sent from each site's canonical origin when no opt-out is set", () => {
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

    expect(maySend(view({ globalPrivacyControl: true }), "web")).toBe(false);
  });

  test("any other origin sends nothing: local, preview, workers.dev, http, the other site, a lookalike", () => {
    for (const origin of ["http://localhost:3000", "http://127.0.0.1:3482", "https://staging.apmjs.dev", "https://apmjs-web-production.example.workers.dev", "http://apmjs.dev", "https://www.apmjs.dev", "https://apmjs.dev.example", "https://docs.apmjs.dev", "null"]) {
      expect(maySend(view({ origin }), "web")).toBe(false);
    }

    expect(maySend(view({ origin: "https://apmjs.dev" }), "docs")).toBe(false);
  });
});

/** A page the docs tracker runs in: where it is, the visitor's signals, the label element (or none), and what it sent. */
type DocsPage = { origin: string; gpc?: unknown; dnt?: { navigator?: unknown; window?: unknown; ms?: unknown }; label: string | null; readyState?: "loading" | "complete" };

/** Runs DOCS_TRACKER against a stand-in document, then fires `events` (DOMContentLoaded, astro:page-load), and returns the fetches. */
function runDocsTracker(page: DocsPage, events: readonly string[] = []): { url: string; body: unknown }[] {
  const sent: { url: string; body: unknown }[] = [];
  const listeners = new Map<string, (() => void)[]>();
  const attrs = new Map<string, string>(page.label === null ? [] : [[PAGE_VIEW_ATTRIBUTE, page.label]]);
  const el = { getAttribute: (n: string) => attrs.get(n) ?? null, hasAttribute: (n: string) => attrs.has(n), setAttribute: (n: string, v: string) => void attrs.set(n, v) };

  const document = {
    currentScript: { dataset: { clientId: "client-1" } },
    readyState: page.readyState ?? "complete",
    querySelector: (selector: string) => (selector === `[${PAGE_VIEW_ATTRIBUTE}]` && page.label !== null ? el : null),
    addEventListener: (type: string, fn: () => void) => listeners.set(type, [...(listeners.get(type) ?? []), fn]),
  };

  const navigator = { globalPrivacyControl: page.gpc, doNotTrack: page.dnt?.navigator ?? null, msDoNotTrack: page.dnt?.ms };
  const window = { doNotTrack: page.dnt?.window };

  const fetch = (url: string, init: RequestInit): Promise<void> => {
    sent.push({ url, body: JSON.parse(String(init.body)) });

    return Promise.resolve();
  };

  new Function("document", "location", "navigator", "window", "fetch", DOCS_TRACKER)(document, { origin: page.origin }, navigator, window, fetch);

  for (const type of events) for (const fn of listeners.get(type) ?? []) fn();

  return sent;
}

describe("the docs site's page views", () => {
  const PROD = { origin: DOCS_ORIGIN, label: "/guides/ci" };

  test("send the label Blume stamped on the page, once per page shown", () => {
    expect(runDocsTracker(PROD, ["astro:page-load"])).toEqual([
      { url: "https://basket.databuddy.cc/track?website_id=client-1", body: { name: "page_view", properties: { site: "docs", route: "/guides/ci" } } },
    ]);
    // a page still parsing sends when it has parsed
    expect(runDocsTracker({ ...PROD, readyState: "loading" })).toEqual([]);
    expect(runDocsTracker({ ...PROD, readyState: "loading" }, ["DOMContentLoaded", "astro:page-load"])).toHaveLength(1);
  });

  test("send nothing from a page with no label (the 404 page) or a label that is not a route", () => {
    expect(runDocsTracker({ origin: DOCS_ORIGIN, label: null }, ["astro:page-load"])).toEqual([]);

    for (const label of ["", "guides/ci", "/Guides", "/a?b=1", "/x#y", "https://evil.example/"]) expect(runDocsTracker({ origin: DOCS_ORIGIN, label }, ["astro:page-load"])).toEqual([]);
  });

  test("send nothing away from https://docs.apmjs.dev", () => {
    for (const origin of ["http://127.0.0.1:4321", "http://localhost:4321", "https://apmjs.dev", "https://docs-preview.example.pages.dev", "http://docs.apmjs.dev"]) {
      expect(runDocsTracker({ ...PROD, origin }, ["astro:page-load"])).toEqual([]);
    }
  });

  test("send nothing with Global Privacy Control or Do Not Track", () => {
    expect(runDocsTracker({ ...PROD, gpc: true })).toEqual([]);

    for (const dnt of [{ navigator: "1" }, { navigator: "yes" }, { window: "1" }, { window: "yes" }, { ms: "1" }]) expect(runDocsTracker({ ...PROD, dnt })).toEqual([]);

    expect(runDocsTracker({ ...PROD, gpc: false, dnt: { navigator: "0", window: "unspecified" } })).toHaveLength(1);
  });

  test("are off without a client id, carry the id as data, not code, and never read the URL", () => {
    expect(docsTracker("")).toEqual([]);
    const [tag] = docsTracker("client-1");

    expect(tag?.content).toBe(DOCS_TRACKER);
    expect(tag?.attributes).toEqual({ "data-client-id": "client-1" });
    expect(DOCS_TRACKER).not.toContain("client-1");
    // the same event and options as the website's
    expect(DOCS_TRACKER).toContain('body:JSON.stringify({name:"page_view",properties:{site:"docs",route}})');
    expect(DOCS_TRACKER).toContain('credentials:"omit",referrerPolicy:"no-referrer",cache:"no-store",redirect:"error"');
    expect(DOCS_TRACKER).not.toMatch(/document\.referrer|document\.title|location\.(search|href|hash|pathname)|onerror|unhandledrejection/);
  });

  test("the docs config loads no Databuddy script, and the PageFooter slot stamps the route", () => {
    const docs = join(WEB, "..", "docs");
    const config = readFileSync(join(docs, "blume.config.ts"), "utf8");

    expect(config).not.toContain("databuddy(");
    expect(config).not.toContain("cdn.databuddy.cc");
    expect(readFileSync(join(docs, "components.ts"), "utf8")).toContain('PageFooter: "./components/PageView.astro"');
    expect(readFileSync(join(docs, "components", "PageView.astro"), "utf8")).toContain(`<span hidden ${PAGE_VIEW_ATTRIBUTE}={route}></span>`);
  });
});

describe("the CSP", () => {
  test("loads scripts from the site alone and lets fetches reach Databuddy's event endpoint, nothing else of theirs", () => {
    const csp = contentSecurityPolicy(false);

    expect(csp).toContain("script-src 'self' 'unsafe-inline';");
    expect(csp).toContain(`connect-src 'self' ${DATABUDDY_INGEST_ORIGIN};`);
    expect(csp.match(/databuddy/g)).toHaveLength(1);
  });
});
