// Databuddy's standard tracker (https://www.databuddy.cc/docs) on apmjs.dev. components/databuddy.tsx, mounted once in
// app/layout.tsx, renders one inline loader (databuddyLoaderScript) and no databuddy.js tag of its own: the loader
// decides whether the tag exists at all. The tracker sends page views (on hard loads and client-router navigations),
// Web Vitals, browser errors and outgoing-link clicks. It sets no cookies; it keeps a random visitor id in
// localStorage and a session id in sessionStorage.
//
// databuddy.js is never fetched:
//   - on a build without a client id: production's builds alone get one (packages/infra/analytics.ts), so staging and
//     local builds render no loader at all;
//   - away from the site's canonical origin (a production build served locally, on a preview host or on workers.dev),
//     and when the visitor has opted out with Global Privacy Control or Do Not Track ("1" or "yes" in
//     navigator.doNotTrack, window.doNotTrack or navigator.msDoNotTrack). The loader sets window.databuddyDisabled
//     and adds no tag, so the browser asks nothing of cdn.databuddy.cc or basket.databuddy.cc;
//   - while the page is one of PRIVATE_ROUTES. A hard load of a private page adds no tag, so databuddy.js never reads
//     that page's URL (its query holds ids and click ids it would keep as attribution). The loader leaves
//     window.__apmLoadDatabuddy behind, and components/databuddy-route-loader.tsx calls it after each client-router
//     navigation: once the visitor reaches a public page, location already names that page and the tag is added.
//   - once a document has loaded the tracker, the loader turns any client-router navigation into a private route
//     (history.pushState, history.replaceState, or popstate) into a full page load of that route instead, so a tracked
//     document never enters a private URL and databuddy.js never sees its path or query parameters (gclid, utm_*).
//
// As defense in depth, the tag also carries PRIVATE_SKIP_PATTERNS and PRIVATE_MASK_PATTERNS.
//
// apps/docs/analytics.ts does the same for docs.apmjs.dev with its own copy of the loader for the docs origin.

import { DATABUDDY_SCRIPT_ORIGIN } from "./databuddy-origin";

export const DATABUDDY_SCRIPT_URL = `${DATABUDDY_SCRIPT_ORIGIN}/databuddy.js`;

/** The routes that never report anything: sign-in, the account, approvals, the device flow, publishing and admin. */
export const PRIVATE_ROUTES = ["/account", "/approve", "/admin", "/device", "/signin", "/publish"] as const;

/** Whether `path` is a private route itself or anything under one ("/accounts-guide" is not under "/account"). */
export function isPrivatePath(path: string): boolean {
  return PRIVATE_ROUTES.some((route) => path === route || path.startsWith(`${route}/`));
}

/** databuddy.js matches "/foo/*" as a prefix of "/foo/" only, so each route is listed bare as well. */
export const PRIVATE_SKIP_PATTERNS: readonly string[] = PRIVATE_ROUTES.flatMap((route) => [route, `${route}/*`]);

/**
 * The same routes, masked wherever databuddy.js still names one: leaving a private page by the client router sends a
 * page_exit and an engagement record for it (the skip patterns are checked against the page being entered, which is
 * public), and those carry the masked path, "/approve/*" for "/approve/stg_…", never the id after the route.
 */
export const PRIVATE_MASK_PATTERNS: readonly string[] = PRIVATE_ROUTES.map((route) => `${route}/**`);

/** Which site a page is on: apmjs.dev, or docs.apmjs.dev. */
export type Site = "web" | "docs";

/** The one origin each site reports from. A copy of the build anywhere else loads nothing. */
export const SITE_ORIGINS = { web: "https://apmjs.dev", docs: "https://docs.apmjs.dev" } as const satisfies Readonly<Record<Site, string>>;

/** What a page can see of where it is and the visitor's opt-outs, as the loader reads them from the browser. */
export type BrowserView = {
  readonly origin: string;
  /** navigator.globalPrivacyControl. */
  readonly globalPrivacyControl: unknown;
  /** navigator.doNotTrack, window.doNotTrack and navigator.msDoNotTrack. */
  readonly doNotTrack: readonly unknown[];
};

/** The values browsers use for Do Not Track on: "1", and "yes" in older Firefox. */
const DNT_ON: ReadonlySet<unknown> = new Set(["1", "yes"]);

/** Whether the visitor asked not to be tracked, by Global Privacy Control or Do Not Track. */
export function optedOut(view: BrowserView): boolean {
  return view.globalPrivacyControl === true || view.doNotTrack.some((v) => DNT_ON.has(v));
}

/** Whether a page on `site` may load the tracker: at its canonical origin, and with no opt-out. The loader's rule. */
export function maySend(view: BrowserView, site: Site): boolean {
  return view.origin === SITE_ORIGINS[site] && !optedOut(view);
}

/** The tracker settings both sites put on the databuddy.js tag, as Databuddy names them (data-<name>). */
export const DATABUDDY_SETTINGS = {
  "track-web-vitals": "true",
  "track-errors": "true",
  "track-outgoing-links": "true",
} as const satisfies Readonly<Record<string, string>>;

/** The data- attributes of a site's databuddy.js tag; the website's also carry the private skip and mask patterns. */
export function databuddyAttributes(site: Site, clientId: string): Readonly<Record<`data-${string}`, string>> {
  const settings = {
    "data-track-web-vitals": DATABUDDY_SETTINGS["track-web-vitals"],
    "data-track-errors": DATABUDDY_SETTINGS["track-errors"],
    "data-track-outgoing-links": DATABUDDY_SETTINGS["track-outgoing-links"],
  };

  if (site === "docs") return { "data-client-id": clientId, ...settings };

  return {
    "data-client-id": clientId,
    "data-skip-patterns": JSON.stringify(PRIVATE_SKIP_PATTERNS),
    "data-mask-patterns": JSON.stringify(PRIVATE_MASK_PATTERNS),
    ...settings,
  };
}

/** The window property the loader leaves for the website's client router to call (components/databuddy-route-loader.tsx). */
export const DATABUDDY_LOAD_GLOBAL = "__apmLoadDatabuddy";

/** The attribute that marks the one databuddy.js tag the loader adds. */
export const DATABUDDY_TAG_MARK = "data-apm-databuddy";

/**
 * The inline script each site renders instead of a databuddy.js tag. Off the canonical origin, under an opt-out, or
 * when reading either throws, it sets window.databuddyDisabled and adds nothing. Otherwise it defines
 * window.__apmLoadDatabuddy and calls it: that adds the databuddy.js tag once, and only while location.pathname is not
 * a private route (the docs have none). apps/docs/analytics.ts keeps its own copy (docsLoaderScript, so the docs build
 * imports nothing from the website); lib/analytics.test.ts checks the two are the same and runs both.
 */
export function databuddyLoaderScript(site: Site, clientId: string): string {
  const origin = JSON.stringify(SITE_ORIGINS[site]);
  const privateRoutes = JSON.stringify(site === "web" ? PRIVATE_ROUTES : []);
  const attributes = JSON.stringify(databuddyAttributes(site, clientId));
  const key = JSON.stringify(DATABUDDY_LOAD_GLOBAL);
  const mark = JSON.stringify(DATABUDDY_TAG_MARK);

  // Once a web document loads databuddy.js, prevent client-router entry into private routes so databuddy.js never
  // reads a private path or query string (such as gclid into did_params) in either normal or late-load timing.
  const navGuard =
    site === "web"
      ? `var h=w.history;if(h){["pushState","replaceState"].forEach(function(m){var orig=h[m];if(typeof orig!=="function")return;h[m]=function(st,ti,u){if(u!=null&&u!==""){try{var t=new URL(String(u),location.origin+location.pathname);if(t.origin===location.origin&&priv(t.pathname)){location[m==="replaceState"?"replace":"assign"](t.pathname+t.search+t.hash);return}}catch(e){}}return orig.apply(this,arguments)}})}if(typeof w.addEventListener==="function")w.addEventListener("popstate",function(e){if(priv(location.pathname)){w.databuddyDisabled=true;e.stopImmediatePropagation();location.reload()}},true);`
      : "";

  const privFn =
    site === "web"
      ? `function priv(p){for(var i=0;i<routes.length;i++)if(p===routes[i]||p.indexOf(routes[i]+"/")===0)return true;return false}`
      : "";

  const privCheck =
    site === "web"
      ? `if(priv(location.pathname))return;`
      : `var p=location.pathname;for(var i=0;i<routes.length;i++)if(p===routes[i]||p.indexOf(routes[i]+"/")===0)return;`;

  return `(function(){var w=window,d=document;try{var n=navigator,on=function(v){return v==="1"||v==="yes"};if(location.origin!==${origin}||n.globalPrivacyControl===true||on(n.doNotTrack)||on(w.doNotTrack)||on(n.msDoNotTrack)){w.databuddyDisabled=true;return}if(typeof w[${key}]!=="function"){var done=false,routes=${privateRoutes},attrs=${attributes};${privFn}w[${key}]=function(){if(done||d.querySelector("script[${DATABUDDY_TAG_MARK}]"))return;${privCheck}done=true;${navGuard}var s=d.createElement("script");s.src=${JSON.stringify(DATABUDDY_SCRIPT_URL)};s.async=true;s.crossOrigin="anonymous";s.setAttribute(${mark},"");for(var k in attrs)s.setAttribute(k,attrs[k]);d.head.appendChild(s)}}w[${key}]()}catch(e){w.databuddyDisabled=true}})();`;
}
