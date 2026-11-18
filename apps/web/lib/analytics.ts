// Page views on apmjs.dev, sent to Databuddy's documented event endpoint (POST https://basket.databuddy.cc/track,
// https://www.databuddy.cc/docs/api/events). Databuddy's own script is not loaded: its documented options cannot turn
// off its automatic page views, page exits, engagement or attribution, and those carry the path, the referrer and click
// ids from any page, the private ones included.
//
// What is sent instead: one event per view of an allowed public page, `{ name: "page_view", properties: { site: "web",
// route: <label> } }`, where the label is one of PAGE_LABELS. A page sends one only when it renders <PageView> with its
// label (components/page-view.tsx), so a new route, a private page, a file view and an error page send nothing until
// someone adds one. Never the URL, the query, the referrer (the request goes out with referrerPolicy no-referrer), the
// title, a package name, a visitor id or anything from the page. No Web Vitals and no error capture: a vital measured
// across a client navigation could belong to a private page as well as to the label it would be filed under.
//
// Nothing is sent when the visitor has opted out (Global Privacy Control, or Do Not Track in any of the places browsers
// put it), or when the page is not at the site's canonical origin: a production build served locally, on a preview
// host or on a workers.dev address sends nothing. The client id is inlined at build time (NEXT_PUBLIC_*), and
// production's builds alone get one (packages/infra/analytics.ts); without it nothing is sent either.

import { DATABUDDY_INGEST_ORIGIN } from "./databuddy-origin";

export const DATABUDDY_TRACK_URL = `${DATABUDDY_INGEST_ORIGIN}/track`;

/** The public pages that report a view, by label. Nothing else ever does. */
export const PAGE_LABELS = ["home", "compare", "docs", "package"] as const;

export type PageLabel = (typeof PAGE_LABELS)[number];

/** Which site sent a view: apmjs.dev, or docs.apmjs.dev (apps/docs/analytics.ts sends the same shape). */
export type Site = "web" | "docs";

/** The one origin each site sends from. A copy of the build anywhere else sends nothing. */
export const SITE_ORIGINS = { web: "https://apmjs.dev", docs: "https://docs.apmjs.dev" } as const satisfies Readonly<Record<Site, string>>;

/** What a page can see of where it is and the visitor's opt-outs, as read from the browser (browserView). */
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

/** Whether a page on `site` may send a view: at its canonical origin, and with no opt-out. */
export function maySend(view: BrowserView, site: Site): boolean {
  return view.origin === SITE_ORIGINS[site] && !optedOut(view);
}

/** The opt-out properties some browsers add, which lib.dom does not declare. */
type OptOutNavigator = Navigator & { readonly globalPrivacyControl?: unknown; readonly doNotTrack?: unknown; readonly msDoNotTrack?: unknown };

type OptOutWindow = Window & { readonly doNotTrack?: unknown };

/** Reads the BrowserView from the running page. */
function browserView(nav: OptOutNavigator, win: OptOutWindow): BrowserView {
  return {
    origin: win.location.origin,
    globalPrivacyControl: nav.globalPrivacyControl,
    doNotTrack: [nav.doNotTrack, win.doNotTrack, nav.msDoNotTrack],
  };
}

/** A page view as a fetch: where it goes and the options it goes with. */
export type PageViewRequest = { readonly url: string; readonly init: RequestInit };

/** The one event a view sends, and the fetch options that keep everything else off it. */
export function pageViewRequest(input: { clientId: string; site: Site; route: string }): PageViewRequest {
  return {
    url: `${DATABUDDY_TRACK_URL}?website_id=${encodeURIComponent(input.clientId)}`,
    init: {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "page_view", properties: { site: input.site, route: input.route } }),
      mode: "cors",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      cache: "no-store",
      redirect: "error",
      keepalive: true,
    },
  };
}

/** Databuddy's client id, inlined at build time; "" on every build but production's. */
const CLIENT_ID = process.env.NEXT_PUBLIC_DATABUDDY_CLIENT_ID?.trim() ?? "";

/** Sends one view of a public page. Never throws and never waits: analytics does not change the page. */
export function sendPageView(label: PageLabel): void {
  if (CLIENT_ID === "") return;

  try {
    // checked on every view, before any request
    if (!maySend(browserView(navigator, window), "web")) return;
    const { url, init } = pageViewRequest({ clientId: CLIENT_ID, site: "web", route: label });

    fetch(url, init).catch(() => undefined);
  } catch {
    // best effort
  }
}
