// Page views on docs.apmjs.dev, in the shape apmjs.dev sends (apps/web/lib/analytics.ts): one event per view of a
// published page, `{ name: "page_view", properties: { site: "docs", route: <route> } }`, posted to Databuddy's
// documented event endpoint. Databuddy's script is not loaded (its page views, exits, engagement and attribution
// cannot be turned off), and neither is its error capture.
//
// The route is the one Blume published the page at, stamped into the page by components/PageView.astro (the
// PageFooter layout slot, components.ts) as data-apm-page-view. Only the pages Blume builds from docs/ render that
// slot, so the 404 page, a draft (left out of production builds) and anything a new layout adds carry no label and
// send nothing. The tracker never reads the URL: not the path, the query, the hash or the referrer (the request goes
// out with referrerPolicy no-referrer), nor the title, a search or anything else from the page.
//
// It sends nothing unless the page is at https://docs.apmjs.dev (a production build served anywhere else is silent)
// and the visitor has not opted out with Global Privacy Control or Do Not Track. Blume's own events (search,
// feedback) go to window.databuddy, which nothing defines, so they go nowhere.

/** The attribute components/PageView.astro puts the page's published route in. */
export const PAGE_VIEW_ATTRIBUTE = "data-apm-page-view";

/** The one origin the docs send from (SITE_ORIGINS.docs in apps/web/lib/analytics.ts). */
export const DOCS_ORIGIN = "https://docs.apmjs.dev";

/**
 * The tracker, a constant (the client id rides in on the tag's data- attribute, as Blume's own head scripts do). It
 * runs in <head>, so it sends once the page has parsed and again on each client-router navigation (astro:page-load);
 * each page shown sends at most one view, because the label element is marked once it has.
 */
export const DOCS_TRACKER = `(()=>{try{const d=document.currentScript&&document.currentScript.dataset;if(!d||!d.clientId)return;const url="https://basket.databuddy.cc/track?website_id="+encodeURIComponent(d.clientId);const optedOut=()=>{const n=navigator;return n.globalPrivacyControl===true||[n.doNotTrack,window.doNotTrack,n.msDoNotTrack].some(v=>v==="1"||v==="yes")};const send=()=>{try{if(location.origin!==${JSON.stringify(DOCS_ORIGIN)}||optedOut())return;const el=document.querySelector("[${PAGE_VIEW_ATTRIBUTE}]");const route=el&&el.getAttribute("${PAGE_VIEW_ATTRIBUTE}");if(!el||!route||!/^\\/[a-z0-9/-]*$/.test(route)||el.hasAttribute("data-apm-sent"))return;el.setAttribute("data-apm-sent","");fetch(url,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:"page_view",properties:{site:"docs",route}}),mode:"cors",credentials:"omit",referrerPolicy:"no-referrer",cache:"no-store",redirect:"error",keepalive:true}).catch(()=>{})}catch{}};if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",send,{once:true});else send();document.addEventListener("astro:page-load",send)}catch{}})();`;

/** The tracker's tag for Blume's script() adapter, or none without a client id. */
export function docsTracker(clientId: string): { content: string; attributes: Record<string, string> }[] {
  return clientId === "" ? [] : [{ content: DOCS_TRACKER, attributes: { "data-client-id": clientId } }];
}
