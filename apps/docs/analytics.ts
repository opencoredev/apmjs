// Databuddy's standard tracker on docs.apmjs.dev: page views on hard loads and client-router navigations, Web Vitals,
// browser errors and outgoing-link clicks, with no cookies (it keeps a random visitor id in localStorage).
// apmjs.dev loads the same tracker the same way (apps/web/lib/analytics.ts).
//
// Blume renders one inline loader (a script() adapter) and no databuddy.js tag. The loader adds the tag only at
// https://docs.apmjs.dev and when the visitor has not opted out with Global Privacy Control or Do Not Track in any of
// the places browsers put it. Anywhere else, or opted out, it sets window.databuddyDisabled and adds nothing, so the
// browser asks nothing of Databuddy at all.
//
// Blume's own events (search, feedback) go to window.databuddy once the tracker has loaded; a search reports its
// length, never its text (search.analytics.queries in blume.config.ts).
import { script, type ScriptAdapter } from "blume/analytics";

/** The one origin the docs report from (SITE_ORIGINS.docs in apps/web/lib/analytics.ts). */
export const DOCS_ORIGIN = "https://docs.apmjs.dev";

/**
 * The inline loader, the website's rule for the docs origin (databuddyLoaderScript("docs", …) in
 * apps/web/lib/analytics.ts, which lib/analytics.test.ts checks this against). The docs have no private routes.
 * window.__apmLoadDatabuddy keeps it to one tag when Astro's client router runs the script again.
 */
export function docsLoaderScript(clientId: string): string {
  const attributes = JSON.stringify({
    "data-client-id": clientId,
    "data-track-web-vitals": "true",
    "data-track-errors": "true",
    "data-track-outgoing-links": "true",
  });

  return `(function(){var w=window,d=document;try{var n=navigator,on=function(v){return v==="1"||v==="yes"};if(location.origin!==${JSON.stringify(DOCS_ORIGIN)}||n.globalPrivacyControl===true||on(n.doNotTrack)||on(w.doNotTrack)||on(n.msDoNotTrack)){w.databuddyDisabled=true;return}if(typeof w["__apmLoadDatabuddy"]!=="function"){var done=false,routes=[],attrs=${attributes};w["__apmLoadDatabuddy"]=function(){if(done||d.querySelector("script[data-apm-databuddy]"))return;var p=location.pathname;for(var i=0;i<routes.length;i++)if(p===routes[i]||p.indexOf(routes[i]+"/")===0)return;done=true;var s=d.createElement("script");s.src="https://cdn.databuddy.cc/databuddy.js";s.async=true;s.crossOrigin="anonymous";s.setAttribute("data-apm-databuddy","");for(var k in attrs)s.setAttribute(k,attrs[k]);d.head.appendChild(s)}}w["__apmLoadDatabuddy"]()}catch(e){w.databuddyDisabled=true}})();`;
}

/** Blume's analytics adapters for the docs: the loader alone. None without a client id. */
export function docsAnalytics(clientId: string): [] | [ScriptAdapter] {
  if (clientId === "") return [];

  return [script({ content: docsLoaderScript(clientId) })];
}
