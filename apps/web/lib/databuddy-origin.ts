// Databuddy's two origins, apart from lib/analytics.ts so the server's CSP (lib/security-headers.ts) can name them
// without pulling in the tracker's configuration.

/** Where databuddy.js is loaded from. The CSP allows this origin in script-src, and no other script origin. */
export const DATABUDDY_SCRIPT_ORIGIN = "https://cdn.databuddy.cc";

/** Where databuddy.js sends page views, Web Vitals, errors and outgoing links. The CSP allows it in connect-src. */
export const DATABUDDY_INGEST_ORIGIN = "https://basket.databuddy.cc";
