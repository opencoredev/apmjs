// Databuddy's event endpoint, apart from lib/analytics.ts so the server's CSP (lib/security-headers.ts) can name it
// without pulling in browser code.

/** Where page views go. The CSP allows this origin in connect-src, and no other Databuddy origin anywhere. */
export const DATABUDDY_INGEST_ORIGIN = "https://basket.databuddy.cc";
