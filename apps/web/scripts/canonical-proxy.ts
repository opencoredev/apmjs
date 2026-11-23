// A TLS proxy that serves local builds at the canonical hostnames, for scripts/analytics-browser.ts: a request for
// apmjs.dev goes to the website's local server and one for docs.apmjs.dev to the docs', as the browser sent it. It also
// stands in for Databuddy's event endpoint, basket.databuddy.cc: every request to it is answered with Databuddy's
// success body and appended to <databuddy log> as one JSON line (method, URL, headers, body), so the check reads what
// the tracker sent in full, beacons included, and nothing reaches Databuddy. Runs as its own process because the check
// drives the browser with blocking calls. Prints its port, then serves until killed.
//
// The docs site is assets only in production, so Cloudflare's asset layer gives every docs answer its headers from
// apps/docs/public/_headers. A local static server sends none, so the proxy sets them from <docs _headers> the way
// Cloudflare does (scripts/headers-file.ts), and the browser sees the docs' real CSP.
//
//   bun scripts/canonical-proxy.ts <website url> <docs url> <cert.pem> <key.pem> <databuddy log> <docs _headers>
//
// Test tooling: never imported by the site.
import { appendFileSync, readFileSync } from "node:fs";
import { headerRules, headersFor } from "./headers-file";

const [webLocal, docsLocal, certPath, keyPath, databuddyLog, docsHeadersFile] = process.argv.slice(2);

if (webLocal === undefined || docsLocal === undefined || certPath === undefined || keyPath === undefined || databuddyLog === undefined || docsHeadersFile === undefined) {
  process.stderr.write("usage: bun scripts/canonical-proxy.ts <website url> <docs url> <cert.pem> <key.pem> <databuddy log> <docs _headers>\n");
  process.exit(2);
}

/** Where each canonical hostname is served from locally. */
const UPSTREAM = new Map([
  ["apmjs.dev", new URL(webLocal)],
  ["docs.apmjs.dev", new URL(docsLocal)],
]);

/** The docs' _headers rules, applied to every docs answer. */
const DOCS_RULES = headerRules(docsHeadersFile);

/** The stand-in for Databuddy's event endpoint. */
const DATABUDDY_HOST = "basket.databuddy.cc";

/** Records one request to the endpoint and answers it as Databuddy does, allowing the page's origin. */
async function collect(req: Request): Promise<Response> {
  const origin = req.headers.get("origin") ?? "*";

  const cors = {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": req.headers.get("access-control-request-headers") ?? "content-type",
    vary: "Origin",
  };

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  appendFileSync(databuddyLog, `${JSON.stringify({ method: req.method, url: req.url, headers: Object.fromEntries(req.headers), body: await req.text() })}\n`);

  return Response.json({ status: "success" }, { headers: cors });
}

/** Forwards a request for a canonical hostname to its local server. */
async function forward(req: Request): Promise<Response> {
  const url = new URL(req.url);

  if (url.hostname === DATABUDDY_HOST) return collect(req);
  const upstream = UPSTREAM.get(url.hostname);

  if (upstream === undefined) return new Response("not a canonical host", { status: 421 });
  const headers = new Headers(req.headers);

  headers.set("accept-encoding", "identity");
  const res = await fetch(new URL(url.pathname + url.search, upstream), { method: req.method, headers, body: req.body, redirect: "manual" });
  const out = new Headers(res.headers);

  // fetch has already decoded the body
  out.delete("content-encoding");
  out.delete("content-length");

  if (url.hostname === "docs.apmjs.dev") for (const [name, value] of headersFor(DOCS_RULES, url.pathname)) out.set(name, value);

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: out });
}

const server = Bun.serve({ port: 0, hostname: "127.0.0.1", tls: { cert: readFileSync(certPath, "utf8"), key: readFileSync(keyPath, "utf8") }, fetch: forward });

process.stdout.write(`${server.port}\n`);
