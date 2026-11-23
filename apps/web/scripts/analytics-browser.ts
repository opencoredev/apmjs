// What the real databuddy.js sends from the website and the docs, with Databuddy's endpoint stubbed: the browser
// resolves basket.databuddy.cc to a local stand-in (scripts/canonical-proxy.ts) that logs every request in full,
// beacons included, and answers as Databuddy does, so nothing reaches Databuddy, while databuddy.js itself loads from
// cdn.databuddy.cc as it does in production. Run it against builds made with a client id
// (NEXT_PUBLIC_DATABUDDY_CLIENT_ID), each served locally:
//
//   bun scripts/analytics-browser.ts <website url> <docs url> <client id>
//
// The loader (lib/analytics.ts) adds the tracker only at https://apmjs.dev and https://docs.apmjs.dev, so the
// check serves the local builds at those origins: a TLS proxy with a throwaway self-signed certificate forwards both
// hostnames to the local servers, and the browser resolves them to it (--host-resolver-rules) and accepts the
// certificate. Nothing reaches the real sites. The same builds opened at their local URLs must send nothing.
//
// databuddy.js sends nothing from a browser it takes for a bot (navigator.webdriver, a HeadlessChrome user agent),
// which an automated browser is, so every session masks both before any page script runs. Without that, every
// "sends nothing" check below would pass whatever the site did; the public-page checks prove the mask works.
//
// Every request to basket.databuddy.cc is read in full (URL, headers, body), and every fetch of either Databuddy host
// is read from the page's resource timing. The served HTML carries no databuddy.js tag, only the inline loader.
// Public pages must send a screen_view for their own path; the private routes (/account, /approve/<id>, /admin,
// /device, /signin, /publish) must not even fetch databuddy.js on a hard load, and must send nothing by the client
// router into them or when a script there throws. A hard load of one with gclid and UTM parameters, then the client
// router to home, sends a home view with none of them. Leaving a private page by the client router sends its page
// exit, and any private route in any request must be the route alone, masked ("/approve/*"): never an id, a code or
// anything after the route; no referrer names one, after a full navigation either. A browser with Global Privacy
// Control, or Do Not Track in any of navigator.doNotTrack, window.doNotTrack or navigator.msDoNotTrack, and a build
// at its local URL, make no request to either Databuddy host on either site and keep no visitor id. The docs load and
// search with their production headers (apps/docs/public/_headers) and log no CSP error. Test tooling: never imported
// by the site. Exits 1 if any check failed.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

const [webLocal, docsLocal, clientId] = process.argv.slice(2);

if (webLocal === undefined || docsLocal === undefined || clientId === undefined) {
  process.stderr.write("usage: bun scripts/analytics-browser.ts <website url> <docs url> <client id>\n");
  process.exit(2);
}

const web = "https://apmjs.dev";
const docs = "https://docs.apmjs.dev";

const scratch = mkdtempSync(join(tmpdir(), "analytics-check-"));

/** A certificate's two PEM files. */
type CertFiles = { readonly cert: string; readonly key: string };

/** A self-signed certificate for both canonical hostnames and Databuddy's endpoint, made for this run alone. */
function certificate(): CertFiles {
  const files: CertFiles = { cert: join(scratch, "cert.pem"), key: join(scratch, "key.pem") };

  const made = Bun.spawnSync(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=apmjs.dev", "-addext", "subjectAltName=DNS:apmjs.dev,DNS:docs.apmjs.dev,DNS:basket.databuddy.cc", "-keyout", files.key, "-out", files.cert],
    { stdout: "pipe", stderr: "pipe" },
  );

  if (made.exitCode !== 0) throw new Error(`openssl: ${made.stderr.toString()}`);

  return files;
}

const cert = certificate();

/** Where the proxy logs each request to Databuddy's endpoint, one JSON line each. */
const databuddyLog = join(scratch, "databuddy.jsonl");

writeFileSync(databuddyLog, "");

// the proxy (scripts/canonical-proxy.ts) is its own process: every browser call below blocks this one
const DOCS_HEADERS = join(import.meta.dir, "..", "..", "docs", "public", "_headers");

const proxy = Bun.spawn(["bun", join(import.meta.dir, "canonical-proxy.ts"), webLocal, docsLocal, cert.cert, cert.key, databuddyLog, DOCS_HEADERS], { stdout: "pipe", stderr: "inherit" });

/** The port the proxy prints once it listens: the first line of its output. */
async function proxyPortOf(out: ReadableStream<Uint8Array>): Promise<number> {
  const reader = out.getReader();
  let text = "";

  while (!text.includes("\n")) {
    const chunk = await reader.read();

    if (chunk.done) throw new Error("the proxy exited before it listened");
    text += new TextDecoder().decode(chunk.value);
  }

  reader.releaseLock();

  return z.coerce.number().int().positive().parse(text.trim());
}

const proxyPort = await proxyPortOf(proxy.stdout);

// --args replaces the launch args from agent-browser's config, so this host's --no-sandbox is given again
const LAUNCH = ["--ignore-https-errors", "--args", `--no-sandbox,--host-resolver-rules=MAP apmjs.dev 127.0.0.1:${proxyPort},MAP docs.apmjs.dev 127.0.0.1:${proxyPort},MAP basket.databuddy.cc 127.0.0.1:${proxyPort}`];

/** Hides the automation databuddy.js's bot check looks for, as a real visitor's browser would show none of it. */
const NOT_A_BOT = `Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
{ const ua = navigator.userAgent.replace(/HeadlessChrome/g, "Chrome"); Object.defineProperty(Navigator.prototype, "userAgent", { get: () => ua, configurable: true }); }
`;

/** A browser session: its name and the init script it launches with (the bot mask, then an opt-out signal if any). */
type Session = { readonly name: string; readonly launch: readonly string[] };

function session(name: string, optOut = ""): Session {
  const path = join(scratch, `${name}.js`);

  writeFileSync(path, `${NOT_A_BOT}${optOut}\n`);

  return { name: `analytics-check-${name}-${process.pid}`, launch: [...LAUNCH, "--init-script", path] };
}

let current = session("main");

const Reply = z.object({ success: z.boolean(), data: z.unknown(), error: z.unknown().optional() });

/** Runs one agent-browser command in the current session and parses its answer's data with `schema`. */
function ab<S extends z.ZodType>(args: readonly string[], schema: S): z.infer<S> {
  const run = Bun.spawnSync(["agent-browser", "--json", "--session", current.name, ...current.launch, ...args], { stdout: "pipe", stderr: "pipe" });
  const reply = Reply.parse(JSON.parse(run.stdout.toString()));

  if (!reply.success) throw new Error(`agent-browser ${args.join(" ")}: ${JSON.stringify(reply.error)}`);

  return schema.parse(reply.data);
}

/** Runs one agent-browser command whose answer is not read. */
function act(args: readonly string[]): void {
  ab(args, z.unknown());
}

/** One request the proxy logged for Databuddy's endpoint. Preflights are answered, not logged: they carry nothing. */
const Logged = z.object({ method: z.string(), url: z.string(), headers: z.record(z.string(), z.string()), body: z.string() });

type Sent = z.infer<typeof Logged>;

/** How many log lines the check has read. */
let logRead = 0;

/** Every request to Databuddy's event endpoint since the last call, in full. */
function databuddyRequests(): Sent[] {
  const lines = readFileSync(databuddyLog, "utf8").split("\n").filter((l) => l !== "");
  const fresh = lines.slice(logRead).map((l) => Logged.parse(JSON.parse(l)));

  logRead = lines.length;

  return fresh;
}

/** The endpoints databuddy.js posts to, each with the client id in the query ("/" takes outgoing-link clicks). */
const ENDPOINTS: ReadonlySet<string> = new Set(["/", "/batch", "/track", "/vitals", "/errors", "/outgoing", "/engagement"]);

/** A request to "/": databuddy.js sends outgoing-link clicks there, typed. */
const Direct = z.looseObject({ type: z.string() });

/** One item of a /batch body: only screen_view is read; the rest are checked for forbidden text alone. */
const Event = z.looseObject({ name: z.string().optional(), path: z.string().optional() });

/**
 * Strings that must never reach Databuddy: the ids, codes and attribution in the private pages' URLs, and the error
 * text thrown there. The public home page is opened with its own, different attribution (PUB1, pubsrc).
 */
const FORBIDDEN = ["stg_", "ABCD", "code=", "next=", "private-boom", "G123", "privsrc"];

/** A private route anywhere in a request, and whatever follows it up to the end of the string. */
const PRIVATE_ROUTE = /\/(account|approve|admin|device|signin|publish)([^"\\]*)/g;

let failures = 0;

function check(ok: boolean, what: string): void {
  process.stdout.write(`${ok ? "PASS" : "FAIL"} ${what}\n`);

  if (!ok) failures += 1;
}

/** The requests sent since the last call: each checked in full, then summarized as `<endpoint>` or `view <path>`. */
const sent = (): string[] => summarize(databuddyRequests());

/** Checks requests in full and summarizes each as `<endpoint>` or `view <path>`. */
function summarize(requests: readonly Sent[]): string[] {
  return requests.flatMap((r) => {
    const url = new URL(r.url);
    const text = JSON.stringify(r);

    check(r.method === "POST" && ENDPOINTS.has(url.pathname) && url.searchParams.get("client_id") === clientId, `a request goes to a Databuddy endpoint with the client id: ${r.method} ${r.url}`);

    for (const word of FORBIDDEN) if (text.includes(word)) check(false, `"${word}" appears in a request: ${text.slice(0, 1500)}`);

    // a private route may appear only as itself or masked, the route alone
    for (const m of text.matchAll(PRIVATE_ROUTE)) if (m[2] !== "" && m[2] !== "/*") check(false, `a private route goes out unmasked, "${m[0]}": ${text.slice(0, 1500)}`);

    if (url.pathname === "/") return [Direct.safeParse(JSON.parse(r.body)).data?.type ?? "/"];

    if (url.pathname !== "/batch") return [url.pathname];
    const events = z.array(Event).safeParse(JSON.parse(r.body));

    check(events.success, `a batch is an array of events: ${r.body.slice(0, 300)}`);

    return (events.success ? events.data : []).map((e) => (e.name === "screen_view" ? `view ${e.path ?? ""}` : (e.name ?? "event")));
  });
}

/** The pages viewed since the last call, by URL. */
const views = (): string[] => sent().filter((s) => s.startsWith("view "));

function expectViews(what: string, want: readonly string[]): void {
  const got = views();

  check(JSON.stringify(got) === JSON.stringify(want.map((u) => `view ${u}`)), `${what}: viewed ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}

/** How many times this document fetched databuddy.js, by its resource timing (client navigations keep the document). */
const trackerFetches = (): number => Number(run(`performance.getEntriesByType("resource").filter((e) => e.name.startsWith("https://cdn.databuddy.cc/")).length`));

/** Any fetch of either Databuddy host this document made, by its resource timing. */
const databuddyFetches = (): string => run(`JSON.stringify(performance.getEntriesByType("resource").map((e) => e.name).filter((n) => n.startsWith("https://cdn.databuddy.cc/") || n.startsWith("https://basket.databuddy.cc/")))`);

/** The page asked nothing of Databuddy at all: no tag, no fetch of either host, nothing sent. */
function expectNoRequests(what: string): void {
  const got = sent();

  check(run(`String(document.querySelector("script[data-apm-databuddy]") === null && typeof window.databuddy === "undefined")`) === "true", `${what}: no databuddy.js tag and no tracker`);
  check(databuddyFetches() === "[]", `${what}: no request to cdn.databuddy.cc or basket.databuddy.cc (got ${databuddyFetches()})`);
  check(got.length === 0, `${what}: sent ${JSON.stringify(got)}, want nothing`);
}

/** The served HTML of `url`: the inline loader, and no databuddy.js tag a parser could start before it. */
async function expectLoaderOnly(url: string): Promise<void> {
  const html = await (await fetch(url)).text();

  // the loader's own text names the URL (s.src="…"); a tag would be <script … src="…">
  check(html.includes("__apmLoadDatabuddy") && !/<script[^>]*\ssrc=["']?https:\/\/cdn\.databuddy\.cc/.test(html), `${url}: the HTML has the inline loader and no databuddy.js tag`);
}

/** CSP violations the console reported since the last call. */
const cspProblems = (): string[] => consoleProblems().filter((m) => /Content Security Policy|Refused to/i.test(m));

/**
 * Leaves the current page for a blank one and reads what that sent: a public page's exit and its last vitals go out
 * as it unloads, and would otherwise arrive while the next page is being checked. They are still checked in full.
 */
function leave(): void {
  act(["open", "about:blank"]);
  settle();
  sent();
}

// databuddy.js batches events for up to 5 s (batchTimeout) before it posts them
const settle = (): void => act(["wait", "6500"]);

const open = (url: string): void => {
  act(["open", url]);
  settle();
};

/** A client-router navigation (Next.js router.push), as a link click would make it. */
const push = (path: string): void => {
  act(["pushstate", path]);
  settle();
};

const Evaluated = z.object({ result: z.unknown().transform((v) => String(v)) });

/** Runs code in the page, as a script there would, and returns its value as text. */
const run = (code: string): string => ab(["eval", code], Evaluated).result;

/** Stubs the status page an outgoing-link click opens, so the check never loads the real one. */
function stubStatusPage(): void {
  act(["network", "route", "https://status.apmjs.dev/**", "--body", "{}"]);
}

/** A docs link click, the docs' client-router navigation. */
function clickDocsLink(): void {
  run(`document.querySelector('a[href="/guides/ci/"], a[href="/guides/ci"]')?.click(); 1`);
  settle();
}

/** Opens the docs search and types a query, as a reader would. */
function searchDocs(): void {
  act(["press", "Control+k"]);
  act(["wait", "800"]);
  act(["keyboard", "type", "install"]);
  act(["wait", "2500"]);
}

const Messages = z.object({ messages: z.array(z.object({ type: z.string(), text: z.string() })) });

/** Console errors and warnings since the last call, such as a React hydration mismatch. */
function consoleProblems(): string[] {
  const got = ab(["console"], Messages).messages.filter((m) => m.type === "error" || m.type === "warning").map((m) => m.text);

  act(["console", "--clear"]);

  return got;
}

/** Each opt-out signal, as an init script that sets it before any page script runs. */
const OPT_OUTS = [
  { name: "gpc", what: "Global Privacy Control", script: `Object.defineProperty(Navigator.prototype, "globalPrivacyControl", { get: () => true, configurable: true });`, probe: "navigator.globalPrivacyControl", want: "true" },
  { name: "dnt", what: "navigator.doNotTrack = 1", script: `Object.defineProperty(Navigator.prototype, "doNotTrack", { get: () => "1", configurable: true });`, probe: "navigator.doNotTrack", want: "1" },
  { name: "dnt-yes", what: "navigator.doNotTrack = yes", script: `Object.defineProperty(Navigator.prototype, "doNotTrack", { get: () => "yes", configurable: true });`, probe: "navigator.doNotTrack", want: "yes" },
  { name: "window-dnt", what: "window.doNotTrack = yes", script: `Object.defineProperty(window, "doNotTrack", { value: "yes", configurable: true });`, probe: "window.doNotTrack", want: "yes" },
  { name: "ms-dnt", what: "navigator.msDoNotTrack = 1", script: `Object.defineProperty(Navigator.prototype, "msDoNotTrack", { get: () => "1", configurable: true });`, probe: "navigator.msDoNotTrack", want: "1" },
] as const;

/** The private routes, each as it is opened with its ids and codes. */
const PRIVATE = ["/account", "/approve/stg_AbCdEf123456", "/admin/reviews", "/device?code=ABCD-1234", "/signin?next=%2Faccount", "/publish"];

try {
  stubStatusPage();

  // the served HTML: the inline loader and no databuddy.js tag, on both sites
  for (const path of ["/", "/compare", "/approve/stg_AbCdEf123456"]) await expectLoaderOnly(`${webLocal}${path}`);
  await expectLoaderOnly(`${docsLocal}/`);

  // the website at https://apmjs.dev, hard loads of the public pages
  open(`${web}/?gclid=PUB1&utm_source=pubsrc`);
  check(run("navigator.webdriver") === "false" && run("typeof window.databuddy") === "object", "the tracker loaded and takes this browser for a visitor");
  check(run("String(window.databuddyDisabled)") === "undefined" && trackerFetches() === 1, "the loader loads databuddy.js once at https://apmjs.dev");
  expectViews("home", [`${web}/`]);
  check(consoleProblems().length === 0, "no console errors or warnings on the home page (no hydration mismatch)");
  open(`${web}/compare`);
  expectViews("compare", [`${web}/compare`]);
  open(`${web}/docs`);
  expectViews("the website's docs page", [`${web}/docs`]);
  open(`${web}/package/react`);
  expectViews("a package page", [`${web}/package/react`]);

  // the private routes, hard loads: databuddy.js is not even fetched
  for (const path of PRIVATE) {
    leave();
    open(`${web}${path}`);
    expectNoRequests(`private page ${path}`);
    check(run("String(window.databuddyDisabled)") === "undefined", `private page ${path}: not taken for an opt-out`);
  }

  // an outgoing link clicked on a private page is not reported
  run(`document.querySelector('a[href="https://status.apmjs.dev"]')?.click(); 1`);
  settle();
  check(run("location.hostname") === "status.apmjs.dev", "the outgoing link on /publish navigated");
  check(sent().length === 0, "an outgoing link clicked on /publish is not reported");

  // a script error on a private page is not reported
  open(`${web}/publish`);
  sent();
  run(`setTimeout(() => { throw new Error("private-boom"); }); Promise.reject(new Error("private-boom")); 1`);
  settle();
  expectNoRequests("an error and a rejection thrown on /publish");

  // client navigation from a tracked public page into a private route with click IDs (both Timing A: after databuddy.js
  // has loaded, and Timing B: immediately while databuddy.js is still loading): the loader converts pushState into a full
  // navigation, so the private route opens in an untracked document, did_params never stores the private click ID, and
  // returning to home sends a clean home view with zero private URL data
  leave();
  open(`${web}/`);
  views();
  push("/approve/stg_AbCdEf123456?gclid=G123&utm_source=privsrc");
  // drain the old home document's unload exit/vitals, which must carry nothing from /approve
  sent();
  check(run("location.pathname + location.search") === "/approve/stg_AbCdEf123456?gclid=G123&utm_source=privsrc", "tracked pushState into /approve/<id>?gclid= navigated via full load");
  expectNoRequests("after tracked pushState into /approve/<id>?gclid=, the private page is untracked");
  check(run(`JSON.stringify(Object.entries(localStorage).concat(Object.entries(sessionStorage)))`).match(/G123|privsrc|stg_/) === null, "Timing A: did_params and storage hold nothing from the private URL");
  push("/");
  const afterPrivateReturn = databuddyRequests();
  const returnSummary = summarize(afterPrivateReturn);

  check(returnSummary.includes(`view ${web}/`), `Timing A: returning from /approve/<id>?gclid= to home views home cleanly: ${JSON.stringify(returnSummary)}`);

  for (const word of ["gclid", "utm_source", "approve", "stg_", "G123", "privsrc"]) {
    const hit = afterPrivateReturn.find((r) => JSON.stringify(r).includes(word));

    check(hit === undefined, `Timing A: nothing sent on return names "${word}"${hit === undefined ? "" : `: ${JSON.stringify(hit).slice(0, 800)}`}`);
  }

  // Timing B: enter a private route via pushState while databuddy.js has not finished executing on the public page
  leave();
  act(["network", "route", "https://cdn.databuddy.cc/**", "--abort"]);
  act(["open", `${web}/`]);
  check(run("typeof window.databuddy") === "undefined", "Timing B: databuddy.js has not executed yet before pushState");
  act(["eval", `history.pushState({}, "", "/approve/stg_AbCdEf123456?gclid=G123&utm_source=privsrc"); 1`]);
  settle();
  sent();
  check(run("location.pathname + location.search") === "/approve/stg_AbCdEf123456?gclid=G123&utm_source=privsrc", "Timing B: immediate pushState into /approve/<id>?gclid= navigated via full load");
  expectNoRequests("Timing B: the private page is untracked");
  check(run(`JSON.stringify(Object.entries(localStorage).concat(Object.entries(sessionStorage)))`).match(/G123|privsrc|stg_/) === null, "Timing B: storage holds nothing from the private URL");
  act(["network", "unroute", "https://cdn.databuddy.cc/**"]);
  push("/");
  const timingBReturn = databuddyRequests();
  const timingBSummary = summarize(timingBReturn);

  check(timingBSummary.includes(`view ${web}/`), `Timing B: returning to home views home cleanly: ${JSON.stringify(timingBSummary)}`);

  for (const word of ["gclid", "utm_source", "approve", "stg_", "G123", "privsrc"]) {
    const hit = timingBReturn.find((r) => JSON.stringify(r).includes(word));

    check(hit === undefined, `Timing B: nothing sent on return names "${word}"${hit === undefined ? "" : `: ${JSON.stringify(hit).slice(0, 800)}`}`);
  }

  // a client-router visit to a private page, then a full navigation: every page sends Referrer-Policy: strict-origin,
  // so the next page's referrer is the origin alone, not the private path
  leave();
  open(`${web}/`);
  views();
  push("/approve/stg_AbCdEf123456");
  sent();
  run(`location.assign("/"); 1`);
  settle();
  check(run("document.referrer") === `${web}/`, `after / -> /approve/<id> -> full /, the referrer is the origin alone (got "${run("document.referrer")}")`);
  expectViews("a full navigation after visiting /approve/<id>", [`${web}/`]);

  // the same from a hard load of the private page
  leave();
  open(`${web}/approve/stg_AbCdEf123456`);
  sent();
  run(`location.assign("/"); 1`);
  settle();
  check(run("document.referrer") === `${web}/`, `after a hard load of /approve/<id> and a full navigation to /, the referrer is the origin alone (got "${run("document.referrer")}")`);
  expectViews("a full navigation from /approve/<id> to home", [`${web}/`]);

  // an error on a public page is reported (track-errors), and an outgoing link click (track-outgoing-links)
  open(`${web}/compare`);
  sent();
  run(`setTimeout(() => { throw new Error("public page error"); }); 1`);
  settle();
  check(sent().includes("/errors"), "an error thrown on a public page is reported to /errors");
  run(`document.querySelector('a[href="https://status.apmjs.dev"]')?.click(); 1`);
  settle();
  check(sent().includes("outgoing_link"), "an outgoing link click on a public page is reported");

  // the docs: hard loads, the client router, search, with the docs' production headers and no CSP error
  leave();
  consoleProblems();
  open(`${docs}/?utm_source=src`);
  check(run("String(window.databuddyDisabled)") === "undefined" && run("typeof window.databuddy") === "object", "the docs' loader loads the tracker at https://docs.apmjs.dev");
  expectViews("the docs home", [`${docs}/`]);
  clickDocsLink();
  check(run("location.pathname").startsWith("/guides/ci"), "a docs link click navigated");
  expectViews("a docs client navigation sends one view", [`${docs}/guides/ci/`]);
  check(trackerFetches() === 1 && Number(run(`document.querySelectorAll("script[data-apm-databuddy]").length`)) <= 1, "the docs fetched databuddy.js once, with at most one tag, after a client navigation");
  searchDocs();
  check(Number(run(`document.querySelectorAll("[data-pagefind-ui] a, .pagefind-ui__result, [role=dialog] a[href*='/'], [cmdk-item], [role=option]").length`)) > 0, "a docs search finds results under the docs CSP");
  sent();
  const docsCsp = cspProblems();

  check(docsCsp.length === 0, `the docs at https://docs.apmjs.dev log no CSP errors: ${JSON.stringify(docsCsp)}`);
  open(`${docs}/guides/ci/`);
  const ciCsp = cspProblems();

  check(ciCsp.length === 0, `a docs hard load of /guides/ci/ logs no CSP errors: ${JSON.stringify(ciCsp)}`);
  views();

  // the same production builds at their local URLs, as a local or preview copy is served: no request at all
  leave();

  for (const path of ["/", "/compare", "/package/react"]) {
    open(`${webLocal}${path}`);
    check(run("String(window.databuddyDisabled)") === "true", `the loader declines at ${new URL(webLocal).origin}${path}`);
    expectNoRequests(`the website at its local URL ${new URL(webLocal).origin}${path}`);
  }

  push("/docs");
  expectNoRequests("a client navigation at the website's local URL");
  open(`${docsLocal}/`);
  check(run("String(window.databuddyDisabled)") === "true", "the docs' loader declines at their local URL");
  expectNoRequests(`the docs at their local URL ${new URL(docsLocal).origin}/`);
  clickDocsLink();
  expectNoRequests("a docs client navigation at the local URL");
  act(["close"]);

  // a hard load of a private page with attribution, in a fresh browser, then the client router to home: nothing on
  // the private page, then a clean home view with none of the private page's URL
  current = session("attribution");
  stubStatusPage();
  open(`${web}/approve/stg_AbCdEf123456?gclid=G123&utm_source=privsrc`);
  expectNoRequests("a hard load of /approve/<id>?gclid=&utm_source=");
  push("/");
  check(run("location.pathname + location.search") === "/", "the client router reached home");
  const attributed = databuddyRequests();
  const clean = summarize(attributed);

  check(clean.includes(`view ${web}/`), `after a private hard load with attribution and the client router to home, home is viewed: ${JSON.stringify(clean)}`);

  for (const word of ["gclid", "utm_source", "approve", "stg_", "G123", "privsrc"]) {
    const hit = attributed.find((r) => JSON.stringify(r).includes(word));

    check(hit === undefined, `nothing sent after that names "${word}"${hit === undefined ? "" : `: ${JSON.stringify(hit).slice(0, 800)}`}`);
  }

  check(trackerFetches() === 1, "databuddy.js was fetched once, after the client router reached home");
  check(run(`JSON.stringify(Object.entries(localStorage).concat(Object.entries(sessionStorage)))`).match(/G123|privsrc|stg_/) === null, "nothing of the private URL is stored in the browser");
  // home's exit and last vitals go out as it unloads: read them here, not during the next browser's checks
  leave();
  act(["close"]);

  // each opt-out signal, in its own browser: nothing is sent from either site, and no visitor id is kept
  for (const optOut of OPT_OUTS) {
    current = session(optOut.name, optOut.script);
    stubStatusPage();
    open(`${web}/`);
    check(run(optOut.probe) === optOut.want, `${optOut.what} is set in the page (${optOut.probe} is ${run(optOut.probe)})`);
    expectNoRequests(`${optOut.what}: the website's home`);
    push("/compare");
    expectNoRequests(`${optOut.what}: a client navigation to compare`);
    open(`${web}/approve/stg_AbCdEf123456`);
    push("/");
    expectNoRequests(`${optOut.what}: a private page, then the client router to home`);
    check(run(`localStorage.getItem("did")`) === "null", `${optOut.what}: no visitor id is stored`);
    open(`${docs}/`);
    check(run(optOut.probe) === optOut.want, `${optOut.what} is set in the docs page`);
    expectNoRequests(`${optOut.what}: the docs home`);
    clickDocsLink();
    expectNoRequests(`${optOut.what}: a docs client navigation`);
    act(["close"]);
  }
} finally {
  try {
    act(["close"]);
  } catch {
    // already closed
  }

  proxy.kill();
  rmSync(scratch, { recursive: true, force: true });
}

process.stdout.write(failures === 0 ? "all checks passed\n" : `${failures} check(s) failed\n`);

process.exit(failures === 0 ? 0 : 1);
