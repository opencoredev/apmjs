// What a real browser sends to Databuddy from the website and the docs, with Databuddy's endpoint stubbed (agent-browser
// routes https://basket.databuddy.cc/** to a canned answer, so nothing reaches Databuddy). Run it against builds made
// with a client id (NEXT_PUBLIC_DATABUDDY_CLIENT_ID), each served locally:
//
//   bun scripts/analytics-browser.ts <website url> <docs url> <client id>
//
// The senders only send from https://apmjs.dev and https://docs.apmjs.dev, so the check serves the local builds at
// those origins: a TLS proxy with a throwaway self-signed certificate forwards both hostnames to the local servers,
// and the browser resolves them to it (--host-resolver-rules) and accepts the certificate. Nothing reaches the real
// sites. The same builds opened at their local URLs must send nothing.
//
// Every request to a Databuddy origin is read in full (URL, headers, body) and must be one page_view with an allowed
// label, with no Referer and none of the private page, its ids, the query or the click ids in it. Moving between
// public and private pages by the client router, in both directions, and an error thrown on a public page must add
// nothing else. A browser with Global Privacy Control, or Do Not Track in any of navigator.doNotTrack,
// window.doNotTrack or navigator.msDoNotTrack, must send nothing on either site. Test tooling: never imported by the
// site. Exits 1 on the first failed check.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

/** A self-signed certificate for both canonical hostnames, made for this run alone. */
function certificate(): CertFiles {
  const files: CertFiles = { cert: join(scratch, "cert.pem"), key: join(scratch, "key.pem") };

  const made = Bun.spawnSync(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=apmjs.dev", "-addext", "subjectAltName=DNS:apmjs.dev,DNS:docs.apmjs.dev", "-keyout", files.key, "-out", files.cert],
    { stdout: "pipe", stderr: "pipe" },
  );

  if (made.exitCode !== 0) throw new Error(`openssl: ${made.stderr.toString()}`);

  return files;
}

const cert = certificate();

// the proxy (scripts/canonical-proxy.ts) is its own process: every browser call below blocks this one
const proxy = Bun.spawn(["bun", join(import.meta.dir, "canonical-proxy.ts"), webLocal, docsLocal, cert.cert, cert.key], { stdout: "pipe", stderr: "inherit" });

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
const LAUNCH = ["--ignore-https-errors", "--args", `--no-sandbox,--host-resolver-rules=MAP apmjs.dev 127.0.0.1:${proxyPort},MAP docs.apmjs.dev 127.0.0.1:${proxyPort}`];

/** A browser session: its name and the init script (an opt-out signal) it launches with, if any. */
type Session = { readonly name: string; readonly launch: readonly string[] };

function session(name: string, initScript?: string): Session {
  if (initScript === undefined) return { name: `analytics-check-${name}-${process.pid}`, launch: LAUNCH };
  const path = join(scratch, `${name}.js`);

  writeFileSync(path, initScript);

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

const Listed = z.object({ requests: z.array(z.object({ requestId: z.string(), method: z.string(), url: z.string() })) });

const Detail = z.object({ url: z.string(), method: z.string(), headers: z.record(z.string(), z.string()), postData: z.string().optional() });

type Sent = z.infer<typeof Detail>;

/** Every request to a Databuddy origin since the last call, in full. Preflights are listed but carry nothing. */
function databuddyRequests(): Sent[] {
  const listed = ab(["network", "requests", "--filter", "databuddy.cc"], Listed).requests;
  const sent = listed.filter((r) => r.method !== "OPTIONS").map((r) => ab(["network", "request", r.requestId], Detail));

  act(["network", "requests", "--clear"]);

  return sent;
}

const PageView = z.strictObject({ name: z.literal("page_view"), properties: z.strictObject({ site: z.enum(["web", "docs"]), route: z.string() }) });

/** Strings that must never reach Databuddy: the private pages, their ids and codes, the query, the package and file. */
const FORBIDDEN = ["approve", "stg_", "device", "ABCD", "account", "signin", "gclid", "G123", "utm", "campaign", "code=", "react", "package.json", "file", "boom", "secret", "admin"];

let failures = 0;

function check(ok: boolean, what: string): void {
  process.stdout.write(`${ok ? "PASS" : "FAIL"} ${what}\n`);

  if (!ok) failures += 1;
}

/** The page views sent since the last call: each checked in full, then returned as `site route`. */
function views(): string[] {
  return databuddyRequests().map((r) => {
    const text = JSON.stringify(r);
    const body = PageView.safeParse(JSON.parse(r.postData ?? "null"));
    const referer = Object.entries(r.headers).find(([k]) => k.toLowerCase() === "referer")?.[1] ?? "";

    check(r.method === "POST" && r.url === `https://basket.databuddy.cc/track?website_id=${clientId}`, `the request goes to /track alone: ${r.method} ${r.url}`);
    check(body.success, `the body is one page_view with a site and a route: ${r.postData ?? ""}`);
    check(referer === "", `no Referer (got "${referer}")`);

    for (const word of FORBIDDEN) if (text.includes(word)) check(false, `"${word}" appears in a request: ${text}`);

    return body.success ? `${body.data.properties.site} ${body.data.properties.route}` : "invalid";
  });
}

function expectViews(what: string, want: readonly string[]): void {
  const got = views();

  check(JSON.stringify(got) === JSON.stringify(want), `${what}: sent ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}

const settle = (): void => act(["wait", "2000"]);

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

/** Stubs Databuddy in the current session: its event endpoint answers, its CDN is refused. */
function stubDatabuddy(): void {
  for (const origin of [web, docs, new URL(webLocal).origin, new URL(docsLocal).origin]) act(["network", "route", "https://basket.databuddy.cc/**", "--body", '{"status":"success"}', "--allow-origin", origin]);
  act(["network", "route", "https://cdn.databuddy.cc/**", "--abort"]);
}

/** A docs link click, the docs' client-router navigation. */
function clickDocsLink(): void {
  run(`document.querySelector('a[href="/guides/ci/"], a[href="/guides/ci"]')?.click(); 1`);
  settle();
}

/** Each opt-out signal, as an init script that sets it before any page script runs. */
const OPT_OUTS = [
  { name: "gpc", what: "Global Privacy Control", script: `Object.defineProperty(Navigator.prototype, "globalPrivacyControl", { get: () => true, configurable: true });`, probe: "navigator.globalPrivacyControl", want: "true" },
  { name: "dnt", what: "navigator.doNotTrack = 1", script: `Object.defineProperty(Navigator.prototype, "doNotTrack", { get: () => "1", configurable: true });`, probe: "navigator.doNotTrack", want: "1" },
  { name: "window-dnt", what: "window.doNotTrack = yes", script: `Object.defineProperty(window, "doNotTrack", { value: "yes", configurable: true });`, probe: "window.doNotTrack", want: "yes" },
  { name: "ms-dnt", what: "navigator.msDoNotTrack = 1", script: `Object.defineProperty(Navigator.prototype, "msDoNotTrack", { get: () => "1", configurable: true });`, probe: "navigator.msDoNotTrack", want: "1" },
] as const;

try {
  stubDatabuddy();

  // the website at https://apmjs.dev, hard loads
  open(`${web}/?gclid=G123&utm_source=src&utm_campaign=campaign`);
  expectViews("home with gclid and utm parameters", ["web home"]);
  open(`${web}/compare`);
  expectViews("compare", ["web compare"]);
  open(`${web}/docs`);
  expectViews("the website's docs page", ["web docs"]);
  open(`${web}/package/react`);
  expectViews("a package page", ["web package"]);
  open(`${web}/package/react/v/18.3.1/file/package.json?line=2`);
  expectViews("a file view", []);

  for (const path of ["/approve/stg_AbCdEf123456?gclid=G123", "/device?code=ABCD-1234", "/account", "/signin?next=%2Faccount", "/publish", "/admin/reviews", "/no-such-page?code=ABCD"]) {
    open(`${web}${path}`);
    expectViews(`private or unknown page ${path}`, []);
  }

  // client navigation, public to private and back
  open(`${web}/`);
  views();
  push("/approve/stg_AbCdEf123456");
  expectViews("client navigation from home to /approve/<id>", []);
  push("/");
  expectViews("client navigation from /approve/<id> to home", ["web home"]);
  push("/device?code=ABCD-1234");
  expectViews("client navigation from home to /device?code=", []);
  push("/compare");
  expectViews("client navigation from /device?code= to compare", ["web compare"]);

  // a private page loaded with a click id, then a public one by the client router: neither the id nor the page leaves
  open(`${web}/approve/stg_AbCdEf123456?gclid=G123&utm_source=src`);
  views();
  push("/package/react");
  expectViews("client navigation from a private page with gclid to a package", ["web package"]);
  push("/package/react/v/18.3.1/file/package.json");
  expectViews("client navigation from a package to one of its files", []);
  push("/package/react");
  expectViews("client navigation from a file back to its package", ["web package"]);

  // a same-origin referrer: a full navigation from a private page to a public one
  open(`${web}/device?code=ABCD-1234`);
  views();
  run(`location.href = "/"`);
  settle();
  check(run("document.referrer").includes("/device"), "the browser did set a same-origin referrer for the next check");
  expectViews("a full navigation from /device?code= to home", ["web home"]);

  // errors on a public page are not captured
  run(`setTimeout(() => { throw new Error("boom at /device?code=ABCD-1234 secret"); }); Promise.reject(new Error("boom /approve/stg_x")); console.error("boom secret"); 1`);
  settle();
  expectViews("an error and a rejection thrown on a public page", []);

  // the docs: hard loads, the client router, the 404 page, errors
  open(`${docs}/?utm_source=src&gclid=G123`);
  expectViews("the docs home with utm and gclid", ["docs /"]);
  clickDocsLink();
  check(run("location.pathname").startsWith("/guides/ci"), "a docs link click navigated");
  expectViews("a docs client navigation", ["docs /guides/ci"]);
  open(`${docs}/no-such-page?code=ABCD-1234`);
  expectViews("the docs 404 page", []);
  open(`${docs}/quickstart/`);
  views();
  run(`setTimeout(() => { throw new Error("boom /device?code=ABCD-1234"); }); 1`);
  settle();
  expectViews("an error thrown on a docs page", []);

  // the same production builds at their local URLs, as a local or preview copy is served: nothing is sent
  for (const path of ["/", "/compare", "/package/react"]) {
    open(`${webLocal}${path}`);
    expectViews(`the website at its local URL ${new URL(webLocal).origin}${path}`, []);
  }

  open(`${docsLocal}/`);
  expectViews(`the docs at their local URL ${new URL(docsLocal).origin}/`, []);
  clickDocsLink();
  expectViews("a docs client navigation at the local URL", []);
  act(["close"]);

  // each opt-out signal, in its own browser: nothing is sent from either site
  for (const optOut of OPT_OUTS) {
    current = session(optOut.name, optOut.script);
    stubDatabuddy();
    open(`${web}/`);
    check(run(optOut.probe) === optOut.want, `${optOut.what} is set in the page (${optOut.probe} is ${run(optOut.probe)})`);
    expectViews(`${optOut.what}: the website's home`, []);
    push("/compare");
    expectViews(`${optOut.what}: a client navigation to compare`, []);
    open(`${web}/package/react`);
    expectViews(`${optOut.what}: a package page`, []);
    open(`${docs}/`);
    check(run(optOut.probe) === optOut.want, `${optOut.what} is set in the docs page`);
    expectViews(`${optOut.what}: the docs home`, []);
    clickDocsLink();
    expectViews(`${optOut.what}: a docs client navigation`, []);
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
