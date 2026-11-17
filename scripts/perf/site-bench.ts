// How long the site's pages (other than package pages) take on a local copy of production: the built website Worker
// (apps/web/dist/worker, from packages/infra/perf/build-web.ts) and the registry Worker, both in workerd, the website
// reaching the registry through its REGISTRY service binding, Postgres behind a proxy that adds a query round trip's
// latency, and a fake npm that answers searches after a delay. Each page is visited cold (fresh isolates, as the first
// visitor in a while gets) and warm (the same isolates, later visits).
//
//   bun scripts/perf/site-bench.ts     # the per-page table on stderr; the score (modeled ms, lower is better) last
//
// A visit is the document, read to its last byte (streamed parts included), then at once the static files the document
// names (styles, scripts, fonts) and the requests the page makes as soon as it hydrates. Search visits use a new query
// each time, so no cache answers them. A cold visit is the median of COLD_RUNS, each on fresh isolates. On a warm visit
// the browser has the static files from before: one whose Cache-Control lets it keep the file asks for nothing, any
// other is asked again with its ETag, and the visit waits ASSET_RTT_MS for that round trip.
//
// What workerd here can't show is added from counts, with weights from production timings (2026-11-15):
//   - a cold isolate's script load: COLD_MS_PER_MB per MB of the Worker's JavaScript, for the website on every cold
//     visit and for the registry on cold visits that call it (production: static pages took 0.5 to 0.8 s on a cold
//     isolate, about 0.1 s warm, with 11 MB of website JS);
//   - a page whose server HTML could not be resumed, so the browser renders those parts itself ($RX boundaries):
//     RX_MS once per document, the wait for the page's JavaScript and hydration before they show.
//
// Latencies (ms): PG_RTT per query round trip, PG_CONNECT per new connection (Hyperdrive keeps the database's
// connections, so the handshake is local), NPM_MS per npm search, NPM_MISS_MS per other npm read.
import { randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { Client } from "pg";
import { z } from "zod";
import { buildWorker, workerModules } from "../../packages/registry/scripts/build.ts";
import { POPULAR_PACKAGES } from "../../apps/web/lib/agent/site.ts";
import * as webBuild from "../../packages/infra/web-build.ts";
import { freshDatabase } from "../../tests/acceptance/postgres.ts";

const ROOT = join(import.meta.dir, "../..");
const WEB = join(ROOT, "apps/web");
const PG_RTT = Number(process.env.PG_RTT ?? 25);
const PG_CONNECT = Number(process.env.PG_CONNECT ?? 10);
const NPM_MS = Number(process.env.NPM_MS ?? 400);
const NPM_MISS_MS = Number(process.env.NPM_MISS_MS ?? 100);
const WARM_RUNS = Number(process.env.WARM_RUNS ?? 3);
const COLD_RUNS = Number(process.env.COLD_RUNS ?? 3);
const ASSET_RTT_MS = 50;
const COLD_MS_PER_MB = 40;
const RX_MS = 300;

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------- fake npm ----------
let npmReads = 0;

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  async fetch(req) {
    npmReads++;
    const url = new URL(req.url);

    if (url.pathname === "/-/v1/search") {
      await wait(NPM_MS);
      const text = url.searchParams.get("text") ?? "x";
      const size = Math.min(20, Number(url.searchParams.get("size") ?? 20));

      const objects = Array.from({ length: size }, (_, i) => ({
        package: { name: i === 0 ? text : `${text}-${i}`, version: "1.0.0", description: `fake ${text} ${i}`, date: "2026-01-01T00:00:00.000Z", links: {}, publisher: { username: "x" }, maintainers: [] },
        score: { final: 0.5, detail: { quality: 0.5, popularity: 0.5, maintenance: 0.5 } },
        searchScore: 1,
        downloads: { weekly: 1000 - i },
      }));

      return Response.json({ objects, total: size, time: new Date().toUTCString() });
    }

    await wait(NPM_MISS_MS);

    return Response.json({ error: "Not found" }, { status: 404 });
  },
});

// ---------- Postgres, seeded, behind a latency proxy ----------
const database = await freshDatabase();

/** What the home page's recent list reads: eight packages published here, one of them later revoked. */
async function seed(url: string): Promise<void> {
  const c = new Client({ connectionString: url });
  await c.connect();
  const at = Date.now() - 3 * 24 * 60 * 60_000;

  for (let i = 0; i < 8; i++) {
    const name = `@bench/pkg-${i}`;
    const version = `1.0.${i}`;
    await c.query("INSERT INTO packages (name, created_at, modified_at, dist_tags, description) VALUES ($1, $2, $2, $3, $4)", [name, at + i, JSON.stringify({ latest: version }), `bench package ${i}`]);
    await c.query(
      "INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, status, status_reason, status_at) VALUES ($1, $2, $3, 'x', 'sha512-x', 1, 'sha512/x', $4, 'bench', $5, $6, $7)",
      [name, version, JSON.stringify({ name, version }), at + i, i === 3 ? "revoked" : "active", i === 3 ? "bench revoke" : null, i === 3 ? at + 100 : null],
    );
    await c.query("INSERT INTO events (package, kind, actor, at, detail) VALUES ($1, 'publish', 'bench', $2, $3)", [name, at + i, JSON.stringify({ version })]);
  }

  await c.query("INSERT INTO events (package, kind, actor, at, detail) VALUES ('@bench/pkg-3', 'revoke', 'bench', $1, $2)", [at + 100, JSON.stringify({ version: "1.0.3", reason: "bench revoke" })]);

  // the popular packages' kept scores, as production holds them (migration 0019; the cron keeps them fresh)
  for (const [i, p] of POPULAR_PACKAGES.entries()) {
    await c.query("INSERT INTO latest_scores (package, version, score, grade, computed_at, asked_at) VALUES ($1, '1.0.0', $2, 'B', $3, $3)", [p.name, 80 + i, Date.now()]);
  }

  await c.end();
}

await seed(database.url);

const target = new URL(database.url);
let pgTrips = 0;

type Pipe = { server: import("bun").Socket<undefined> | null; queue: Uint8Array[]; chunks: number };

/** A message the client sends once it is signed in: a query (simple or extended protocol), not the startup or SASL. */
const isQuery = (chunk: Uint8Array, index: number): boolean => index > 0 && chunk[0] !== 0x70;

const proxy = Bun.listen<Pipe>({
  hostname: "127.0.0.1",
  port: 0,
  socket: {
    async open(client) {
      client.data = { server: null, queue: [], chunks: 0 };
      await wait(PG_CONNECT);

      const server = await Bun.connect({
        hostname: target.hostname,
        port: Number(target.port || 5432),
        socket: {
          data: (_s, chunk) => void client.write(chunk),
          close: () => client.end(),
          error: () => client.end(),
        },
      });

      client.data.server = server;

      for (const q of client.data.queue) server.write(q);
      client.data.queue = [];
    },
    data(client, chunk) {
      const copy = new Uint8Array(chunk);
      const query = isQuery(copy, client.data.chunks++);

      const send = () => {
        if (client.data.server) client.data.server.write(copy);
        else client.data.queue.push(copy);
      };

      if (!query) return send();
      pgTrips++;
      setTimeout(send, PG_RTT);
    },
    close(client) {
      client.data.server?.end();
    },
  },
});

const proxied = new URL(database.url);

proxied.hostname = "127.0.0.1";

proxied.port = String(proxy.port);

// ---------- the two Workers ----------
const registryScript = await buildWorker("worker", mkdtempSync(`${tmpdir()}/apm-bench-`));
const workerDir = join(WEB, "dist");
const moduleType = (file: string): "ESModule" | "CompiledWasm" | "Data" => (file.endsWith(".js") ? "ESModule" : file.endsWith(".wasm") ? "CompiledWasm" : "Data");

function listFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);

    return statSync(p).isDirectory() ? listFiles(p) : [p];
  });
}

const webFiles = listFiles(join(workerDir, "worker"));
const entry = join(workerDir, "worker", "worker.js");
const webModules = [entry, ...webFiles.filter((f) => f !== entry)].map((path) => ({ type: moduleType(path), path }));
const jsMb = (files: string[]) => files.filter((f) => f.endsWith(".js")).reduce((n, f) => n + statSync(f).size, 0) / 1e6;
const webMb = jsMb(webFiles);
const registryMb = jsMb([registryScript]);

/** The deploy's asset routing (packages/infra/web-build.ts) as workerd's router takes it: what runs the Worker first. */
type RouterConfig = { invoke_user_worker_ahead_of_assets: boolean; has_user_worker: true; static_routing?: { user_worker: string[]; asset_worker: string[] } };

function routerConfig(): RouterConfig {
  const parsed = z.object({ WEB_ASSETS: z.object({ runWorkerFirst: z.union([z.literal(true), z.array(z.string())]) }) }).safeParse(webBuild);
  const first = parsed.success ? parsed.data.WEB_ASSETS.runWorkerFirst : true;

  if (first === true) return { invoke_user_worker_ahead_of_assets: true, has_user_worker: true };

  return {
    invoke_user_worker_ahead_of_assets: false,
    has_user_worker: true,
    static_routing: { user_worker: first.filter((p) => !p.startsWith("!")), asset_worker: first.filter((p) => p.startsWith("!")).map((p) => p.slice(1)) },
  };
}

const REGISTRY_URL = "http://registry.bench/";
const WEB_URL = "http://127.0.0.1/";

// counts what the website asks the registry, by path, between reads of /__bench
const COUNTER = `
let seen = [];
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/__bench") { const out = seen; seen = []; return Response.json(out); }
    seen.push(req.method + " " + url.pathname);
    return env.REAL.fetch(req);
  },
};`;

const options = () => ({
  host: "127.0.0.1",
  port: 0,
  workers: [
    {
      name: "web",
      modules: webModules,
      modulesRoot: workerDir,
      compatibilityDate: "2026-08-06",
      compatibilityFlags: ["nodejs_compat"],
      assets: { directory: join(WEB, ".open-next/assets"), binding: "ASSETS", routerConfig: routerConfig() },
      bindings: { APM_REGISTRY: REGISTRY_URL, APM_CLIENT_IP_HEADER: "cf-connecting-ip" },
      serviceBindings: { REGISTRY: "counter", WORKER_SELF_REFERENCE: "web" },
      ratelimits: { AGENT_RATE_LIMIT: { namespace_id: "4801", simple: { limit: 60, period: 60 } } },
    },
    { name: "counter", modules: true, script: COUNTER, compatibilityDate: "2026-07-30", serviceBindings: { REAL: "registry" } },
    {
      name: "registry",
      modules: workerModules(registryScript),
      modulesRoot: join(registryScript, ".."),
      compatibilityDate: "2026-07-30",
      compatibilityFlags: ["nodejs_compat"],
      bindings: {
        APM_REGISTRY_URL: REGISTRY_URL,
        APM_PUBLIC_URL: WEB_URL,
        APM_UPSTREAM: `http://127.0.0.1:${npm.port}/`,
        APM_NAME_POLICY: "scoped",
        APM_AUTH_SECRET: randomBytes(32).toString("base64url"),
      },
      r2Buckets: ["BLOBS"],
      hyperdrives: { HYPERDRIVE: proxied.toString() },
    },
  ],
});

/** One visit to a page: the document, then what the page fetches once it hydrates. `{q}` is a fresh search query. */
type Visit = { page: string; doc: string; after: string[] };

const VISITS: Visit[] = [
  { page: "home", doc: "/", after: ["/-/apm/v1/account"] },
  { page: "search", doc: "/?q={q}", after: ["/-/apm/v1/account", "/api/search?q={q}"] },
  { page: "compare", doc: "/compare", after: ["/-/apm/v1/account"] },
  { page: "publish", doc: "/publish", after: ["/-/apm/v1/account"] },
  { page: "signin", doc: "/signin", after: ["/-/apm/v1/account", "/-/apm/v1/auth/config"] },
  { page: "account", doc: "/account", after: ["/-/apm/v1/account"] },
  { page: "device", doc: "/device", after: ["/-/apm/v1/account"] },
  { page: "docs", doc: "/docs", after: ["/-/apm/v1/account"] },
];

type Timed = { path: string; ms: number; ttfb: number; status: number; text: string; headers: Headers };

async function get(base: URL, path: string, headers: Record<string, string> = {}): Promise<Timed> {
  const start = performance.now();
  const res = await fetch(new URL(path, base), { headers: { "cf-connecting-ip": "203.0.113.7", accept: "text/html,application/json", ...headers }, redirect: "manual" });
  const ttfb = performance.now() - start;
  const text = await res.text();

  return { path, ms: performance.now() - start, ttfb, status: res.status, text, headers: res.headers };
}

let queries = 0;
const fill = (path: string, q: string) => path.replaceAll("{q}", q);

/** The static files a document names: its styles, scripts and preloaded fonts. */
const assetsOf = (html: string): string[] => [...new Set([...html.matchAll(/(?:href|src)="(\/_next\/static\/[^"]+)"/g)].map((m) => m[1] ?? ""))].filter((p) => p !== "");

/** Whether a browser may reuse a file without asking: a max-age above zero, and no no-cache or no-store. */
const keepable = (cc: string): boolean => !/no-cache|no-store/.test(cc) && Number(/max-age=(\d+)/.exec(cc)?.[1] ?? 0) > 0;

/** What the browser holds from an earlier visit: each static file's validator and whether it may reuse it as is. */
type Held = Map<string, { etag: string | null; keep: boolean }>;

type Visited = { ms: number; doc: Timed; rx: number; held: Held; asked: number };

async function visit(base: URL, v: Visit, held: Held | null): Promise<Visited> {
  const q = `bench${++queries}`;
  const doc = await get(base, fill(v.doc, q));
  const start = performance.now();
  const assets = assetsOf(doc.text);
  // a warm visit asks again only for what the browser may not keep
  const ask = held ? assets.filter((a) => !held.get(a)?.keep) : assets;
  const files = Promise.all(ask.map((a) => get(base, a, held?.get(a)?.etag ? { "if-none-match": held.get(a)?.etag ?? "" } : {})));
  const [rest, fetched] = await Promise.all([Promise.all(v.after.map((p) => get(base, fill(p, q)))), files]);
  const failed = [...rest, ...fetched].find((r) => r.status >= 400 && r.status !== 401);

  if (doc.status >= 500 || failed) throw new Error(`${v.page}: ${doc.status >= 500 ? `document answered ${doc.status}` : `${failed?.path} answered ${failed?.status}`}`);
  const rx = (doc.text.match(/\$RX\("/g) ?? []).length;
  expect(v, doc, rest);
  const next: Held = new Map(held ?? []);

  for (const f of fetched) if (f.status === 200) next.set(f.path, { etag: f.headers.get("etag"), keep: keepable(f.headers.get("cache-control") ?? "") });
  const revalidated = held !== null && ask.length > 0;
  const ms = doc.ms + (rest.length + fetched.length > 0 ? performance.now() - start : 0) + (revalidated ? ASSET_RTT_MS : 0);

  return { ms, doc, rx, held: next, asked: ask.length };
}

/**
 * What each page's HTML must hold (review of de5c7b7, finding 2: an empty page passed): its title, the site header and
 * footer, the scripts that hydrate it, and its own content. Text a page renders on the server (`html`) is matched in
 * its markup; a view that renders in the browser (`views`, the client components the RSC payload names) is matched as
 * a client reference, so a page whose view is dropped, or that no longer hydrates it, fails.
 *
 * This reads server HTML only and runs no JavaScript. A page whose content renders in the browser (publish, account,
 * device) is checked by its placeholder and the component reference its payload names, not by its rendered view: a
 * view that renders nothing still passes here (re-check of 38c87f9).
 */
type PageContent = { title: string; html: string[]; views: string[] };

const PAGE_CONTENT: ReadonlyMap<string, PageContent> = new Map<string, PageContent>([
  ["home", { title: "apm: check npm packages before you install them", html: [">Search npm packages and check their security score<", ">Popular packages<", ">Recently on this registry<"], views: ["SearchHome"] }],
  ["search", { title: "apm: check npm packages before you install them", html: [">Search npm packages and check their security score<", ">Popular packages<"], views: ["SearchHome"] }],
  ["compare", { title: "npm vs apm: what changes when you switch", html: [">npm and apm, side by side.<", ">An undo button<", ">A score per version<"], views: [] }],
  ["publish", { title: "Publish · apm", html: ["animate-pulse rounded-2xl bg-muted"], views: ["PublishView"] }],
  ["signin", { title: "Sign in · apm", html: [">Sign in to apm<", "Your apm scope is your GitHub login."], views: ["SignInView"] }],
  ["account", { title: "Account · apm", html: ["animate-pulse rounded-2xl bg-muted"], views: ["AccountView"] }],
  ["device", { title: "Log in the CLI · apm", html: ["animate-pulse rounded-2xl bg-muted"], views: ["DeviceView"] }],
  ["docs", { title: "apm docs: setup, CLI, score and AI review", html: [">How apm works<", ">Use it with Bun<", ">Use it with npm or pnpm<"], views: [] }],
]);

/** On every page: the header's home link and nav, the footer, and the header's client parts. */
const SHELL = { html: ['aria-label="apm home"', 'aria-label="Main"', "Your package manager stays the same."], views: ["SiteNav", "AccountButton", "SearchBar"] };

/** A client component the page's RSC payload names, as it appears escaped inside the inline script. */
const viewRef = (name: string): string => `\\"${name}\\"`;

/**
 * What the pages must still show, so no step wins by showing less: each page's content (PAGE_CONTENT); the home page
 * lists every seeded package and the revoked one as revoked; a search answers with npm's hits; the account answer is a
 * 401 marked private.
 */
function expect(v: Visit, doc: Timed, rest: Timed[]): void {
  const fail = (why: string) => {
    throw new Error(`${v.page}: ${why}`);
  };

  if (doc.status !== 200) fail(`document answered ${doc.status}`);
  const content = PAGE_CONTENT.get(v.page);

  if (!content) fail("no content check for this page");

  if (!doc.text.includes(`<title>${content?.title ?? ""}</title>`)) fail(`the title is not "${content?.title}"`);

  for (const text of [...SHELL.html, ...(content?.html ?? [])]) if (!doc.text.includes(text)) fail(`the page lost ${JSON.stringify(text)}`);

  for (const view of [...SHELL.views, ...(content?.views ?? [])]) if (!doc.text.includes(viewRef(view))) fail(`the page no longer renders ${view}`);

  if (!/<script src="\/_next\/static\/chunks\/[^"]+\.js"/.test(doc.text)) fail("the page loads no scripts, so nothing hydrates");

  if (process.env.BENCH_DUMP) void Bun.write(`${process.env.BENCH_DUMP}/${v.page}.html`, doc.text);

  if (v.page === "home" || v.page === "search") {
    // eight entries: the revoke and the seven newest publishes
    for (let i = 1; i < 8; i++) if (!doc.text.includes(`pkg-${i}@1.0.${i}`)) fail(`the recent list lost @bench/pkg-${i}`);

    if (!/revoked/.test(doc.text) || !doc.text.includes("bench revoke")) fail("the recent list lost the revoke");

    if (!doc.text.includes("Popular packages")) fail("the popular packages are gone");
  }

  for (const r of rest) {
    if (r.path.startsWith("/api/search")) {
      const hits = SearchHits.safeParse(JSON.parse(r.text)).data?.hits;

      if (r.status !== 200 || hits?.length !== 20) fail(`search answered ${r.status} with ${hits?.length ?? "no"} hits`);
    }

    if (r.path === "/-/apm/v1/account") {
      const cc = r.headers.get("cache-control") ?? "";
      const vary = (r.headers.get("vary") ?? "").toLowerCase();

      if (r.status !== 401) fail(`account answered ${r.status} to a visitor who is not signed in`);

      if (!cc.includes("private") || !cc.includes("no-store") || !vary.includes("cookie")) fail(`account answer is not private: cache-control "${cc}", vary "${vary}"`);
    }

    if (r.path === "/-/apm/v1/auth/config" && r.status !== 200) fail(`auth config answered ${r.status}`);
  }
}

const SearchHits = z.object({ hits: z.array(z.unknown()) });
const Calls = z.array(z.string());

async function registryCalls(mf: Miniflare): Promise<string[]> {
  const counter = await mf.getWorker("counter");
  const res = await counter.fetch("http://counter/__bench");

  return Calls.parse(await res.json());
}

const log = (s: string) => process.stderr.write(`${s}\n`);

log(`web worker js ${webMb.toFixed(2)} MB, registry ${registryMb.toFixed(2)} MB; pg rtt ${PG_RTT}ms connect ${PG_CONNECT}ms, npm ${NPM_MS}ms`);

let total = 0;
let measured = 0;
let modeled = 0;
let rxTotal = 0;

const median = (xs: number[]): number => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] ?? 0;

for (const v of VISITS) {
  // cold: the median of COLD_RUNS first visits, each on fresh isolates (and an empty browser cache)
  const colds: { visited: Visited; pg: number; calls: string[] }[] = [];
  let mf: Miniflare | null = null;
  let base: URL | null = null;

  for (let i = 0; i < COLD_RUNS; i++) {
    await mf?.dispose();
    mf = new Miniflare(options());
    base = await mf.ready;
    const before = pgTrips;
    const visited = await visit(base, v, null);
    colds.push({ visited, pg: pgTrips - before, calls: await registryCalls(mf) });
  }

  if (!mf || !base) throw new Error("COLD_RUNS must be at least 1");
  const coldMs = median(colds.map((c) => c.visited.ms));
  const cold = colds.find((c) => c.visited.ms === coldMs) ?? colds[0];

  if (!cold) throw new Error("no cold visit");
  const coldModel = webMb * COLD_MS_PER_MB + (cold.calls.length > 0 ? registryMb * COLD_MS_PER_MB : 0) + (cold.visited.rx > 0 ? RX_MS : 0);
  // warm: later visits to the same isolates, by a browser that keeps what the last visit let it keep
  const warm: number[] = [];
  let held = cold.visited.held;
  let calls: string[] = [];
  let trips = 0;
  let rx = 0;
  let asked = 0;

  for (let i = 0; i < WARM_RUNS; i++) {
    const before = pgTrips;
    const w = await visit(base, v, held);
    held = w.held;
    warm.push(w.ms);
    calls = await registryCalls(mf);
    trips = pgTrips - before;
    rx = w.rx;
    asked = w.asked;
  }

  await mf.dispose();
  const warmMs = median(warm);
  const warmModel = rx > 0 ? RX_MS : 0;
  measured += coldMs + warmMs;
  modeled += coldModel + warmModel;
  rxTotal += cold.visited.rx + rx;
  total += coldMs + coldModel + warmMs + warmModel;
  log(
    `${v.page.padEnd(8)} cold ${(coldMs + coldModel).toFixed(0).padStart(5)}ms (measured ${coldMs.toFixed(0)}: ttfb ${cold.visited.doc.ttfb.toFixed(0)} doc ${cold.visited.doc.ms.toFixed(0)}, ${cold.visited.asked} files; registry calls ${cold.calls.length}, pg trips ${cold.pg}, $RX ${cold.visited.rx})` +
      `  warm ${(warmMs + warmModel).toFixed(0).padStart(5)}ms (${asked} files asked again)  registry calls ${calls.length} [${calls.join(", ")}] pg trips ${trips} $RX ${rx}`,
  );
}

log(`measured ${measured.toFixed(0)}ms modeled ${modeled.toFixed(0)}ms resume fallbacks ${rxTotal} npm reads ${npmReads}`);

proxy.stop(true);

await npm.stop(true);

await database.drop();

console.log(total.toFixed(0));

process.exit(0);
