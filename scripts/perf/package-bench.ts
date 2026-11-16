// How soon a package page shows its content, on a local copy of production: the built website Worker
// (apps/web/dist/worker, from packages/infra/build-web.ts) and the registry Worker, both in workerd, the website reaching
// the registry through its REGISTRY service binding, Postgres behind a proxy that adds a query round trip's latency, and
// a fake npm that serves a recorded packument (react's by default, with a long readme added), its version documents and
// tarballs after a delay.
//
//   bun scripts/perf/package-bench.ts     # the per-step table on stderr; the score (median ms to content) last
//   APM_PERF_FIXTURE=~/.cache/apm-perf-fixtures/next.json APM_PERF_LATEST=unscorable bun scripts/perf/package-bench.ts
//
// The npm package is named as the fixture names it. APM_PERF_LATEST=unscorable makes it next as production has it:
// its latest version recorded too large to analyze instead of scored, so no version of it has a score, its packument
// carries no readme (the page then asks for the tarball's), and its latest tarball is served over the 32 MiB cap. A
// fixture with its own readme keeps it; one without gets APM_PERF_README in the scored mode.
//
// Each step loads a page's document and reads it to its last byte, noting its first byte (`ttfb`), when the name's <h1>
// streamed in (`h1`), when
// the part that waits for the package answer did (`content`: the score section) and when the document ended (`done`).
// Pages: an npm package apm scored (its kept summary current, then older than five minutes, so the registry asks npm
// whether it changed) and a package published here. Beside them, the registry's package answer alone, with the
// database and npm time its Server-Timing reports. Cold steps run on fresh isolates (the first visitor in a while),
// warm ones on the same isolates.
//
// Freshness is part of the check, so no step wins by keeping an answer: after the timed steps the bench revokes the
// local package's latest version, drops the npm package's score and dismisses nothing else, and each next view must
// show it. The bench fails if one does not.
//
// Latencies (ms): PG_RTT per query round trip (production's registry in Miami reaches Neon in us-east-2 in about 75:
// a HEAD of a package, two queries, answers in about 210 against a 53 ms ping), PG_CONNECT per new connection, NPM_MS
// per npm read (npm is behind Cloudflare too). BENCH_UPSTREAM_TTL_MS sets the registry's APM_UPSTREAM_TTL_MS.
import { createHash, randomBytes } from "node:crypto";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { Client } from "pg";
import { z } from "zod";
import { buildWorker } from "../../packages/registry/scripts/build.ts";
import * as webBuild from "../../packages/infra/web-build.ts";
import { freshDatabase } from "../../tests/acceptance/postgres.ts";
import { pkgTgz } from "../../tests/acceptance/harness.ts";
import { SCORER } from "../../packages/core/src/score.ts";

const ROOT = join(import.meta.dir, "../..");
const WEB = join(ROOT, "apps/web");
const PG_RTT = Number(process.env.PG_RTT ?? 75);
const PG_CONNECT = Number(process.env.PG_CONNECT ?? 10);
const NPM_MS = Number(process.env.NPM_MS ?? 40);
const WARM_RUNS = Number(process.env.WARM_RUNS ?? 5);
const COLD_RUNS = Number(process.env.COLD_RUNS ?? 3);

// 0: no isolate or shared copy of npm's answers, as on production when a view lands on an isolate that has not read
// the package in the last minute. The default is the registry's own (DEFAULT_TTL_MS in upstream.ts)
const UPSTREAM_TTL_MS = process.env.BENCH_UPSTREAM_TTL_MS ?? "60000";
const FIXTURE = process.env.APM_PERF_FIXTURE ?? join(homedir(), ".cache", "apm-perf-fixtures", "react.json");

const UNSCORABLE = z.enum(["scored", "unscorable"]).parse(process.env.APM_PERF_LATEST ?? "scored") === "unscorable";

// the readme npm sends in the packument when the fixture has none (react's): a long one, so the page renders one as
// zod's or ajv's does
const README = readFileSync(process.env.APM_PERF_README ?? join(homedir(), ".cache", "apm-perf-fixtures", "readme.md"), "utf8");

const MINUTE = 60_000;

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const log = (s: string) => process.stderr.write(`${s}\n`);
const median = (xs: number[]): number => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] ?? 0;

// ---------- fake npm, serving the recorded packument as UPSTREAM ----------
const LOCAL = "@bench/local";

const Recorded = z.looseObject({
  name: z.string(),
  readme: z.string().optional(),
  "dist-tags": z.record(z.string(), z.string()),
  versions: z.record(z.string(), z.looseObject({ dist: z.looseObject({}) })),
});

const recorded = Recorded.parse(JSON.parse(readFileSync(FIXTURE, "utf8")));
const UPSTREAM = recorded.name;
const latest = recorded["dist-tags"].latest;

if (latest === undefined) throw new Error(`${FIXTURE} has no latest tag`);

const tarball = pkgTgz({ name: UPSTREAM, version: latest, main: "index.js", license: "MIT" }, { "index.js": "module.exports = 1;\n", "README.md": `# ${UPSTREAM}\n\nA stand-in readme.\n` });
const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;
const shasum = createHash("sha1").update(tarball).digest("hex");

// next 16.4.6's tarball is 43.7 MB: the registry refuses to download it for a readme once it sees the length
const OVER_CAP = UNSCORABLE ? new Uint8Array(43_700_000) : null;
let npmReads = 0;

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  async fetch(req) {
    npmReads++;
    await wait(NPM_MS);
    const path = decodeURIComponent(new URL(req.url).pathname.slice(1));

    if (path.endsWith(".tgz")) return new Response(OVER_CAP !== null && path.endsWith(`-${latest}.tgz`) ? OVER_CAP : tarball, { headers: { "content-type": "application/octet-stream" } });
    const [name, ...rest] = path.split("/");

    if (name !== UPSTREAM) return Response.json({ error: "Not found" }, { status: 404 });
    const text = rest.length === 0 ? packument : (versionDocs.get(rest.join("/")) ?? null);

    if (text === null) return Response.json({ error: "Not found" }, { status: 404 });
    const etag = `"${createHash("sha1").update(text).digest("hex")}"`;
    const headers = { "content-type": "application/json", etag };

    if (req.method === "HEAD") return new Response(null, { headers });

    if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers });

    return new Response(text, { headers });
  },
});

const versions = Object.fromEntries(
  Object.entries(recorded.versions).map(([v, doc]) => [v, { ...doc, name: UPSTREAM, dist: { ...doc.dist, tarball: `${npm.url.href}${UPSTREAM}/-/${UPSTREAM}-${v}.tgz`, integrity, shasum, signatures: undefined } }]),
);

const readme = UNSCORABLE ? (recorded.readme ?? "") : recorded.readme || README;
const packument = JSON.stringify({ ...recorded, _id: UPSTREAM, name: UPSTREAM, readme, versions });
const versionDocs = new Map(Object.entries(versions).map(([v, doc]) => [v, JSON.stringify(doc)]));

// ---------- Postgres, seeded, behind a latency proxy ----------
const database = await freshDatabase();

async function sql(text: string, params: unknown[] = []): Promise<unknown[]> {
  const c = new Client({ connectionString: database.url });
  await c.connect();

  try {
    return (await c.query(text, params)).rows;
  } finally {
    await c.end();
  }
}

/** A package published here, with ten versions and an owner. */
async function seedLocal(): Promise<void> {
  const at = Date.now() - 3 * 24 * 60 * MINUTE;
  const last = "1.0.9";

  await sql("INSERT INTO packages (name, created_at, modified_at, dist_tags, description, readme) VALUES ($1, $2, $2, $3, 'a package published here', '# local\n\nIts readme.')", [
    LOCAL,
    at,
    JSON.stringify({ latest: last }),
  ]);

  for (let i = 0; i < 10; i++) {
    const version = `1.0.${i}`;
    await sql(
      "INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, status) VALUES ($1, $2, $3, 'x', 'sha512-x', 1, 'sha512/x', $4, 'bench', 'active')",
      [LOCAL, version, JSON.stringify({ name: LOCAL, version }), at + i * MINUTE],
    );
  }

  await sql("INSERT INTO users (name, password_hash, email, created_at) VALUES ('bench', '', '', $1) ON CONFLICT DO NOTHING", [at]).catch(() => []);
  await sql("INSERT INTO owners (package, \"user\") VALUES ($1, 'bench')", [LOCAL]).catch(() => []);
}

await seedLocal();

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

      // BENCH_SQL=1 prints the start of each statement the registry sends (a Parse or a simple Query message)
      if (process.env.BENCH_SQL && (copy[0] === 0x50 || copy[0] === 0x51)) log(`sql: ${new TextDecoder().decode(copy.subarray(5, 200)).replace(/[\0\s]+/g, " ").slice(0, 120)}`);
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
// the test entry: the production Worker plus the analysis-job control the bench scores the npm package with
// both build roots are removed when the bench exits, passed or failed (review of 0c27e9d)
const buildRoots: string[] = [];

process.on("exit", () => {
  for (const root of buildRoots) rmSync(root, { recursive: true, force: true });
});

function buildRoot(prefix: string): string {
  const root = mkdtempSync(`${tmpdir()}/${prefix}`);

  buildRoots.push(root);

  return root;
}

const registryScript = await buildWorker("worker-test", buildRoot("apm-bench-"));
const moduleType = (file: string): "ESModule" | "CompiledWasm" | "Data" => (file.endsWith(".js") ? "ESModule" : file.endsWith(".wasm") ? "CompiledWasm" : "Data");

function listFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);

    return statSync(p).isDirectory() ? listFiles(p) : [p];
  });
}

/**
 * The website build, copied so one require can be pointed elsewhere: the readme renderer (vfile) requires
 * "node:process", which Cloudflare provides and the local workerd does not ("No such module"), so the copy hands it
 * the global `process` that nodejs_compat installs. Nothing else changes.
 */
function webCopy(): string {
  const dir = join(buildRoot("apm-bench-web-"), "dist");
  cpSync(join(WEB, "dist"), dir, { recursive: true });

  for (const file of listFiles(join(dir, "worker")).filter((f) => f.endsWith(".js"))) {
    const text = readFileSync(file, "utf8");
    const patched = text.replace(/\(\)=>[A-Za-z_$][\w$]*\("node:process"\)/g, "()=>globalThis.process");

    if (patched !== text) writeFileSync(file, patched);
  }

  return dir;
}

const workerDir = webCopy();
const webFiles = listFiles(join(workerDir, "worker"));
const entry = join(workerDir, "worker", "worker.js");
const webModules = [entry, ...webFiles.filter((f) => f !== entry)].map((path) => ({ type: moduleType(path), path }));

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
const CONTROL = randomBytes(24).toString("hex");
const DEBUG_TOKEN = "package-bench-debug-token";

// what the website asks the registry, with when each request started and how long its answer took to its last byte,
// read and cleared at /__bench (printed per view with BENCH_SQL=1)
const CALLS = `
let seen = [];
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/__bench") { const out = seen; seen = []; return Response.json(out); }
    const start = Date.now();
    if (env.SLOW_MATCH && req.method === "GET" && url.pathname.includes(env.SLOW_MATCH)) await new Promise((r) => setTimeout(r, Number(env.SLOW_MS)));
    const res = await env.REAL.fetch(req);
    const body = await res.arrayBuffer();
    seen.push({ at: start, ms: Date.now() - start, call: req.method + " " + url.pathname + " " + res.status });
    return new Response(body, res);
  },
};`;

const Calls = z.array(z.object({ at: z.number(), ms: z.number(), call: z.string() }));

/** The registry requests since the last read, each with its start relative to the first. */
async function calls(mf: Miniflare): Promise<string[]> {
  const res = await (await mf.getWorker("calls")).fetch("http://calls/__bench");
  const list = Calls.parse(await res.json());
  const first = list.reduce((n, c) => Math.min(n, c.at), Number.POSITIVE_INFINITY);

  return list.toSorted((a, b) => a.at - b.at).map((c) => `+${c.at - first}ms ${c.ms}ms ${c.call}`);
}

/** Registry GETs whose path holds `match` are held back `ms` (BENCH_SERVE only). */
const slow = { match: "", ms: 0 };

const options = () => ({
  host: "127.0.0.1",
  port: Number(process.env.BENCH_SERVE ?? 0),
  workers: [
    {
      name: "web",
      modules: webModules,
      modulesRoot: workerDir,
      compatibilityDate: "2026-07-30",
      compatibilityFlags: ["nodejs_compat"],
      assets: { directory: join(WEB, ".open-next/assets"), binding: "ASSETS", routerConfig: routerConfig() },
      bindings: { APM_REGISTRY: REGISTRY_URL, APM_CLIENT_IP_HEADER: "cf-connecting-ip" },
      serviceBindings: { REGISTRY: "calls", WORKER_SELF_REFERENCE: "web" },
      ratelimits: { AGENT_RATE_LIMIT: { namespace_id: "4801", simple: { limit: 600, period: 60 } } },
    },
    { name: "calls", modules: true, script: CALLS, compatibilityDate: "2026-07-30", serviceBindings: { REAL: "registry" }, bindings: { SLOW_MATCH: slow.match, SLOW_MS: String(slow.ms) } },
    {
      name: "registry",
      modules: [{ type: "ESModule" as const, path: registryScript }],
      modulesRoot: join(registryScript, ".."),
      compatibilityDate: "2026-07-30",
      compatibilityFlags: ["nodejs_compat"],
      bindings: {
        APM_REGISTRY_URL: REGISTRY_URL,
        APM_PUBLIC_URL: WEB_URL,
        APM_UPSTREAM: npm.url.href,
        APM_NAME_POLICY: "scoped",
        APM_AUTH_SECRET: randomBytes(32).toString("base64url"),
        APM_DEBUG_TOKEN_HASH: createHash("sha256").update(DEBUG_TOKEN).digest("hex"),
        APM_REVIEW_TOKEN_HASH: createHash("sha256").update("package-bench-service").digest("hex"),
        APM_ADMINS: "",
        TEST_CONTROL_SECRET: CONTROL,
        APM_UPSTREAM_TTL_MS: UPSTREAM_TTL_MS,
      },
      r2Buckets: ["BLOBS"],
      hyperdrives: { HYPERDRIVE: proxied.toString() },
    },
  ],
});

// ---------- one view ----------
// a browser's: Next.js holds the whole document back for agents it takes for bots (htmlLimitedBots), so a page with
// no User-Agent or a crawler's streams nothing until its slowest read is in
const BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

type View = { ttfb: number; h1: number; content: number; done: number; text: string; status: number };

/** Loads `path` as a browser does, noting when the h1 and the score section streamed in. */
async function view(base: URL, path: string): Promise<View> {
  if (process.env.BENCH_SQL) log(`--- a view of ${path}`);
  const start = performance.now();
  const res = await fetch(new URL(path, base), { headers: { "cf-connecting-ip": "203.0.113.7", accept: "text/html", "accept-encoding": "identity", "user-agent": BROWSER_UA }, redirect: "manual" });
  const reader = res.body?.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let ttfb = Number.NaN;
  let h1 = Number.NaN;
  let content = Number.NaN;

  for (;;) {
    const chunk = reader ? await reader.read() : { done: true as const, value: undefined };

    if (chunk.done) break;
    const piece = decoder.decode(chunk.value, { stream: true });
    text += piece;
    const t = performance.now() - start;

    if (process.env.BENCH_CHUNKS) log(`  chunk +${t.toFixed(0)}ms ${piece.length} chars: ${piece.replace(/\s+/g, " ").slice(0, 90)}`);

    if (Number.isNaN(ttfb)) ttfb = t;

    if (Number.isNaN(h1) && /<h1[^>]*>[^<]+</.test(text)) h1 = t;

    if (Number.isNaN(content) && text.includes('id="score"')) content = t;
  }

  return { ttfb, h1, content, done: performance.now() - start, text, status: res.status };
}

/** The registry's package answer alone, with the database and npm time its Server-Timing reports. */
async function answer(mf: Miniflare, name: string): Promise<{ ms: number; db: number; npm: number; trips: number }> {
  const registry = await mf.getWorker("registry");
  const before = pgTrips;

  if (process.env.BENCH_SQL) log(`--- the package answer for ${name}`);
  const start = performance.now();
  const res = await registry.fetch(`${REGISTRY_URL}-/apm/v1/packages/${name.replace("/", "%2f")}`, { headers: { "x-apm-debug": DEBUG_TOKEN } });
  await res.arrayBuffer();

  if (res.status !== 200) throw new Error(`the package answer for ${name} answered ${res.status}`);
  const ms = performance.now() - start;
  const timing = res.headers.get("server-timing") ?? "";
  const dur = (metric: string) => Number(new RegExp(`(?:^|, )${metric};dur=([\\d.]+)`).exec(timing)?.[1] ?? 0);

  return { ms, db: dur("db"), npm: dur("npm-version") + dur("npm-head") + dur("npm"), trips: pgTrips - before };
}

async function control(mf: Miniflare, path: string, body: { name: string; version: string }): Promise<void> {
  const registry = await mf.getWorker("registry");
  const res = await registry.fetch(`${REGISTRY_URL}${path}`, { method: "POST", headers: { "content-type": "application/json", "x-apm-test-control": CONTROL }, body: JSON.stringify(body) });

  if (res.status !== 200) throw new Error(`${path} answered ${res.status}: ${await res.text()}`);
}

/** What a loaded page must hold, so no step wins by showing less. */
function expectPage(v: View, name: string, checks: readonly string[]): void {
  if (process.env.BENCH_DUMP) writeFileSync(join(process.env.BENCH_DUMP, `${name.replace("/", "_")}.html`), v.text);

  if (v.status !== 200) throw new Error(`${name}: answered ${v.status}`);

  // a part React could not resume from the server's HTML is rendered again in the browser, after hydration
  if (v.text.includes("$RX(")) throw new Error(`${name}: the server HTML was not resumed ($RX)`);

  for (const c of [`>${name}</h1>`, ">Security score<", ">Versions<", ...checks]) if (!v.text.includes(c)) throw new Error(`${name}: the page lost ${JSON.stringify(c)}`);
}

const upstreamPath = `/package/${UPSTREAM}`;
const localPath = `/package/${LOCAL}`;

const upstreamChecks = UNSCORABLE
  ? [`>${latest}<`, "apm cannot score this version", "Proxied from the public npm registry", "Readme not shown"]
  : [`>${latest}<`, "/100<", "Proxied from the public npm registry", "Show readme"];

const localChecks = [">1.0.9<", "a package published here"];

// ---------- the run ----------

type Row = { label: string; ttfb: number; h1: number; content: number; done: number };

const rows: Row[] = [];
const answers: { label: string; ms: number; db: number; npm: number; trips: number }[] = [];

const ageKept = () => sql("UPDATE kept_packages SET computed_at = computed_at - $1", [6 * MINUTE]);

const TOO_LARGE_DETAIL = "the tarball (43.7 MB) is larger than the 32 MiB apm downloads";

/**
 * Scores the npm package (or records its latest unscorable, as the analysis does for next) and lets its next view
 * keep its summary. BENCH_ALLOW_UNKEPT=1 goes on when none was kept, to measure code from before such a package got one.
 */
async function prepare(): Promise<void> {
  const mf = new Miniflare(options());
  const base = await mf.ready;
  await view(base, upstreamPath);

  if (UNSCORABLE) {
    // with no digest, as production's rows for next were recorded before migration 0022: the page then asks the
    // registry for the readme (it cannot tell the outcome is about today's tarball) and the registry refuses it
    await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ($1, $2, $3, 'too-large', $4, $5)", [UPSTREAM, latest, SCORER, TOO_LARGE_DETAIL, Date.now()]);
  } else await control(mf, "__test/analysis-job", { name: UPSTREAM, version: latest });
  await view(base, upstreamPath);
  await wait(500);
  const kept = await sql("SELECT package FROM kept_packages");

  log(`kept summaries: ${kept.length}`);

  if (kept.length !== 1 && !process.env.BENCH_ALLOW_UNKEPT) throw new Error(`expected one kept summary, found ${kept.length}`);
  await mf.dispose();
}

await prepare();

// BENCH_SERVE=<port>: serve the two Workers there until stopped, for a browser (BENCH_SLOW_MATCH=<path part> and
// BENCH_SLOW_MS hold back the registry GETs whose path holds it, to see a loading state)
if (process.env.BENCH_SERVE) {
  slow.match = process.env.BENCH_SLOW_MATCH ?? "";
  slow.ms = Number(process.env.BENCH_SLOW_MS ?? 0);
  const served = new Miniflare(options());
  log(`serving ${(await served.ready).href}package/${UPSTREAM} and ${LOCAL}`);
  await new Promise(() => {});
}

const summarize = (label: string, views: View[]) => {
  rows.push({ label, ttfb: median(views.map((v) => v.ttfb)), h1: median(views.map((v) => v.h1)), content: median(views.map((v) => v.content)), done: median(views.map((v) => v.done)) });
};

for (const [label, path, name, checks] of [
  ["npm package", upstreamPath, UPSTREAM, upstreamChecks],
  ["local package", localPath, LOCAL, localChecks],
] as const) {
  const colds: View[] = [];

  for (let i = 0; i < COLD_RUNS; i++) {
    const mf = new Miniflare(options());
    const v = await view(await mf.ready, path);
    expectPage(v, name, checks);
    colds.push(v);
    await mf.dispose();
  }

  summarize(`${label}, cold`, colds);
  const mf = new Miniflare(options());
  const base = await mf.ready;
  await view(base, path);
  const warm: View[] = [];

  for (let i = 0; i < WARM_RUNS; i++) {
    await calls(mf);
    const v = await view(base, path);
    expectPage(v, name, checks);
    warm.push(v);

    if (process.env.BENCH_SQL) {
      log(`  h1 ${v.h1.toFixed(0)}ms, done ${v.done.toFixed(0)}ms; the registry calls of that view:`);

      for (const c of await calls(mf)) log(`  ${c}`);
    }
  }

  summarize(`${label}, warm`, warm);

  const timed: Awaited<ReturnType<typeof answer>>[] = [];

  for (let i = 0; i < WARM_RUNS; i++) timed.push(await answer(mf, name));
  const mid = timed.toSorted((a, b) => a.ms - b.ms)[Math.floor(timed.length / 2)];

  if (mid) answers.push({ label: `${label} answer, warm`, ...mid });

  if (name === UPSTREAM) {
    // the kept summary past KEPT_PACKAGE_FRESH_MS: the registry asks npm whether the packument changed
    const aged: View[] = [];

    for (let i = 0; i < WARM_RUNS; i++) {
      await ageKept();
      const v = await view(base, path);
      expectPage(v, name, checks);
      aged.push(v);
      await wait(200);
    }

    summarize(`${label}, warm, summary 6 min old`, aged);
    const old: Awaited<ReturnType<typeof answer>>[] = [];

    for (let i = 0; i < WARM_RUNS; i++) {
      await ageKept();
      old.push(await answer(mf, name));
      await wait(200);
    }

    const m = old.toSorted((a, b) => a.ms - b.ms)[Math.floor(old.length / 2)];

    if (m) answers.push({ label: `${label} answer, summary 6 min old`, ...m });
  }

  // freshness: a write shows on the very next view of these warm isolates
  if (name === LOCAL) {
    await sql("UPDATE versions SET status = 'revoked', status_reason = 'bench revoke', status_at = $2 WHERE package = $1 AND version = '1.0.9'", [LOCAL, Date.now()]);
    const after = await view(base, path);

    if (!after.text.includes("1.0.9 (revoked)")) throw new Error("the revoke did not show on the next view");
    await sql("UPDATE versions SET status = 'active', status_reason = NULL, status_at = NULL WHERE package = $1 AND version = '1.0.9'", [LOCAL]);
  } else if (UNSCORABLE) {
    // the recorded outcome hidden under another scorer's name, then given back: each must show on the next view
    await sql("UPDATE analysis_outcomes SET scorer = scorer || '-hidden' WHERE package = $1 AND outcome IS NOT NULL", [UPSTREAM]);
    const after = await view(base, path);

    if (after.text.includes("apm cannot score this version")) throw new Error("the hidden outcome still showed on the next view");
    await sql("DELETE FROM analysis_outcomes WHERE package = $1 AND scorer = $2", [UPSTREAM, SCORER]);
    await sql("UPDATE analysis_outcomes SET scorer = left(scorer, -7) WHERE package = $1", [UPSTREAM]);
    const back = await view(base, path);

    if (!back.text.includes("apm cannot score this version")) throw new Error("the restored outcome did not show on the next view");
  } else {
    // the stored score hidden under another scorer's name, then given back: each must show on the next view
    await sql("UPDATE upstream_analysis SET scorer = scorer || '-hidden' WHERE package = $1", [UPSTREAM]);
    const after = await view(base, path);

    if (after.text.includes("/100<")) throw new Error("the hidden score still showed on the next view");
    await sql("UPDATE upstream_analysis SET scorer = left(scorer, -7) WHERE package = $1", [UPSTREAM]);
    const back = await view(base, path);

    if (!back.text.includes("/100<")) throw new Error("the restored score did not show on the next view");
  }

  await mf.dispose();
}

const ms = (n: number) => (Number.isNaN(n) ? "    -" : n.toFixed(0).padStart(5));


log(`${UPSTREAM}${UNSCORABLE ? " (latest unscorable)" : ""}: pg rtt ${PG_RTT}ms connect ${PG_CONNECT}ms, npm ${NPM_MS}ms, upstream ttl ${UPSTREAM_TTL_MS}ms; ${COLD_RUNS} cold, ${WARM_RUNS} warm runs`);

log(`${"step".padEnd(42)}  ttfb    h1 content  done`);

for (const r of rows) log(`${r.label.padEnd(42)} ${ms(r.ttfb)} ${ms(r.h1)} ${ms(r.content)} ${ms(r.done)}`);

for (const a of answers) log(`${a.label.padEnd(42)} ${ms(a.ms)}ms (db ${a.db.toFixed(0)}ms in ${a.trips} round trips, npm ${a.npm.toFixed(0)}ms)`);

log(`npm reads ${npmReads}`);

proxy.stop(true);

await npm.stop(true);

await database.drop();

// the score: the median time to content over the warm steps
console.log(median(rows.flatMap((r) => (r.label.includes("warm") ? [r.content] : []))).toFixed(0));

process.exit(0);
