// How long a fresh `npm install` takes through the registry: the Worker bundle in workerd against real npm
// (registry.npmjs.org, read-only), Postgres behind a proxy that adds a round trip's latency to every query, R2 calls
// made later by the same kind of delay (the test entry's TEST_R2_DELAY_MS), and npm's answers counted as they pass
// through workerd's outbound fetch. npm talks to the registry through a recording proxy that reads each answer's
// Server-Timing (with the bench's own debug token), so every install shows where the Worker's time went per request as
// well as what npm saw. Everything runs one step at a time.
//
//   TMPDIR=<a scratch dir> bun scripts/perf/npm-install-bench.ts
//
// Steps: `npm`, npm install of PACKAGES (react react-dom zod express lodash axios, 81 packages) straight from
// registry.npmjs.org with an empty cache and no lockfile, for reference (BENCH_NPM=0 skips it); `cold`, the same
// install through a fresh registry; `warm`, again on the same registry with a new empty npm cache, as a second machine
// in the same data center would make it; `later`, again once the upstream TTL (BENCH_UPSTREAM_TTL_MS, 10 s here, 60 s
// in production) has passed, as an install minutes later makes it, or one served by an isolate that has not seen these
// packages. For each: the wall time; the requests npm made by kind (median, p90 and slowest, from npm's own http log,
// which counts from when npm queued the request, so it includes the wait for one of npm's 15 sockets); the same
// requests as the Worker saw them (time to its answer's headers, and to its last byte), with the median and p90 of
// each Server-Timing phase; the database statements and the requests sent to npm. Then single requests, three times
// each: the install document of express and react and four tarballs (react, lodash, typescript, next's 43.7 MB).
// Numbers move by about half a second between runs with npm's own latency; compare runs.
//
// The recording proxy takes each request as it arrives, then notes when the Worker's headers came and when the body's
// last byte went out (or that it broke, or the client went away). An install still running at BENCH_INSTALL_TIMEOUT_MS
// (180 s) is killed and counted as a stall, and the bench prints the requests it had sent that had no answer or an
// unfinished body, or that none was out (the client stalled on its own). The Worker logs a slow-response line for any
// answer past 5 s and a stall line for any bounded wait that ran out (worker.ts, deadline.ts), in this same output.
// Local stalls seen on 2026-11-18 were all empty 302 bodies sent chunked on the local hops: workerd gzips even an
// empty body when the client accepts gzip (production sends Content-Length: 0), and the recorder streams every answer.
// BENCH_IDENTITY=1 asks workerd for unencoded answers and BENCH_BUFFER=1 sends each answer whole with its length;
// with both, 22 database-mode rounds ran with no stall, against 6 in 55 before (2 of them in 22 with BENCH_IDENTITY alone,
// where the client hung with every answer sent). Both are off by default, so
// timings compare with earlier runs.
//
// Then the client matrix (BENCH_MATRIX=0 skips it): `bun add` and `npm install` with no lockfile, and `bun install
// --frozen-lockfile` and `npm ci` from the lockfile the first made, each with a new, empty cache, BENCH_RUNS times (3)
// after one round that warms the registry, through the registry and (unless BENCH_NPM=0) straight from npm; it prints
// the median of each. BENCH_INSTALL_CHECKS=edge runs the Worker with APM_INSTALL_CHECKS=edge (edge-checks.ts), so the
// same bench measures before (database, the default) and after.
//
// Freshness is checked last, so no step wins by keeping an answer: lodash@4.17.21 is confirmed malicious the way an apm
// reviewer's confirmation writes it (the block list, then the database) and its tarball must answer 410 on the very
// next request (within 4 s, an edge view's age, with BENCH_INSTALL_CHECKS=edge), then the mark is dismissed and taken
// off the list as the cron's sync does, and it must answer 200 with npm's bytes. The bench prints FAIL and exits 1 if
// either does not hold, or if an install through the registry fails.
//
// PG_RTT (ms, default 40: us-east-2 from a US colo through Hyperdrive) is added to each statement, PG_CONNECT
// (default 10) to each new connection, R2_RTT (ms, "30" or a uniform range, default "20-50"; "0" for none) to each R2
// call. BENCH_SQL=1 prints the start of every
// statement sent; BENCH_INSTALLS=0 skips the installs.
import { randomBytes, createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Miniflare } from "miniflare";
import { Client } from "pg";
import { z } from "zod";
import { buildWorker, workerModules } from "../../packages/registry/scripts/build.ts";
import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "../../packages/registry/scripts/compat.ts";
import { freshDatabase } from "../../tests/acceptance/postgres.ts";

const PG_RTT = Number(process.env.PG_RTT ?? 40);
const R2_RTT = process.env.R2_RTT ?? "20-50";
const PG_CONNECT = Number(process.env.PG_CONNECT ?? 10);
const PACKAGES = ["react", "react-dom", "zod", "express", "lodash", "axios"];
const ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";
const TARBALLS = ["react/-/react-19.2.0.tgz", "lodash/-/lodash-4.17.21.tgz", "typescript/-/typescript-5.9.3.tgz", "next/-/next-16.4.6.tgz"];
const DOCUMENTS = ["express", "react"];

// how long one install may take before it is killed and counted as a stall (BENCH_INSTALL_TIMEOUT_MS)
const INSTALL_TIMEOUT_MS = Number(process.env.BENCH_INSTALL_TIMEOUT_MS ?? 180_000);

// production keeps answers from npm for 60 s; shorter here so the `later` install comes after it without a long wait
const UPSTREAM_TTL_MS = Number(process.env.BENCH_UPSTREAM_TTL_MS ?? 10_000);

// what an install read checks before its answer (worker.ts, APM_INSTALL_CHECKS): the database statement, or the edge view
const INSTALL_CHECKS = process.env.BENCH_INSTALL_CHECKS === "edge" ? "edge" : "database";
const RUNS = Number(process.env.BENCH_RUNS ?? 3);

const log = (line: string): void => void process.stdout.write(`${line}\n`);
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// ---------- Postgres behind a latency proxy ----------
const database = await freshDatabase();
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
        socket: { data: (_s, chunk) => void client.write(chunk), close: () => client.end(), error: () => client.end() },
      });

      client.data.server = server;

      for (const q of client.data.queue) server.write(q);
      client.data.queue = [];
    },
    data(client, chunk) {
      const copy = new Uint8Array(chunk);
      const query = isQuery(copy, client.data.chunks++);

      const send = (): void => {
        if (client.data.server) client.data.server.write(copy);
        else client.data.queue.push(copy);
      };

      if (!query) return send();

      // a statement starts with Parse (extended protocol) or Query (simple); Bind, Execute and Sync follow it
      if (copy[0] === 0x50 || copy[0] === 0x51) pgTrips++;

      if (process.env.BENCH_SQL && (copy[0] === 0x50 || copy[0] === 0x51)) log(`  sql: ${new TextDecoder().decode(copy.subarray(5, 200)).replace(/[\0\s]+/g, " ").slice(0, 110)}`);
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

// ---------- npm, through workerd's outbound fetch ----------
let npmCalls = 0;
let npmBytes = 0;

async function outbound(req: Request): Promise<Response> {
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body, redirect: "manual" });

  npmCalls++;

  if (!res.body) return new Response(null, { status: res.status, headers: res.headers });

  const counted = res.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, c) {
        npmBytes += chunk.length;
        c.enqueue(chunk);
      },
    }),
  );

  const headers = new Headers(res.headers);

  // the body was decoded by this fetch: its length and encoding are no longer the ones npm sent
  headers.delete("content-encoding");
  headers.delete("content-length");

  return new Response(counted, { status: res.status, headers });
}

// ---------- the registry ----------
const root = mkdtempSync(join(tmpdir(), "apm-npm-install-bench-"));

process.on("exit", () => rmSync(root, { recursive: true, force: true }));

// the test entry is the shipped Worker plus controls only a caller with TEST_CONTROL_SECRET can use; workerd refuses
// the plain entry's non-handler exports
const script = await buildWorker("worker-test", root);
const port = 20_000 + Math.floor(Math.random() * 20_000);
const worker = `http://127.0.0.1:${port}/`;

// the bench's own debug token: every answer carries its full Server-Timing to the recording proxy
const debugToken = randomBytes(24).toString("base64url");

// ---------- npm's requests, as the Worker answered them ----------
/**
 * One request the recorder took, from the moment it arrived: when the Worker's headers came and when the last byte of
 * the body went out (null while either is still to come), or how it ended without one.
 */
type Served = {
  path: string;
  status: number;
  /** Bench-clock ms (performance.now) when the client's request reached the recorder. */
  arrivedAt: number;
  headersMs: number | null;
  endMs: number | null;
  /** Why the request ended without its whole answer: the Worker's fetch failed, the body broke, or the client went away. */
  ended: "fetch-failed" | "body-error" | "client-cancelled" | null;
  /** How the Worker's answer said its body ends: its Content-Length and Transfer-Encoding as they came to the recorder. */
  framing: string;
  phases: Map<string, number>;
};

let served: Served[] = [];

/** Every request since the bench started, never reset: what a stalled install is checked against. */
const everything: Served[] = [];

/** Server-Timing's metrics, by name: "db;dur=41.2;desc=\"1\", total;dur=90.1" is db 41.2 and total 90.1. */
function phasesOf(header: string | null): Map<string, number> {
  const out = new Map<string, number>();

  for (const part of (header ?? "").split(",")) {
    const m = /^\s*([\w-]+);dur=([\d.]+)/.exec(part);

    if (m?.[1] && m[2]) out.set(m[1], Number(m[2]));
  }

  return out;
}

const recorder = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(req) {
    const url = new URL(req.url);
    const headers = new Headers(req.headers);

    headers.set("x-apm-debug", debugToken);

    // BENCH_IDENTITY=1 asks workerd for unencoded answers: with gzip accepted it sends even an empty 302 gzipped and
    // chunked, and the stalls this bench reproduced were all such bodies left unfinished on the local hops
    if (process.env.BENCH_IDENTITY === "1") headers.set("accept-encoding", "identity");
    const start = performance.now();
    // recorded on arrival, so a request the Worker never answers is still listed
    const entry: Served = { path: url.pathname, status: 0, arrivedAt: start, headersMs: null, endMs: null, ended: null, framing: "", phases: new Map() };

    served.push(entry);
    everything.push(entry);
    let res: Response;

    try {
      res = await fetch(`${worker}${url.pathname.slice(1)}${url.search}`, { method: req.method, headers, decompress: false, redirect: "manual" });
    } catch (e) {
      entry.ended = "fetch-failed";
      throw e;
    }

    entry.headersMs = performance.now() - start;
    entry.status = res.status;
    entry.framing = `content-length ${res.headers.get("content-length") ?? "none"}, transfer-encoding ${res.headers.get("transfer-encoding") ?? "none"}`;
    entry.phases = phasesOf(res.headers.get("server-timing"));

    if (!res.body) {
      entry.endMs = entry.headersMs;

      return new Response(null, { status: res.status, headers: res.headers });
    }

    // BENCH_BUFFER=1: the whole body is read, then sent with its length, so no answer reaches the client chunked
    if (process.env.BENCH_BUFFER === "1") {
      try {
        const bytes = new Uint8Array(await res.arrayBuffer());

        entry.endMs = performance.now() - start;
        const sent = new Headers(res.headers);

        sent.delete("transfer-encoding");
        sent.set("content-length", String(bytes.length));

        return new Response(bytes, { status: res.status, headers: sent });
      } catch (e) {
        entry.ended = "body-error";
        throw e;
      }
    }

    // the body passed on chunk by chunk, so its end, a break, or the client going away is seen when it happens
    const reader = res.body.getReader();

    const body = new ReadableStream<Uint8Array>({
      async pull(c) {
        try {
          const { done, value } = await reader.read();

          if (done) {
            entry.endMs = performance.now() - start;
            c.close();
          } else c.enqueue(value);
        } catch (e) {
          entry.ended = "body-error";
          c.error(e);
        }
      },
      cancel(reason) {
        if (entry.endMs === null) entry.ended = "client-cancelled";

        return reader.cancel(reason);
      },
    });

    return new Response(body, { status: res.status, headers: res.headers });
  },
});

const base = `http://127.0.0.1:${recorder.port}/`;

const control = randomBytes(32).toString("base64url");
const controlled = (path: string, init: RequestInit = {}): Promise<Response> => fetch(`${worker}${path}`, { ...init, headers: { "x-apm-test-control": control } });

const mf = new Miniflare({
  modules: workerModules(script),
  modulesRoot: dirname(script),
  compatibilityDate: COMPATIBILITY_DATE,
  compatibilityFlags: [...COMPATIBILITY_FLAGS],
  bindings: {
    APM_REGISTRY_URL: base,
    APM_PUBLIC_URL: base,
    APM_UPSTREAM: "https://registry.npmjs.org/",
    APM_LEGACY_AUTH: "0",
    APM_NAME_POLICY: "scoped",
    APM_AUTH_SECRET: randomBytes(32).toString("base64url"),
    APM_UPSTREAM_TTL_MS: String(UPSTREAM_TTL_MS),
    APM_DEBUG_TOKEN_HASH: createHash("sha256").update(debugToken).digest("hex"),
    TEST_CONTROL_SECRET: control,
    TEST_R2_DELAY_MS: R2_RTT,
    APM_INSTALL_CHECKS: INSTALL_CHECKS,
  },
  r2Buckets: ["BLOBS"],
  queueProducers: { ANALYSIS_QUEUE: { queueName: "apm-analysis" } },
  hyperdrives: { HYPERDRIVE: proxied.toString() },
  outboundService: outbound,
  host: "127.0.0.1",
  port,
});

await mf.ready;

// the cron's first sync, so the block list exists as it does in production: edge views take the database path until then
if (!(await controlled("__test/sweep", { method: "POST" })).ok) throw new Error("the sweep failed");

// ---------- npm install ----------
type Fetch = { kind: "document" | "tarball"; status: number; ms: number };

const quantile = (xs: readonly number[], q: number): number => {
  const sorted = xs.toSorted((a, b) => a - b);

  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] ?? 0;
};

const summary = (fetches: readonly Fetch[], kind: Fetch["kind"]): string => {
  const ms = fetches.flatMap((f) => (f.kind === kind ? [f.ms] : []));

  return `${kind}s ${ms.length}: median ${quantile(ms, 0.5)} p90 ${quantile(ms, 0.9)} max ${quantile(ms, 1)} ms`;
};

const spread = (ms: readonly number[]): string => `${Math.round(quantile(ms, 0.5))}/${Math.round(quantile(ms, 0.9))}`;

/** What the Worker did for one kind of request: time to headers and to the last byte, then each phase, as median/p90 ms. */
function servedSummary(rows: readonly Served[], kind: Fetch["kind"]): string {
  const mine = rows.filter((r) => (kind === "tarball") === r.path.endsWith(".tgz"));
  const names = [...new Set(mine.flatMap((r) => [...r.phases.keys()]))].filter((n) => n !== "total");
  const phases = names.map((n) => `${n} ${spread(mine.flatMap((r) => (r.phases.has(n) ? [r.phases.get(n) ?? 0] : [])))}`);

  return `  worker ${kind}s ${mine.length}: headers ${spread(mine.flatMap((r) => (r.headersMs === null ? [] : [r.headersMs])))} end ${spread(mine.flatMap((r) => (r.endMs === null ? [] : [r.endMs])))} | ${phases.join(", ")} (median/p90 ms)`;
}

/**
 * After a client was killed at INSTALL_TIMEOUT_MS: every request it sent since `since` (bench clock) that had no
 * answer's headers, an unfinished body or a broken one, with how long it had been out. None listed means the client
 * stalled without a request out to the registry (the shape production saw: npm's request never reached the Worker).
 */
function reportStall(label: string, since: number): void {
  const now = performance.now();
  const mine = everything.filter((r) => r.arrivedAt >= since);
  const open = mine.filter((r) => r.headersMs === null || r.endMs === null || r.ended !== null);
  const last = mine.reduce((at, r) => Math.max(at, r.arrivedAt), since);

  log(`  STALL ${label}: killed after ${INSTALL_TIMEOUT_MS} ms; ${mine.length} requests reached the registry, ${open.length} without a whole answer; last request arrived ${Math.round(now - last)} ms before the kill`);

  for (const r of open) {
    const state = r.headersMs === null ? "no headers" : r.endMs === null ? `headers after ${Math.round(r.headersMs)} ms, body unfinished` : `ended ${r.ended ?? "?"}`;

    log(`    ${r.path} ${r.status || "-"} ${state}${r.ended !== null && r.headersMs === null ? ` (${r.ended})` : ""}, out ${Math.round(now - r.arrivedAt)} ms${r.framing === "" ? "" : ` (${r.framing})`}`);
  }

  if (open.length === 0) log("    no request was out: the client stalled before sending one (or between them)");
}

/** Runs `child` until it exits or INSTALL_TIMEOUT_MS passes, then kills it and reports what was still out. */
/** A running install's stall timer: `stop` ends it and says whether it fired. */
type StallTimer = { stop: () => boolean };

function stallTimer(child: { kill: () => void }, label: string): StallTimer {
  const since = performance.now();
  let fired = false;

  const timer = setTimeout(() => {
    fired = true;
    reportStall(label, since);
    child.kill();
  }, INSTALL_TIMEOUT_MS);

  return {
    stop: () => {
      clearTimeout(timer);

      return fired;
    },
  };
}

/**
 * npm install of PACKAGES in a new project with a new, empty cache. The child runs without blocking this process,
 * which serves workerd's outbound fetches and the database proxy.
 */
async function install(label: string, registry = base): Promise<boolean> {
  const dir = mkdtempSync(join(root, `${label}-`));

  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bench", version: "1.0.0", private: true }));
  const trips = pgTrips;
  const calls = npmCalls;

  served = [];
  const start = performance.now();

  const child = Bun.spawn(
    ["npm", "install", `--registry=${registry}`, `--cache=${join(dir, ".npm-cache")}`, "--no-audit", "--no-fund", "--ignore-scripts", "--loglevel=http", ...PACKAGES],
    { cwd: dir, stdout: "ignore", stderr: "pipe", env: { ...process.env, npm_config_userconfig: join(dir, ".npmrc-none") } },
  );

  const timer = stallTimer(child, `npm install (${label})`);
  const stderr = await new Response(child.stderr).text();
  const code = await child.exited;

  if (timer.stop()) stalls++;
  const seconds = (performance.now() - start) / 1000;
  const fetches: Fetch[] = [];

  // npm http fetch GET 200 http://127.0.0.1:1234/react 87ms (cache miss)
  for (const line of stderr.split("\n")) {
    const m = /http fetch GET (\d+) (\S+) (\d+)ms/.exec(line);

    if (m) fetches.push({ kind: m[2]?.endsWith(".tgz") ? "tarball" : "document", status: Number(m[1]), ms: Number(m[3]) });
  }

  const ok = code === 0 && fetches.length > 0 && fetches.every((f) => f.status === 200);

  log(`${label.padEnd(5)} ${ok ? "ok" : "FAILED"} ${seconds.toFixed(2)} s  ${summary(fetches, "document")}; ${summary(fetches, "tarball")}; pg statements ${pgTrips - trips}, npm requests ${npmCalls - calls}`);

  if (registry === base) {
    log(servedSummary(served, "document"));
    log(servedSummary(served, "tarball"));
    const redirected = served.filter((r) => r.status === 302).length;
    // every package-lock entry must name this registry: one that names npm would send later installs around apm
    const lock = z.object({ packages: z.record(z.string(), z.object({ resolved: z.string().optional() })) }).safeParse(JSON.parse(readFileSync(join(dir, "package-lock.json"), "utf8")));
    const resolved = lock.success ? Object.values(lock.data.packages).flatMap((p) => (p.resolved === undefined ? [] : [p.resolved])) : [];
    const elsewhere = resolved.filter((r) => !r.startsWith(base));

    log(`  redirects ${redirected}; package-lock resolved ${resolved.length}, naming another registry ${elsewhere.length}${elsewhere[0] ? ` (${elsewhere[0]})` : ""}`);

    if (!lock.success || elsewhere.length > 0) lockfileOk = false;
  }

  if (!ok) log(stderr.split("\n").filter((l) => !l.includes("http fetch")).slice(-8).join("\n"));

  return ok;
}

/**
 * Another client's install of PACKAGES through the registry, with a new, empty store: it must succeed, and its lockfile
 * must not name npm's registry (a lockfile that did would send later installs around apm).
 */
async function otherClient(label: "pnpm" | "bun"): Promise<boolean> {
  const dir = mkdtempSync(join(root, `${label}-`));

  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bench", version: "1.0.0", private: true }));
  served = [];
  const start = performance.now();

  const cmd =
    label === "pnpm"
      ? ["pnpm", "add", `--registry=${base}`, `--store-dir=${join(dir, ".store")}`, `--cache-dir=${join(dir, ".cache")}`, "--ignore-scripts", ...PACKAGES]
      : ["bun", "add", `--registry=${base}`, `--cache-dir=${join(dir, ".cache")}`, "--ignore-scripts", ...PACKAGES];

  const child = Bun.spawn(cmd, { cwd: dir, stdout: "pipe", stderr: "pipe", env: { ...process.env, npm_config_userconfig: join(dir, ".npmrc-none"), BUN_INSTALL_CACHE_DIR: join(dir, ".cache") } });
  const timer = stallTimer(child, label);
  const [out, err] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()]);
  const code = await child.exited;

  if (timer.stop()) stalls++;
  const lockfile = label === "pnpm" ? "pnpm-lock.yaml" : "bun.lock";
  let lock = "";

  try {
    lock = readFileSync(join(dir, lockfile), "utf8");
  } catch {
    lock = "";
  }

  const namesNpm = lock.includes("registry.npmjs.org");
  const installed = PACKAGES.every((p) => existsSync(join(dir, "node_modules", p, "package.json")));
  const ok = code === 0 && lock !== "" && !namesNpm && installed;

  log(`${label.padEnd(5)} ${ok ? "ok" : "FAILED"} ${((performance.now() - start) / 1000).toFixed(2)} s  redirects ${served.filter((r) => r.status === 302).length}, ${lockfile} names npm ${String(namesNpm)}, packages installed ${String(installed)}`);
  log(servedSummary(served, "tarball"));

  if (!ok) log(`${out}\n${err}`.split("\n").slice(-10).join("\n"));

  return ok;
}

// ---------- single requests ----------
async function timed(path: string, headers: Record<string, string> = {}): Promise<{ status: number; ms: number; bytes: number; sha512: string }> {
  const start = performance.now();
  const res = await fetch(`${base}${path}`, { headers });
  const body = new Uint8Array(await res.arrayBuffer());

  return { status: res.status, ms: Math.round(performance.now() - start), bytes: body.length, sha512: createHash("sha512").update(body).digest("base64") };
}

// ---------- the client matrix ----------
type Client = "bun add" | "bun install --frozen-lockfile" | "npm install" | "npm ci";

const CLIENTS: readonly Client[] = ["bun add", "bun install --frozen-lockfile", "npm install", "npm ci"];

/** The command for `client` in `dir` against `registry`, with the cache in `dir`. */
function commandOf(client: Client, registry: string, dir: string): string[] {
  const cache = join(dir, ".cache");

  switch (client) {
    case "bun add":
      return ["bun", "add", `--registry=${registry}`, `--cache-dir=${cache}`, "--ignore-scripts", ...PACKAGES];
    case "bun install --frozen-lockfile":
      return ["bun", "install", "--frozen-lockfile", `--registry=${registry}`, `--cache-dir=${cache}`, "--ignore-scripts"];
    case "npm install":
      return ["npm", "install", `--registry=${registry}`, `--cache=${cache}`, "--no-audit", "--no-fund", "--ignore-scripts", ...PACKAGES];
    case "npm ci":
      return ["npm", "ci", `--registry=${registry}`, `--cache=${cache}`, "--no-audit", "--no-fund", "--ignore-scripts"];
    default: {
      const _exhaustive: never = client;

      return _exhaustive;
    }
  }
}

/** The lockfile each client writes or reads. */
const lockfileOf = (client: Client): string => (client.startsWith("bun") ? "bun.lock" : "package-lock.json");

/** A project as an install with no lockfile left it: its package.json and its lockfile. */
type Project = { manifest: string; lock: string };

/**
 * One run of `client` in a new directory with a new, empty cache; a frozen install starts from `from` (what the
 * matching install with no lockfile left). Seconds, and the project it left, or null when it failed.
 */
async function clientRun(client: Client, registry: string, from: Project | null): Promise<{ seconds: number; project: Project } | null> {
  const dir = mkdtempSync(join(root, "matrix-"));

  writeFileSync(join(dir, "package.json"), from?.manifest ?? JSON.stringify({ name: "bench", version: "1.0.0", private: true }));

  if (from !== null) writeFileSync(join(dir, lockfileOf(client)), from.lock);
  const start = performance.now();

  const child = Bun.spawn(commandOf(client, registry, dir), {
    cwd: dir,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, npm_config_userconfig: join(dir, ".npmrc-none"), BUN_INSTALL_CACHE_DIR: join(dir, ".cache") },
  });

  const timer = stallTimer(child, `${client} via ${registry === base ? "apm" : registry}`);
  const [out, err] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()]);
  const code = await child.exited;

  if (timer.stop()) stalls++;
  const seconds = (performance.now() - start) / 1000;
  const installed = PACKAGES.every((p) => existsSync(join(dir, "node_modules", p, "package.json")));

  if (code !== 0 || !installed || !existsSync(join(dir, lockfileOf(client)))) {
    log(`  ${client} via ${registry} FAILED (exit ${code})\n${`${out}\n${err}`.split("\n").slice(-8).join("\n")}`);
    rmSync(dir, { recursive: true, force: true });

    return null;
  }

  const project = { manifest: readFileSync(join(dir, "package.json"), "utf8"), lock: readFileSync(join(dir, lockfileOf(client)), "utf8") };

  rmSync(dir, { recursive: true, force: true });

  return { seconds, project };
}

/**
 * The matrix for one registry: a round that warms it, then RUNS rounds; each round runs the two installs with no
 * lockfile, then the frozen installs from the lockfiles they wrote. The median seconds of each client.
 */
async function matrix(registry: string): Promise<Map<Client, number[]> | null> {
  const times = new Map<Client, number[]>(CLIENTS.map((c) => [c, []]));
  let failedRounds = 0;

  for (let round = 0; round <= RUNS; round++) {
    const bun = await clientRun("bun add", registry, null);
    const bunFrozen = bun === null ? null : await clientRun("bun install --frozen-lockfile", registry, bun.project);
    const npmPlain = await clientRun("npm install", registry, null);
    const npmCi = npmPlain === null ? null : await clientRun("npm ci", registry, npmPlain.project);

    // a failed round (a stall included) is counted and the rest still run, so one run of the bench sees every stall
    if (bun === null || bunFrozen === null || npmPlain === null || npmCi === null) {
      failedRounds++;
      log(`  round ${round} via ${registry === base ? "apm" : registry} failed`);
      continue;
    }

    // a lockfile that names npm's registry would send later installs around apm
    if (registry === base && (bun.project.lock.includes("registry.npmjs.org") || npmPlain.project.lock.includes("registry.npmjs.org"))) lockfileOk = false;

    if (round === 0) continue;
    times.get("bun add")?.push(bun.seconds);
    times.get("bun install --frozen-lockfile")?.push(bunFrozen.seconds);
    times.get("npm install")?.push(npmPlain.seconds);
    times.get("npm ci")?.push(npmCi.seconds);
  }

  return failedRounds === 0 ? times : null;
}

const median = (xs: readonly number[]): number => {
  const sorted = xs.toSorted((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);

  return sorted.length % 2 === 1 ? (sorted[mid] ?? 0) : ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2;
};

log(`pg rtt ${PG_RTT} ms, connect ${PG_CONNECT} ms, r2 ${R2_RTT} ms, install checks ${INSTALL_CHECKS}; real npm; ${new Date().toISOString()}`);

let failed = false;
let lockfileOk = true;

/** Installs killed at INSTALL_TIMEOUT_MS. */
let stalls = 0;

// BENCH_INSTALLS=0: the single requests and the freshness check only
if (process.env.BENCH_INSTALLS !== "0") {
  if (process.env.BENCH_NPM !== "0") await install("npm", "https://registry.npmjs.org/");
  failed = !(await install("cold"));
  failed = !(await install("warm")) || failed;
  // past the upstream TTL: the data center's copies are there, and npm is asked whether they are still current
  await wait(UPSTREAM_TTL_MS + 1_000);
  failed = !(await install("later")) || failed;

  // BENCH_CLIENTS=0 skips them
  if (process.env.BENCH_CLIENTS !== "0") {
    failed = !(await otherClient("pnpm")) || failed;
    failed = !(await otherClient("bun")) || failed;
  }
}

// BENCH_MATRIX=0 skips the client matrix
if (process.env.BENCH_MATRIX !== "0") {
  const apm = await matrix(base);
  const direct = process.env.BENCH_NPM === "0" ? null : await matrix("https://registry.npmjs.org/");

  if (apm === null) failed = true;
  log(`matrix   median of ${RUNS} runs after a warming round, seconds (install checks ${INSTALL_CHECKS})`);

  for (const client of CLIENTS) {
    const through = apm?.get(client) ?? [];
    const npmOnly = direct?.get(client) ?? [];

    log(`  ${client.padEnd(30)} apm ${median(through).toFixed(2)} [${through.map((t) => t.toFixed(2)).join(" ")}]${direct === null ? "" : `  npm ${median(npmOnly).toFixed(2)} [${npmOnly.map((t) => t.toFixed(2)).join(" ")}]`}`);
  }
}

for (const name of DOCUMENTS) {
  const tries: string[] = [];

  for (let i = 0; i < 3; i++) {
    const t = await timed(name, { accept: ACCEPT });

    tries.push(`${t.status}:${t.ms}`);
    await wait(300);
  }

  log(`document ${name.padEnd(30)} ${tries.join(" ")} ms`);
}

for (const path of TARBALLS) {
  const tries: string[] = [];
  let size = 0;

  for (let i = 0; i < 3; i++) {
    const t = await timed(path);

    tries.push(`${t.status}:${t.ms}`);
    size = t.bytes;
    await wait(300);
  }

  log(`tarball  ${path.split("/").at(-1)?.padEnd(30)} ${tries.join(" ")} ms  ${(size / 1e6).toFixed(1)} MB`);
}

// ---------- freshness: a block shows on the very next request, and so does its undo ----------
const sql = new Client({ connectionString: database.url });

await sql.connect();

const lodash = "lodash/-/lodash-4.17.21.tgz";
const before = await timed(lodash);
const digest = `sha512-${Buffer.from(before.sha512, "base64").toString("hex")}`;
const BlockList = z.object({ format: z.literal(1), syncedAt: z.number().nullable(), local: z.array(z.unknown()), confirmed: z.array(z.object({ name: z.string(), version: z.string() }).loose()) });
const LIST_KEY = "__test/blobs/state%2Finstall-blocklist.json";

/** Rewrites the block list's confirmed entries for lodash@4.17.21, as a confirmation (review.ts) or a sync after a dismissal does. */
async function listLodash(on: boolean): Promise<void> {
  const list = BlockList.parse(await (await controlled(LIST_KEY)).json());
  const others = list.confirmed.filter((e) => !(e.name === "lodash" && e.version === "4.17.21"));
  const confirmed = on ? [...others, { name: "lodash", version: "4.17.21", digest, addedAt: Date.now() }] : others;

  await controlled(LIST_KEY, { method: "PUT", body: JSON.stringify({ ...list, confirmed }) });
}

/** The first answer to `path` with `status`, asked every 100 ms for up to 10 s: its status and how long it took to come. */
async function until(path: string, status: number): Promise<{ status: number; ms: number; sha512: string }> {
  const start = performance.now();
  let t = await timed(path);

  while (t.status !== status && performance.now() - start < 10_000) {
    await wait(100);
    t = await timed(path);
  }

  return { status: t.status, ms: Math.round(performance.now() - start), sha512: t.sha512 };
}

// the block list first, then the database, as review.ts confirms
await listLodash(true);

await sql.query(
  `INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ('lodash', '4.17.21', $1, 'flagged', '{}', 0, 'confirmed')
   ON CONFLICT (package, version, digest) DO UPDATE SET human_state = 'confirmed'`,
  [digest],
);

const blocked = await until(lodash, 410);

await sql.query("UPDATE reviews SET human_state = 'dismissed' WHERE package = 'lodash' AND version = '4.17.21'");

// what the cron's sync does once the grace period has passed
await listLodash(false);

const back = await until(lodash, 200);

// the database path refuses on the very next request; an edge view within its age (edge-checks.ts, 4 s)
const allowedMs = INSTALL_CHECKS === "database" ? 0 : 4_000;

if (blocked.status !== 410 || blocked.ms > allowedMs + 500) failed = true;

if (back.status !== 200 || back.sha512 !== before.sha512) failed = true;

log(`fresh    lodash@4.17.21 confirmed: ${blocked.status} after ${blocked.ms} ms (want 410 within ${allowedMs} ms); dismissed: ${back.status} after ${back.ms} ms, same bytes ${String(back.sha512 === before.sha512)}`);

await sql.end();

await mf.dispose();

await recorder.stop(true);

proxy.stop(true);

await database.drop();

if (!lockfileOk) {
  log("FAIL package-lock.json names a registry other than this one");
  failed = true;
}

log(`stalls ${stalls} (installs killed at ${INSTALL_TIMEOUT_MS} ms)`);

log(failed ? "FAIL" : "ok");

process.exitCode = failed ? 1 : 0;
