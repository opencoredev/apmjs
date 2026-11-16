// How long the install packument takes, the document npm, pnpm and bun ask for with npm's install Accept header, on a
// local copy of production: the registry Worker bundle in workerd against real npm (registry.npmjs.org, read-only),
// Postgres behind a proxy that adds a query round trip's latency, and npm's answers counted and timed as they pass
// through workerd's outbound fetch.
//
//   bun scripts/perf/install-bench.ts                      # the default packages
//   bun scripts/perf/install-bench.ts @mastra/core next     # these
//
// For each package: `first`, the first request on a fresh registry (nothing cached); `warm`, the same isolate again
// at once; `stale`, after the isolate's upstream TTL (BENCH_UPSTREAM_TTL_MS, 4 s here; production keeps 60 s) has
// passed, the request a repeat install minutes later makes. Each prints its first byte, last byte, the database round
// trips, and what npm was asked (status, bytes, ms). The score (median ms of the stale steps) is printed last.
//
// Freshness is part of it, so no step wins by keeping an answer: after the timed steps the bench marks one version of
// each package confirmed malicious by an apm reviewer, and the very next request must leave that version out; it then
// undoes it and the next must have it again. The bench fails if one does not.
//
// Latencies (ms): PG_RTT per query round trip (production's registry reaches Neon in about 75 from Miami; Smart
// Placement brings that down), PG_CONNECT per new connection.
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Miniflare } from "miniflare";
import { Client } from "pg";
import { z } from "zod";
import { buildWorker } from "../../packages/registry/scripts/build.ts";
import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "../../packages/registry/scripts/compat.ts";
import { freshDatabase } from "../../tests/acceptance/postgres.ts";

const PG_RTT = Number(process.env.PG_RTT ?? 75);
const PG_CONNECT = Number(process.env.PG_CONNECT ?? 10);
const UPSTREAM_TTL_MS = Number(process.env.BENCH_UPSTREAM_TTL_MS ?? 4_000);
const NAMES = process.argv.length > 2 ? process.argv.slice(2) : ["@mastra/core", "@clerk/backend", "prisma", "@prisma/client", "react", "next", "lodash"];
const ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

const log = (line: string): void => void process.stderr.write(`${line}\n`);
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const encodeName = (name: string): string => (name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name));

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
      pgTrips++;

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
type NpmCall = { url: string; status: number; bytes: number; ms: number; conditional: boolean };

let npmCalls: NpmCall[] = [];

/** Passes the Worker's fetch to the real host and counts what came back as it is read. */
async function outbound(req: Request): Promise<Response> {
  const start = performance.now();
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body, redirect: "manual" });
  const call: NpmCall = { url: req.url, status: res.status, bytes: 0, ms: 0, conditional: req.headers.has("if-none-match") };

  npmCalls.push(call);

  if (!res.body) {
    call.ms = performance.now() - start;

    return new Response(null, { status: res.status, headers: res.headers });
  }

  const counted = res.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, c) {
        call.bytes += chunk.length;
        c.enqueue(chunk);
      },
      flush() {
        call.ms = performance.now() - start;
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
const root = mkdtempSync(join(tmpdir(), "apm-install-bench-"));

process.on("exit", () => rmSync(root, { recursive: true, force: true }));

const script = await buildWorker("worker", root);
const port = 20_000 + Math.floor(Math.random() * 20_000);
const base = `http://127.0.0.1:${port}/`;

const mf = new Miniflare({
  modules: [{ type: "ESModule", path: script }],
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
  },
  r2Buckets: ["BLOBS"],
  queueProducers: { ANALYSIS_QUEUE: { queueName: "apm-analysis" } },
  hyperdrives: { HYPERDRIVE: proxied.toString() },
  outboundService: outbound,
  host: "127.0.0.1",
  port,
});

await mf.ready;

const Packument = z.object({ "dist-tags": z.record(z.string(), z.string()), versions: z.record(z.string(), z.object({ dist: z.object({ integrity: z.string().optional(), tarball: z.string() }) })) });

type Step = { ttfb: number; total: number; status: number; bytes: number; trips: number; npm: NpmCall[]; versions: Set<string>; integrity: Map<string, string> };

async function ask(name: string): Promise<Step> {
  npmCalls = [];
  const trips = pgTrips;
  const start = performance.now();
  const res = await fetch(`${base}${encodeName(name)}`, { headers: { accept: ACCEPT } });
  const reader = res.body?.getReader();
  let ttfb = Number.NaN;
  const parts: Uint8Array[] = [];

  for (;;) {
    const got = reader ? await reader.read() : { done: true as const, value: undefined };

    if (got.done) break;

    if (Number.isNaN(ttfb)) ttfb = performance.now() - start;
    parts.push(got.value);
  }

  const total = performance.now() - start;
  const text = Buffer.concat(parts).toString("utf8");
  const versions = new Set<string>();
  const integrity = new Map<string, string>();

  if (res.status === 200) {
    const body = Packument.parse(JSON.parse(text));

    for (const [v, doc] of Object.entries(body.versions)) {
      versions.add(v);
      integrity.set(v, doc.dist.integrity ?? "");
    }
  }

  // background work (shared-cache copies, queued analyses) settles before the next step is timed
  await wait(300);

  return { ttfb: Number.isNaN(ttfb) ? total : ttfb, total, status: res.status, bytes: text.length, trips: pgTrips - trips, npm: npmCalls, versions, integrity };
}

const npmText = (calls: readonly NpmCall[]): string =>
  calls.length === 0 ? "npm: none" : `npm: ${calls.map((c) => `${c.conditional ? "cond " : ""}${c.status} ${(c.bytes / 1e6).toFixed(1)}MB ${Math.round(c.ms)}ms`).join(", ")}`;

const row = (name: string, kind: string, s: Step): string =>
  `${name.padEnd(16)} ${kind.padEnd(6)} ${String(s.status)} ttfb ${String(Math.round(s.ttfb)).padStart(5)} ms  done ${String(Math.round(s.total)).padStart(5)} ms  ${(s.bytes / 1e6).toFixed(2)} MB  pg ${s.trips}  ${npmText(s.npm)}`;

// ---------- timed steps ----------
const sql = new Client({ connectionString: database.url });

await sql.connect();

log(`pg rtt ${PG_RTT} ms, connect ${PG_CONNECT} ms; upstream ttl ${UPSTREAM_TTL_MS} ms; real npm`);

const stale: number[] = [];
let failed = false;

for (const name of NAMES) {
  const first = await ask(name);

  log(row(name, "first", first));

  if (first.status !== 200) {
    failed = true;
    continue;
  }

  log(row(name, "warm", await ask(name)));
  await wait(UPSTREAM_TTL_MS + 500);
  const again = await ask(name);

  log(row(name, "stale", again));
  stale.push(again.total);

  // integrity is npm's
  for (const [v, i] of again.integrity) {
    if (i !== first.integrity.get(v)) {
      log(`  FAIL ${name}@${v}: integrity changed between requests`);
      failed = true;
    }
  }

  // freshness: a version confirmed malicious is gone on the very next request, and back once that is undone
  const latest = [...again.versions].at(-1) ?? "";
  const integrity = again.integrity.get(latest) ?? "";
  const hex = Buffer.from(integrity.replace(/^sha512-/, ""), "base64").toString("hex");

  await sql.query(
    `INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, $2, $3, 'flagged', '{}', 0, 'confirmed')
     ON CONFLICT (package, version, digest) DO UPDATE SET human_state = 'confirmed'`,
    [name, latest, `sha512-${hex}`],
  );
  const blocked = await ask(name);

  if (blocked.versions.has(latest)) {
    log(`  FAIL ${name}@${latest}: confirmed malicious, still served on the next request`);
    failed = true;
  } else log(row(name, "block", blocked));

  await sql.query("UPDATE reviews SET human_state = 'dismissed' WHERE package = $1 AND version = $2", [name, latest]);
  const unblocked = await ask(name);

  if (!unblocked.versions.has(latest)) {
    log(`  FAIL ${name}@${latest}: unblocked, still missing on the next request`);
    failed = true;
  } else log(row(name, "undo", unblocked));
}

await sql.end();

await mf.dispose();

proxy.stop(true);

await database.drop();

const sorted = stale.toSorted((a, b) => a - b);
const median = sorted[Math.floor(sorted.length / 2)] ?? 0;

process.stdout.write(`${failed ? "FAIL" : Math.round(median)}\n`);

process.exitCode = failed ? 1 : 0;
