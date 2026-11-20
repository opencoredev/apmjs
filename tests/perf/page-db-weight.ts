// How much the database sends for each registry read a package page makes, for a package like next: many versions
// scored, each analysis carrying a long list of files apm did not read (next@16.4.6's is 2,656 files, about 270 KB of
// its 300 KB). Runs the bundled registry Worker in workerd (the acceptance harness) against a local npm serving a
// recorded packument, through a database link that counts the bytes Postgres sends, and stores `--analyses` analyses
// of that size. Each read is made `--runs` times, one at a time, so every byte the link carries belongs to it.
//
//   bun tests/perf/page-db-weight.ts [--fixture <packument.json>] [--analyses 15] [--runs 10]
//
// Prints one line per read: p50 and p90 of its total time, the database time Server-Timing reports, and the KiB the
// database sent while it ran. That count also holds work the registry runs beside it (the queue analysing a version a
// page view queued), so read the p50; PERF_DEBUG=1 prints every run's. No network: the fixture is a file on disk
// (~/.cache/apm-perf-fixtures/next.json by default).
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";
import { pkgTgz, startRegistry } from "../acceptance/harness";

const args = process.argv.slice(2);

const arg = (name: string): string | undefined => {
  const i = args.indexOf(name);

  return i === -1 ? undefined : args[i + 1];
};

const FIXTURE = arg("--fixture") ?? join(homedir(), ".cache", "apm-perf-fixtures", "next.json");
const ANALYSES = Number(arg("--analyses") ?? 15);
const RUNS = Number(arg("--runs") ?? 10);

/** Files next@16.4.6's analysis lists as not read. */
const SKIPPED_FILES = 2_656;

const Recorded = z.looseObject({
  name: z.string(),
  "dist-tags": z.record(z.string(), z.string()),
  versions: z.record(z.string(), z.looseObject({ dist: z.looseObject({}) })),
  time: z.record(z.string(), z.string()),
});

const recorded = Recorded.parse(JSON.parse(readFileSync(FIXTURE, "utf8")));
const latest = recorded["dist-tags"].latest;

if (latest === undefined) throw new Error(`${FIXTURE} has no latest tag`);

/** The newest versions by publish time, latest first: the ones a busy package has analyses of. */
const newest = Object.keys(recorded.versions)
  .filter((v) => v !== latest)
  .toSorted((a, b) => Date.parse(recorded.time[b] ?? "") - Date.parse(recorded.time[a] ?? ""));

const scored = [latest, ...newest.slice(0, Math.max(0, ANALYSES - 1))];
const older = newest.find((v) => /^\d+\.\d+\.\d+$/.test(v));

if (older === undefined) throw new Error(`${FIXTURE} has no stable version before latest`);

const NAME = "perf-big";
const bytes = pkgTgz({ name: NAME, version: "1.0.0", main: "index.js", license: "MIT" }, { "index.js": "module.exports = 1;\n", "README.md": `# ${NAME}\n` });
const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
const shasum = createHash("sha1").update(bytes).digest("hex");

/** The packument npm serves, written once its tarball URLs can name this server. */
let body = "";

/** Each version's document, as npm serves it under /<name>/<version>. */
let versions: Record<string, z.infer<typeof Recorded>["versions"][string]> = {};

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch(req): Response {
    const path = decodeURIComponent(new URL(req.url).pathname.slice(1));

    if (path.endsWith(".tgz")) return new Response(bytes, { headers: { "content-type": "application/octet-stream" } });
    const [name, ...rest] = path.split("/");

    if (name !== NAME) return Response.json({ error: "Not found" }, { status: 404 });
    const text = rest.length === 0 ? body : versionDoc(rest.join("/"));

    if (text === null) return Response.json({ error: "Not found" }, { status: 404 });
    const etag = `"${createHash("sha1").update(text).digest("hex")}"`;
    const headers = { "content-type": "application/json", etag };

    if (req.method === "HEAD") return new Response(null, { headers });

    if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers });

    return new Response(text, { headers });
  },
});

versions = Object.fromEntries(
  Object.entries(recorded.versions).map(([v, doc]) => [v, { ...doc, name: NAME, dist: { ...doc.dist, tarball: `${npm.url.href}${NAME}/-/${NAME}-${v}.tgz`, integrity, shasum, signatures: undefined } }]),
);

body = JSON.stringify({ ...recorded, _id: NAME, name: NAME, versions });

function versionDoc(spec: string): string | null {
  const v = recorded["dist-tags"][spec] ?? spec;
  const one = versions[v];

  return one === undefined ? null : JSON.stringify(one);
}

const DEBUG_TOKEN = "perf-db-weight-debug-token";
const clock = Date.parse(recorded.time[latest] ?? "") + 30 * 24 * 60 * 60_000;

const reg = await startRegistry({
  namePolicy: "scoped",
  legacyAuth: false,
  now: () => clock,
  upstream: npm.url.href,
  databaseLink: true,
  env: {
    APM_DEBUG_TOKEN_HASH: createHash("sha256").update(DEBUG_TOKEN).digest("hex"),
    APM_REVIEW_TOKEN_HASH: createHash("sha256").update("perf-db-weight-service").digest("hex"),
    APM_ADMINS: "",
  },
});

const link = reg.databaseLink;

if (link === null) throw new Error("the registry started without its database link");

const base = reg.url.endsWith("/") ? reg.url : `${reg.url}/`;

/** One metric's milliseconds in a Server-Timing value, 0 when it is absent. */
const timingMs = (timing: string | null, metric: string): number => Number(new RegExp(`(?:^|, )${metric};dur=([\\d.]+)`).exec(timing ?? "")?.[1] ?? 0);

const quantile = (xs: readonly number[], q: number): number => {
  const sorted = xs.toSorted((a, b) => a - b);

  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] ?? 0;
};

async function measure(label: string, path: string): Promise<void> {
  const total: number[] = [];
  const db: number[] = [];
  const kib: number[] = [];

  for (let i = 0; i < RUNS; i++) {
    const before = link?.received() ?? 0;
    const start = performance.now();
    const res = await fetch(`${base}${path}`, { headers: { "x-apm-debug": DEBUG_TOKEN } });
    await res.arrayBuffer();
    total.push(performance.now() - start);

    if (res.status !== 200) throw new Error(`${path} answered ${res.status}`);
    db.push(timingMs(res.headers.get("server-timing"), "db"));
    // what the request left running after its answer (a seeding claim) is small; let it land before the next one
    await Bun.sleep(150);
    kib.push(((link?.received() ?? 0) - before) / 1024);
  }

  if (process.env.PERF_DEBUG) console.log(`${label}: db KiB per run ${kib.map((k) => k.toFixed(0)).join(" ")}`);
  const f = (xs: number[]) => `p50 ${quantile(xs, 0.5).toFixed(0)} p90 ${quantile(xs, 0.9).toFixed(0)}`;
  console.log(`${label.padEnd(26)} total ms ${f(total)} | db ms ${f(db)} | db KiB ${f(kib)}`);
}

try {
  // the page is viewed, its newest versions scored, and their analyses made as large as next's
  await fetch(`${base}-/apm/v1/packages/${NAME}`);
  await reg.analysisJob({ name: NAME, version: latest });
  const rows = z.array(z.object({ digest: z.string(), scorer: z.string(), analysis: z.looseObject({}) })).parse(await reg.query("SELECT digest, scorer, analysis FROM upstream_analysis WHERE package = $1 AND version = $2", [NAME, latest]));
  const row = rows[0];

  if (row === undefined) throw new Error(`${NAME}@${latest} was not analysed`);
  const skipped = Array.from({ length: SKIPPED_FILES }, (_, i) => ({ path: `dist/compiled/some-vendored-library/build/chunks/module-${String(i).padStart(5, "0")}.production.min.js`, size: 20_000 + i, reason: "over-budget" }));
  const analysis = { ...row.analysis, skipped };

  for (const v of scored) {
    await reg.query(
      "INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (package, version, digest, scorer) DO UPDATE SET analysis = EXCLUDED.analysis",
      [NAME, v, row.digest, row.scorer, JSON.stringify(analysis), clock],
    );
  }

  // viewed again now that it has scores: its summary is kept (kept-package.ts), as next's is in production
  await fetch(`${base}-/apm/v1/packages/${NAME}`);
  await Bun.sleep(500);
  console.log(`${NAME}: ${Object.keys(recorded.versions).length} versions, ${scored.length} analyses of ${(JSON.stringify(analysis).length / 1024).toFixed(0)} KiB, ${RUNS} runs each`);

  // a view queues the package's other recent versions; let the queue's runs of them end before anything is counted
  await fetch(`${base}-/apm/v1/packages/${NAME}`);
  await Bun.sleep(5_000);
  await measure("package answer", `-/apm/v1/packages/${NAME}`);
  await measure("version answer", `-/apm/v1/packages/${NAME}/versions/${older}`);
  await measure("version answer (latest)", `-/apm/v1/packages/${NAME}/versions/${latest}`);
  await measure("review answer", `-/apm/v1/review/${NAME}/latest`);
  await measure("score answer", `-/apm/v1/score/${NAME}/${older}`);
  await measure("readme answer", `-/apm/v1/readme/${NAME}/${latest}`);
  await measure("file answer", `-/apm/v1/file/${NAME}/${latest}?path=package.json`);
} finally {
  await reg.stop();
  await npm.stop(true);
}
