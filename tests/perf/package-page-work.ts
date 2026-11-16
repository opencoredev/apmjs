// How much of npm's package metadata a package page waits for: the climb check for package pages that show at once.
// Runs the bundled registry Worker in workerd (the acceptance harness) against a local npm that serves a recorded
// packument (react's by default) and counts the packument bytes each of a page's registry requests read itself, from
// npm or from the data center's cache, as its Server-Timing header reports them (timing.ts: the "npm" and "npm-cache"
// counts, made where every packument is fetched). Work the registry does after it answered (a cron sweep, a refresh it
// left running) has no request's timing and is not on the page's path, so it is not counted. What npm served while a
// page read was in flight is printed beside it as a cross-check. No network: the fixture is a file on disk.
//
//   bun tests/perf/package-page-work.ts [--fixture <packument.json>] [--mode count|time]
//
// count (the default) prints the KiB on the critical path as the last line. time prints the median milliseconds of
// the page's requests after the first view instead.
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

const FIXTURE = arg("--fixture") ?? process.env.APM_PERF_FIXTURE ?? join(homedir(), ".cache", "apm-perf-fixtures", "react.json");
const MODE = z.enum(["count", "time"]).parse(arg("--mode") ?? "count");

const MINUTE = 60_000;

const Recorded = z.looseObject({
  name: z.string(),
  "dist-tags": z.record(z.string(), z.string()),
  versions: z.record(z.string(), z.looseObject({ dist: z.looseObject({}) })),
  time: z.record(z.string(), z.string()),
});

const recorded = Recorded.parse(JSON.parse(readFileSync(FIXTURE, "utf8")));
const latest = recorded["dist-tags"].latest;

if (latest === undefined) throw new Error(`${FIXTURE} has no latest tag`);

// a version shown on its own page: the newest stable one before latest
const older = Object.keys(recorded.versions)
  .filter((v) => v !== latest && /^\d+\.\d+\.\d+$/.test(v))
  .toSorted((a, b) => Date.parse(recorded.time[b] ?? "") - Date.parse(recorded.time[a] ?? ""))[0];

if (older === undefined) throw new Error(`${FIXTURE} has no stable version before latest`);

/** The package as two names: one seen before (kept, swept), one asked about for the first time. */
const SEEN = "perf-seen";
const FIRST = "perf-first";

const tgz = (name: string) => pkgTgz({ name, version: "1.0.0", main: "index.js", license: "MIT" }, { "index.js": "module.exports = 1;\n", "README.md": `# ${name}\n\nA stand-in readme.\n` });
const tarballs = new Map([SEEN, FIRST].map((n) => [n, tgz(n)]));

/** The recorded packument as npm would send it for `name`, every tarball pointing at this npm and matching its bytes. */
function packumentFor(name: string, base: string): string {
  const bytes = tarballs.get(name);

  if (!bytes) throw new Error(`no tarball for ${name}`);
  const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  const shasum = createHash("sha1").update(bytes).digest("hex");

  const versions = Object.fromEntries(
    Object.entries(recorded.versions).map(([v, doc]) => [v, { ...doc, name, dist: { ...doc.dist, tarball: `${base}${name}/-/${name}-${v}.tgz`, integrity, shasum, signatures: undefined } }]),
  );

  return JSON.stringify({ ...recorded, _id: name, name, versions });
}

let active = 0;
let counted = 0;
let requests = 0;
let served = 0;

/** Not scored, printed: the page reads' npm HEADs and version documents, by Server-Timing, and their bytes npm sent. */
let heads = 0;
let versionDocs = 0;
let versionDocBytes = 0;
const bodies = new Map<string, string>();

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch(req) {
    const path = decodeURIComponent(new URL(req.url).pathname.slice(1));
    const tarball = /^([^/]+)\/-\/.+\.tgz$/.exec(path);

    if (tarball) {
      const bytes = tarballs.get(tarball[1] ?? "");

      return bytes ? new Response(bytes, { headers: { "content-type": "application/octet-stream" } }) : new Response("Not found", { status: 404 });
    }

    // any JSON npm answers about a package (its packument, a version's document) counts
    const [name, ...rest] = path.split("/");
    const body = name ? bodies.get(name) : undefined;

    if (body === undefined) return Response.json({ error: "Not found" }, { status: 404 });
    const text = rest.length === 0 ? body : versionDoc(name ?? "", body, rest.join("/"));

    if (text === null) return Response.json({ error: "Not found" }, { status: 404 });
    // as registry.npmjs.org does: an ETag on every answer, no body for a HEAD, and a 304 for If-None-Match
    const etag = `"${createHash("sha1").update(text).digest("hex")}"`;
    const headers = { "content-type": "application/json", etag };

    if (req.method === "HEAD") return new Response(null, { headers });

    if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers });

    if (active > 0) served += Buffer.byteLength(text);

    if (active > 0 && rest.length > 0) versionDocBytes += Buffer.byteLength(text);

    return new Response(text, { headers });
  },
});

const DocOf = z.object({ "dist-tags": z.record(z.string(), z.string()), versions: z.record(z.string(), z.unknown()) });

/** Each package's packument parsed once, for its version documents. */
const parsedDocs = new Map<string, z.infer<typeof DocOf>>();

/** npm's answer for /<name>/<version or tag>: that version's document. */
function versionDoc(name: string, body: string, spec: string): string | null {
  const doc = parsedDocs.get(name) ?? DocOf.parse(JSON.parse(body));

  parsedDocs.set(name, doc);
  const v = doc["dist-tags"][spec] ?? spec;
  const one = doc.versions[v];

  return one === undefined ? null : JSON.stringify(one);
}

bodies.set(SEEN, packumentFor(SEEN, npm.url.href));

bodies.set(FIRST, packumentFor(FIRST, npm.url.href));

let clock = Date.parse(recorded.time[latest] ?? "") + 30 * 24 * 60 * MINUTE;

// npm's answers are trusted for TTL_MS of wall time (the isolate and shared caches use the wall clock), production's
// minute scaled down; the registry's own clock (its database rows, the sweep) moves by the test clock instead
const TTL_MS = 1_500;

// the operator's debug token: its answers carry Server-Timing, whose npm and npm-cache counts say how many packuments
// the request read from npm and from the data center's cache (parsed as a whole either way)
const DEBUG_TOKEN = "perf-check-debug-token";

const reg = await startRegistry({
  now: () => clock,
  upstream: npm.url.href,
  upstreamTtlMs: TTL_MS,
  env: { APM_DEBUG_TOKEN_HASH: createHash("sha256").update(DEBUG_TOKEN).digest("hex") },
  // the AI review's routes are on in production, and the page reads one on every view
  review: { serviceTokenHash: createHash("sha256").update("perf-check-service").digest("hex"), admins: [] },
});

/** How many operations a Server-Timing value counts for `metric`. */
const timingCount = (timing: string | null, metric: string): number => Number(new RegExp(`(?:^|, )${metric};dur=[\\d.]+;desc="(\\d+)"`).exec(timing ?? "")?.[1] ?? 0);

/** How many packuments a Server-Timing value says the request read, from npm and from the data center's cache. */
function packumentReads(timing: string | null): number {
  return timingCount(timing, "npm") + timingCount(timing, "npm-cache");
}

/** One registry request on a page's path: counted while it runs, its body read to the end. */
async function onPath(path: string, method: "GET" | "HEAD" = "GET"): Promise<{ status: number; ms: number }> {
  active += 1;
  const start = performance.now();

  try {
    const res = await fetch(`${reg.url}${path}`, { method, headers: { "x-apm-debug": DEBUG_TOKEN } });
    await res.arrayBuffer();
    const name = path.split("/")[4] ?? "";
    const timing = res.headers.get("server-timing");

    if (timing === null) throw new Error(`${method} ${path} sent no Server-Timing`);
    const reads = packumentReads(timing);
    counted += reads * Buffer.byteLength(bodies.get(name) ?? "");
    requests += reads;
    heads += timingCount(timing, "npm-head");
    versionDocs += timingCount(timing, "npm-version");

    return { status: res.status, ms: performance.now() - start };
  } finally {
    active -= 1;
  }
}

type Read = readonly ["GET" | "HEAD", string];

/**
 * A view of the package page, of its older version's page and of one file, with the registry reads the website makes
 * for each (proxy.ts's HEAD first, then the page's reads together, lib/package-reads.ts): the package answer, its log,
 * the AI review, the readme from the tarball (npm's packument carries none for these packages) and an older version's
 * score. Each group's reads run at once, as the page starts them.
 */
async function visit(name: string): Promise<{ kib: number; ms: number }> {
  const before = counted;
  const file = `-/apm/v1/file/${name}/${latest}?path=package.json`;

  const groups: (readonly Read[])[] = [
    [["HEAD", `-/apm/v1/packages/${name}`]],
    [
      ["GET", `-/apm/v1/packages/${name}`],
      ["GET", `-/apm/v1/packages/${name}/events`],
      ["GET", `-/apm/v1/review/${name}/latest`],
    ],
    [["GET", `-/apm/v1/readme/${name}/${latest}`]],
    [
      ["GET", `-/apm/v1/packages/${name}`],
      ["GET", `-/apm/v1/packages/${name}/events`],
      ["GET", `-/apm/v1/review/${name}/${older}`],
      ["GET", `-/apm/v1/score/${name}/${older}`],
    ],
    [["HEAD", file]],
    [["GET", file]],
  ];

  let ms = 0;

  for (const group of groups) {
    const start = performance.now();
    const answers = await Promise.all(group.map(([method, path]) => onPath(path, method)));

    answers.forEach((r, i) => {
      const [method, path] = group[i] ?? ["GET", ""];

      // an upstream package's log answers 404 until apm's reviewers act on it
      if (r.status !== 200 && !(r.status === 404 && path.endsWith("/events"))) throw new Error(`${method} ${path} answered ${r.status}`);
    });
    ms += performance.now() - start;
  }

  return { kib: (counted - before) / 1024, ms };
}

/** Lets work the registry left running after its answers (waitUntil) finish before the clock moves. */
const settle = () => Bun.sleep(300);

try {
  // the seen package was viewed before and both its versions were scored: a popular package
  await fetch(`${reg.url}-/apm/v1/packages/${SEEN}`);
  await reg.analysisJob({ name: SEEN, version: latest });
  await reg.analysisJob({ name: SEEN, version: older });
  await reg.analysisJob({ name: FIRST, version: latest });
  await reg.analysisJob({ name: FIRST, version: older });
  await settle();

  const results: { label: string; kib: number; ms: number }[] = [];
  const at = clock;

  // a later view finds npm's answer past its TTL in both caches, as one minutes later does in production
  const step = async (label: string, name: string, offset: number, warm = false) => {
    if (!warm) await Bun.sleep(TTL_MS + 200);
    clock = at + offset;
    const r = await visit(name);
    results.push({ label, ...r });
    await settle();
  };

  const sweep = async (offset: number) => {
    clock = at + offset;
    await reg.sweep();
    await settle();
  };

  await step("seen, 5 min later", SEEN, 5 * MINUTE);
  await sweep(10 * MINUTE);
  await step("seen, 16 min later", SEEN, 16 * MINUTE);
  await step("seen, 20 s after that", SEEN, 16 * MINUTE + 20_000, true);
  await sweep(20 * MINUTE);
  await sweep(30 * MINUTE);
  await step("seen, 3 h later", SEEN, 180 * MINUTE);
  await step("first view of a scored package", FIRST, 181 * MINUTE);

  for (const r of results) console.log(`${r.label}: ${r.kib.toFixed(0)} KiB of packuments, ${r.ms.toFixed(0)} ms`);
  console.log(`packument reads on the path: ${requests}; npm served ${(served / 1024).toFixed(0)} KiB while a page read was in flight`);
  console.log(`not scored: npm HEADs on the path ${heads}; version documents on the path ${versionDocs} (${(versionDocBytes / 1024).toFixed(1)} KiB served while a page read was in flight)`);

  if (MODE === "count") console.log(Math.round(results.reduce((n, r) => n + r.kib, 0)));
  else console.log(Math.round(results.slice(0, -1).toSorted((a, b) => a.ms - b.ms)[Math.floor((results.length - 1) / 2)]?.ms ?? 0));
} finally {
  await reg.stop();
  await npm.stop(true);
}
