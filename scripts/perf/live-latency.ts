// How long a deployed apm answers, from where you run it: the registry reads the package page makes and the pages
// themselves, each asked `--runs` times one after another, with p50 and p90. Read-only GETs, about 10 per endpoint.
//
//   bun scripts/perf/live-latency.ts                                   # production, https://apmjs.dev
//   bun scripts/perf/live-latency.ts --base https://apmjs-web-staging.<subdomain>.workers.dev
//   bun scripts/perf/live-latency.ts --base https://registry.apmjs.dev --only api
//   APM_DEBUG_TOKEN=... bun scripts/perf/live-latency.ts               # adds each answer's Server-Timing phases
//
// Each endpoint is asked once first and that answer is not counted, so the connection is open and its handshake is
// not counted either: from a laptop, a new TLS connection adds 0.1 to 0.7 s that has nothing to do with apm (measured
// 2026-11-19 from Miami against Cloudflare's own /cdn-cgi/trace). `ttfb` is the time to the answer's headers, `total`
// to its last byte (a page streams its slow parts, so `total` is when the page is complete). With APM_DEBUG_TOKEN (the
// stage's ~/.config/apmjs/debug-token-<stage>, whose hash the deploy sets), registry answers carry Server-Timing
// (packages/registry/src/timing.ts): "db" is every database query, "npm*" npm's answers.
//
// Compare two builds by running it before and after, from the same machine, a few minutes apart.
import { z } from "zod";

const Args = z.object({
  base: z.url().default("https://apmjs.dev"),
  runs: z.coerce.number().int().min(1).max(30).default(10),
  only: z.enum(["all", "api", "pages"]).default("all"),
  name: z.string().min(1).default("next"),
});

function parseArgs(argv: readonly string[]): z.infer<typeof Args> {
  const raw: Record<string, string> = {};

  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    const value = argv[i + 1];

    if (key === undefined || value === undefined) throw new Error(`expected --flag value pairs, got ${argv.join(" ")}`);
    raw[key] = value;
  }

  return Args.parse(raw);
}

const args = parseArgs(process.argv.slice(2));
const base = args.base.endsWith("/") ? args.base.slice(0, -1) : args.base;
const token = process.env.APM_DEBUG_TOKEN?.trim() ?? "";
const headers: Record<string, string> = token === "" ? {} : { "x-apm-debug": token };

type Sample = { ttfb: number; total: number; status: number; bytes: number; phases: Map<string, number> };

/** Each metric's milliseconds in a Server-Timing value. */
function phasesOf(value: string | null): Map<string, number> {
  const out = new Map<string, number>();

  for (const part of (value ?? "").split(",")) {
    const m = /^\s*([\w-]+);dur=([\d.]+)/.exec(part);

    if (m?.[1] !== undefined && m[2] !== undefined) out.set(m[1], Number(m[2]));
  }

  return out;
}

async function sample(path: string): Promise<Sample> {
  const start = performance.now();
  const res = await fetch(`${base}${path}`, { headers, redirect: "manual" });
  const ttfb = performance.now() - start;
  const bytes = (await res.arrayBuffer()).byteLength;

  return { ttfb, total: performance.now() - start, status: res.status, bytes, phases: phasesOf(res.headers.get("server-timing")) };
}

const quantile = (xs: readonly number[], q: number): number => {
  const sorted = xs.toSorted((a, b) => a - b);

  return sorted[Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)] ?? Number.NaN;
};

const ms = (n: number): string => (Number.isNaN(n) ? "-" : n.toFixed(0)).padStart(6);

async function measure(path: string): Promise<void> {
  await sample(path);
  const samples: Sample[] = [];

  for (let i = 0; i < args.runs; i++) samples.push(await sample(path));
  const statuses = [...new Set(samples.map((s) => s.status))].join("/");
  const kib = (quantile(samples.map((s) => s.bytes), 0.5) / 1024).toFixed(1);
  const ttfb = samples.map((s) => s.ttfb);
  const total = samples.map((s) => s.total);
  const metrics = [...new Set(samples.flatMap((s) => [...s.phases.keys()]))];
  const phases = metrics.map((m) => `${m} ${quantile(samples.map((s) => s.phases.get(m) ?? 0), 0.5).toFixed(0)}`).join(", ");

  console.log(`${path.padEnd(52)} ${statuses.padEnd(7)} ${kib.padStart(7)} KiB  ttfb p50 ${ms(quantile(ttfb, 0.5))} p90 ${ms(quantile(ttfb, 0.9))}  total p50 ${ms(quantile(total, 0.5))} p90 ${ms(quantile(total, 0.9))}${phases === "" ? "" : `  [${phases}]`}`);
}

const Listing = z.object({ latest: z.string().nullable(), versions: z.array(z.object({ version: z.string() })) });
const listing = Listing.parse(await (await fetch(`${base}/-/apm/v1/packages/${args.name}`, { headers })).json());
const latest = listing.latest ?? "latest";

// an older stable version: its page reads the version's own score and answer
const older = listing.versions.find((v) => v.version !== latest && /^\d+\.\d+\.\d+$/.test(v.version))?.version ?? latest;

const API = [
  `/-/apm/v1/packages/${args.name}/versions/${latest}`,
  `/-/apm/v1/packages/${args.name}`,
  "/-/apm/v1/packages/react",
  `/-/apm/v1/review/${args.name}/${latest}`,
  `/-/apm/v1/packages/${args.name}/events`,
  "/-/apm/v1/health",
  "/-/ping",
];

const PAGES = ["/", `/package/${args.name}`, "/package/react", `/package/${args.name}?v=${older}`];

console.log(`${base}: ${args.runs} runs per endpoint after one uncounted, ${token === "" ? "no debug token" : "with the debug token"}, ${new Date().toISOString()}`);

for (const path of [...(args.only === "pages" ? [] : API), ...(args.only === "api" ? [] : PAGES)]) await measure(path);
