// Runs adversarial generators (adversarial.ts) in a process of its own and prints what each came to. The termination
// suite spawns it with a kill timer: synchronous work cannot be interrupted from inside the process doing it.
// Input on stdin: [{ name, n, maxWork, compose? }], where `compose` names more generators whose files are merged in.
// Output: [{ name, n, cpuMs, wallMs, used, limit, exhausted, incomplete, score, refused, error }].
import { z } from "zod";
import { analyze, ArchiveError, finalize, Meter, MeterExhausted, readTarball, unfinishedAnalysis, type Analysis } from "../../src/index.ts";
import { GENERATORS, PROBE_MANIFEST, tarballOf, type Built } from "./adversarial.ts";

const Job = z.object({ name: z.string(), n: z.number(), maxWork: z.number(), compose: z.array(z.object({ name: z.string(), n: z.number() })).optional() });
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function built(name: string, n: number): Built {
  const g = GENERATORS.find((x) => x.name === name);

  if (!g) throw new Error(`no generator ${name}`);

  return g.make(n);
}

function cpuMs(): number {
  const u = process.cpuUsage();

  return (u.user + u.system) / 1000;
}

const jobs = z.array(Job).parse(await Bun.stdin.json());

// a first analysis loads the modules and warms the engine, so the times below are of the work, not of the start
analyze({ name: PROBE_MANIFEST.name, manifest: PROBE_MANIFEST, files: readTarball(tarballOf({ "index.js": "require('x')(process.env.A)" })), publisher: "a", previousPublishers: [] });

const out = [];

for (const job of jobs) {
  const parts = [built(job.name, job.n), ...(job.compose ?? []).map((c) => built(c.name, c.n))];
  const merged: Record<string, string> = {};
  let bytes: Uint8Array | null = null;

  parts.forEach((p, i) => {
    if (p.kind === "tarball") bytes ??= p.bytes;
    else for (const [path, text] of Object.entries(p.files)) merged[i === 0 ? path : `c${i}/${path}`] = text;
  });

  // a hand-built archive is read as it is; files, with any composed ones, are packed together
  const tgz = bytes ?? tarballOf(merged);
  const meter = new Meter(job.maxWork);
  const t0 = performance.now();
  const c0 = cpuMs();
  let analysis: Analysis | null = null;
  let refused: string | null = null;
  let error: string | null = null;

  try {
    const files = readTarball(tgz, 48 * 1024 * 1024, meter);

    analysis = analyze({ name: PROBE_MANIFEST.name, manifest: PROBE_MANIFEST, files, publisher: "a", previousPublishers: [], meter });
  } catch (e) {
    if (e instanceof MeterExhausted) analysis = unfinishedAnalysis({ name: PROBE_MANIFEST.name, manifest: PROBE_MANIFEST, files: [], phase: e.phase, limit: e.limit });
    else if (e instanceof ArchiveError) refused = `${e.kind}: ${e.message}`;
    else error = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  }

  const cpu = cpuMs() - c0;
  const incomplete = analysis?.signals.find((s) => s.id === "incomplete")?.evidence ?? null;

  out.push({
    name: job.name,
    n: job.n,
    cpuMs: cpu,
    wallMs: performance.now() - t0,
    used: meter.used,
    limit: meter.limit,
    exhausted: meter.exhausted,
    byPhase: meter.byPhase,
    incomplete,
    score: analysis ? finalize(analysis, STATE).score : null,
    refused,
    error,
  });
}

process.stdout.write(JSON.stringify(out));
