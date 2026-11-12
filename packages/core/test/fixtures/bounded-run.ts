// Runs analyze on packages given as JSON on stdin, in a process of its own, and prints what each came to. The
// boundedness tests (bounded.test.ts) spawn it with a kill timer: an analysis that never returns would block the test
// process itself, since no timeout can interrupt synchronous work, so it runs here where a timer can stop it.
// Input: [{ files: { path: text }, maxAnalysisMs? }]. Output: [{ ms, score, signals: [{ id, points, evidence }] }].
import { z } from "zod";
import { analyze, finalize, type TarEntry } from "../../src/index.ts";

const Case = z.object({ files: z.record(z.string(), z.string()), maxAnalysisMs: z.number().optional() });
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

const cases = z.array(Case).parse(await Bun.stdin.json());

const out = cases.map((c) => {
  const manifest = { name: "bounded-probe", version: "1.0.0", license: "MIT", main: "index.js" };
  const files = [entry("package.json", JSON.stringify(manifest)), ...Object.entries(c.files).map(([p, t]) => entry(p, t))];
  const t = performance.now();
  const a = analyze({ name: "bounded-probe", manifest, files, publisher: "a", previousPublishers: [], maxAnalysisMs: c.maxAnalysisMs });
  const ms = performance.now() - t;

  return { ms, score: finalize(a, STATE).score, signals: a.signals.map((s) => ({ id: s.id, points: s.points, evidence: s.evidence })) };
});

process.stdout.write(JSON.stringify(out));
