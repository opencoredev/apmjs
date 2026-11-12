// Scores the AI review evaluation's 40 malicious samples, the 70-package corpus and any extra tarballs with one copy
// of packages/core, and writes every score and signal to a JSON file. Bytes only: nothing is installed or run.
// Usage, from the repo root:
//   bun tools/score-eval/eval.ts <core src dir> <out.json> [extra .tgz ...]
// Compare two scorers by running it on a checkout of each (`git worktree add /tmp/apm-v9 origin/main`) and then
//   bun tools/score-eval/compare.ts <before.json> <after.json>
import { readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { z } from "zod";
import { loadDir, loadTgz, type SampleFiles } from "../ai-review/samples.ts";

const [coreArg, outArg, ...extra] = process.argv.slice(2);

if (!coreArg || !outArg) {
  console.error("usage: bun tools/score-eval/eval.ts <core src dir> <out.json> [extra .tgz ...]");
  process.exit(2);
}

// another checkout's scorer, with this one's signatures (a scorer this old or new keeps them)
const core: Pick<typeof import("../../packages/core/src/score.ts"), "analyze" | "finalize"> = await import(resolve(coreArg, "score.ts"));

const Report = z.object({ score: z.number(), signals: z.array(z.object({ id: z.string(), points: z.number(), evidence: z.array(z.string()) })), capabilities: z.array(z.object({ id: z.string() })).optional() });
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null };
const MalIndex = z.array(z.object({ id: z.string(), root: z.string() }));

type Row = { set: string; id: string; score: number; signals: { id: string; points: number; evidence: string[] }[]; capabilities: string[] };

const rows: Row[] = [];


function run(set: string, id: string, s: SampleFiles): void {
  const name = z.string().catch(id).parse(s.manifest.name);

  try {
    const r = Report.parse(core.finalize(core.analyze({ name, manifest: s.manifest, files: s.files, publisher: "a", previousPublishers: [] }), { ...STATE, status: "active" }));
    rows.push({ set, id, score: r.score, signals: r.signals.map((x) => ({ ...x, evidence: x.evidence.slice(0, 3) })), capabilities: (r.capabilities ?? []).map((c) => c.id) });
  } catch (e) {
    rows.push({ set, id, score: -1, signals: [{ id: `error: ${String(e).slice(0, 200)}`, points: 0, evidence: [] }], capabilities: [] });
  }
}

const samples = join(homedir(), ".cache", "apm-ai-review-samples", "malicious", "index.json");

for (const m of MalIndex.parse(JSON.parse(readFileSync(samples, "utf8")))) {
  const s = loadDir(m.root);

  if (s) run("malicious", m.id, s);
}

const corpus = join(homedir(), ".cache", "apm-corpus", "tgz");

for (const f of readdirSync(corpus).sort()) run("corpus", f.replace(/\.tgz$/, ""), loadTgz(join(corpus, f)));

for (const f of extra) run("extra", basename(f), loadTgz(f));

await Bun.write(outArg, JSON.stringify(rows, null, 1));

for (const r of rows) console.log(`${r.set.padEnd(9)} ${String(r.score).padStart(3)} ${r.id.padEnd(48)} ${r.signals.map((s) => `${s.id}${s.points ? s.points : ""}`).join(" ")}`);
