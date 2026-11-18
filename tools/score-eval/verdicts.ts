// Scores the malicious samples, the held-out malicious candidates and the 70-package corpus with one copy of
// packages/core, as eval.ts does, and records the install verdict each would get from its own analysis: review-first
// for a risk signal (riskSignalsIn), a score under the floor or an incomplete reading (readingOf), install otherwise.
// Compare two copies with `bun tools/score-eval/verdict-diff.ts <before.json> <after.json>`: no malicious or held-out
// sample may move from review-first to install.
// Usage, from the repo root:
//   bun tools/score-eval/verdicts.ts <core src dir> <out.json> [extra .tgz ...]
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { z } from "zod";
import { loadDir, loadTgz, type SampleFiles } from "../ai-review/samples.ts";
import { VerdictRow } from "./verdict-row.ts";

const [coreArg, outArg, ...extra] = process.argv.slice(2);

if (!coreArg || !outArg) {
  console.error("usage: bun tools/score-eval/verdicts.ts <core src dir> <out.json> [extra .tgz ...]");
  process.exit(2);
}

type Core = Pick<typeof import("../../packages/core/src/score.ts"), "analyze" | "finalize" | "readingOf" | "riskSignalsIn" | "SCORE_FLOOR">;

const core: Core = await import(resolve(coreArg, "score.ts"));
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;
const MalIndex = z.array(z.object({ id: z.string(), root: z.string() }));


type Row = z.infer<typeof VerdictRow>;

const rows: Row[] = [];

function run(set: string, id: string, s: SampleFiles): void {
  const name = z.string().catch(id).parse(s.manifest.name);

  try {
    const r = core.finalize(core.analyze({ name, manifest: s.manifest, files: s.files, publisher: "a", previousPublishers: [] }), { ...STATE });
    const reading = core.readingOf(r);
    const risks = core.riskSignalsIn(r).map((x) => x.id);
    const held = risks.length > 0 || r.score < core.SCORE_FLOOR || reading.kind === "incomplete";

    rows.push({ set, id, score: r.score, verdict: held ? "review-first" : "install", reading: reading.kind, risks, signals: r.signals.map((x) => ({ id: x.id, points: x.points, confidence: x.confidence, evidence: x.evidence.slice(0, 3) })) });
  } catch (e) {
    rows.push({ set, id, score: -1, verdict: "error", reading: "error", risks: [], signals: [{ id: `error: ${String(e).slice(0, 200)}`, points: 0, evidence: [] }] });
  }
}

const samples = join(homedir(), ".cache", "apm-ai-review-samples", "malicious", "index.json");
const picked = MalIndex.parse(JSON.parse(readFileSync(samples, "utf8")));

for (const m of picked) {
  const s = loadDir(m.root);

  if (s) run("malicious", m.id, s);
}

const candidates = join(homedir(), ".cache", "apm-ai-review-samples", "malicious", "candidates.json");
const pickedIds = new Set(picked.map((m) => m.id));

for (const m of existsSync(candidates) ? MalIndex.parse(JSON.parse(readFileSync(candidates, "utf8"))) : []) {
  if (pickedIds.has(m.id)) continue;
  const s = loadDir(m.root);

  if (s) run("held-out", m.id, s);
}

const corpus = join(homedir(), ".cache", "apm-corpus", "tgz");

for (const f of readdirSync(corpus).sort()) run("corpus", f.replace(/\.tgz$/, ""), loadTgz(join(corpus, f)));

for (const f of extra) run("extra", basename(f), loadTgz(f));

await Bun.write(outArg, JSON.stringify(rows, null, 1));

for (const r of rows) console.log(`${r.set.padEnd(9)} ${r.verdict.padEnd(12)} ${String(r.score).padStart(3)} ${r.id.padEnd(48)} ${r.reading} ${r.risks.join(",")}`);
