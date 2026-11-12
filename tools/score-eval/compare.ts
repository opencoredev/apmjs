// Compares two runs of eval.ts: how many malicious samples each refuses, the corpus distribution, and every sample.
// Usage: bun tools/score-eval/compare.ts <before.json> <after.json>
import { readFileSync } from "node:fs";
import { z } from "zod";

const Rows = z.array(z.object({ set: z.string(), id: z.string(), score: z.number(), signals: z.array(z.object({ id: z.string(), points: z.number() })) }));
const [beforePath, afterPath] = process.argv.slice(2);

if (!beforePath || !afterPath) {
  console.error("usage: bun tools/score-eval/compare.ts <before.json> <after.json>");
  process.exit(2);
}

const before = Rows.parse(JSON.parse(readFileSync(beforePath, "utf8")));
const after = Rows.parse(JSON.parse(readFileSync(afterPath, "utf8")));
const FLOOR = 40;
const BUCKETS = [["100", 100, 101], ["90-99", 90, 100], ["80-89", 80, 90], ["60-79", 60, 80], ["40-59", 40, 60], ["below 40", 0, 40]] as const;

function summary(rows: readonly z.infer<typeof Rows>[number][]): string {
  const scores = rows.map((r) => r.score);
  const mean = scores.reduce((n, x) => n + x, 0) / Math.max(1, scores.length);
  const buckets = BUCKETS.map(([label, lo, hi]) => `${label}: ${scores.filter((x) => x >= lo && x < hi).length}`).join(", ");

  return `n ${scores.length}, mean ${mean.toFixed(1)}, below ${FLOOR}: ${scores.filter((x) => x < FLOOR).length}, 80+: ${scores.filter((x) => x >= 80).length} (${buckets})`;
}

for (const set of new Set(after.map((r) => r.set))) {
  console.log(`${set}\n  before ${summary(before.filter((r) => r.set === set))}\n  after  ${summary(after.filter((r) => r.set === set))}`);
}

for (const r of [...after].sort((a, b) => a.set.localeCompare(b.set) || a.score - b.score)) {
  const was = before.find((b) => b.set === r.set && b.id === r.id)?.score;
  const risks = r.signals.filter((s) => s.points !== 0).map((s) => `${s.id} ${s.points}`).join(", ");

  console.log(`${r.set.padEnd(9)} ${String(was ?? "-").padStart(3)} -> ${String(r.score).padStart(3)}  ${r.id.padEnd(48)} ${risks}`);
}
