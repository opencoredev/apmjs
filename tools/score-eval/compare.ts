// Compares two runs of eval.ts: the scorer live now (v9) before, the candidate after. It reports how many malicious
// samples each refuses (all of them, and those whose payload is in their own tarball), the corpus distribution, every
// sample, and the standing check: every sample v9 refuses that the candidate passes. That list must be empty, or each
// entry must be a false positive v9 had, named with its reason in v9-false-positives.json. It exits 1 otherwise.
// Usage: bun tools/score-eval/compare.ts <v9.json> <after.json>
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

const Rows = z.array(z.object({ set: z.string(), id: z.string(), score: z.number(), payload: z.enum(["self-contained", "none"]).optional(), signals: z.array(z.object({ id: z.string(), points: z.number() })) }));
const Justified = z.array(z.object({ set: z.string(), id: z.string(), reason: z.string().min(20) }));
const [beforePath, afterPath] = process.argv.slice(2);

if (!beforePath || !afterPath) {
  console.error("usage: bun tools/score-eval/compare.ts <v9.json> <after.json>");
  process.exit(2);
}

type Row = z.infer<typeof Rows>[number];

const before = Rows.parse(JSON.parse(readFileSync(beforePath, "utf8")));
const after = Rows.parse(JSON.parse(readFileSync(afterPath, "utf8")));
const justified = Justified.parse(JSON.parse(readFileSync(join(import.meta.dir, "v9-false-positives.json"), "utf8")));
const FLOOR = 40;
const BUCKETS = [["100", 100, 101], ["90-99", 90, 100], ["80-89", 80, 90], ["60-79", 60, 80], ["40-59", 40, 60], ["below 40", 0, 40]] as const;

function summary(rows: readonly Row[]): string {
  const scores = rows.map((r) => r.score);
  const mean = scores.reduce((n, x) => n + x, 0) / Math.max(1, scores.length);
  const buckets = BUCKETS.map(([label, lo, hi]) => `${label}: ${scores.filter((x) => x >= lo && x < hi).length}`).join(", ");

  return `n ${scores.length}, mean ${mean.toFixed(1)}, below ${FLOOR}: ${scores.filter((x) => x < FLOOR).length}, 80+: ${scores.filter((x) => x >= 80).length} (${buckets})`;
}

for (const set of new Set(after.map((r) => r.set))) {
  console.log(`${set}\n  before ${summary(before.filter((r) => r.set === set))}\n  after  ${summary(after.filter((r) => r.set === set))}`);

  // a payload in the tarball is what a tarball scorer can be held to; the rest hand off to a dependency or carry none
  for (const payload of ["self-contained", "none"] as const) {
    const ids = new Set(after.filter((r) => r.set === set && r.payload === payload).map((r) => r.id));

    if (ids.size === 0) continue;
    console.log(`  ${payload === "none" ? "no payload in this tarball" : "self-contained payload"} (${ids.size})\n    before ${summary(before.filter((r) => r.set === set && ids.has(r.id)))}\n    after  ${summary(after.filter((r) => r.set === set && ids.has(r.id)))}`);
  }
}

for (const r of [...after].sort((a, b) => a.set.localeCompare(b.set) || a.score - b.score)) {
  const was = before.find((b) => b.set === r.set && b.id === r.id)?.score;
  const risks = r.signals.filter((s) => s.points !== 0).map((s) => `${s.id} ${s.points}`).join(", ");

  console.log(`${r.set.padEnd(9)} ${String(was ?? "-").padStart(3)} -> ${String(r.score).padStart(3)}  ${r.id.padEnd(48)} ${r.payload === "none" ? "[no payload] " : ""}${risks}`);
}

// the standing check: refused by v9 (before), passed by the candidate (after)
const regressed = after.filter((r) => {
  const was = before.find((b) => b.set === r.set && b.id === r.id)?.score;

  return was !== undefined && was >= 0 && was < FLOOR && r.score >= FLOOR;
});

console.log(`\nrefused by v9, passed by the candidate: ${regressed.length}`);

let unjustified = 0;

for (const r of regressed) {
  const j = justified.find((x) => x.set === r.set && x.id === r.id);

  if (!j) unjustified++;
  console.log(`  ${r.set} ${r.id}: ${before.find((b) => b.set === r.set && b.id === r.id)?.score} -> ${r.score}  ${j ? `v9 false positive: ${j.reason}` : "NOT JUSTIFIED"}`);
}

if (unjustified > 0) process.exit(1);
