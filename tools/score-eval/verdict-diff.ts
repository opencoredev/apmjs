// Compares two runs of verdicts.ts: per set, how many are review-first before and after, and every sample whose
// verdict, score, reading or risk signals changed. Exits 1 when a malicious or held-out sample moves from review-first
// to install.
// Usage: bun tools/score-eval/verdict-diff.ts <before.json> <after.json>
import { readFileSync } from "node:fs";
import { z } from "zod";
import { VerdictRow } from "./verdict-row.ts";

const [beforePath, afterPath] = process.argv.slice(2);

if (!beforePath || !afterPath) {
  console.error("usage: bun tools/score-eval/verdict-diff.ts <before.json> <after.json>");
  process.exit(2);
}

const Rows = z.array(VerdictRow);
const before = Rows.parse(JSON.parse(readFileSync(beforePath, "utf8")));
const after = Rows.parse(JSON.parse(readFileSync(afterPath, "utf8")));
const key = (r: { set: string; id: string }): string => `${r.set} ${r.id}`;
const was = new Map(before.map((r) => [key(r), r]));
const MALICIOUS = new Set(["malicious", "held-out"]);
let loosened = 0;

for (const set of new Set(after.map((r) => r.set))) {
  const count = (rows: readonly { set: string; verdict: string }[]): string => `${rows.filter((r) => r.set === set && r.verdict === "review-first").length}/${rows.filter((r) => r.set === set).length} review-first`;

  console.log(`${set}: before ${count(before)}, after ${count(after)}`);
}

for (const r of after) {
  const b = was.get(key(r));

  if (!b) {
    console.log(`  new      ${key(r)} ${r.verdict}`);
    continue;
  }

  const lostRisks = b.risks.filter((x) => !r.risks.includes(x));
  const gainedRisks = r.risks.filter((x) => !b.risks.includes(x));
  const changed = b.verdict !== r.verdict || lostRisks.length > 0 || gainedRisks.length > 0 || b.score !== r.score || b.reading !== r.reading;

  if (!changed) continue;
  const loosens = MALICIOUS.has(r.set) && b.verdict === "review-first" && r.verdict !== "review-first";

  if (loosens) loosened++;
  console.log(`  ${loosens ? "LOOSENED" : "changed "} ${key(r)}: ${b.verdict} ${b.score} ${b.reading} [${b.risks.join(",")}] -> ${r.verdict} ${r.score} ${r.reading} [${r.risks.join(",")}]${lostRisks.length > 0 ? ` lost ${lostRisks.join(",")}` : ""}${gainedRisks.length > 0 ? ` gained ${gainedRisks.join(",")}` : ""}`);
}

const verdict = loosened === 0 ? "no malicious or held-out sample loosened" : `${loosened} malicious or held-out samples loosened`;

console.log(verdict);

process.exit(loosened === 0 ? 0 : 1);
