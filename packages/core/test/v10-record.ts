// Records what apm-score-v10 scores each stored review fixture, so a change to the expectations is written with its
// reason (`v10` and `v10why` in the fixture files, made by `bun test/v10-merge.ts`). With APM_RECORD_V10 set to a
// file, the fixture tests append one line per fixture and skip their score assertions; otherwise this does nothing.
import { appendFileSync } from "node:fs";
import type { ScoreReport } from "../src/index.ts";

const OUT = process.env.APM_RECORD_V10;

export const RECORDING = OUT !== undefined && OUT !== "";

/** What a fixture's v10 reason starts with when v3 refused it and v10 does not: it holds capabilities, not a malware pattern. */
export const ABOVE_FLOOR = "above the floor by design:";

export function recordV10(set: string, name: string, r: ScoreReport): void {
  if (!RECORDING || OUT === undefined) return;
  const risks = r.signals.filter((s) => s.points < 0).map((s) => [s.id, s.points]);
  const capabilities = r.capabilities.map((c) => c.id);

  appendFileSync(OUT, `${JSON.stringify({ set, name, score: r.score, risks, capabilities })}\n`);
}
