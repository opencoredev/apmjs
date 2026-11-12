// The property apm-score-v9 is built to hold, as one check every test can run: on any package, its findings include
// every finding apm-score-v3 makes there (test/v3, copied from git history), and so its score is at or below v3's.
//
// A finding is a signal and what it cites: for evidence that names a file and line (`lib/a.js:4: …`) that is the
// file, for the rest (`package.json scripts.postinstall: …`, `binding.gyp: …`, a binary's path) the part before the
// first ": ". Lines are not compared: v3 cites the first match of a rule and v9 may cite an earlier or a better one
// in the same file (the call the tree confirmed before a comment that names it).
import { citedSource, finalize, type Analysis, type AnalyzeInput } from "../src/index.ts";
import { analyze as analyzeV3, finalize as finalizeV3 } from "./v3/score.ts";

/** The input both scorers take: what `analyze` reads, less the options v3 did not have. */
export type SupersetInput = Pick<AnalyzeInput, "name" | "manifest" | "files" | "publisher" | "previousPublishers">;

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

/** Every v3 finding the v9 analysis lacks, and a line when v9 scores higher; empty when the property holds. */
export function supersetGaps(input: SupersetInput, v9: Analysis): string[] {
  const v3 = analyzeV3(input);
  const gaps: string[] = [];

  for (const s3 of v3.signals) {
    const s9 = v9.signals.find((s) => s.id === s3.id);

    if (!s9) {
      gaps.push(`${s3.id}: v3 has it (${s3.evidence[0] ?? ""}), v9 does not`);
      continue;
    }

    if (s3.points < 0 && s9.confidence !== "confirmed") gaps.push(`${s3.id}: v3 confirms it, v9 has it as ${s9.confidence}`);

    if (s9.points > s3.points) gaps.push(`${s3.id}: v9 takes ${s9.points}, v3 took ${s3.points}`);

    // past the kept evidence v9 counts items instead of listing them, and keeps every source they cite in `sources`
    const cited = new Set([...s9.evidence, ...(s9.more ?? [])].map(citedSource));

    for (const source of s9.sources ?? []) cited.add(source);

    for (const e of s3.evidence) if (!cited.has(citedSource(e))) gaps.push(`${s3.id}: v3 cites ${citedSource(e)} (${e}), v9 does not`);
  }

  const score3 = finalizeV3(v3, STATE).score;
  const score9 = finalize(v9, STATE).score;

  if (score9 > score3) gaps.push(`score: v9 ${score9} is above v3 ${score3}`);

  return gaps;
}

/** The v3 score of the same input, for tests that report it. */
export function scoreOfV3(input: SupersetInput): number {
  return finalizeV3(analyzeV3(input), STATE).score;
}
