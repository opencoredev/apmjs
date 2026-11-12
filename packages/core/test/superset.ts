// The property apm-score-v10 keeps from v9: on any package, its findings include every finding apm-score-v3 makes there
// (test/v3, copied from git history). Since v10 a finding is either a risk signal or a capability (`findingsOf` names
// each by v9's id), and the score is not compared: v10 scores capabilities at 0 by design. Detection is what must not
// shrink, and this checks it.
//
// A finding is a signal and what it cites: for evidence that names a file and line (`lib/a.js:4: …`) that is the
// file, for the rest (`package.json scripts.postinstall: …`, `binding.gyp: …`, a binary's path) the part before the
// first ": ". Lines are not compared: v3 cites the first match of a rule and v10 may cite an earlier or a better one
// in the same file (the call the tree confirmed before a comment that names it).
import { citedSource, finalize, findingsOf, type Analysis, type AnalyzeInput } from "../src/index.ts";
import { analyze as analyzeV3, finalize as finalizeV3 } from "./v3/score.ts";

/** The input both scorers take: what `analyze` reads, less the options v3 did not have. */
export type SupersetInput = Pick<AnalyzeInput, "name" | "manifest" | "files" | "publisher" | "previousPublishers">;

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

/** Every v3 finding the v10 analysis lacks (as a risk signal or a capability); empty when the property holds. */
export function supersetGaps(input: SupersetInput, v10: Analysis): string[] {
  const v3 = analyzeV3(input);
  const findings = findingsOf(v10);
  const gaps: string[] = [];

  for (const s3 of v3.signals) {
    const s10 = findings.find((s) => s.id === s3.id);

    if (!s10) {
      gaps.push(`${s3.id}: v3 has it (${s3.evidence[0] ?? ""}), v10 does not`);
      continue;
    }

    if (s3.points < 0 && s10.confidence !== "confirmed") gaps.push(`${s3.id}: v3 confirms it, v10 has it as ${s10.confidence}`);

    // past the kept evidence v10 counts items instead of listing them, and keeps every source they cite in `sources`
    const cited = new Set([...s10.evidence, ...(s10.more ?? [])].map(citedSource));

    for (const source of s10.sources ?? []) cited.add(source);

    for (const e of s3.evidence) if (!cited.has(citedSource(e))) gaps.push(`${s3.id}: v3 cites ${citedSource(e)} (${e}), v10 does not`);
  }

  return gaps;
}

/** The v3 score of the same input, for tests that report it. */
export function scoreOfV3(input: SupersetInput): number {
  return finalizeV3(analyzeV3(input), STATE).score;
}

/** The v10 score of an analysis, scored as the tests score it (published long ago, active). */
export function scoreOf(analysis: Analysis): number {
  return finalize(analysis, STATE).score;
}
