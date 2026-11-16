// What apm-score-v11 takes of apm-score-v10's stored analyses (review of e8616ca, finding 2): an analysis v11 would
// store the same is read as v11's, with its coverage stated and its v10 name kept for dismissals; anything else is
// analysed again (upstream) or kept as stored (a package published on apm, which nothing analyses again).
import { describe, expect, test } from "bun:test";
import { analyze, coverageText, finalize, parseAnalysis, PREVIOUS_SCORER, reusableAnalysis, SCORER, storedAnalysis, type Analysis } from "../src/index.ts";

const enc = new TextEncoder();
const manifest = { name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" };

function v11(): Analysis {
  const files = [["package.json", JSON.stringify(manifest)], ["index.js", "module.exports = 1;\n"]].map(([path, text]) => ({ path: path ?? "", size: (text ?? "").length, mode: 0o644, data: enc.encode(text ?? "") }));

  return analyze({ name: "pkg", manifest, files, publisher: "a", previousPublishers: [] });
}

function v10(change: (a: Analysis) => Analysis = (a) => a): Analysis {
  const { coverage: _coverage, ...rest } = v11();

  return change({ ...rest, scorer: PREVIOUS_SCORER });
}

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };
const incomplete = { id: "incomplete" as const, label: "Analysis incomplete", points: -61, evidence: ["not analyzed: big.js (34.0 MB, over the 32 MB limit)"], confidence: "confirmed" as const };

describe("reusableAnalysis", () => {
  test("takes the current scorer's analysis as it is", () => {
    const a = v11();

    expect(a.scorer).toBe(SCORER);
    expect(reusableAnalysis(a)).toEqual(a);
  });

  test("takes a clean v10 analysis, states it complete and keeps its v10 name", () => {
    expect(reusableAnalysis(v10())).toMatchObject({ scorer: PREVIOUS_SCORER, coverage: { kind: "complete" } });
  });

  test("leaves out a v10 analysis v11 scores differently, and every older scorer's", () => {
    expect(reusableAnalysis(v10((a) => ({ ...a, signals: [...a.signals, incomplete] })))).toBeNull();
    expect(reusableAnalysis(v10((a) => ({ ...a, skipped: [{ path: "big.js", size: 1, reason: "too-large" }] })))).toBeNull();
    expect(reusableAnalysis({ ...v10(), scorer: "apm-score-v9" })).toBeNull();
    expect(storedAnalysis(parseAnalysis({ scorer: PREVIOUS_SCORER, signals: "none" }))).toBeNull();
  });
});

describe("storedAnalysis, for a package published on apm", () => {
  test("reads a clean v10 analysis as v11 would, and keeps one v11 would score differently as v10 stored it", () => {
    expect(storedAnalysis(v10())?.coverage).toEqual({ kind: "complete" });
    const kept = storedAnalysis(v10((a) => ({ ...a, signals: [...a.signals, incomplete] })));

    // v10's -61 stands: stricter than v11, never a pass
    expect(kept?.scorer).toBe(PREVIOUS_SCORER);
    expect(finalize(kept ?? v11(), STATE).score).toBeLessThan(40);
  });
});

describe("coverageText", () => {
  test("an analysis that stopped is said to have stopped, never given a count of files", () => {
    expect(coverageText({ kind: "partial", omittedFiles: 0, omittedBytes: 0, reasons: ["stopped"], notes: [] })).toBe("its analysis stopped before it finished, so nothing in it was cleared");
    expect(coverageText({ kind: "partial", omittedFiles: 2, omittedBytes: 2_000_000, reasons: ["over-budget"], notes: [] })).toBe("2 files (2.0 MB) not read");
  });
});
