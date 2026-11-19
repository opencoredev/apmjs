// Review of c456c92: an incomplete analysis installed whenever no flow stop was recorded. Fail-closed, it installs only
// when apm-score-v11 records that its one gap is whole files left unread for their size or the byte budget. The real
// scorer, finalize and the CLI's verdict, end to end (the website's verdict answers the same: explain-verdicts.json).
import { describe, expect, test } from "bun:test";
import { analyze, finalize, type AnalyzeInput } from "../../core/src/index.ts";
import { explain, readingOf, type ResolvedInput } from "../src/explain.ts";
import { machO } from "../../core/test/executables.ts";

const enc = new TextEncoder();
const entry = (path: string, text: string) => ({ path, size: enc.encode(text).length, mode: 0o644, data: enc.encode(text) });
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };

function verdictOf(index: string, extra: Partial<AnalyzeInput> = {}, more: { path: string; text: string }[] = []) {
  const manifest = { name: "probe-pkg", version: "1.0.0", main: "index.js", license: "MIT" };
  const files = [entry("package.json", JSON.stringify(manifest)), entry("index.js", index), ...more.map((m) => entry(m.path, m.text))];
  const report = finalize(analyze({ name: manifest.name, manifest, files, publisher: "fake", previousPublishers: [], ...extra }), STATE);
  const resolved: ResolvedInput = { kind: "ok", version: "1.0.0", report, skipped: [], deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "off" }, warnings: [], risks: [] } };

  return { report, v: explain({ name: "probe-pkg", range: null, resolved, review: { kind: "off" }, older: { kind: "not-needed" } }) };
}

describe("fail-closed: an incomplete analysis is review-first unless its one gap is size, on the current scorer's record", () => {
  // finding 1: parser limits record no flow stop
  test("5,000 nested parens (the parser's stack): review-first, graded by its score", () => {
    const { report, v } = verdictOf(`module.exports = ${"(".repeat(5000)}1${")".repeat(5000)};\n`);

    expect(report.signals.map((s) => s.id)).toContain("incomplete");
    expect(v.verdict).toBe("review-first");
    expect(report.grade).toBe("F");
  });

  test("240,001 statements (past the token cap): review-first", () => {
    const { report, v } = verdictOf("0;".repeat(240_001));

    expect(report.signals.map((s) => s.id)).toContain("incomplete");
    expect(v.verdict).toBe("review-first");
    expect(report.grade).not.toBe("P");
  });

  // finding 2: a reduced retry stores incomplete beside a byte-budget omission, and the stop it may have seen is lost
  test("a reduced retry that read at most 4 MB, with a file past the budget: review-first, never P", () => {
    const { report, v } = verdictOf("module.exports = 1;\n", { maxScannedBytes: 64, incompleteBecause: ["2 earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB"] }, [{ path: "big.js", text: `module.exports = "${"x".repeat(200)}";\n` }]);

    expect(report.coverage).toMatchObject({ kind: "partial", reasons: ["over-budget"] });
    expect(v.verdict).toBe("review-first");
    expect(report.grade).not.toBe("P");
  });

  // finding 4: the work meter out with nothing left unread for its size was 39, and P or a letter at random
  test("the work meter out: review-first, graded F, not P", () => {
    const { report, v } = verdictOf("module.exports = 1;\n", { maxWork: 100 });

    expect(report.signals.map((s) => s.id)).toContain("incomplete");
    expect(v.verdict).toBe("review-first");
    expect(report.grade).toBe("F");
  });

  // the product goal: next's case, a file past the byte budget and nothing else, installs graded P with the counts
  test("a file left unread for the byte budget and nothing else: install, graded P, saying how much was not read", () => {
    const { report, v } = verdictOf("module.exports = 1;\n", { maxScannedBytes: 64 }, [{ path: "big.js", text: `module.exports = "${"x".repeat(200)}";\n` }]);

    expect(report.signals.map((s) => s.id)).not.toContain("incomplete");
    expect(report.grade).toBe("P");
    expect(v.verdict).toBe("install");
    expect(v.summary).toContain("apm read only part of probe-pkg@1.0.0: 1 file");
    expect(v.notes.map((n) => n.kind)).toContain("partial-analysis");
  });
});

// Round 12 review of 7cd0b2b, P2: one Mach-O of 60,000 lines of `'child_'+'process';` passed what one binary's reading
// may keep, and its findings were dropped and the file reported unread for the budget: 100 (P), which installs, where
// production (274d284) scored 65 (C), complete. Its reading keeps every signal it finds and says it did not finish.
describe("a binary's reading that stopped at what it may hold: never higher than production, never installed", () => {
  test("60,000 lines of 'child_'+'process' in one Mach-O: at most production's 65, review-first", () => {
    const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT" };
    const data = machO({ size: 256, tail: enc.encode(`\n${"'child_'+'process';\n".repeat(60_000)}`) });
    const files = [entry("package.json", JSON.stringify(manifest)), { path: "lib/b000000", size: data.length, mode: 0o755, data }];
    const report = finalize(analyze({ name: manifest.name, manifest, files, publisher: "fake", previousPublishers: [] }), STATE);
    const resolved: ResolvedInput = { kind: "ok", version: "1.0.0", report, skipped: [], deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "off" }, warnings: [], risks: [] } };
    const v = explain({ name: "probe-pkg", range: null, resolved, review: { kind: "off" }, older: { kind: "not-needed" } });

    // production (274d284): 65 (C), complete; on 7cd0b2b: 100 (P), partial, which installs
    expect(report.score).toBeLessThanOrEqual(65);
    expect(report.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["obfuscated", "suspicious-combination", "incomplete"]));
    // not a size or budget omission: nothing is left out, and the reading is incomplete
    expect(report.coverage).toEqual({ kind: "complete" });
    expect(readingOf({ scorer: report.scorer, signals: report.signals, coverage: report.coverage ?? null })).toEqual({ kind: "incomplete" });
    expect(v.verdict).toBe("review-first");
  }, 60_000);
});
