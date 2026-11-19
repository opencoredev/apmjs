// Round 16 review of c272202: production's walk must read what production's would, and for a streamed read that is
// what production's plan held. The branch's plan held what scripts run first and what shell scripts run, and resolved
// paths from the package's folder too, all from the one budget: a file production's plan held could be left out, and
// one it left out held, so production's walk read other files than production's did (on c272202, over these packages
// and two budgets, 42 streamed readings were complete and above production's, and 103 installed where production's did
// not). Now planLayers' `production` is production's plan, and what the second layer holds comes from what that leaves
// of the budget, hidden from production's walk (AnalyzeInput.extraHeld).
//
// The property, against production itself: the wider packages (package-cases.ts, widerCases) read as a stream at 60
// and 160 bytes by production (274d284) into fixtures/production-streamed.json, its plan and its result. On every one
// the plan's production layer is production's plan, the score is at most production's, and it installs only where
// production's does.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { analyze, finalize, firstPass, planLayers, RISK_SIGNALS, SCORE_FLOOR, type AnalyzeInput, type TarEntry } from "../src/index.ts";
import { widerCases } from "./package-cases.ts";

const Recorded = z.array(z.object({ name: z.string(), budget: z.number(), plan: z.array(z.string()), score: z.number(), coverage: z.string(), reasons: z.array(z.string()), risks: z.array(z.string()), ids: z.array(z.string()) }));
const PRODUCTION = Recorded.parse(JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "production-streamed.json"), "utf8")));

const enc = new TextEncoder();
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };
const BUDGETS = [60, 160] as const;

const isRisk = (id: string): boolean => RISK_SIGNALS.some((r) => r === id);

// a partial reading whose only gaps are files left out for their size or the budget installs, with a warning (P)
const installs = (x: { score: number; coverage: string; ids: readonly string[] }, reasons: readonly string[] = []): boolean =>
  x.score >= SCORE_FLOOR && !x.ids.some((id) => isRisk(id) || id === "incomplete" || id === "unanalyzed-files") && (x.coverage === "complete" || reasons.every((r) => r === "too-large" || r === "over-budget"));

describe("a streamed read's plan: production's, and what the second layer holds besides", () => {
  const cases = widerCases().flatMap((c) => BUDGETS.map((budget) => ({ ...c, budget })));

  test("the fixture is the readings this test makes", () => {
    expect(PRODUCTION.map((p) => `${p.name} @${p.budget}`)).toEqual(cases.map((c) => `${c.name} @${c.budget}`));
  });

  test(`${cases.length} streamed readings: production's plan, never above production's score, installed only where production's was`, () => {
    const failures: string[] = [];

    cases.forEach((c, i) => {
      const want = PRODUCTION[i];

      if (want === undefined) return;
      const all: TarEntry[] = [{ path: "package.json", data: enc.encode(JSON.stringify(c.manifest)), mode: 0o644 }, ...c.files].map((f) => ({ ...f, size: f.data.length }));
      const fp = firstPass({ holdBytes: c.budget, lookFileBytes: 1 << 30, lookTotalBytes: 1 << 30 });

      for (const f of all) if (fp.hold(f) !== "head") fp.look(f, f.data);
      const plan = planLayers({ manifest: c.manifest, files: all, imports: fp.imports, shellRuns: fp.shellRuns, budget: c.budget });

      if ([...plan.production].sort().join("|") !== want.plan.join("|")) failures.push(`${c.name} @${c.budget}: plan ${[...plan.production].sort().join(", ")}, production's ${want.plan.join(", ")}`);
      const wanted = new Set([...plan.production, ...plan.extra, "package.json"]);
      const files = all.map((f) => (wanted.has(f.path) ? f : { ...f, data: f.data.slice(0, 64) }));

      const input: AnalyzeInput = {
        name: "probe",
        manifest: c.manifest,
        files,
        notHeld: new Set(files.filter((f, j) => f !== all[j])),
        extraHeld: plan.extra,
        stoppedBecause: fp.stopped === null ? [] : [fp.stopped],
        publisher: "a",
        previousPublishers: [],
        maxScannedBytes: c.budget,
        coverageNotes: fp.importsCut ? ["cut"] : [],
      };

      const r = finalize(analyze(input), STATE);
      const ids = r.signals.map((s) => s.id);
      const reasons = r.coverage?.kind === "partial" ? r.coverage.reasons : [];

      if (r.score > want.score) failures.push(`${c.name} @${c.budget}: ${r.score} above production's ${want.score}`);

      if (installs({ score: r.score, coverage: r.coverage?.kind ?? "none", ids }, reasons) && !installs(want, want.reasons)) failures.push(`${c.name} @${c.budget}: installs where production's does not`);
    });

    expect(failures).toEqual([]);
  }, 600_000);
});
