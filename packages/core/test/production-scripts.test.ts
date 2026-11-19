// Round 17 review of b287849, P1: scriptTargets learned python3, python, perl, ruby, source, `.`, dash and ksh, and
// production's walk, its reading plan, its floor and its install roots took their roots from it. `postinstall: python3
// lib/loader` put lib/loader first; its require made the package's own `python3` file JavaScript before it was read, and
// the facts in its comment went: 0 (F), review-first, became 87, install. Production's callers now read a command as
// production did (scriptTargetsBefore); only the second layer reads what scriptTargets adds.
//
// The property, against production itself: packages that run a file from a script (package-cases.ts, scriptCases) read
// by production (274d284) into fixtures/production-scripts.json, whole and streamed at 60 and 160 bytes. On every one the
// score is at most production's, it installs only where production's does, a streamed plan's production layer is
// production's plan, and production's risks stay unless the reading stopped for its resources (scoring 0). On b287849
// 13 whole readings and 53 streamed ones scored above production's.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { analyze, finalize, firstPass, planLayers, RISK_SIGNALS, SCORE_FLOOR, type AnalyzeInput, type TarEntry } from "../src/index.ts";
import { scriptCases, type CaseManifest } from "./package-cases.ts";

const Reading = z.object({ name: z.string(), score: z.number(), coverage: z.string(), reasons: z.array(z.string()), risks: z.array(z.string()), ids: z.array(z.string()) });

const Recorded = z.object({ whole: z.array(Reading), streamed: z.array(Reading.extend({ budget: z.number(), plan: z.array(z.string()) })) });
const PRODUCTION = Recorded.parse(JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "production-scripts.json"), "utf8")));

const enc = new TextEncoder();
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };
const COMMENT = "/* fetch('x');readFileSync('.npmrc'); */";

const isRisk = (id: string): boolean => RISK_SIGNALS.some((r) => r === id);

// a partial reading whose only gaps are files left out for their size or the budget installs, with a warning (P)
const installs = (x: { score: number; coverage: string; reasons: readonly string[]; ids: readonly string[] }): boolean =>
  x.score >= SCORE_FLOOR && !x.ids.some((id) => isRisk(id) || id === "incomplete" || id === "unanalyzed-files") && (x.coverage === "complete" || (x.reasons.length > 0 && x.reasons.every((r) => r === "too-large" || r === "over-budget")));

function entries(manifest: CaseManifest, files: readonly { path: string; data: Uint8Array; mode: number }[]): TarEntry[] {
  return [{ path: "package.json", data: enc.encode(JSON.stringify(manifest)), mode: 0o644 }, ...files].map((f) => ({ ...f, size: f.data.length }));
}

function summary(input: AnalyzeInput) {
  const r = finalize(analyze(input), STATE);
  const ids = r.signals.map((s) => s.id);

  return { score: r.score, coverage: r.coverage?.kind ?? "none", reasons: r.coverage?.kind === "partial" ? r.coverage.reasons : [], ids, signals: r.signals };
}

/** What `x` did that production's reading `want` did not allow: above it, installed where it was not, a risk lost. */
function worse(name: string, x: { score: number; coverage: string; reasons: readonly string[]; ids: readonly string[] }, want: z.infer<typeof Reading>): string[] {
  const out: string[] = [];
  // a reading stopped for its resources scores 0 and is held: it names no risk it did not reach
  const stopped = x.score === 0 && x.ids.some((id) => id === "incomplete");

  if (x.score > want.score) out.push(`${name}: ${x.score} above production's ${want.score}`);

  if (installs(x) && !installs(want)) out.push(`${name}: installs where production's does not`);

  if (!stopped) for (const id of want.risks) if (!x.ids.some((y) => y === id)) out.push(`${name}: lost ${id}`);

  return out;
}

describe("a script's command read as production read it, by production's walk, plan, floor and install roots", () => {
  for (const interpreter of ["python3", "python", "perl", "ruby", "source", "dash", "ksh"]) {
    for (const reverse of [false, true]) {
      test(`postinstall: ${interpreter} lib/loader, whose require loads the package's own \`${interpreter}\` file${reverse ? ", loader first" : ""}: 0 (F), as production`, () => {
        const manifest: CaseManifest = { name: "probe", version: "1.0.0", license: "MIT", scripts: { postinstall: `${interpreter} lib/loader` } };

        const files = [
          { path: interpreter, data: enc.encode(COMMENT), mode: 0o644 },
          { path: "lib/loader", data: enc.encode(`require('../${interpreter}');`), mode: 0o644 },
        ];

        if (reverse) files.reverse();
        const r = summary({ name: "probe", manifest, files: entries(manifest, files), publisher: "a", previousPublishers: [] });

        // on b287849: 87, install-script and credential-mention, install
        expect(r.score).toBe(0);
        expect(r.coverage).toBe("complete");
        expect([...r.ids].sort()).toEqual(["credential-read", "exfiltration", "install-network", "install-script"]);
      });
    }
  }

  const cases = scriptCases();

  test("the fixture is the packages this test makes", () => {
    expect(PRODUCTION.whole.map((p) => p.name)).toEqual(cases.map((c) => c.name));
    expect(PRODUCTION.streamed.map((p) => `${p.name} @${p.budget}`)).toEqual(cases.flatMap((c) => [60, 160].map((b) => `${c.name} @${b}`)));
  });

  test(`${cases.length} packages read whole: never above production's score, installed only where production's was, its risks kept`, () => {
    const failures = cases.flatMap((c, i) => {
      const want = PRODUCTION.whole[i];

      return want === undefined ? [] : worse(c.name, summary({ name: "probe", manifest: c.manifest, files: entries(c.manifest, c.files), publisher: "a", previousPublishers: [], ...c.options }), want);
    });

    expect(failures).toEqual([]);
  }, 600_000);

  test(`${2 * cases.length} streamed readings: production's plan, never above production's score, installed only where production's was`, () => {
    const failures = cases.flatMap((c, i) =>
      [60, 160].flatMap((budget, j) => {
        const want = PRODUCTION.streamed[2 * i + j];

        if (want === undefined) return [];
        const all = entries(c.manifest, c.files);

        const fp = firstPass({ holdBytes: budget, lookFileBytes: 1 << 30, lookTotalBytes: 1 << 30 });

        for (const f of all) if (fp.hold(f) !== "head") fp.look(f, f.data);
        const plan = planLayers({ manifest: c.manifest, files: all, imports: fp.imports, shellRuns: fp.shellRuns, budget });
        const wanted = new Set([...plan.production, ...plan.extra, "package.json"]);
        const files = all.map((f) => (wanted.has(f.path) ? f : { ...f, data: f.data.slice(0, 64) }));

        const r = summary({
          name: "probe",
          manifest: c.manifest,
          files,
          notHeld: new Set(files.filter((f, k) => f !== all[k])),
          extraHeld: plan.extra,
          stoppedBecause: fp.stopped === null ? [] : [fp.stopped],
          publisher: "a",
          previousPublishers: [],
          maxScannedBytes: budget,
          coverageNotes: fp.importsCut ? ["cut"] : [],
        });

        const planned = [...plan.production].sort();

        return [...worse(`${c.name} @${budget}`, r, want), ...(planned.join("|") === want.plan.join("|") ? [] : [`${c.name} @${budget}: plan ${planned.join(", ")}, production's ${want.plan.join(", ")}`])];
      }),
    );

    expect(failures).toEqual([]);
  }, 600_000);
});
