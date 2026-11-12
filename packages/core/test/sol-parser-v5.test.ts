// Every fixture from the independent review of apm-score-v5 (apmjs-bughunt/sol-parser-v5/REPORT.md), and the variants
// found while closing it, scored by v6. All are inert: harmless calls to example.invalid and `require('child_process')`
// with nothing run. A fixture is the main file of an MIT package with no other deductions; `extra` adds files,
// `manifest` adds package.json fields, and `pad` puts the source behind filler that keeps it from being parsed as a
// tree (`js`: 240,001 `0;` statements, past the token limit; `ts`: a 1 MB comment, past the TypeScript size limit).
//
// `detection` fixtures hold code that runs (or a control next to it): v6 must find what it does, with the confidence
// and points written here, and never score above apm-score-v3. `precision` fixtures are ones where v3 confirmed more
// than the code does; `why` says what v6 reads instead. Where apm-score-v8, which keeps only the proofs that rest on
// how code is read, changed a result, `v8`, `signals8` and `v8why` record it; `kept` names the read-time proof
// (a comment, a regex body, an erased type, a JSON or declaration file) of a fixture that stays above v3.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { analyze, finalize, POINTS, POSSIBLE_POINTS, SCORE_FLOOR, type ScoreReport, type TarEntry } from "../src/index.ts";
import lexerData from "./fixtures/sol-lexer.json";
import fixtureData from "./fixtures/sol-parser-v5.json";

const CodeSignal = z.enum(["shell-exec", "network", "credential-access", "eval", "obfuscated"]);

const Fixture = z.object({
  name: z.string(),
  file: z.string(),
  src: z.string(),
  extra: z.record(z.string(), z.string()).optional(),
  manifest: z.record(z.string(), z.unknown()).optional(),
  pad: z.enum(["js", "ts"]).optional(),
  kind: z.enum(["detection", "precision"]),
  why: z.string().optional(),
  v3: z.number(),
  v4: z.number(),
  v5: z.number(),
  v6: z.number(),
  signals: z.partialRecord(CodeSignal, z.enum(["confirmed", "possible"])),
  v8: z.number().optional(),
  signals8: z.partialRecord(CodeSignal, z.enum(["confirmed", "possible"])).optional(),
  v8why: z.string().optional(),
  kept: z.enum(["comment", "regex", "type", "data"]).optional(),
});

type Fixture = z.infer<typeof Fixture>;

const fixtures = z.array(Fixture).parse(fixtureData);

const LexerFixture = z.object({ name: z.string(), file: z.string(), src: z.string(), kind: z.enum(["detection", "precision"]), v3: z.number() });

const lexerFixtures = z.array(LexerFixture).parse(lexerData);

const PADDING = { js: "0;".repeat(240_001), ts: `/*${"x".repeat(1024 * 1024)}*/\n` } as const;

const possiblePoints = new Map<string, number>(Object.entries(POSSIBLE_POINTS));

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function score(f: Pick<Fixture, "file" | "src" | "extra" | "manifest" | "pad">): ScoreReport {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: f.file, ...f.manifest };
  const src = f.pad ? PADDING[f.pad] + f.src : f.src;
  const files = [entry("package.json", JSON.stringify(manifest)), entry(f.file, src), ...Object.entries(f.extra ?? {}).map(([p, t]) => entry(p, t))];
  const a = analyze({ name: "probe-pkg", manifest, files, publisher: "a", previousPublishers: [] });

  return finalize(a, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null });
}

describe("the v5 review's fixtures", () => {
  test("all are here: 90 from the review, 16 found while fixing it", () => {
    expect(fixtures.length).toBe(106);
    expect(fixtures.every((f) => f.kind === "detection" || (f.why ?? "").length > 0)).toBe(true);
    expect(fixtures.every((f) => (f.v8 === undefined) === (f.v8why === undefined) && (f.v8 === undefined || f.v8 <= f.v3))).toBe(true);
  });

  for (const f of fixtures) {
    test(`${f.kind}: ${f.name}`, () => {
      const r = score(f);
      const found = Object.fromEntries(r.signals.filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]));

      expect(found).toEqual(f.signals8 ?? f.signals);

      for (const s of r.signals) {
        if (!(s.id in POSSIBLE_POINTS)) continue;
        const confirmed = s.confidence === "confirmed";
        expect(s.points, `${s.id} points`).toBe(confirmed ? POINTS[s.id] : (possiblePoints.get(s.id) ?? Number.NaN));
        expect(s.evidence.every((e) => e.includes("[possible:") === !confirmed)).toBe(true);
      }

      const want = f.v8 ?? f.v6;

      expect(r.score).toBe(want);
      expect(r.score < SCORE_FLOOR).toBe(want < SCORE_FLOOR);

      if (f.kept === undefined) expect(r.score).toBeLessThanOrEqual(f.v3);

      if (f.kind === "detection") {
        expect(f.kept).toBeUndefined();
        expect(r.score).toBeLessThanOrEqual(f.v3);

        if (f.v3 < SCORE_FLOOR) expect(r.score).toBeLessThan(SCORE_FLOOR);
      }
    });
  }

  test("the review's launch blockers are refused", () => {
    for (const name of ["fallback-js-padded", "fallback-ts-padded", "decorator-full", "scope-floor", "getter-floor", "wildcard-export", "logical-floor", "apply-floor", "bound-floor"]) {
      const f = fixtures.find((x) => x.name === name);

      expect(f, name).toBeDefined();

      if (f) expect(score(f).score, name).toBeLessThan(SCORE_FLOOR);
    }
  });
});

describe("a file with no tree is read at least as strongly as apm-score-v3 read it", () => {
  // every detection fixture of both reviews, put behind a 1 MB comment in a .ts file so no tree is built
  const single = [...lexerFixtures.filter((f) => f.kind === "detection"), ...fixtures.filter((f) => f.kind === "detection" && !f.extra && !f.manifest)];

  for (const f of single) {
    test(`padded: ${f.name}`, () => {
      const r = score({ file: "index.ts", src: f.src, pad: "ts" });

      expect(r.score).toBeLessThanOrEqual(f.v3);

      if (f.v3 < SCORE_FLOOR) expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("padding cannot lift the escaped payload over the floor in either language", () => {
    const f = fixtures.find((x) => x.name === "fallback-plain");

    expect(f).toBeDefined();

    if (!f) return;

    for (const pad of ["js", "ts"] as const) expect(score({ ...f, file: pad === "js" ? "index.js" : "index.ts", pad }).score).toBe(score(f).score);
  });
});
