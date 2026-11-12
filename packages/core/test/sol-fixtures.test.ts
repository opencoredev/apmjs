// Every fixture from the independent review of apm-score-v4 (apmjs-bughunt/sol-lexer/REPORT.md), scored by v5. Each
// is the main file of an MIT package with no other deductions. All are inert: harmless calls to example.invalid and
// `require('child_process')` with nothing run.
//
// `detection` fixtures hold code that runs (or a control next to it): v5 must find what it does, with the confidence
// and points written here, and never score above apm-score-v3, the last scorer that read every file raw. `precision`
// fixtures are ones where v3 confirmed more than the code does; `why` says what v5 reads instead.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { analyze, finalize, POINTS, POSSIBLE_POINTS, SCORE_FLOOR, type TarEntry } from "../src/index.ts";
import fixtureData from "./fixtures/sol-lexer.json";

const Fixture = z.object({
  name: z.string(),
  file: z.string(),
  src: z.string(),
  kind: z.enum(["detection", "precision"]),
  why: z.string().optional(),
  v3: z.number(),
  v4: z.number(),
  v5: z.number(),
  signals: z.partialRecord(z.enum(["shell-exec", "network", "credential-access", "eval", "obfuscated"]), z.enum(["confirmed", "possible"])),
});

const fixtures = z.array(Fixture).parse(fixtureData);

const possiblePoints = new Map<string, number>(Object.entries(POSSIBLE_POINTS));

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function score(f: z.infer<typeof Fixture>) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: f.file };
  const a = analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry(f.file, f.src)], publisher: "a", previousPublishers: [] });

  return finalize(a, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null });
}

describe("the review's fixtures", () => {
  test("all 104 are here, 83 detection and 21 precision", () => {
    expect(fixtures.length).toBe(104);
    expect(fixtures.filter((f) => f.kind === "detection").length).toBe(83);
    expect(fixtures.every((f) => f.kind === "detection" || (f.why ?? "").length > 0)).toBe(true);
  });

  for (const f of fixtures) {
    test(`${f.kind}: ${f.name}`, () => {
      const r = score(f);
      const found = Object.fromEntries(r.signals.filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]));

      expect(found).toEqual(f.signals);

      for (const s of r.signals) {
        if (!(s.id in POSSIBLE_POINTS)) continue;
        const confirmed = s.confidence === "confirmed";
        expect(s.points, `${s.id} points`).toBe(confirmed ? POINTS[s.id] : (possiblePoints.get(s.id) ?? Number.NaN));
        // a confirmed signal shows only confirmed evidence; a possible one says why on every line
        expect(s.evidence.every((e) => e.includes("[possible:") === !confirmed)).toBe(true);
      }

      expect(r.score).toBe(f.v5);
      // which side of the refusal floor it lands on is part of the claim
      expect(r.score < SCORE_FLOOR).toBe(f.v5 < SCORE_FLOOR);

      if (f.kind === "detection") {
        expect(r.score).toBeLessThanOrEqual(f.v3);

        if (f.v3 < SCORE_FLOOR) expect(r.score).toBeLessThan(SCORE_FLOOR);
      }
    });
  }

  test("the floor-crossing wrappers are refused again", () => {
    for (const name of ["floor-bypass-cr", "floor-bypass-of", "floor-bypass-html", "joined-floor"]) {
      const f = fixtures.find((x) => x.name === name);

      expect(f, name).toBeDefined();

      if (f) expect(score(f).score, name).toBeLessThan(SCORE_FLOOR);
    }
  });
});
