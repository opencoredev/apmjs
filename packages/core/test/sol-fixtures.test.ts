// Every fixture from the independent review of apm-score-v4 (apmjs-bughunt/sol-lexer/REPORT.md), scored by the
// current scorer. Each is the main file of an MIT package with no other deductions. All are inert: harmless calls to
// example.invalid and `require('child_process')` with nothing run.
//
// `detection` fixtures hold code that runs (or a control next to it): they must find what it does, with the
// confidence and points written here, and never score above apm-score-v3, the last scorer that read every file raw.
// `precision` fixtures are ones where v3 confirmed more than the code does; `why` says what v5 read instead. Since
// apm-score-v7 a finding v3 made stands unless the tree proves it harmless; where that proof does not exist, `v7`,
// `signals7` and `floor` give the score, the signals and the reason, and v7 equals v3 there. apm-score-v8 keeps
// only the proofs that rest on how code is read (comments, regex bodies, erased types, JSON and declaration files);
// where that changed a result, `v8`, `signals8` and `v8why` record it. No fixture scores above v3 unless `kept`
// names the read-time proof that puts it there.
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
  v7: z.number().optional(),
  signals7: z.partialRecord(z.enum(["shell-exec", "network", "credential-access", "eval", "obfuscated"]), z.enum(["confirmed", "possible"])).optional(),
  floor: z.string().optional(),
  v8: z.number().optional(),
  signals8: z.partialRecord(z.enum(["shell-exec", "network", "credential-access", "eval", "obfuscated"]), z.enum(["confirmed", "possible"])).optional(),
  v8why: z.string().optional(),
  kept: z.enum(["comment", "regex", "type", "data"]).optional(),
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
    // every result v7 changed is explained, and each is v3's own
    expect(fixtures.every((f) => (f.v7 === undefined) === (f.floor === undefined) && (f.v7 === undefined || f.v7 === f.v3))).toBe(true);
    // every result v8 changed says why, and none of them is above v3
    expect(fixtures.every((f) => (f.v8 === undefined) === (f.v8why === undefined) && (f.v8 === undefined || f.v8 <= f.v3))).toBe(true);
  });

  for (const f of fixtures) {
    test(`${f.kind}: ${f.name}`, () => {
      const r = score(f);
      const found = Object.fromEntries(r.signals.filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]));

      expect(found).toEqual(f.signals8 ?? f.signals7 ?? f.signals);

      for (const s of r.signals) {
        if (!(s.id in POSSIBLE_POINTS)) continue;
        const confirmed = s.confidence === "confirmed";
        expect(s.points, `${s.id} points`).toBe(confirmed ? POINTS[s.id] : (possiblePoints.get(s.id) ?? Number.NaN));
        // a confirmed signal shows only confirmed evidence; a possible one says why on every line
        expect(s.evidence.every((e) => e.includes("[possible:") === !confirmed)).toBe(true);
      }

      const want = f.v8 ?? f.v7 ?? f.v5;

      expect(r.score).toBe(want);
      // which side of the refusal floor it lands on is part of the claim
      expect(r.score < SCORE_FLOOR).toBe(want < SCORE_FLOOR);

      // only a proof that rests on how the code is read can put a fixture above v3
      if (f.kept === undefined) expect(r.score).toBeLessThanOrEqual(f.v3);

      if (f.kind === "detection") {
        expect(f.kept).toBeUndefined();
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
