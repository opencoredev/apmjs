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
// where that changed a result, `v8`, `signals8` and `v8why` record it. apm-score-v9 keeps none of those either: v3's
// rules read all text, so where that changed a result, `v9`, `signals9` and `v9why` record it, and no fixture scores
// above v3.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { analyze, finalize, POINTS, POSSIBLE_POINTS, SCORE_FLOOR, type TarEntry, findingsOf } from "../src/index.ts";
import fixtureData from "./fixtures/sol-lexer.json";
import { supersetGaps } from "./superset.ts";
import { ABOVE_FLOOR, RECORDING, recordV10 } from "./v10-record.ts";

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
  v9: z.number().optional(),
  signals9: z.partialRecord(z.enum(["shell-exec", "network", "credential-access", "eval", "obfuscated"]), z.enum(["confirmed", "possible"])).optional(),
  v9why: z.string().optional(),
  v10: z.number().optional(),
  v10why: z.string().optional(),
});

const fixtures = z.array(Fixture).parse(fixtureData);

const possiblePoints = new Map<string, number>(Object.entries(POSSIBLE_POINTS));

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function inputOf(f: z.infer<typeof Fixture>) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: f.file };

  return { name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry(f.file, f.src)], publisher: "a", previousPublishers: [] };
}

function score(f: z.infer<typeof Fixture>) {
  const a = analyze(inputOf(f));

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
    // every result v9 changed says why, and none of them is above v3
    expect(fixtures.every((f) => (f.v9 === undefined) === (f.v9why === undefined) && (f.v9 === undefined || f.v9 <= f.v3))).toBe(true);
    // every result apm-score-v10 changed says why
    expect(fixtures.every((f) => (f.v10 === undefined) === (f.v10why === undefined))).toBe(true);
  });

  for (const f of fixtures) {
    test(`${f.kind}: ${f.name}`, () => {
      const r = score(f);
      const found = Object.fromEntries(findingsOf(r).filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]));

      expect(found).toEqual(f.signals9 ?? f.signals8 ?? f.signals7 ?? f.signals);

      for (const s of r.signals) {
        if (!(s.id in POSSIBLE_POINTS)) continue;
        const confirmed = s.confidence === "confirmed";
        expect(s.points, `${s.id} points`).toBe(confirmed ? POINTS[s.id] : (possiblePoints.get(s.id) ?? Number.NaN));
        // a confirmed signal shows only confirmed evidence; a possible one says why on every line
        expect(s.evidence.every((e) => e.includes("[possible:") === !confirmed)).toBe(true);
      }

      // apm-score-v10 keeps every finding v3 makes, as a risk signal or a capability
      expect(supersetGaps(inputOf(f), r)).toEqual([]);
      recordV10("sol-lexer", f.name, r);

      if (RECORDING) return;
      const want = f.v10 ?? f.v9 ?? f.v8 ?? f.v7 ?? f.v5;

      expect(r.score).toBe(want);
      // which side of the refusal floor it lands on is part of the claim
      expect(r.score < SCORE_FLOOR).toBe(want < SCORE_FLOOR);

      // v3 refused it: v10 refuses it too, unless the fixture holds capabilities and no malware pattern, and says so
      if (f.kind === "detection" && f.v3 < SCORE_FLOOR && r.score >= SCORE_FLOOR) expect(f.v10why ?? "").toStartWith(ABOVE_FLOOR);
    });
  }

  test("the floor-crossing wrappers hide nothing: each keeps every v3 finding and scores no higher than the control payload with them", () => {
    // v3 refused these at 30; apm-score-v10 scores their capabilities at 0, so the claim is that the wrapper is no help
    const bare = score({ name: "bare", file: "index.js", src: "require('child_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1');", kind: "detection", v3: 30, v4: 30, v5: 30, signals: {} });

    for (const name of ["floor-bypass-cr", "floor-bypass-of", "floor-bypass-html", "joined-floor"]) {
      const f = fixtures.find((x) => x.name === name);

      expect(f, name).toBeDefined();

      if (f) {
        expect(supersetGaps(inputOf(f), score(f)), name).toEqual([]);
        expect(score(f).score, name).toBeLessThanOrEqual(bare.score);
      }
    }
  });
});
