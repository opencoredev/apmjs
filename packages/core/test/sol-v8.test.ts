// Every fixture from the independent review of apm-score-v8 (apmjs-bughunt/sol-v8/REPORT.md), scored by the current
// scorer. v8 left comments, regex bodies and erased TypeScript out of its reading whenever no evaluator, shell or
// computed load stood in the package; each fixture here reads such text back at runtime and runs it (through
// `new Worker(code, { eval: true })`, which v8 did not take for an evaluator) or uses it as data (an environment
// variable's name, a path, a URL), or hides the evaluator behind a computed load in a file no entry reaches. Each
// scored 100 under v8, three of them from v3's refused 30. apm-score-v9 reads all text, so each holds every finding v3
// makes, and scores at or below v3.
//
// All are inert: they name example.invalid, `child_process` and a token. Each is also run once in a node:vm context
// whose process, fetch, fs, worker_threads and module loading only record what they are asked for; its Worker runs
// `{ eval: true }` source in that same context, and TypeScript is stripped by Bun's transpiler first. The review ran
// the same programs on real node Workers and node's vm; this checks that each still runs its operations.
import { describe, expect, test } from "bun:test";
import vm from "node:vm";
import { z } from "zod";
import { analyze, CAPABILITY_LABELS, finalize, HIDDEN_NOTES, SCORE_FLOOR, TEXT_MATCH, type ScoreReport, type TarEntry, findingsOf } from "../src/index.ts";
import fixtureData from "./fixtures/sol-v8.json";
import { ABOVE_FLOOR, RECORDING, recordV10 } from "./v10-record.ts";
import { scoreOfV3, supersetGaps, type SupersetInput } from "./superset.ts";

const Fixture = z.object({
  name: z.string(),
  family: z.enum(["comment-as-data", "regex-as-data", "type-as-data", "worker-eval", "off-graph-load"]),
  main: z.string(),
  /** The file the review ran. */
  run: z.string(),
  files: z.record(z.string(), z.string()),
  v3: z.number(),
  v8: z.number(),
  v9: z.number(),
  /** What running it does, under recording stubs, in order of first use. */
  runs: z.array(z.string()),
  v10: z.number().optional(),
  v10why: z.string().optional(),
});

type Fixture = z.infer<typeof Fixture>;

const fixtures = z.array(Fixture).parse(fixtureData);

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function inputOf(f: Fixture): SupersetInput {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: f.main };

  return { name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(f.files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] };
}

function score(f: Fixture): ScoreReport {
  return finalize(analyze(inputOf(f)), STATE);
}

const typescript = new Bun.Transpiler({ loader: "ts" });

/** What a recording stub of a builtin module offers the code it runs. */
type StubModule = { Worker?: (code: string, options?: { eval?: boolean }) => void; readFileSync?: (path: string) => string; runInThisContext?: (code: string) => void };

/** Runs the fixture's file under recording stubs and returns what it asked for. */
function trace(f: Fixture): string[] {
  const src = f.files[f.run] ?? "";
  const calls: string[] = [];
  const record = <T>(call: string, value: T): T => (calls.push(call), value);
  const env = new Proxy({}, { get: (_t, k) => record(`env:${String(k)}`, undefined) });
  const context = vm.createContext({});

  const run = (code: string): void => {
    vm.runInContext(code, context, { timeout: 1000 });
  };

  const require = (m: string): StubModule => {
    // the file reading its own source; Bun's transpiler names TypeScript input `input.ts` in the `__filename` it adds
    if (m === "fs") return { readFileSync: (p: string) => (p === f.run || p === "input.ts" ? src : record(`read:${p}`, "")) };

    if (m === "worker_threads") {
      return {
        Worker: function Worker(code: string, options?: { eval?: boolean }): void {
          if (options?.eval) run(code);
        },
      };
    }

    if (m === "node:vm") return record("load:node:vm", { runInThisContext: run });

    return record(`module:${m}`, {});
  };

  Object.assign(context, {
    process: { env, argv: ["node", f.run, "node:vm", "runInThisContext"], getBuiltinModule: (m: string) => record(`module:${m}`, {}) },
    fetch: (u: string) => record(`fetch:${u}`, Promise.resolve()),
    require,
    __filename: f.run,
  });
  run(f.run.endsWith(".ts") ? typescript.transformSync(src) : src);

  return calls;
}

describe("the v8 review's fixtures", () => {
  test("all 18 are here: the 17 counterexamples and the declared-entry control", () => {
    expect(fixtures.length).toBe(18);
    expect(fixtures.filter((f) => f.v8 > f.v3).length).toBe(17);
    // three crossed the refusal floor, from 30 to 100
    expect(fixtures.filter((f) => f.v3 < SCORE_FLOOR && f.v8 >= SCORE_FLOOR).length).toBe(3);
  });

  for (const f of fixtures) {
    test(`${f.family}: ${f.name}`, () => {
      const r = score(f);

      expect(scoreOfV3(inputOf(f))).toBe(f.v3);
      expect(supersetGaps(inputOf(f), analyze(inputOf(f)))).toEqual([]);
      recordV10("sol-v8", f.name, r);

      if (RECORDING) return;
      const want = f.v10 ?? f.v9;

      expect(r.score).toBe(want);
      expect(r.score < SCORE_FLOOR).toBe(want < SCORE_FLOOR);

      // v3 refused it: v10 refuses it too, unless the fixture holds capabilities and no malware pattern, and says so
      if (f.v3 < SCORE_FLOOR && r.score >= SCORE_FLOOR) expect(f.v10why ?? "").toStartWith(ABOVE_FLOOR);
    });

    test(`${f.name}: runs what it holds (liveness, under recording stubs)`, () => {
      expect(trace(f)).toEqual(expect.arrayContaining(f.runs));
    });
  }

  test("a Worker run with eval: true is an evaluator the tree confirms, cited at the call", () => {
    for (const f of fixtures.filter((x) => x.family === "worker-eval")) {
      const ev = findingsOf(score(f)).find((s) => s.id === "eval");

      expect(ev?.confidence, f.name).toBe("confirmed");
      expect(ev?.label, f.name).toBe(CAPABILITY_LABELS.eval);
      expect(ev?.evidence.some((e) => e.includes("Worker") && !e.includes(TEXT_MATCH.trim().slice(0, -1))), f.name).toBe(true);
    }
  });

  test("text read back as data counts, and its evidence says where the text sits", () => {
    const where = { "comment-as-data": HIDDEN_NOTES.comment, "regex-as-data": HIDDEN_NOTES.regex, "type-as-data": HIDDEN_NOTES.type } as const;

    for (const f of fixtures) {
      const family = f.family;

      if (family === "worker-eval" || family === "off-graph-load") continue;
      const evidence = findingsOf(score(f)).flatMap((s) => s.evidence);

      expect(evidence.some((e) => e.endsWith(where[family])), f.name).toBe(true);
    }
  });

  test("a computed load counts in a file no entry reaches, as it does in the declared entry", () => {
    for (const name of ["dynamic-other-opaque", "dynamic-other-opaque-floor", "dynamic-entry-opaque-control"]) {
      const f = fixtures.find((x) => x.name === name);
      const d = f ? findingsOf(score(f)).find((s) => s.id === "dynamic-require") : undefined;

      expect(d?.evidence[0], name).toStartWith(`${f?.run}:2: require(process.argv[2])`);
    }
  });
});

describe("evaluators v3 did not know: Worker and inspector", () => {
  const scored = (src: string) => finalize(analyze(inputOf({ name: "x", family: "worker-eval", main: "index.js", run: "index.js", files: { "index.js": src }, v3: 0, v8: 0, v9: 0, runs: [] })), STATE);
  const evalOf = (src: string) => findingsOf(scored(src)).find((s) => s.id === "eval")?.confidence;

  test("options in a constant or a spread may hold eval: true", () => {
    expect(evalOf("const { Worker } = require('worker_threads');\nconst o = { eval: true };\nnew Worker(code, o);\n")).toBe("possible");
    expect(evalOf("const { Worker } = require('node:worker_threads');\nnew Worker(code, { ...opts });\n")).toBe("possible");
  });

  test("a Worker started from a file, or with eval: false, runs no string", () => {
    expect(evalOf("const { Worker } = require('worker_threads');\nnew Worker('./job.js');\nnew Worker('./job.js', { eval: false, workerData: 1 });\n")).toBeUndefined();
  });

  test("the source a Worker evaluates is read as code", () => {
    const r = scored("const { Worker } = require('worker_threads');\nnew Worker(\"process.getBuiltinModule('child_process')\", { eval: true });\n");

    expect(findingsOf(r).find((s) => s.id === "shell-exec")?.confidence).toBe("confirmed");
    expect(findingsOf(r).find((s) => s.id === "eval")?.confidence).toBe("confirmed");
  });

  test("loading inspector is a possible evaluator; asking a session to evaluate is one", () => {
    expect(evalOf("const inspector = require('node:inspector');\n")).toBe("possible");
    expect(evalOf("const { Session } = require('node:inspector');\nconst s = new Session();\ns.connect();\ns.post('Runtime.evaluate', { expression: code });\n")).toBe("confirmed");
    expect(evalOf("const { Session } = require('inspector');\nconst s = new Session();\ns.post('Profiler.start');\n")).toBe("possible");
  });
});
