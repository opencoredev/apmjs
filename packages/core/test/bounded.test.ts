// Criterion 1 of apm-score-v10: analysis stays bounded in time and work for any input, and a limit it hits shows in
// the result, never as a clean score. The fourth review held on two decoder gaps: a regex the decoder ran could
// backtrack outside every budget (P1), and a decoder stopped at its output limit read as if it had finished (P2).
// Every package here is an inert string; nothing runs and no host is contacted.
import { describe, expect, test } from "bun:test";
import { parse } from "acorn";
import { join } from "node:path";
import { z } from "zod";
import { MAX_DECODER_STEPS, runDecoder, safeRegexCost, type Known } from "../src/decode.ts";
import { analyze, finalize, SCORE_FLOOR, type TarEntry } from "../src/index.ts";

const RUNNER = join(import.meta.dir, "fixtures", "bounded-run.ts");

const Result = z.array(z.object({ ms: z.number(), score: z.number(), signals: z.array(z.object({ id: z.string(), points: z.number(), evidence: z.array(z.string()) })) }));

type Case = { files: Record<string, string>; maxAnalysisMs?: number };

/**
 * Runs the cases in a child process killed after `killMs`: an analysis that never returns cannot be interrupted from
 * inside the process that runs it. A kill is a failure, with how long it ran.
 */
async function runBounded(cases: readonly Case[], killMs: number): Promise<{ wallMs: number; results: z.infer<typeof Result> }> {
  const t = performance.now();
  const proc = Bun.spawn(["bun", RUNNER], { stdin: new Blob([JSON.stringify(cases)]), stdout: "pipe", stderr: "pipe" });
  const timer = setTimeout(() => proc.kill(9), killMs);

  try {
    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
    const wallMs = performance.now() - t;

    if (code !== 0) throw new Error(`the analysis did not finish: exit ${code} after ${Math.round(wallMs)} ms${proc.signalCode ? ` (killed, ${proc.signalCode})` : ""}\n${err.slice(0, 2000)}`);

    return { wallMs, results: Result.parse(JSON.parse(out)) };
  } finally {
    clearTimeout(timer);
  }
}

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function analyzeFiles(files: Readonly<Record<string, string>>) {
  const manifest = { name: "bounded-probe", version: "1.0.0", license: "MIT", main: "index.js" };
  const a = analyze({ name: "bounded-probe", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] });

  return { a, score: finalize(a, STATE).score };
}

const fnOf = (src: string) => {
  const first = parse(src, { ecmaVersion: "latest" }).body[0];

  if (first?.type !== "FunctionDeclaration") throw new Error("expected a function");

  return first;
};

const host = { constant: () => null, localFunction: () => null };
const text = (value: string): Known => ({ kind: "text", value });

/** The reviewer's package: 40 optional atoms, then a fixed run, against 40 `a`s and a `!` that fails every path. */
const REVIEWER_PATTERN = `^${"a?".repeat(40)}a{20}$`;
const REVIEWER_PACKAGE = `function g(h){return h.replace(/${REVIEWER_PATTERN}/,'')}require(g('${"a".repeat(40)}!'))`;

describe("P1: a regex the decoder runs stays inside its budgets", () => {
  test("the reviewer's 184-byte package finishes inside a 100 ms analysis budget", async () => {
    // the review's package was 184 bytes; this spelling of it is 180
    expect(REVIEWER_PACKAGE.length).toBeLessThan(200);
    // before the fix this ran for minutes: native replace backtracked 2^40 paths outside the step counter
    const { wallMs, results } = await runBounded([{ files: { "index.js": REVIEWER_PACKAGE }, maxAnalysisMs: 100 }], 20_000);
    const [r] = results;

    expect(r?.ms ?? Infinity).toBeLessThan(1_000);
    expect(wallMs).toBeLessThan(10_000);
    // the decoder did not run the pattern, so the computed require stays unknown and is reported as one
    expect(r?.signals.some((s) => s.id === "dynamic-require")).toBe(true);
  }, 30_000);

  test("the subset refuses every pattern with more than one choice, and keeps the decoders packages use", () => {
    for (const p of [REVIEWER_PATTERN, "a?b?", "a??", "(a+)+$", "a*", "a+", "a{1,3}", "a{2,}", "a|b", "(?:ab)", "(?=a)", "\\1", "\\k<x>", "[a-z]{2}?", "a{2}{3}", "\\p{L}", "a{100}", "[", "[]"]) {
      expect({ p, cost: safeRegexCost(p, "g") }).toEqual({ p, cost: null });
    }

    expect(safeRegexCost("a", "v")).toBeNull();
    expect(safeRegexCost("a", "gg")).toBeNull();

    for (const p of ["..", ".{2}", "[0-9a-f]{2}", "%[0-9A-F]{2}", "\\\\x[0-9a-f]{2}", "^\\s", "[^a-z]", "\\bx?y$", "[\\]\\\\]{3}", "\\u00"]) expect({ p, ok: safeRegexCost(p, "gi") !== null }).toEqual({ p, ok: true });

    expect(runDecoder(fnOf("function g(h){return h.replace(/../g,m=>String.fromCharCode(parseInt(m,16)))}"), [text("6178696f73")], host)).toEqual({ kind: "decoded", value: "axios" });
    expect(runDecoder(fnOf(`function g(h){return h.replace(/${REVIEWER_PATTERN}/,'')}`), [text(`${"a".repeat(40)}!`)], host)).toEqual({ kind: "unsupported" });
  });

  test("a pattern at the subset's limits, on the longest input, takes milliseconds and is charged to the step budget", () => {
    const widest = `^${"[a-z]".repeat(39)}a?[a-z]{24}$`;

    expect(safeRegexCost(widest, "g")).not.toBeNull();
    const input = `${"a".repeat(64 * 1024 - 1)}!`;
    const t = performance.now();
    const r = runDecoder(fnOf(`function g(h){return h.replace(/${widest}/g,'x')}`), [text(input)], host);

    expect(performance.now() - t).toBeLessThan(500);
    // 64K starts at up to 128 characters each is more than one call's steps: stopped, and said so
    expect(r).toMatchObject({ kind: "exhausted" });
    expect(MAX_DECODER_STEPS).toBe(200_000);
  });

  test("a fuzz of quantifier combinations finishes under a tight budget, each decode honest", async () => {
    // a seeded generator, so a failure names a pattern that fails again
    let seed = 0x5eed;

    const rand = (n: number): number => {
      seed = (seed * 1_103_515_245 + 12_345) & 0x7fff_ffff;

      return seed % n;
    };

    const atoms = ["a", ".", "[a-z]", "\\w", "[^b]", "\\d", "(?:a)", "(a)", "(?:a|aa)"];
    const quants = ["", "?", "??", "{2}", "{20}", "{0,20}", "{1,}", "*", "+", "*?", "{2}?"];
    const patterns: string[] = [REVIEWER_PATTERN];

    for (let i = 0; i < 400; i++) {
      const parts: string[] = [];
      const runs = 1 + rand(4);

      for (let r = 0; r < runs; r++) {
        // a repeated atom-and-quantifier, up to 40 times: how optional atoms pile into exponential backtracking
        const piece = (atoms[rand(atoms.length)] ?? "a") + (quants[rand(quants.length)] ?? "");
        parts.push(piece.repeat(1 + rand(40)));
      }

      patterns.push(`${rand(2) === 0 ? "^" : ""}${parts.join("")}${rand(2) === 0 ? "$" : ""}`);
    }

    const accepted = patterns.filter((p) => safeRegexCost(p, "g") !== null);

    // the fuzz reaches both sides of the subset
    expect(accepted.length).toBeGreaterThan(10);
    expect(accepted.length).toBeLessThan(patterns.length);

    for (const p of accepted) {
      // at most one optional atom and no open-ended repeat: the claim the cost rests on
      expect({ p, optional: (p.match(/(?<!\\)\?/g) ?? []).length <= 1, open: /[*+]|\{\d+,/.test(p) }).toEqual({ p, optional: true, open: false });
    }

    // every pattern, accepted or not, runs as a decoder on inputs built to make it backtrack, one file each
    const inputs = [`${"a".repeat(40)}!`, `${"a".repeat(2_000)}!`];
    const files: Record<string, string> = {};

    patterns.forEach((p, i) => {
      files[`f${i}.js`] = `function g(h){return h.replace(/${p}/g,'')}module.exports=[${inputs.map((x) => `require(g('${x}'))`).join(",")}]`;
    });

    const { wallMs, results } = await runBounded([{ files, maxAnalysisMs: 5_000 }], 60_000);

    expect(results[0]?.ms ?? Infinity).toBeLessThan(5_000);
    expect(wallMs).toBeLessThan(30_000);
  }, 90_000);
});

describe("P2: a decoder that hits its limit makes the analysis incomplete", () => {
  const OVER_OUTPUT = `function g(h){return h.split('').map(c=>h+h+h+h).join('')}require(g('${"y".repeat(4_000)}'))`;

  test("the reviewer's over-output decoder used as a require target is incomplete, below the floor", () => {
    const { a, score } = analyzeFiles({ "index.js": OVER_OUTPUT });
    const incomplete = a.signals.find((s) => s.id === "incomplete");

    // before the fix: 98, with no incomplete mark and no warning
    expect(incomplete?.evidence.join("\n") ?? "").toContain("decoder function");
    expect(incomplete?.evidence.join("\n") ?? "").toContain("stopped running at its limit");
    expect(score).toBeLessThan(SCORE_FLOOR);
  });

  test("the step limit and the call depth count as exhausted too", () => {
    const steps = runDecoder(fnOf("function g(h){return h.split('').map(c=>c.split('').map(d=>d+d).join('')).join('')}"), [text("z".repeat(60_000))], host);
    // the decoder has no comparisons, so a recursion it runs only stops at the depth limit
    const local = fnOf("function d(s){return d(s.slice(1))+s[0]}");
    const deep = runDecoder(local, [text("abcdefgh")], { constant: () => null, localFunction: () => local });

    expect(steps).toMatchObject({ kind: "exhausted" });
    expect(deep).toMatchObject({ kind: "exhausted" });
    expect(runDecoder(fnOf("function g(h){return h}"), [text("x")], host, { steps: 0 })).toMatchObject({ kind: "exhausted" });
  });

  test("a file's shared decoder allowance and its decoded-text budget are limits the analysis reports", () => {
    // heavy calls with short results spend a file's step allowance: the ones past it are reported, not dropped
    const heavy = `function g(h){return h.split('').map(c=>c+c).join('').slice(0,8)}`;
    const calls = Array.from({ length: 30 }, (_, i) => `require(g('${String.fromCharCode(97 + (i % 26)).repeat(30_000)}'))`).join(";");
    const spent = analyzeFiles({ "index.js": `${heavy};${calls}` });

    expect(spent.a.signals.find((s) => s.id === "incomplete")?.evidence.join("\n") ?? "").toContain("more than 200000 steps");
    expect(spent.score).toBeLessThan(SCORE_FLOOR);

    // and decoded text past the file's 256 KB budget: the result apm drops is a limit it hit, not a clean miss
    const wide = `function g(h){return h.split('').map(c=>c+c).join('')}`;
    const many = Array.from({ length: 8 }, (_, i) => `require(g('${String.fromCharCode(97 + i).repeat(30_000)}'))`).join(";");
    const capped = analyzeFiles({ "index.js": `${wide};${many}` });

    expect(capped.a.signals.find((s) => s.id === "incomplete")?.evidence.join("\n") ?? "").toContain("more than 256 KB of decoded text");
    expect(capped.score).toBeLessThan(SCORE_FLOOR);
  });

  test("a decoder apm does not run at all stays as it was: unknown, not incomplete", () => {
    const { a } = analyzeFiles({ "index.js": "function g(h){for(;;){}return h}require(g('x'))" });

    expect(a.signals.some((s) => s.id === "incomplete")).toBe(false);
    expect(a.signals.some((s) => s.id === "dynamic-require")).toBe(true);
  });
});

describe("flow reading has a work budget of its own", () => {
  /**
   * Helpers imported from other files, each level passing every helper's result to the next: labels multiply with
   * every level. Eight helpers four levels deep took 59 million steps and 8.6 s before the budget; one more level is
   * minutes.
   */
  function imported(helpers: number, levels: number): string {
    const vars = Array.from({ length: helpers }, (_, i) => `v${i}`);
    const lines = ["import {spawn} from 'node:child_process';", ...vars.map((_, i) => `import {m${i}} from './m${i}.js';`)];

    lines.push(`const s0=(${vars.join(",")})=>({${vars.map((v, i) => `${v}:m${i}(${v})`).join(",")}});`);

    for (let i = 1; i < levels; i++) {
      const renamed = vars.map((v) => `${v}:w${v}`).join(",");
      const passed = vars.map((v, j) => `m${j}(${v},${vars[(j + 1) % helpers] ?? v})`).join(",");

      lines.push(`const s${i}=(${vars.join(",")})=>{const {${renamed}}=s${i - 1}(${passed});return s${i - 1}(${vars.map((v) => `w${v}`).join(",")})};`);
    }

    lines.push(`export const run=(a)=>spawn(s${levels - 1}(${vars.map(() => "a").join(",")}));`);

    return lines.join("\n");
  }

  test("a 1 KB file that multiplies labels stops at the budget, and the analysis is incomplete", async () => {
    const index = imported(8, 5);
    const files = Object.fromEntries([["index.js", index], ...Array.from({ length: 8 }, (_, i) => [`m${i}.js`, `export const m${i}=(a,b)=>[a,b];`])]);

    expect(index.length).toBeLessThan(2_000);
    const { results } = await runBounded([{ files }], 60_000);
    const r = results[0];
    const incomplete = r?.signals.find((s) => s.id === "incomplete");

    expect(incomplete?.evidence.join("\n") ?? "").toContain("stopped following where values go at its work budget");
    expect(r?.score ?? 100).toBeLessThan(SCORE_FLOOR);
    expect(r?.ms ?? Infinity).toBeLessThan(20_000);
  }, 90_000);
});

