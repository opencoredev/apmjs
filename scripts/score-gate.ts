// The climb score's arithmetic: how many tests did not pass, from what the runner reported. A test counts as not passed
// when it failed, was skipped or left to do, or was declared and never ran (a crash in a file's setup or import). Any
// failure the runner reports, a nonzero exit included, makes the score at least 1 (review of 2a098b1, finding 13).
//
// Every declared test is matched to the runner's report by a stable id, its file and line (bun's JUnit report gives
// each case the line of its name), so extra runs of one parameterised test cannot stand in for another that never ran.
// A focused test (.only) runs part of the suite by design, so any makes the score at least 1 (review of 2b7767f,
// finding 8).

/** A test's declaration: `test(`/`it(` with any modifiers, `test.each(...)(` and `test.skip(` included. */
const DECLARATION = /^\s*(?:test|it)(?:\.(?:each|if|skipIf|todoIf|skip|todo|only|failing|serial|concurrent)(?:\([^)]*\))?)*\(/gm;

/** A focused test or suite: `test.only`, `it.only`, `describe.only` (with any modifiers), or any `.only(` call. */
const FOCUSED = /\b(?:test|it|describe)(?:\.\w+)*\.only\b|\.only\s*\(/;

const lineAt = (source: string, index: number): number => source.slice(0, index).split("\n").length;

/** The line of each test one file declares, as bun's report numbers it: the line its name argument starts on. */
export function declaredLines(source: string): number[] {
  return [...source.matchAll(DECLARATION)].map((m) => {
    const after = m.index + m[0].length;
    const name = after + (/^\s*/.exec(source.slice(after))?.[0].length ?? 0);

    return lineAt(source, name);
  });
}

/** The number of tests one file declares. */
export function declaredTests(source: string): number {
  return declaredLines(source).length;
}

/** The lines of a file that focus its run (`.only`), which the gate refuses. */
export function focusedLines(source: string): number[] {
  return source.split("\n").flatMap((line, i) => (FOCUSED.test(line) && !/^\s*\/\//.test(line) ? [i + 1] : []));
}

/** One file's runtime results from the JUnit report: cases that ran, passed and failed, and the lines that ran. */
type FileResult = { ran: number; passed: number; failed: number; lines: Set<number> };

const empty = (): FileResult => ({ ran: 0, passed: 0, failed: 0, lines: new Set() });

/** Per file, from bun's JUnit report: every <testcase>, its <failure>, <error> or <skipped>, and its line. */
export function junitResults(xml: string): Map<string, FileResult> {
  const out = new Map<string, FileResult>();

  for (const m of xml.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g)) {
    const attrs = m[1] ?? "";
    const body = m[2] ?? "";
    const file = /\bfile="([^"]*)"/.exec(attrs)?.[1] ?? "";
    const line = Number(/\bline="(\d+)"/.exec(attrs)?.[1]);
    const r = out.get(file) ?? empty();
    const failed = /<(?:failure|error)\b/.test(body);
    const skipped = /<skipped\b/.test(body);
    // a hook that threw (beforeAll, an error between tests) is reported as an unnamed case: a failure, not a test that ran
    const hook = /\bname="\(unnamed\)"/.test(attrs);

    if (!hook) {
      r.ran++;

      if (Number.isFinite(line)) r.lines.add(line);
    }

    if (failed) r.failed++;
    else if (!skipped && !hook) r.passed++;
    out.set(file, r);
  }

  return out;
}

/** What the console printed: each "(fail)" line, and the final summary's fail and error counts. */
export function consoleFailures(text: string) {
  const failLines = text.split("\n").filter((l) => l.startsWith("(fail)"));
  const last = (re: RegExp): number => Number([...text.matchAll(re)].at(-1)?.[1] ?? 0);

  return { failLines, failCount: last(/^\s*(\d+) fail$/gm), errorCount: last(/^\s*(\d+) errors?$/gm) };
}

/** One file's declared tests' lines, and the lines that focus its run. */
export type FileInventory = { declared: readonly number[]; focused: readonly number[] };

/** Per file, its inventory. */
export type Inventory = ReadonlyMap<string, FileInventory>;

/** Reads a test file's inventory from its source. */
export function inventoryOf(source: string): FileInventory {
  return { declared: declaredLines(source), focused: focusedLines(source) };
}

export type Gate = { score: number; notRun: number; failed: number; focused: number; files: { file: string; declared: number; ran: number; passed: number; missing: number[]; focused: number[] }[] };

/**
 * The score: per file, the cases that ran and did not pass, plus the declared tests that never ran, each by its line
 * (at least the declared count less the cases that ran); at least 1 when the runner reported any failure, error or
 * nonzero exit, or a file focuses its run.
 */
export function gateScore(input: { inventory: Inventory; junit: string; console: string; exitCode: number }): Gate {
  const results = junitResults(input.junit);
  const files = [...new Set([...input.inventory.keys(), ...results.keys()])].sort();

  const rows = files.map((file) => {
    const r = results.get(file) ?? empty();
    const inv = input.inventory.get(file) ?? { declared: [], focused: [] };
    const missing = [...new Set(inv.declared)].filter((l) => !r.lines.has(l));

    return { file, declared: inv.declared.length, ran: r.ran, passed: r.passed, missing, focused: [...inv.focused] };
  });

  const notRunOf = (r: (typeof rows)[number]): number => Math.max(r.declared - r.ran, r.missing.length, 0);
  const notPassed = rows.reduce((sum, r) => sum + (r.ran - r.passed) + notRunOf(r), 0);
  const notRun = rows.reduce((sum, r) => sum + notRunOf(r), 0);
  const focused = rows.reduce((sum, r) => sum + r.focused.length, 0);
  const c = consoleFailures(input.console);
  const failed = Math.max([...results.values()].reduce((s, r) => s + r.failed, 0), c.failLines.length, c.failCount);
  const anyFailure = failed > 0 || c.errorCount > 0 || input.exitCode !== 0 || focused > 0;

  return { score: anyFailure ? Math.max(1, notPassed) : notPassed, notRun, failed, focused, files: rows };
}
