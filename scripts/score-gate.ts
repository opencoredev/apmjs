// The climb score's arithmetic: how many tests did not pass, from what the runner reported. A test counts as not passed
// when it failed, was skipped or left to do, or was declared and never ran (a crash in a file's setup or import). Any
// failure the runner reports, a nonzero exit included, makes the score at least 1 (review of 2a098b1, finding 13).

/** The tests one file declares in its source: each `test(`/`it(` call, a `test.each(...)(` or `test.skip(` included. */
export function declaredTests(source: string): number {
  return (source.match(/^\s*(?:test|it)(?:\.(?:each|if|skipIf|todoIf|skip|todo|only|failing|serial|concurrent)(?:\([^)]*\))?)*\(/gm) ?? []).length;
}

/** One file's runtime results from the JUnit report: cases that ran and cases that passed. */
type FileResult = { ran: number; passed: number; failed: number };

/** Per file, from bun's JUnit report: every <testcase>, its <failure>, <error> or <skipped>. */
export function junitResults(xml: string): Map<string, FileResult> {
  const out = new Map<string, FileResult>();

  for (const m of xml.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g)) {
    const attrs = m[1] ?? "";
    const body = m[2] ?? "";
    const file = /\bfile="([^"]*)"/.exec(attrs)?.[1] ?? "";
    const r = out.get(file) ?? { ran: 0, passed: 0, failed: 0 };
    const failed = /<(?:failure|error)\b/.test(body);
    const skipped = /<skipped\b/.test(body);
    // a hook that threw (beforeAll, an error between tests) is reported as an unnamed case: a failure, not a test that ran
    const hook = /\bname="\(unnamed\)"/.test(attrs);

    if (!hook) r.ran++;

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

export type Gate = { score: number; notRun: number; failed: number; files: { file: string; declared: number; ran: number; passed: number }[] };

/**
 * The score: per file, the tests that did not pass, counted as max(declared, ran) − passed, since describe.each runs a
 * declared test more than once; at least 1 when the runner reported any failure, error or nonzero exit.
 */
export function gateScore(input: { declared: ReadonlyMap<string, number>; junit: string; console: string; exitCode: number }): Gate {
  const results = junitResults(input.junit);
  const files = [...new Set([...input.declared.keys(), ...results.keys()])].sort();

  const rows = files.map((file) => {
    const r = results.get(file) ?? { ran: 0, passed: 0, failed: 0 };

    return { file, declared: input.declared.get(file) ?? 0, ran: r.ran, passed: r.passed };
  });

  const notPassed = rows.reduce((sum, r) => sum + Math.max(r.declared, r.ran) - r.passed, 0);
  const notRun = rows.reduce((sum, r) => sum + Math.max(0, r.declared - r.ran), 0);
  const c = consoleFailures(input.console);
  const failed = Math.max([...results.values()].reduce((s, r) => s + r.failed, 0), c.failLines.length, c.failCount);
  const anyFailure = failed > 0 || c.errorCount > 0 || input.exitCode !== 0;

  return { score: anyFailure ? Math.max(1, notPassed) : notPassed, notRun, failed, files: rows };
}
