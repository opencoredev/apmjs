// The climb score's arithmetic: how many tests did not pass, from what the runner reported. A test counts as not passed
// when it failed, was skipped or left to do, or was declared and never ran (a crash in a file's setup or import). Any
// failure the runner reports, a nonzero exit included, makes the score at least 1 (review of 2a098b1, finding 13).
//
// Every declared test is matched to the runner's report by a stable id, its file and line (bun's JUnit report gives
// each case the line of its name), so extra runs of one parameterised test cannot stand in for another that never ran.
// A focused test (.only) runs part of the suite by design, so any makes the score at least 1 (review of 2b7767f,
// finding 8). The inventory reads each file's syntax with TypeScript's parser, so a test declared or focused through an
// alias (`import { test as check }`, `check.only.each(...)`) counts like any other (review of efef668, finding 4), and
// scripts/score.ts also runs bun with .only turned into an error (score-preload.ts).
import ts from "typescript";

/** A modifier that keeps a test function a test function: `test.skip`, `test.only`, `describe.concurrent`. */
const STATIC_MODIFIERS = new Set(["skip", "todo", "only", "failing", "serial", "concurrent"]);

/** A modifier that is called with its configuration first: `test.each([...])(...)`, `test.if(cond)(...)`. */
const CALLED_MODIFIERS = new Set(["each", "if", "skipIf", "todoIf", "failingIf", "runIf"]);

/** bun:test's exports that declare a test or a suite (x...: skipped). */
const EXPORTS = new Map<string, "test" | "describe">([
  ["test", "test"],
  ["it", "test"],
  ["xtest", "test"],
  ["xit", "test"],
  ["describe", "describe"],
  ["xdescribe", "describe"],
]);

/**
 * What an expression is to the inventory: bun:test itself (an import or require of it), or a function that declares
 * a test or a suite, focused when `.only` is anywhere in its modifier chain. `pending`: a called modifier was named and
 * its configuration call has not happened yet, so the next call configures rather than declares.
 */
type Ref = { kind: "module" } | { kind: "fn"; fn: "test" | "describe"; focused: boolean; pending: boolean };

function member(r: Ref | null, name: string): Ref | null {
  if (r === null) return null;

  if (r.kind === "module") {
    const fn = EXPORTS.get(name);

    return fn !== undefined ? { kind: "fn", fn, focused: false, pending: false } : name === "default" ? r : null;
  }

  if (r.pending) return null;

  if (STATIC_MODIFIERS.has(name)) return { ...r, focused: r.focused || name === "only" };

  return CALLED_MODIFIERS.has(name) ? { ...r, pending: true } : null;
}

/** The name a member access reads: `a.b` and `a["b"]`. */
function memberName(node: ts.Node): { object: ts.Expression; name: string } | null {
  if (ts.isPropertyAccessExpression(node)) return { object: node.expression, name: node.name.text };

  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) return { object: node.expression, name: node.argumentExpression.text };

  return null;
}

const isBunTest = (node: ts.Node): boolean => ts.isStringLiteralLike(node) && node.text === "bun:test";

/** What `expr` is, through aliases, member accesses, configuration calls, parentheses and type assertions. */
function resolve(expr: ts.Expression, bindings: ReadonlyMap<string, Ref>): Ref | null {
  if (ts.isParenthesizedExpression(expr) || ts.isNonNullExpression(expr) || ts.isAsExpression(expr) || ts.isSatisfiesExpression(expr) || ts.isTypeAssertionExpression(expr)) return resolve(expr.expression, bindings);

  if (ts.isIdentifier(expr)) return bindings.get(expr.text) ?? null;
  const m = memberName(expr);

  if (m !== null) return member(resolve(m.object, bindings), m.name);

  if (ts.isCallExpression(expr)) {
    if (ts.isIdentifier(expr.expression) && expr.expression.text === "require" && expr.arguments[0] !== undefined && isBunTest(expr.arguments[0])) return { kind: "module" };
    const callee = resolve(expr.expression, bindings);

    // a configuration call (`test.each([...])`) gives back a function that declares; a declaration gives back nothing
    return callee?.kind === "fn" && callee.pending ? { ...callee, pending: false } : null;
  }

  return null;
}

/**
 * Every name that stands for bun:test or one of its test functions: the globals test, it and describe, imports from
 * bun:test (renamed, namespace or default), and variables bound to any of those (`const check = test`, `const fit =
 * test.only`, `const { test: t } = bt`, `require("bun:test")`), in any order.
 */
function bindingsOf(file: ts.SourceFile): Map<string, Ref> {
  const bindings = new Map<string, Ref>([
    ["test", { kind: "fn", fn: "test", focused: false, pending: false }],
    ["it", { kind: "fn", fn: "test", focused: false, pending: false }],
    ["describe", { kind: "fn", fn: "describe", focused: false, pending: false }],
  ]);

  const aliases: { name: ts.BindingName; init: ts.Expression }[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && isBunTest(node.moduleSpecifier) && node.importClause !== undefined) {
      const clause = node.importClause;

      if (clause.name !== undefined) bindings.set(clause.name.text, { kind: "module" });
      const named = clause.namedBindings;

      if (named !== undefined && ts.isNamespaceImport(named)) bindings.set(named.name.text, { kind: "module" });

      if (named !== undefined && ts.isNamedImports(named)) {
        for (const spec of named.elements) {
          const r = member({ kind: "module" }, (spec.propertyName ?? spec.name).text);

          if (r !== null) bindings.set(spec.name.text, r);
        }
      }
    }

    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) aliases.push({ name: node.name, init: node.initializer });
    ts.forEachChild(node, visit);
  };

  visit(file);

  // an alias of an alias may come before it: repeat until nothing new is bound
  for (let changed = true; changed; ) {
    changed = false;

    for (const a of aliases) {
      const r = resolve(a.init, bindings);

      if (r === null) continue;

      const bind = (name: string, ref: Ref | null): void => {
        if (ref === null || JSON.stringify(bindings.get(name)) === JSON.stringify(ref)) return;
        bindings.set(name, ref);
        changed = true;
      };

      if (ts.isIdentifier(a.name)) bind(a.name.text, r);
      else if (ts.isObjectBindingPattern(a.name)) {
        for (const el of a.name.elements) {
          const prop = el.propertyName ?? el.name;

          if (ts.isIdentifier(el.name) && (ts.isIdentifier(prop) || ts.isStringLiteralLike(prop))) bind(el.name.text, member(r, prop.text));
        }
      }
    }
  }

  return bindings;
}

/** One file's declared tests' lines, and the lines that focus its run. */
export type FileInventory = { declared: readonly number[]; focused: readonly number[] };

/**
 * A test file's inventory, read from its syntax (review of efef668, finding 4): each call that declares a test, by
 * whatever name it reaches bun:test's test or it, and the line its name argument starts on (as bun's report numbers
 * it); and each place a `.only` focuses a test or a suite, through any alias or modifier chain (`check.only.each`).
 */
export function inventoryOf(source: string): FileInventory {
  const file = ts.createSourceFile("test.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const bindings = bindingsOf(file);
  const declared: number[] = [];
  const focused = new Set<number>();
  const lineOf = (pos: number): number => file.getLineAndCharacterOfPosition(pos).line + 1;

  const visit = (node: ts.Node): void => {
    const m = memberName(node);

    if (m !== null && m.name === "only" && ts.isExpression(node)) {
      const r = resolve(node, bindings);

      if (r?.kind === "fn" && r.focused) focused.add(lineOf(node.getStart(file)));
    }

    if (ts.isCallExpression(node)) {
      const r = resolve(node.expression, bindings);

      if (r?.kind === "fn" && !r.pending) {
        if (r.fn === "test") declared.push(lineOf(node.arguments[0]?.getStart(file) ?? node.expression.getEnd()));

        if (r.focused) focused.add(lineOf(node.getStart(file)));
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(file);

  return { declared, focused: [...focused].sort((a, b) => a - b) };
}

/** The line of each test one file declares, as bun's report numbers it: the line its name argument starts on. */
export function declaredLines(source: string): number[] {
  return [...inventoryOf(source).declared];
}

/** The number of tests one file declares. */
export function declaredTests(source: string): number {
  return declaredLines(source).length;
}

/** The lines of a file that focus its run (`.only`), which the gate refuses. */
export function focusedLines(source: string): number[] {
  return [...inventoryOf(source).focused];
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

/** Per file, its inventory. */
export type Inventory = ReadonlyMap<string, FileInventory>;

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
