// Review of 2a098b1, finding 13: the release score printed 0 and exited 0 while a test failed, because describe.each
// made passes outnumber the statically declared tests. These run the real scripts/score.ts on small test directories,
// and check the arithmetic on its own.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { declaredLines, declaredTests, focusedLines, gateScore, inventoryOf } from "../../../scripts/score-gate.ts";

const SCORE = join(import.meta.dir, "..", "..", "..", "scripts", "score.ts");
const base = mkdtempSync(join(tmpdir(), "apm-score-gate-"));

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

let n = 0;

/** scripts/score.ts on a directory holding `files`: its last line (the score) and its exit code. */
async function score(files: Record<string, string>): Promise<{ score: string; code: number; out: string }> {
  const dir = join(base, `case-${++n}`, "acceptance");

  mkdirSync(dir, { recursive: true });

  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  const proc = Bun.spawn([process.execPath, SCORE, "--dir", dir], { stdout: "pipe", stderr: "pipe", env: { ...process.env, TMPDIR: base } });
  const [out, , code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  return { score: out.trim().split("\n").at(-1) ?? "", code, out };
}

const each = `import { describe, expect, test } from "bun:test";
describe.each([1, 2, 3])("case %d", (n) => {
  test("one", () => expect(n).toBeGreaterThan(0));
  test("two", () => expect(n).not.toBe(2));
});
`;

describe("scripts/score.ts", () => {
  test("a failing describe.each case: nonzero score and exit, though passes outnumber declarations (on 2a098b1: 0, exit 0)", async () => {
    const r = await score({ "each.test.ts": each });

    expect(r.score, r.out).toBe("1");
    expect(r.code).toBe(1);
    expect(r.out).toContain("(fail) case 2 > two");
  });

  test("a setup that throws: the tests it declared never ran, and count", async () => {
    const r = await score({ "pass.test.ts": each.replace("not.toBe(2)", "toBeGreaterThan(0)"), "setup.test.ts": 'import { beforeAll, test } from "bun:test";\nbeforeAll(() => { throw new Error("setup broke"); });\ntest("a", () => {});\ntest("b", () => {});\n' });

    expect(r.score, r.out).toBe("2");
    expect(r.code).toBe(1);
    expect(r.out).toContain("(not run) acceptance/setup.test.ts: 2 of 2 declared tests never ran");
  });

  test("a file that fails to import: its tests count as not run", async () => {
    const r = await score({ "broken.test.ts": 'import { test } from "bun:test";\nthrow new Error("import broke");\ntest("x", () => {});\n' });

    expect(r.score, r.out).toBe("1");
    expect(r.code).toBe(1);
  });

  test("review of 2b7767f, finding 8: test.only inside describe.each leaves an ordinary test unrun; the gate names both and fails (on 2b7767f: 0, exit 0)", async () => {
    const only = "import {describe,test,expect} from 'bun:test';\ndescribe.each([1,2,3])('row %s',()=>{\n  test.only('runs',()=>expect(1).toBe(1));\n});\ntest('must not disappear',()=>{throw new Error('unrun');});\n";
    const r = await score({ "only.test.ts": only });

    // the run cannot narrow to the focused test (score-preload.ts makes .only an error), so the ordinary one runs too
    expect(Number(r.score), r.out).toBeGreaterThanOrEqual(1);
    expect(r.code).toBe(1);
    expect(r.out).toContain("(focused) acceptance/only.test.ts:3");
    expect(r.out).toContain("(fail) must not disappear");
  });

  // review of efef668, finding 4: the reviewer's counterexample, a renamed import with .only.each
  test("an aliased check.only.each fails the gate, and the ordinary check still runs (on efef668: 0, exit 0)", async () => {
    const alias = "import {test as check,describe,expect} from 'bun:test';\ndescribe('aliased tests',()=>{\n  check.only.each([1,2,3])('focused %s',n=>expect(n).toBeGreaterThan(0));\n  check('must not disappear',()=>{throw new Error('unrun');});\n});\n";
    const r = await score({ "alias.test.ts": alias });

    expect(Number(r.score), r.out).toBeGreaterThanOrEqual(1);
    expect(r.code).toBe(1);
    expect(r.out).toContain("(focused) acceptance/alias.test.ts:3");
    expect(r.out).toMatch(/declared=2 /);
  });

  test("a focus the source hides from the inventory still fails the run: .only reached through a function argument", async () => {
    const hidden = "import { test } from 'bun:test';\nconst focus = (t: typeof test) => t.only;\nfocus(test)('focused', () => {});\ntest('ordinary', () => { throw new Error('unrun'); });\n";
    const r = await score({ "hidden.test.ts": hidden });

    expect(Number(r.score), r.out).toBeGreaterThanOrEqual(1);
    expect(r.code).toBe(1);
  });

  test("a describe.only focuses the run too", async () => {
    const r = await score({ "d.test.ts": 'import { describe, test } from "bun:test";\ndescribe.only("a", () => {\n  test("x", () => {});\n});\n' });

    expect(r.score, r.out).toBe("1");
    expect(r.code).toBe(1);
  });

  // review of a24c6aa, finding 3: the reviewer's fixture scored 0 with exit 0 while a failing test was skipped
  test("a focus through a helper's test.each result fails the run, and the ordinary test runs (on a24c6aa: 0, exit 0)", async () => {
    const derived = "import { test } from 'bun:test';\nconst rows = (t: typeof test) => t.each([1, 2, 3]);\nconst ordinary = (t: typeof test) => t('must run', () => { throw new Error('failed'); });\nrows(test).only('focused %d', () => {});\nordinary(test);\n";
    const r = await score({ "derived.test.ts": derived });

    expect(r.out).toContain("(focused) acceptance/derived.test.ts:4");
    expect(Number(r.score), r.out).toBeGreaterThanOrEqual(1);
    expect(r.code).toBe(1);
  });

  test("a focus no source reading can see is refused when it runs: .only of test.each, test.if, describe.each and skipIf results, chained too, by computed name", async () => {
    // no other test is declared, so a focus that is not refused leaves nothing unrun for the inventory to count; the same
    // file with the key "concurrent" is the control: it scores 0, so the refusal is the only thing that fails
    const pick = (expr: string, key: string) => `import { describe, test } from 'bun:test';\nconst key = [${JSON.stringify(key.slice(0, 2))}, ${JSON.stringify(key.slice(2))}].join('');\n(${expr} as any)[key]('focused %s', () => {});\n`;

    for (const expr of ["test.each([1, 2])", "test.if(true)", "describe.each([1])", "test.skipIf(false)", "test.if(true).each([1])"]) {
      const focused = await score({ "computed.test.ts": pick(expr, "only") });
      const control = await score({ "computed.test.ts": pick(expr, "concurrent") });

      expect([focused.code, control.code, control.score], `${expr}\n${focused.out}\n${control.out}`).toEqual([1, 0, "0"]);
    }
  }, 60_000);

  test("review of 137141c: a computed .only on xdescribe is refused too, so the failing test it would hide fails the run (on 137141c: 0)", async () => {
    // the reviewer's fixture: through the namespace and helpers, so the inventory declares nothing and only the runtime guard can refuse
    const src = "import * as bt from 'bun:test';\nconst key = ['on', 'ly'].join('');\nconst take = (f: any) => f[key];\nconst ordinary = (f: any) => f('ordinary', () => { throw Error('must run'); });\ntake(bt.xdescribe)('focus', () => {});\nordinary(bt.test);\n";
    const r = await score({ "x.test.ts": src });

    expect(r.code, r.out).toBe(1);
    expect(r.score).not.toBe("0");
  }, 60_000);

  // review of a24c6aa, finding 4: one alias name bound to test at file scope and to describe in a suite
  test("an alias name reused in another scope: the inventory finishes and counts each by its own binding (on a24c6aa: never finished)", async () => {
    const shadow = 'import { test, describe } from "bun:test";\nconst check = test;\ncheck("top", () => {});\ndescribe("inner", () => {\n  const check = describe;\n  check("group", () => {\n    test("nested", () => {});\n  });\n});\n';
    const r = await score({ "shadow.test.ts": shadow });

    expect(r.score, r.out).toBe("0");
    expect(r.code).toBe(0);
    expect(r.out).toContain("declared=2 ran=2 pass=2");
  }, 30_000);

  // review of a24c6aa, finding 6: reading .only must not throw, only calling it
  test("helpers that copy a test function's properties run as without the preload (on a24c6aa: 1)", async () => {
    const byValue = "import { test } from 'bun:test';\nfunction wrap(fn: any) {\n  const check: any = (...args: any[]) => fn(...args);\n  for (const name of Object.getOwnPropertyNames(fn)) {\n    if (['name', 'length', 'prototype', 'caller', 'arguments'].includes(name)) continue;\n    Object.defineProperty(check, name, { value: fn[name], configurable: true });\n  }\n  return check;\n}\nconst check = wrap(test);\ncheck('ordinary passing helper', () => {});\n";
    const byDescriptor = "import { test } from 'bun:test';\nconst copy = (fn: any) => {\n  const check: any = (...args: any[]) => fn(...args);\n  for (const name of Object.getOwnPropertyNames(fn)) Object.defineProperty(check, name, Object.getOwnPropertyDescriptor(fn, name)!);\n  return check;\n};\nconst check = copy(test);\ncheck('ordinary', () => {});\ncheck.each([1, 2])('rows %d', () => {});\n";
    const r = await score({ "value.test.ts": byValue, "descriptor.test.ts": byDescriptor });

    expect(r.score, r.out).toBe("0");
    expect(r.code).toBe(0);
  });

  test("calling .only copied onto a helper is still refused", async () => {
    const copied = (key: string) =>
      `import { test } from 'bun:test';\nconst copy = (fn: any) => {\n  const check: any = (...args: any[]) => fn(...args);\n  for (const name of Object.getOwnPropertyNames(fn)) Object.defineProperty(check, name, Object.getOwnPropertyDescriptor(fn, name)!);\n  return check;\n};\nconst key = [${JSON.stringify(key.slice(0, 2))}, ${JSON.stringify(key.slice(2))}].join('');\ncopy(test)[key]('focused', () => {});\ntest('ordinary', () => {});\n`;

    const [focused, control] = [await score({ "copied.test.ts": copied("only") }), await score({ "copied.test.ts": copied("concurrent") })];

    expect([focused.code, control.code, control.score], `${focused.out}\n${control.out}`).toEqual([1, 0, "0"]);
  });

  test("everything passing, describe.each included: 0, exit 0", async () => {
    const r = await score({ "pass.test.ts": each.replace("not.toBe(2)", "toBeGreaterThan(0)") });

    expect(r.score, r.out).toBe("0");
    expect(r.code).toBe(0);
  });
});

describe("gateScore", () => {
  const inventory = new Map([["a.test.ts", { declared: [1, 2], focused: [] }]]);
  const passing = '<testcase name="one" file="a.test.ts" line="1" /><testcase name="two" file="a.test.ts" line="2" />';

  test("a (fail) line, a fail count or a nonzero exit each make the score at least 1", () => {
    expect(gateScore({ inventory, junit: passing, console: "", exitCode: 0 }).score).toBe(0);
    expect(gateScore({ inventory, junit: passing, console: "(fail) somewhere > x\n", exitCode: 0 }).score).toBe(1);
    expect(gateScore({ inventory, junit: passing, console: " 1 fail\n", exitCode: 0 }).score).toBe(1);
    expect(gateScore({ inventory, junit: passing, console: "", exitCode: 1 }).score).toBe(1);
  });

  test("skipped and todo tests did not pass", () => {
    expect(gateScore({ inventory, junit: '<testcase name="one" file="a.test.ts" line="1" /><testcase name="two" file="a.test.ts" line="2"><skipped /></testcase>', console: "", exitCode: 0 }).score).toBe(1);
  });

  test("finding 8: extra runs of one declared test do not stand in for another that never ran", () => {
    const g = gateScore({ inventory, junit: '<testcase name="one" file="a.test.ts" line="1" /><testcase name="one" file="a.test.ts" line="1" /><testcase name="one" file="a.test.ts" line="1" />', console: "", exitCode: 0 });

    expect(g.score).toBe(1);
    expect(g.files[0]?.missing).toEqual([2]);
  });

  test("finding 8: a focused file fails the gate even when every case passed", () => {
    expect(gateScore({ inventory: new Map([["a.test.ts", { declared: [1, 2], focused: [1] }]]), junit: passing, console: "", exitCode: 0 }).score).toBe(1);
  });

  test("a declaration's line is the line its name starts on, as bun reports it", () => {
    expect(declaredLines('test("a", () => {});\ntest(\n  "b",\n  () => {},\n);\ntest.each([\n  [1],\n])("c %d", () => {});\n')).toEqual([1, 3, 8]);
  });

  test("focus is found in test.only, it.only, describe.only and .only( forms, not in comments", () => {
    expect(focusedLines('test.only("a", f);\nit.only("b", f);\ndescribe.only("c", f);\ndescribe.each([1]).only("d", f);\n// test.only is refused\ntest("e", f);\n')).toEqual([1, 2, 3, 4]);
  });

  test("review of 137141c: reading .only without calling it focuses nothing; calling it through the saved name does", () => {
    expect(focusedLines('import { test } from "bun:test";\nconst saved = test.only;\ntest("a", f);\n')).toEqual([]);
    expect(focusedLines('import { test } from "bun:test";\nconst saved = test.only;\nsaved("a", f);\n')).toEqual([3]);
  });

  test("review of efef668, finding 4: tests and focus found through renamed imports, namespaces, require and aliases", () => {
    const src = [
      "import { test as check, it as spec, describe as group } from 'bun:test';",
      "import * as bt from 'bun:test';",
      "const { test: t2 } = require('bun:test');",
      "const fit = check.only;",
      "const later = t3;",
      "const t3 = bt.test;",
      "group('g', () => {",
      "  check('a', f);",
      "  spec.skip('b', f);",
      "  check.only.each([1, 2])('c %d', f);",
      "  bt.it('d', f);",
      "  t2.if(true)('e', f);",
      "  fit('f', f);",
      "  later('g', f);",
      "  bt['test']['only']('h', f);",
      "  group.each([1])('i', () => {});",
      "  check.each.only;",
      "  other('not a test', f);",
      "  (check as typeof check).todo('j');",
      "});",
      "// check.only in a comment is not a focus",
      "const s = 'check.only(\"not code\")';",
    ].join("\n");

    const inv = inventoryOf(src);

    expect(inv.declared).toEqual([8, 9, 10, 11, 12, 13, 14, 15, 19]);
    // line 4 only reads check.only (review of 137141c): the focus is where it is called, through fit on line 13
    expect(inv.focused).toEqual([10, 13, 15]);
  });

  test("review of a24c6aa, finding 4: each binding of a reused name resolves on its own, and cycles end", () => {
    const shadow = 'import { test, describe } from "bun:test";\nconst check = test;\ncheck("top", () => {});\ndescribe("inner", () => {\n  const check = describe;\n  check("group", () => test("nested", () => {}));\n});\ncheck.only("f", () => {});\n';

    expect(inventoryOf(shadow)).toEqual({ declared: [3, 6, 8], focused: [8] });
    expect(inventoryOf("const a = b;\nconst b = a;\nconst c = c;\ntest('x', () => {});\n")).toEqual({ declared: [4], focused: [] });
    expect(inventoryOf("function f(test: any) {\n  test('not bun', () => {});\n}\n").declared).toEqual([]);
  });

  test("review of a24c6aa, finding 3: a .only call the inventory cannot resolve counts as focused; reading one does not", () => {
    const src = "import { test } from 'bun:test';\nconst rows = (t: typeof test) => t.each([1]);\nrows(test).only('a %d', f);\nhelper().only.each([1])('b', f);\nconst opts = { only: false };\nif (opts.only) {}\nconst n = options.only.length;\n";

    expect(inventoryOf(src).focused).toEqual([3, 4]);
  });

  test("a renamed import declares tests under its new name", () => {
    expect(inventoryOf("import { test as check } from 'bun:test';\ncheck('a', f);\n").declared).toEqual([2]);
  });

  test("declarations count test.each and test.skip, not describe", () => {
    expect(declaredTests('describe("x", () => {\n  test("a", () => {});\n  test.each([1])("b %d", () => {});\n  it.skip("c", () => {});\n});\n')).toBe(3);
  });
});
