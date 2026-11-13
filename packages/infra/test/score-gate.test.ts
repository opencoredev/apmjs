// Review of 2a098b1, finding 13: the release score printed 0 and exited 0 while a test failed, because describe.each
// made passes outnumber the statically declared tests. These run the real scripts/score.ts on small test directories,
// and check the arithmetic on its own.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { declaredLines, declaredTests, focusedLines, gateScore } from "../../../scripts/score-gate.ts";

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

    expect(r.score, r.out).toBe("1");
    expect(r.code).toBe(1);
    expect(r.out).toContain("(focused) acceptance/only.test.ts:3");
    expect(r.out).toContain("(not run) acceptance/only.test.ts:5: the test declared there never ran");
  });

  test("a describe.only focuses the run too", async () => {
    const r = await score({ "d.test.ts": 'import { describe, test } from "bun:test";\ndescribe.only("a", () => {\n  test("x", () => {});\n});\n' });

    expect(r.score, r.out).toBe("1");
    expect(r.code).toBe(1);
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

  test("declarations count test.each and test.skip, not describe", () => {
    expect(declaredTests('describe("x", () => {\n  test("a", () => {});\n  test.each([1])("b %d", () => {});\n  it.skip("c", () => {});\n});\n')).toBe(3);
  });
});
