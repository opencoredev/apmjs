// Review of 2a098b1, finding 13: the release score printed 0 and exited 0 while a test failed, because describe.each
// made passes outnumber the statically declared tests. These run the real scripts/score.ts on small test directories,
// and check the arithmetic on its own.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { declaredTests, gateScore } from "../../../scripts/score-gate.ts";

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

  test("everything passing, describe.each included: 0, exit 0", async () => {
    const r = await score({ "pass.test.ts": each.replace("not.toBe(2)", "toBeGreaterThan(0)") });

    expect(r.score, r.out).toBe("0");
    expect(r.code).toBe(0);
  });
});

describe("gateScore", () => {
  const declared = new Map([["a.test.ts", 2]]);
  const passing = '<testcase name="one" file="a.test.ts" /><testcase name="two" file="a.test.ts" />';

  test("a (fail) line, a fail count or a nonzero exit each make the score at least 1", () => {
    expect(gateScore({ declared, junit: passing, console: "", exitCode: 0 }).score).toBe(0);
    expect(gateScore({ declared, junit: passing, console: "(fail) somewhere > x\n", exitCode: 0 }).score).toBe(1);
    expect(gateScore({ declared, junit: passing, console: " 1 fail\n", exitCode: 0 }).score).toBe(1);
    expect(gateScore({ declared, junit: passing, console: "", exitCode: 1 }).score).toBe(1);
  });

  test("skipped and todo tests did not pass", () => {
    expect(gateScore({ declared, junit: '<testcase name="one" file="a.test.ts" /><testcase name="two" file="a.test.ts"><skipped /></testcase>', console: "", exitCode: 0 }).score).toBe(1);
  });

  test("declarations count test.each and test.skip, not describe", () => {
    expect(declaredTests('describe("x", () => {\n  test("a", () => {});\n  test.each([1])("b %d", () => {});\n  it.skip("c", () => {});\n});\n')).toBe(3);
  });
});
