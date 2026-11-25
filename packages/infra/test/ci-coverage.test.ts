// Every test file in the repository runs somewhere in CI, or is named here with the reason it does not. A test directory
// CI never names passes CI by never running: packages/bun-scanner, packages/ai-review and tests/launch-audit were in
// that state, so a regression in them could not fail a pull request.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join, posix } from "node:path";
import { z } from "zod";

const ROOT = join(import.meta.dir, "..", "..", "..");

/** Test directories CI covers by other means than `bun test <path>`, or deliberately leaves to a local run. */
const ELSEWHERE = {
  "tests/acceptance": "scripts/score.ts runs it in the acceptance step and gates on every declared test",
  "tools/oxlint/anti-slop/rules": "the vendored anti-slop step runs each file with node",
  "tools/oxlint/anti-slop/effect/rules": "the vendored anti-slop step runs each file with node",
  "apps/web/test": "builds the site in workerd and needs Google Fonts over the network; a local check (CONTRIBUTING.md)",
} satisfies Record<string, string>;

const Workflow = z.object({ jobs: z.record(z.string(), z.object({ steps: z.array(z.object({ run: z.string().optional(), "working-directory": z.string().optional() })) })) });

/** Every path a `bun test` command in the CI workflow names, relative to the repository root. */
function ciTestPaths(): string[] {
  const wf = Workflow.parse(Bun.YAML.parse(readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8")));
  const paths: string[] = [];

  for (const job of Object.values(wf.jobs)) {
    for (const step of job.steps) {
      for (const m of (step.run ?? "").matchAll(/\bbun test((?:\s+[^\s;&|]+)+)/g)) {
        for (const arg of (m[1] ?? "").trim().split(/\s+/)) if (!arg.startsWith("-")) paths.push(posix.normalize(posix.join(step["working-directory"] ?? ".", arg)));
      }
    }
  }

  return paths;
}

function trackedTestFiles(): string[] {
  const out = Bun.spawnSync(["git", "ls-files", "*.test.ts", "*.test.tsx"], { cwd: ROOT });

  if (out.exitCode !== 0) throw new Error(`git ls-files failed: ${out.stderr.toString()}`);

  return out.stdout.toString().split("\n").filter((f) => f !== "");
}

const under = (file: string, dir: string): boolean => file === dir || file.startsWith(`${dir}/`);

describe("CI runs every test", () => {
  test("each tracked test file is under a path a CI `bun test` names, or is covered elsewhere for a stated reason", () => {
    const named = ciTestPaths();
    const files = trackedTestFiles();

    expect(files.length).toBeGreaterThan(0);
    const missed = files.filter((f) => !named.some((p) => under(f, p)) && !Object.keys(ELSEWHERE).some((d) => posix.dirname(f) === d));

    expect(missed).toEqual([]);
  });

  test("every exception still names a directory with tests, so the list cannot go stale", () => {
    const dirs = new Set(trackedTestFiles().map((f) => posix.dirname(f)));

    expect(Object.keys(ELSEWHERE).filter((d) => !dirs.has(d))).toEqual([]);
  });
});
