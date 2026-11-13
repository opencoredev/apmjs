// Climb score: the number of acceptance tests that did not pass (scripts/score-gate.ts counts them). The last line is
// the score, and the process exits nonzero whenever it is not 0. `--dir <path>` scores another test directory.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { declaredTests, gateScore } from "./score-gate.ts";

const at = process.argv.indexOf("--dir");
const dir = at > 0 && process.argv[at + 1] !== undefined ? resolve(process.argv[at + 1] ?? "") : join(import.meta.dir, "..", "tests", "acceptance");
const cwd = resolve(dir, "..");
const files = readdirSync(dir).filter((f) => f.endsWith(".test.ts"));

// the JUnit report names each file relative to where bun test runs
const declared = new Map(files.map((f) => [relative(cwd, join(dir, f)), declaredTests(readFileSync(join(dir, f), "utf8"))]));

// Every sandbox, registry data dir and package-manager cache the tests make lands under one
// TMPDIR that is removed afterwards, so repeated runs can't fill /tmp.
const scratch = mkdtempSync(join(tmpdir(), "apm-score-run-"));
const junitPath = join(scratch, "junit.xml");
const proc = Bun.spawn(["bun", "test", "--timeout", "90000", "--reporter=junit", `--reporter-outfile=${junitPath}`, relative(cwd, dir) || "."], { cwd, stdout: "pipe", stderr: "pipe", env: { ...process.env, NO_COLOR: "1", TMPDIR: scratch } });
let text: string;
let junit = "";
let exitCode: number;

try {
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  text = out + err;
  exitCode = code;

  try {
    junit = readFileSync(junitPath, "utf8");
  } catch {
    // no report: the run crashed before writing it, and every declared test counts as not run
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

const gate = gateScore({ declared, junit, console: text, exitCode });

process.stdout.write(text.split("\n").filter((l) => l.startsWith("(fail)")).join("\n") + "\n");

for (const f of gate.files.filter((x) => x.declared > x.ran)) process.stdout.write(`(not run) ${f.file}: ${f.declared - f.ran} of ${f.declared} declared tests never ran\n`);

process.stdout.write(`declared=${[...declared.values()].reduce((a, b) => a + b, 0)} ran=${gate.files.reduce((a, f) => a + f.ran, 0)} pass=${gate.files.reduce((a, f) => a + f.passed, 0)} failed=${gate.failed} exit=${exitCode}\n`);

process.stdout.write(`${gate.score}\n`);

process.exitCode = gate.score === 0 ? 0 : 1;
