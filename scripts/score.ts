// Climb score: number of acceptance tests that did not pass.
// Counts declared tests statically, so a crash in setup cannot hide failures.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = join(import.meta.dir, "..", "tests", "acceptance");
const files = readdirSync(dir).filter((f) => f.endsWith(".test.ts"));
let declared = 0;

for (const f of files) {
  const src = readFileSync(join(dir, f), "utf8");
  declared += (src.match(/^\s*test\(/gm) ?? []).length;
}

// Every sandbox, registry data dir and package-manager cache the tests make lands under one
// TMPDIR that is removed afterwards, so repeated runs can't fill /tmp.
const scratch = mkdtempSync(join(tmpdir(), "apm-score-run-"));
const proc = Bun.spawn(["bun", "test", "--timeout", "90000", dir], { stdout: "pipe", stderr: "pipe", env: { ...process.env, NO_COLOR: "1", TMPDIR: scratch } });
let out: string;
let err: string;

try {
  [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

const text = out + err;

// bun prints its summary last ("  278 pass"); a test that runs bun test inside itself prints an earlier one,
// so read the final summary line, not the first match.
const summaries = [...text.matchAll(/^\s*(\d+) pass$/gm)];
const pass = Number(summaries.at(-1)?.[1] ?? 0);
const failedNames = text.split("\n").filter((l) => l.startsWith("(fail)"));

process.stdout.write(failedNames.join("\n") + "\n");

process.stdout.write(`declared=${declared} pass=${pass}\n`);

process.stdout.write(`${Math.max(0, declared - pass)}\n`);
