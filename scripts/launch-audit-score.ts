// Launch-audit hill-climb score: number of launch-audit checks that did not pass.
// Counts declared tests statically so a setup crash cannot masquerade as 0 failures.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const dir = join(root, "tests", "launch-audit");
const webTest = join(root, "apps", "web", "test", "launch-audit.test.ts");
const files = [...readdirSync(dir).filter((f) => f.endsWith(".test.ts")).sort().map((f) => join(dir, f)), webTest];
let declared = 0;

for (const f of files) {
  const src = readFileSync(f, "utf8");

  declared += (src.match(/^\s*test\(/gm) ?? []).length;
}

const scratch = mkdtempSync(join(tmpdir(), "apm-launch-audit-"));

const proc = Bun.spawn(["bun", "test", "--timeout", "90000", ...files], {
  stdout: "pipe",
  stderr: "pipe",
  env: { ...process.env, NO_COLOR: "1", TMPDIR: scratch },
});

let out = "";
let err = "";

try {
  [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

const text = out + err;
const pass = Number(/(\d+) pass/.exec(text)?.[1] ?? 0);
const failed = text.split("\n").filter((l) => l.startsWith("(fail)") || l.startsWith("✗"));

if (failed.length > 0) process.stdout.write(`${failed.join("\n")}\n`);

process.stdout.write(`declared=${declared} pass=${pass}\n`);

process.stdout.write(`${Math.max(0, declared - pass)}\n`);
