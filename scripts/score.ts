// Climb score: number of acceptance tests that did not pass.
// Counts declared tests statically, so a crash in setup cannot hide failures.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = join(import.meta.dir, "..", "tests", "acceptance");
const files = readdirSync(dir).filter((f) => f.endsWith(".test.ts"));
let declared = 0;
for (const f of files) {
  const src = readFileSync(join(dir, f), "utf8");
  declared += (src.match(/^\s*test\(/gm) ?? []).length;
}
const proc = Bun.spawn(["bun", "test", "--timeout", "90000", dir], { stdout: "pipe", stderr: "pipe", env: { ...process.env, NO_COLOR: "1" } });
const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
const text = out + err;
const pass = Number(/(\d+) pass/.exec(text)?.[1] ?? 0);
const failedNames = text.split("\n").filter((l) => l.startsWith("(fail)"));
process.stdout.write(failedNames.join("\n") + "\n");
process.stdout.write(`declared=${declared} pass=${pass}\n`);
process.stdout.write(`${Math.max(0, declared - pass)}\n`);
