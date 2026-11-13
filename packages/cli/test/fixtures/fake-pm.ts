// A stand-in npm, pnpm or bun for the CLI's tests: `bun fake-pm.ts <pm> <args...>`. It records each call, and acts out
// the install a test describes in $APM_FAKE_DIR: an add writes after.json's lockfile, package.json entries and
// node_modules; a frozen install or a remove puts node_modules back to before.json's; running install scripts (npm
// rebuild, pnpm rebuild, bun install without --ignore-scripts) leaves a `scripts-ran` marker.
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

/** A package in node_modules; `bin`, a script its binary (named like it) prints. */
const Module = z.object({ name: z.string(), version: z.string(), bin: z.string().optional() });
const After = z.object({ lockfile: z.string(), lock: z.string(), deps: z.record(z.string(), z.string()), modules: z.array(Module) });
const BeforeState = z.object({ modules: z.array(Module) });

const [pm = "npm", ...args] = process.argv.slice(2);
const dir = process.env.APM_FAKE_DIR ?? "";
const cwd = process.cwd();

appendFileSync(join(dir, "pm.log"), `${JSON.stringify({ pm, args })}\n`);

/** node_modules holds exactly `modules`, one flat directory each. */
function lay(modules: readonly z.infer<typeof Module>[]): void {
  rmSync(join(cwd, "node_modules"), { recursive: true, force: true });

  for (const m of modules) {
    const at = join(cwd, "node_modules", ...m.name.split("/"));

    mkdirSync(at, { recursive: true });
    writeFileSync(join(at, "package.json"), JSON.stringify({ name: m.name, version: m.version, bin: m.bin === undefined ? undefined : "cli.sh" }));

    if (m.bin !== undefined) {
      const bin = join(cwd, "node_modules", ".bin", m.name);

      mkdirSync(join(cwd, "node_modules", ".bin"), { recursive: true });
      writeFileSync(bin, `#!/bin/sh\necho ${JSON.stringify(m.bin)} "$@"\n`);
      chmodSync(bin, 0o755);
    }
  }
}

const specs = args.slice(1).filter((a) => !a.startsWith("-"));
const verb = args[0] ?? "";
const adds = (pm === "npm" ? verb === "install" : verb === "add") && specs.length > 0;
const restores = (verb === "install" && specs.length === 0 && (pm !== "bun" || args.includes("--ignore-scripts"))) || ["uninstall", "remove"].includes(verb);
const runsScripts = verb === "rebuild" || (pm === "bun" && verb === "install" && !args.includes("--ignore-scripts"));

if (adds) {
  const after = After.parse(JSON.parse(readFileSync(join(dir, "after.json"), "utf8")));
  const pj = z.object({ dependencies: z.record(z.string(), z.string()).optional() }).loose().parse(JSON.parse(readFileSync(join(cwd, "package.json"), "utf8")));

  writeFileSync(join(cwd, after.lockfile), after.lock);
  writeFileSync(join(cwd, "package.json"), JSON.stringify({ ...pj, dependencies: { ...pj.dependencies, ...after.deps } }));
  lay(after.modules);
} else if (restores) {
  const before = existsSync(join(dir, "before.json")) ? BeforeState.parse(JSON.parse(readFileSync(join(dir, "before.json"), "utf8"))) : { modules: [] };

  lay(before.modules);
} else if (runsScripts) {
  writeFileSync(join(dir, "scripts-ran"), args.join(" "));
}
