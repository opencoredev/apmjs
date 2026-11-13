// A stand-in npm, pnpm, bun or yarn for the CLI's tests: `bun fake-pm.ts <pm> <args...>`. It records each call (with
// the directory it ran in) in $APM_FAKE_DIR/pm.log and acts out what a test describes in $APM_FAKE_DIR/scenario.json:
// a lockfile-only add writes the scenario's lockfile and package.json entries where it runs and installs nothing; a
// frozen install lays the scenario's node_modules; a rebuild (or bun's install with scripts on, or yarn's install)
// records which install scripts it would run in `scripts-ran`. `yarn --version` prints the scenario's yarn version.
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";

/** A package directory the install lays: `path` relative to the install root, `raw` a package.json that is not JSON, `bare` none at all. */
export const Module = z.object({ path: z.string(), name: z.string(), version: z.string(), bin: z.string().optional(), raw: z.string().optional(), bare: z.boolean().optional() });

export const Scenario = z.object({
  /** The lockfile the add computes, relative to where the add runs (a workspace member writes ../../<lockfile>). */
  lockAt: z.string(),
  lock: z.string(),
  /** Entries the add puts in package.json's dependencies. */
  deps: z.record(z.string(), z.string()),
  /** node_modules after the install, relative to the install root. */
  modules: z.array(Module),
  /** A file the add also changes where it runs (relative to there), which apm never copies back. */
  alsoChanges: z.string().optional(),
  /** A file of the real project the add edits while apm checks (someone else editing the project). */
  editsProject: z.string().optional(),
  /** What the install writes over the lockfile (a package manager that does not keep it frozen). */
  installRewritesLock: z.string().optional(),
  /** The add fails with this exit code. */
  addFails: z.number().optional(),
  /** The install keeps what node_modules held, laying `modules` over it (a package left from before stays). */
  keep: z.boolean().optional(),
  yarnVersion: z.string().optional(),
});

export type Scenario = z.infer<typeof Scenario>;

const [pm = "npm", ...args] = process.argv.slice(2);
const dir = process.env.APM_FAKE_DIR ?? "";
const cwd = process.cwd();

// `production`: pnpm reads a production install from npm_config_production, which apm sets for its rebuild
appendFileSync(join(dir, "pm.log"), `${JSON.stringify({ pm, args, cwd, production: process.env.npm_config_production })}\n`);

const scenario = Scenario.parse(JSON.parse(readFileSync(join(dir, "scenario.json"), "utf8")));
const ran = (what: string): void => appendFileSync(join(dir, "scripts-ran"), `${what}\n`);

/** node_modules holds exactly `modules` (with `keep`, what it held besides). */
function lay(modules: readonly z.infer<typeof Module>[]): void {
  if (scenario.keep !== true) rmSync(join(cwd, "node_modules"), { recursive: true, force: true });

  for (const m of modules) {
    const at = join(cwd, m.path);

    mkdirSync(at, { recursive: true });

    // `bare`: code with no package.json at all
    if (m.bare === true) {
      writeFileSync(join(at, "index.js"), "module.exports = 'unnamed';\n");
      continue;
    }

    writeFileSync(join(at, "package.json"), m.raw ?? JSON.stringify({ name: m.name, version: m.version, bin: m.bin === undefined ? undefined : { [m.name]: "cli.sh" } }));

    if (m.bin !== undefined) {
      const bin = join(cwd, "node_modules", ".bin", m.name);

      mkdirSync(dirname(bin), { recursive: true });
      writeFileSync(bin, m.bin);
      chmodSync(bin, 0o755);
    }
  }
}

const verb = args[0] ?? "";
const specs = args.slice(1).filter((a) => !a.startsWith("-") && a !== "update-lockfile");
const lockOnly = args.includes("--package-lock-only") || args.includes("--lockfile-only") || (pm === "yarn" && args.includes("update-lockfile"));
const adds = (pm === "npm" ? verb === "install" : verb === "add") && specs.length > 0;

function writeAdd(): void {
  const pj = z.object({ dependencies: z.record(z.string(), z.string()).optional() }).loose().parse(JSON.parse(readFileSync(join(cwd, "package.json"), "utf8")));

  writeFileSync(join(cwd, scenario.lockAt), scenario.lock);
  writeFileSync(join(cwd, "package.json"), JSON.stringify({ ...pj, dependencies: { ...pj.dependencies, ...scenario.deps } }));

  if (scenario.alsoChanges !== undefined) appendFileSync(join(cwd, scenario.alsoChanges), "\n# changed by the add\n");

  if (scenario.editsProject !== undefined) appendFileSync(scenario.editsProject, " ");
}

if (pm === "yarn" && verb === "--version") {
  process.stdout.write(`${scenario.yarnVersion ?? "1.22.22"}\n`);
} else if (adds && lockOnly) {
  if (scenario.addFails !== undefined) process.exit(scenario.addFails);
  writeAdd();
} else if (adds) {
  // an add that installs (classic yarn): lockfile, package.json, node_modules, and its scripts run
  writeAdd();
  lay(scenario.modules);
  ran(`${pm} ${args.join(" ")}`);
} else if (verb === "rebuild") {
  ran(`${pm} ${args.join(" ")}`);
} else if (verb === "ci" || verb === "install") {
  if (existsSync(join(cwd, "node_modules")) && pm === "bun" && !args.includes("--ignore-scripts")) {
    // bun installs again what apm removed, running its scripts
    lay(scenario.modules);
    ran(`${pm} ${args.join(" ")}`);
  } else {
    lay(scenario.modules);

    if (scenario.installRewritesLock !== undefined) writeFileSync(join(cwd, scenario.lockAt.split("/").at(-1) ?? scenario.lockAt), scenario.installRewritesLock);

    if (pm === "yarn") ran(`${pm} ${args.join(" ")}`);
  }
}
