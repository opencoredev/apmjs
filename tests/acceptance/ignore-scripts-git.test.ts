// Review of 4a9c8fb, finding 1: npm runs a git dependency's `prepare` while it installs, --ignore-scripts or not, so
// `apm add --ignore-scripts` (and apm x, and apm add with no packages) ran a dependency's code. The reviewer's
// reproducer: a registry package whose dependency is a local git repository with a prepare script.
//
// With scripts ignored, apm now refuses before anything is installed when the lockfile the package manager computed
// holds a dependency that is not a registry version, and names it. Real npm, pnpm and bun against the real registry;
// the git repository's prepare only writes a marker file.
//
// Review of 96f0ba7, finding 1: npm builds a git dependency while it computes the lockfile (its tree builder extracts
// the repository and its directory packer runs prepare), before apm can read that lockfile. So with scripts ignored apm
// never starts npm: a logging stand-in for npm and npx first on PATH proves no npm process ran.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { treeHash } from "../../packages/cli/test/fixtures/tree-hash.ts";
import { addUser, apm, makeSandbox, run, startRegistry, writePackage, writeProjectConfig, type Registry } from "./harness";

type Pm = "pnpm" | "bun";

/** The package managers apm runs with scripts ignored; npm is refused before it starts (its own describe below). */
const PMS: readonly Pm[] = ["pnpm", "bun"];
const DAY = 24 * 60 * 60 * 1000;
let clock = Date.parse("2026-10-01T00:00:00Z");
let reg: Registry;
let alice: string;
let work: string;
let marks: string;
let gitUrl: string;
let bundleUrl: string;
let spy: ReturnType<typeof npmSpy>;

/** npm and npx stand-ins that log every start, then run the real one: an empty log means npm never started. */
function npmSpy() {
  const dir = join(work, "spy-bin");
  const log = join(work, "npm-starts.log");

  mkdirSync(dir);

  for (const tool of ["npm", "npx"]) {
    const real = Bun.which(tool);

    if (real === null) throw new Error(`${tool} is not installed`);
    writeFileSync(join(dir, tool), `#!/bin/sh\nprintf '%s\\n' "${tool} $*" >> ${JSON.stringify(log)}\nexec ${JSON.stringify(real)} "$@"\n`, { mode: 0o755 });
  }

  return { dir, log };
}

/** `env` with `dir` first on its PATH. */
function onPath(dir: string, env: Record<string, string>) {
  return { ...env, PATH: `${dir}:${env.PATH ?? ""}` };
}

const npmStarts = (): string[] => (existsSync(spy.log) ? readFileSync(spy.log, "utf8").trim().split("\n").filter((l) => l !== "") : []);

/**
 * A git repository whose prepare script leaves a marker: any marker means a dependency's code ran. `bundled`: it also
 * bundles a dependency (committed in its node_modules), which makes npm extract and pack it, prepare included, while it
 * only computes a lockfile (review of 96f0ba7, finding 1).
 */
function gitFixture(name: string, bundled: boolean): string {
  const repo = join(work, name);
  const env = { PATH: process.env.PATH ?? "", HOME: work, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };

  mkdirSync(repo);
  const bundle = bundled ? { dependencies: { inner: "1.0.0" }, bundleDependencies: ["inner"] } : {};

  writeFileSync(join(repo, "package.json"), JSON.stringify({ name, version: "1.0.0", main: "index.js", scripts: { prepare: "node mark.js" }, ...bundle }));
  writeFileSync(join(repo, "mark.js"), `require("node:fs").writeFileSync(require("node:path").join(${JSON.stringify(marks)}, "prepare-${name}-" + process.pid), "ran");\n`);
  writeFileSync(join(repo, "index.js"), "module.exports = 1;\n");

  if (bundled) {
    mkdirSync(join(repo, "node_modules", "inner"), { recursive: true });
    writeFileSync(join(repo, "node_modules", "inner", "package.json"), JSON.stringify({ name: "inner", version: "1.0.0" }));
  }

  for (const args of [["init", "-q", "-b", "main"], ["add", "-f", "."], ["-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-qm", "fixture"]]) {
    const r = Bun.spawnSync(["git", ...args], { cwd: repo, env });

    if (r.exitCode !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr.toString()}`);
  }

  return `git+file://${repo}`;
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice");
  work = mkdtempSync(join(tmpdir(), "apm-ignore-git-"));
  marks = mkdtempSync(join(work, "marks-"));
  gitUrl = gitFixture("gitdep", false);
  bundleUrl = gitFixture("gitbundle", true);
  spy = npmSpy();

  const publish = async (spec: Parameters<typeof writePackage>[1]): Promise<void> => {
    const sb = makeSandbox(reg, alice);
    const r = await run(["bun", "publish"], { cwd: writePackage(work, spec, reg, alice), env: sb.env });

    if (r.code !== 0) throw new Error(`publish ${spec.name}: ${r.out}`);
  };

  await publish({ name: "plainleaf", version: "1.0.0" });
  // the reviewer's harder case: the git dependency bundles one of its own (on the registry too: bun resolves it there)
  await publish({ name: "inner", version: "1.0.0" });
  await publish({ name: "bundleparent", version: "1.0.0", dependencies: { gitbundle: bundleUrl }, extra: { bin: { bundleparent: "cli.js" } }, files: { "index.js": "module.exports = 1;\n", "cli.js": "#!/usr/bin/env node\nconsole.log('bundleparent ran');\n" } });
  // the reproducer: a registry version whose one dependency is the git repository
  await publish({ name: "gitparent", version: "1.0.0", dependencies: { gitdep: gitUrl }, extra: { bin: { gitparent: "cli.js" } }, files: { "index.js": "module.exports = 1;\n", "cli.js": "#!/usr/bin/env node\nconsole.log('gitparent ran');\n" } });
  clock += 10 * DAY;
}, 120_000);

afterAll(async () => {
  await reg?.stop();
  rmSync(work, { recursive: true, force: true });
});

/** How a test asks apm to ignore scripts: the flag, or the environment. */
type How = { name: string; args: string[]; env: Record<string, string> };

const HOWS: readonly How[] = [
  { name: "--ignore-scripts", args: ["--ignore-scripts"], env: {} },
  { name: "APM_IGNORE_SCRIPTS=1", args: [], env: { APM_IGNORE_SCRIPTS: "1" } },
];

const ran = (): string[] => readdirSync(marks).sort();

function clearMarks(): void {
  for (const m of readdirSync(marks)) rmSync(join(marks, m));
}

/** A project with these dependencies and nothing installed, configured for the test registry. */
function project(deps: Record<string, string> = {}) {
  const sb = makeSandbox(reg, alice);
  const root = mkdtempSync(join(work, "app-"));

  writeProjectConfig(root, reg, alice);
  // trusted (bun) and allowed to build (pnpm), so only --ignore-scripts or apm holds a script back
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0", private: true, dependencies: deps, trustedDependencies: ["gitdep", "gitbundle"], pnpm: { onlyBuiltDependencies: ["gitdep", "gitbundle"] } }, null, 2));

  return { root, env: { ...sb.env, npm_config_store_dir: join(sb.home, ".pnpm-store"), TMPDIR: tmpdir() } };
}

/**
 * Whether this npm runs a git dependency's prepare with --ignore-scripts. npm 11.0.0 made --ignore-scripts cover
 * prepare ("applies to all lifecycle scripts, include prepare", its breaking changes); 10.9.9 still runs it. apm
 * refuses npm with scripts ignored in either case, since npm 10 is still in use and npm still clones the repository.
 */
async function npmRunsGitPrepare(env: Record<string, string>): Promise<boolean> {
  const v = await run(["npm", "--version"], { cwd: tmpdir(), env });
  const major = Number(/^(\d+)\./.exec(v.stdout.trim())?.[1]);

  expect(Number.isFinite(major), v.out).toBe(true);

  return major < 11;
}

test("the reproducer: npm install --ignore-scripts of the registry package runs the git dependency's prepare (npm 10 and older)", async () => {
  clearMarks();
  const p = project();
  const prepares = await npmRunsGitPrepare(p.env);
  const r = await run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "gitparent@1.0.0"], { cwd: p.root, env: p.env, timeoutMs: 120_000 });

  expect(r.code, r.out).toBe(0);
  expect(existsSync(join(p.root, "node_modules", "gitdep", "package.json")), r.out).toBe(true);
  expect(ran().length > 0, prepares ? "npm 10 ran gitdep's prepare despite --ignore-scripts" : "npm 11 holds back gitdep's prepare with --ignore-scripts").toBe(prepares);
});

test("the reproducer, lockfile only: npm install --package-lock-only --ignore-scripts clones the git dependency, and runs the prepare of one that bundles", async () => {
  // what apm on 96f0ba7 ran to compute the lockfile it then checked: by then npm had cloned the repository, and for a
  // git dependency with bundled dependencies it had packed it, running its prepare (npm 9.2)
  const gitLog = join(work, "git-starts.log");
  const gitSpy = join(work, "git-spy");

  mkdirSync(gitSpy, { recursive: true });
  writeFileSync(join(gitSpy, "git"), `#!/bin/sh\nprintf '%s\\n' "git $*" >> ${JSON.stringify(gitLog)}\nexec ${JSON.stringify(Bun.which("git"))} "$@"\n`, { mode: 0o755 });

  for (const [name, repo, prepares] of [["gitparent", "gitdep", false], ["bundleparent", "gitbundle", true]] as const) {
    clearMarks();
    rmSync(gitLog, { force: true });
    const p = project();
    const npmPrepares = await npmRunsGitPrepare(p.env);
    const r = await run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", `${name}@1.0.0`], { cwd: p.root, env: onPath(gitSpy, p.env), timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(0);
    expect(existsSync(join(p.root, "node_modules")), r.out).toBe(false);
    expect(readFileSync(gitLog, "utf8"), "npm cloned the git dependency while computing the lockfile").toContain(`clone file://${join(work, repo)}`);
    expect(ran().length > 0, `npm ran ${repo}'s prepare while computing the lockfile (npm 10 and older, a dependency that bundles)`).toBe(prepares && npmPrepares);
  }
});

/** What the npm tests run: apm command and arguments, and the project's dependencies. */
type NpmCase = { name: string; args: string[]; deps: Record<string, string> };

const NPM_CASES: readonly NpmCase[] = [
  { name: "apm add gitparent@1.0.0", args: ["add", "gitparent@1.0.0"], deps: {} },
  { name: "apm add (no packages) for a project depending on it", args: ["add"], deps: { gitparent: "1.0.0" } },
  { name: "apm x gitparent@1.0.0", args: ["x", "gitparent@1.0.0"], deps: {} },
  { name: "apm add bundleparent@1.0.0", args: ["add", "bundleparent@1.0.0"], deps: {} },
  { name: "apm x bundleparent@1.0.0", args: ["x", "bundleparent@1.0.0"], deps: {} },
  { name: "apm add plainleaf@1.0.0 (registry versions only)", args: ["add", "plainleaf@1.0.0"], deps: {} },
];

describe("with npm and scripts ignored, npm is never started", () => {
  const spied = (env: Record<string, string>) => onPath(spy.dir, env);

  beforeAll(() => {
    rmSync(spy.log, { force: true });
  });

  test("control: the stand-in logs a start", async () => {
    const p = project();
    const r = await run(["npm", "--version"], { cwd: p.root, env: spied(p.env) });

    expect(r.code, r.out).toBe(0);
    expect(npmStarts()).toEqual(["npm --version"]);
    rmSync(spy.log, { force: true });
  });

  test("control: without --ignore-scripts, apm add through the stand-in starts npm (so an empty log below means npm never ran)", async () => {
    const p = project();
    const r = await apm(["add", "--pm", "npm", "plainleaf@1.0.0"], { cwd: p.root, env: spied(p.env), timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(0);
    expect(npmStarts().some((l) => l.startsWith("npm install --package-lock-only")), npmStarts().join("\n")).toBe(true);
    rmSync(spy.log, { force: true });
  });

  for (const how of HOWS) {
    for (const what of NPM_CASES) {
      test(`${what.name} (${how.name}) is refused before npm starts; no prepare runs and the project is unchanged`, async () => {
        clearMarks();
        const p = project(what.deps);
        const before = treeHash(p.root);
        const [cmd = "", ...rest] = what.args;
        const r = await apm([cmd, "--pm", "npm", ...how.args, ...rest], { cwd: p.root, env: spied({ ...p.env, ...how.env }), timeoutMs: 120_000 });

        expect(r.code, r.out).toBe(1);
        expect(r.out).toContain("refused: with --ignore-scripts apm does not run npm");
        expect(r.out).toContain(`apm ${cmd} --pm bun or --pm pnpm`);
        expect(npmStarts(), r.out).toEqual([]);
        expect(ran(), r.out).toEqual([]);
        expect(r.out).not.toMatch(/(git|bundle)parent ran/);
        expect(treeHash(p.root).lines, r.out).toEqual(before.lines);
      });
    }
  }

  test("apm x under yarn (which uses npm) is refused the same way", async () => {
    const p = project();
    const r = await apm(["x", "--pm", "yarn", "--ignore-scripts", "gitparent@1.0.0"], { cwd: p.root, env: spied(p.env), timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(1);
    expect(r.out).toContain("refused: with --ignore-scripts apm does not run npm");
    expect(npmStarts(), r.out).toEqual([]);
  });
});

describe.each(PMS)("with the real %s and scripts ignored", (pm) => {
  for (const parent of [{ name: "gitparent", dep: "gitdep" }, { name: "bundleparent", dep: "gitbundle" }]) {
    const named = new RegExp(`${parent.dep} \\(git: (git\\+)?file://`);

    for (const how of HOWS) {
      test(`apm add (${how.name}) of ${parent.name} is refused before anything installs, and no prepare runs`, async () => {
        clearMarks();
        const p = project();
        const before = treeHash(p.root);
        const r = await apm(["add", `${parent.name}@1.0.0`, "--pm", pm, ...how.args], { cwd: p.root, env: { ...p.env, ...how.env }, timeoutMs: 120_000 });

        expect(r.code, r.out).toBe(1);
        expect(r.out).toContain("refused: with --ignore-scripts apm installs only registry versions");
        expect(r.out).toMatch(named);
        expect(r.out).toContain("Nothing was installed or run, and your project is unchanged.");
        expect(ran(), r.out).toEqual([]);
        expect(treeHash(p.root).lines, r.out).toEqual(before.lines);
      });
    }

    test(`apm x --ignore-scripts of ${parent.name} is refused before anything installs, and neither prepare nor the binary runs`, async () => {
      clearMarks();
      const p = project();
      const r = await apm(["x", "--pm", pm, "--ignore-scripts", `${parent.name}@1.0.0`], { cwd: p.root, env: p.env, timeoutMs: 120_000 });

      expect(r.code, r.out).toBe(1);
      expect(r.out).toMatch(named);
      expect(r.out).toContain("apm installed nothing and ran no install script and no binary.");
      expect(r.out).not.toContain(`${parent.name} ran`);
      expect(ran(), r.out).toEqual([]);
    });

    test(`apm add with no packages and --ignore-scripts, for a project that depends on ${parent.name}: refused, nothing installed, project unchanged`, async () => {
      clearMarks();
      const p = project({ [parent.name]: "1.0.0" });
      const before = treeHash(p.root);
      const r = await apm(["add", "--pm", pm, "--ignore-scripts"], { cwd: p.root, env: p.env, timeoutMs: 120_000 });

      expect(r.code, r.out).toBe(1);
      expect(r.out).toMatch(named);
      expect(ran(), r.out).toEqual([]);
      expect(existsSync(join(p.root, "node_modules")), r.out).toBe(false);
      expect(treeHash(p.root).lines, r.out).toEqual(before.lines);
    });
  }

  test("apm add with no packages and --ignore-scripts still installs a project of registry versions, from the lockfile it computed", async () => {
    const p = project({ plainleaf: "1.0.0" });
    const r = await apm(["add", "--pm", pm, "--ignore-scripts"], { cwd: p.root, env: p.env, timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("no install script ran (--ignore-scripts)");
    expect(JSON.parse(readFileSync(join(p.root, "node_modules", "plainleaf", "package.json"), "utf8")).version).toBe("1.0.0");
  });

  test("apm add --ignore-scripts of a registry package with only registry dependencies still installs it", async () => {
    const p = project();
    const r = await apm(["add", "plainleaf@1.0.0", "--pm", pm, "--ignore-scripts"], { cwd: p.root, env: p.env, timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(0);
    expect(JSON.parse(readFileSync(join(p.root, "node_modules", "plainleaf", "package.json"), "utf8")).version).toBe("1.0.0");
  });
});
