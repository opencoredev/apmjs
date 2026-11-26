// A project's registry setting in a file git ignores: it works on this machine only, so a clone or CI installs from npm.
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative } from "node:path";
import { z } from "zod";
import { parseNpmrc, sameRegistry } from "./config.ts";

const BunfigRegistry = z.object({ install: z.object({ registry: z.union([z.string(), z.object({ url: z.string() }).loose().transform((o) => o.url)]).optional() }).loose().optional() }).loose();

const YarnrcRegistry = z.object({ npmRegistryServer: z.string().optional() }).loose();

/** How long one `git check-ignore` may take before apm stops waiting and says nothing. */
const GIT_TIMEOUT_MS = 2_000;

/** The registry a project config file sets, by its name; null when it sets none or apm cannot read it. */
function registryIn(path: string): string | null {
  try {
    const text = readFileSync(path, "utf8");

    if (path.endsWith(".npmrc")) return parseNpmrc(text).get("registry") ?? null;

    if (path.endsWith("bunfig.toml")) return BunfigRegistry.safeParse(Bun.TOML.parse(text)).data?.install?.registry ?? null;

    return YarnrcRegistry.safeParse(Bun.YAML.parse(text)).data?.npmRegistryServer ?? null;
  } catch {
    return null;
  }
}

/** Whether `dir` is inside a git work tree: a .git folder (or a worktree's .git file) in it or above it. */
function inGitTree(dir: string): boolean {
  for (let d = dir; ; d = dirname(d)) {
    if (existsSync(join(d, ".git"))) return true;

    if (dirname(d) === d) return false;
  }
}

/**
 * The project config files that point installs at `registry` (.npmrc from `cwd` up to `root`, bunfig.toml and
 * .yarnrc.yml at `root`) and that git ignores, relative to `cwd`. Empty outside a git work tree, without git, or
 * when git does not answer in time: this only ever adds a warning, never a failure or a wait.
 */
export function ignoredRegistryFiles(input: { cwd: string; root: string; registry: string }): string[] {
  if (!inGitTree(input.root) || Bun.which("git") === null) return [];
  const npmrcs: string[] = [];
  const below = relative(input.root, input.cwd);

  // a cwd outside the project (never, from apm add) reads only the project's own
  for (let d = below.startsWith("..") || isAbsolute(below) ? input.root : input.cwd; ; d = dirname(d)) {
    npmrcs.push(join(d, ".npmrc"));

    if (d === input.root || dirname(d) === d) break;
  }

  return [...npmrcs, join(input.root, "bunfig.toml"), join(input.root, ".yarnrc.yml")].flatMap((f) => {
    const set = existsSync(f) ? registryIn(f) : null;

    if (set === null || !sameRegistry(set, input.registry)) return [];
    // tracked files are never reported as ignored, so a committed .npmrc that a .gitignore also names passes
    const r = Bun.spawnSync(["git", "check-ignore", "-q", "--", f], { cwd: dirname(f), stdin: "ignore", stdout: "ignore", stderr: "ignore", timeout: GIT_TIMEOUT_MS });

    return r.exitCode === 0 ? [relative(input.cwd, f) || f] : [];
  });
}
