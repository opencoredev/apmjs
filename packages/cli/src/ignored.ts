// A project's registry setting in a file git ignores: it works on this machine only, so a clone or CI installs from npm.
import { closeSync, existsSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { z } from "zod";
import { withoutSecrets } from "./child.ts";
import { sameRegistry } from "./config.ts";
import type { Pm } from "./pm.ts";

const BunfigRegistry = z.object({ install: z.object({ registry: z.union([z.string(), z.object({ url: z.string() }).loose().transform((o) => o.url)]).optional() }).loose().optional() }).loose();

const YarnrcRegistry = z.object({ npmRegistryServer: z.string().optional() }).loose();

const PackageManagerField = z.object({ packageManager: z.string().optional() }).loose();

const YarnPath = z.object({ yarnPath: z.string().optional() }).loose();

/** A config file larger than this is not read: a real one is a few lines, and this check only ever adds a warning. */
const MAX_CONFIG_BYTES = 256 * 1024;

/** A small file's text; null when it is missing, too large or unreadable. */
function smallText(path: string): string | null {
  try {
    return statSync(path).size <= MAX_CONFIG_BYTES ? readFileSync(path, "utf8") : null;
  } catch {
    return null;
  }
}

/**
 * Whether the project at `root` runs yarn 2 or later, the yarn that reads .yarnrc.yml (yarn 1 does not), without running
 * yarn: `packageManager` names yarn 2 or later, or yarn.lock is yarn 2's format (it starts with a __metadata entry).
 */
function yarnBerry(root: string): boolean {
  try {
    const pm = PackageManagerField.safeParse(JSON.parse(smallText(join(root, "package.json")) ?? "{}")).data?.packageManager ?? "";

    if (/^yarn@(?:[2-9]|\d{2,})\./.test(pm)) return true;

    if (YarnPath.safeParse(Bun.YAML.parse(smallText(join(root, ".yarnrc.yml")) ?? "")).data?.yarnPath !== undefined) return true;

    return /^__metadata:/m.test(headText(join(root, "yarn.lock")));
  } catch {
    return false;
  }
}

/** The first few kilobytes of a file (yarn 2's lockfile names its format at the top), or "" when there is none. */
function headText(path: string): string {
  if (!existsSync(path)) return "";
  const fd = openSync(path, "r");

  try {
    const buf = Buffer.alloc(4096);

    return buf.subarray(0, readSync(fd, buf, 0, buf.length, 0)).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

/** The package manager's own config files that can point it at a registry: bunfig.toml where bun runs and at the root, .yarnrc.yml for yarn 2 and later. */
function nativeConfigs(input: { root: string; member: string; pm: Pm }): string[] {
  switch (input.pm) {
    case "bun":
      return [...new Set([join(input.root, input.member, "bunfig.toml"), join(input.root, "bunfig.toml")])];
    case "yarn":
      return yarnBerry(input.root) ? [join(input.root, ".yarnrc.yml")] : [];
    case "npm":
    case "pnpm":
      return [];
    default: {
      const _exhaustive: never = input.pm;

      return _exhaustive;
    }
  }
}

/** How long all of apm's git calls for this check may take together before apm stops asking and says nothing. */
const GIT_BUDGET_MS = 2_000;

/** The registry the package manager's own config file at `path` sets (bunfig.toml or .yarnrc.yml); null when none or unreadable. */
function nativeRegistry(path: string): string | null {
  try {
    const text = smallText(path);

    if (text === null) return null;

    if (path.endsWith("bunfig.toml")) return BunfigRegistry.safeParse(Bun.TOML.parse(text)).data?.install?.registry ?? null;

    return YarnrcRegistry.safeParse(Bun.YAML.parse(text)).data?.npmRegistryServer ?? null;
  } catch {
    return null;
  }
}

/** Whether a .git folder (or a worktree's .git file) is in `dir` or above it: only then is git asked anything. */
function gitAbove(dir: string): boolean {
  for (let d = dir; ; d = dirname(d)) {
    if (existsSync(join(d, ".git"))) return true;

    if (dirname(d) === d) return false;
  }
}

/** git with these arguments in `cwd`, within `deadline`: its exit code and output, or null when it could not run in time. */
function git(args: string[], cwd: string, deadline: number): { code: number; out: string } | null {
  const left = deadline - Date.now();

  if (left <= 0) return null;

  try {
    const r = Bun.spawnSync(["git", ...args], { cwd, env: withoutSecrets(process.env), stdin: "ignore", stdout: "pipe", stderr: "ignore", timeout: left });

    return r.exitCode === null ? null : { code: r.exitCode, out: r.stdout.toString() };
  } catch {
    return null;
  }
}

/**
 * The files that point the package manager at `registry` and that git ignores, relative to `cwd`: `npmrc`, the project
 * .npmrc apm itself took the registry from (npm, pnpm, bun and yarn 1 read it too), and the package manager's own
 * config (nativeConfigs) when it names that registry. Empty outside a git work
 * tree, without git, or when git fails or does not answer in time: this only ever adds a warning, never a failure.
 */
export function ignoredRegistryFiles(input: { cwd: string; root: string; member: string; pm: Pm; registry: string; npmrc: string | null }): string[] {
  const native = nativeConfigs(input).filter((f) => {
    const set = existsSync(f) ? nativeRegistry(f) : null;

    return set !== null && sameRegistry(set, input.registry);
  });

  const files = [...(input.npmrc === null ? [] : [input.npmrc]), ...native];

  if (files.length === 0 || !gitAbove(input.root) || Bun.which("git") === null) return [];
  const deadline = Date.now() + GIT_BUDGET_MS;

  if (git(["rev-parse", "--is-inside-work-tree"], input.root, deadline)?.out.trim() !== "true") return [];

  // tracked files are never reported as ignored, so a committed .npmrc that a .gitignore also names passes
  return files.flatMap((f) => (git(["check-ignore", "-q", "--", f], dirname(f), deadline)?.code === 0 ? [relative(input.cwd, f) || f] : []));
}
