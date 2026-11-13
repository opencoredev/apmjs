// The package manager apm drives. apm never replaces it: it decides what to install, then runs it.
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";

export type Pm = "bun" | "npm" | "pnpm" | "yarn";
export const PMS: readonly Pm[] = ["bun", "npm", "pnpm", "yarn"];

export function isPm(v: string): v is Pm {
  return (PMS as readonly string[]).includes(v);
}

export type Detection = { pm: Pm; why: string };

const LOCKFILES: [string, Pm][] = [
  ["bun.lock", "bun"],
  ["bun.lockb", "bun"],
  ["pnpm-lock.yaml", "pnpm"],
  ["package-lock.json", "npm"],
  ["npm-shrinkwrap.json", "npm"],
  ["yarn.lock", "yarn"],
];

function findUp(cwd: string, test: (dir: string) => Detection | null): Detection | null {
  let dir = cwd;
  for (let i = 0; i < 20; i++) {
    const hit = test(dir);
    if (hit) return hit;
    if (existsSync(join(dir, ".git"))) return null;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/** --pm flag, then the nearest lockfile, then package.json "packageManager", then bun when installed, else npm. */
export function detectPm(cwd: string, flag: string | null): Detection {
  if (flag) {
    if (!isPm(flag)) throw new Error(`--pm must be one of ${PMS.join(", ")}`);
    return { pm: flag, why: "--pm flag" };
  }
  const byLock = findUp(cwd, (dir) => {
    for (const [file, pm] of LOCKFILES) if (existsSync(join(dir, file))) return { pm, why: file };
    return null;
  });
  if (byLock) return byLock;
  const byField = findUp(cwd, (dir) => {
    const p = join(dir, "package.json");
    if (!existsSync(p)) return null;
    try {
      const pj: unknown = JSON.parse(readFileSync(p, "utf8"));
      if (typeof pj === "object" && pj !== null && "packageManager" in pj && typeof pj.packageManager === "string") {
        const name = pj.packageManager.split("@")[0] ?? "";
        if (isPm(name)) return { pm: name, why: `packageManager in ${p}` };
      }
    } catch {
      // ignore unreadable package.json
    }
    return null;
  });
  if (byField) return byField;
  if (Bun.which("bun")) return { pm: "bun", why: "default (bun is installed)" };
  return { pm: "npm", why: "default" };
}

/** The add command. `ignoreScripts` holds every install script back until apm has verified what was installed. */
export function addArgs(pm: Pm, specs: string[], opts: { dev: boolean; ignoreScripts: boolean }): string[] {
  const hold = opts.ignoreScripts ? ["--ignore-scripts"] : [];

  switch (pm) {
    case "bun":
      return ["bun", "add", ...(opts.dev ? ["--dev"] : []), ...hold, ...specs];
    case "npm":
      return ["npm", "install", ...(opts.dev ? ["--save-dev"] : []), ...hold, ...specs];
    case "pnpm":
      return ["pnpm", "add", ...(opts.dev ? ["--save-dev"] : []), ...hold, ...specs];
    case "yarn":
      return ["yarn", "add", ...(opts.dev ? ["--dev"] : []), ...hold, ...specs];
    default: {
      const _exhaustive: never = pm;
      return _exhaustive;
    }
  }
}

export function packArgs(pm: Pm, dest: string): string[] {
  switch (pm) {
    case "bun":
      return ["bun", "pm", "pack", "--destination", dest];
    case "npm":
      return ["npm", "pack", "--pack-destination", dest];
    case "pnpm":
      return ["pnpm", "pack", "--pack-destination", dest];
    case "yarn":
      return ["yarn", "pack", "--out", join(dest, "%s-%v.tgz")];
    default: {
      const _exhaustive: never = pm;
      return _exhaustive;
    }
  }
}

export function publishArgs(pm: Pm, tarball: string, tag: string | null): string[] {
  const tagArgs = tag ? ["--tag", tag] : [];
  switch (pm) {
    case "bun":
      return ["bun", "publish", tarball, ...tagArgs];
    case "npm":
      return ["npm", "publish", tarball, ...tagArgs];
    case "pnpm":
      return ["pnpm", "publish", tarball, "--no-git-checks", ...tagArgs];
    case "yarn":
      return ["npm", "publish", tarball, ...tagArgs];
    default: {
      const _exhaustive: never = pm;
      return _exhaustive;
    }
  }
}

export function execArgs(pm: Pm, spec: string, args: string[]): string[] {
  switch (pm) {
    case "bun":
      return ["bunx", spec, ...args];
    case "npm":
    case "yarn":
      return ["npx", "--yes", spec, ...args];
    case "pnpm":
      return ["pnpm", "dlx", spec, ...args];
    default: {
      const _exhaustive: never = pm;
      return _exhaustive;
    }
  }
}

export type RunOpts = { cwd: string; env: Record<string, string | undefined>; quiet?: boolean; stdoutToStderr?: boolean };

/** Runs a command with inherited output (or captured when quiet). Returns exit code and captured text. */
export async function runCmd(cmd: string[], opts: RunOpts): Promise<{ code: number; out: string }> {
  const capture = opts.quiet === true;
  const proc = Bun.spawn(cmd, {
    cwd: opts.cwd,
    env: opts.env,
    stdin: "inherit",
    stdout: capture ? "pipe" : opts.stdoutToStderr ? "pipe" : "inherit",
    stderr: capture ? "pipe" : "inherit",
  });
  let out = "";
  if (capture) {
    const [a, b] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
    out = a + b;
  } else if (opts.stdoutToStderr) {
    const text = await new Response(proc.stdout).text();
    process.stderr.write(text);
  }
  const code = await proc.exited;
  return { code, out };
}

/**
 * The add that only computes the lockfile: it writes package.json and the lockfile and installs nothing, with every
 * script off. apm runs it in a directory of its own (see lockfirst.ts). yarn berry's `--mode update-lockfile` is its
 * own form of it; classic yarn has none.
 */
export function lockOnlyArgs(pm: Pm, specs: readonly string[], opts: { dev: boolean }): string[] {
  switch (pm) {
    case "npm":
      return ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", ...(opts.dev ? ["--save-dev"] : []), ...specs];
    case "pnpm":
      return ["pnpm", "add", "--lockfile-only", "--ignore-scripts", ...(opts.dev ? ["--save-dev"] : []), ...specs];
    case "bun":
      return ["bun", "add", "--lockfile-only", "--ignore-scripts", ...(opts.dev ? ["--dev"] : []), ...specs];
    case "yarn":
      return ["yarn", "add", "--mode", "update-lockfile", ...(opts.dev ? ["--dev"] : []), ...specs];
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/**
 * The install of exactly the lockfile apm checked, every script off. npm has no frozen install but `ci`, which deletes
 * node_modules first: apm uses it when there is no node_modules to keep, and otherwise npm install, which keeps what it
 * need not change (a patch the user made in an untouched package, say); apm then confirms the lockfile is unchanged
 * byte for byte, which is what frozen means (verify.ts).
 */
export function frozenInstallArgs(pm: Exclude<Pm, "yarn">, opts: { keepNodeModules: boolean }): string[] {
  switch (pm) {
    case "npm":
      return opts.keepNodeModules ? ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"] : ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"];
    case "pnpm":
      return ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"];
    case "bun":
      return ["bun", "install", "--frozen-lockfile", "--ignore-scripts"];
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/** Which yarn runs in a directory: berry (2 and up) has a lockfile-only mode, classic (1) has none. */
export type YarnLine = { kind: "berry"; version: string } | { kind: "classic"; version: string } | { kind: "unknown"; why: string };

/** `yarn --version` in `cwd` (which runs the project's own yarn release, as yarn itself would). */
export async function yarnLine(input: { cwd: string; env: Record<string, string | undefined> }): Promise<YarnLine> {
  try {
    const r = await runCmd(["yarn", "--version"], { cwd: input.cwd, env: input.env, quiet: true });
    const version = r.out.trim().split("\n").at(-1)?.trim() ?? "";
    const major = Number(/^(\d+)\./.exec(version)?.[1]);

    if (r.code !== 0 || !Number.isFinite(major)) return { kind: "unknown", why: `yarn --version exited ${r.code}` };

    return major >= 2 ? { kind: "berry", version } : { kind: "classic", version };
  } catch (e) {
    return { kind: "unknown", why: e instanceof Error ? e.message : String(e) };
  }
}
