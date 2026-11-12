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

export function addArgs(pm: Pm, specs: string[], dev: boolean): string[] {
  switch (pm) {
    case "bun":
      return ["bun", "add", ...(dev ? ["--dev"] : []), ...specs];
    case "npm":
      return ["npm", "install", ...(dev ? ["--save-dev"] : []), ...specs];
    case "pnpm":
      return ["pnpm", "add", ...(dev ? ["--save-dev"] : []), ...specs];
    case "yarn":
      return ["yarn", "add", ...(dev ? ["--dev"] : []), ...specs];
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
