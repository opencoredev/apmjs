// The platform apm asks the registry to check an install for. The registry skips an optional package built for
// another platform, as the package manager does, but only when apm can say which platform the package manager will
// install for. A force flag or an os/cpu override makes the package manager install packages the walk would skip, so
// apm then asks for "any" and every optional package is checked (review of 93274c8, finding 2). apm never forwards
// flags to the package manager, so what can be in effect is what the environment and the config files say.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import { parseNpmrc, userconfigPath } from "./config.ts";
import type { Pm } from "./pm.ts";

type Env = Record<string, string | undefined>;

/** What an install is for, as the registry reads it: node's platform and architecture, or "any" for each. */
export type InstallTarget = { os: string; cpu: string };

export const ANY_TARGET: InstallTarget = { os: "any", cpu: "any" };

/** The platform to ask about, and when it is "any", the setting that made it so. */
export type TargetChoice = { kind: "host"; target: InstallTarget } | { kind: "any"; target: InstallTarget; why: string };

/** The config keys that make npm (and pnpm, which reads the same) install for another platform, or for all of them. */
const NPM_KEYS = ["force", "os", "cpu"] as const;

/** pnpm's own key for the platforms it installs optional packages for, in .npmrc spelling. */
const PNPM_ARCH_KEY = /^supported[-_]?architectures/i;

/** Whether a config value turns its setting on: everything but an explicit false, so a value apm misreads checks more. */
function isOn(key: string, value: string): boolean {
  return key !== "force" || !/^(false|0)$/i.test(value.trim());
}

/**
 * The first of `keys` set in `env` under one of `prefixes`, read as npm reads its environment: case-insensitively,
 * with `-` and `_` alike.
 */
function envSetting(env: Env, prefixes: readonly string[], keys: readonly string[]): string | null {
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase().replaceAll("-", "_");
    const prefix = prefixes.find((p) => lower.startsWith(p));

    if (prefix === undefined) continue;
    const key = lower.slice(prefix.length);

    if (keys.includes(key) && isOn(key, value)) return `${name}=${value}`;
  }

  return null;
}

function readText(path: string): string | null {
  try {
    return existsSync(path) ? readFileSync(path, "utf8") : null;
  } catch {
    return null;
  }
}

/** `file` in `cwd` and each directory above it, nearest first. */
function upward(cwd: string, file: string): string[] {
  const out: string[] = [];
  let dir = cwd;

  for (let i = 0; i < 20; i++) {
    const p = join(dir, file);

    if (existsSync(p)) out.push(p);
    const parent = dirname(dir);

    if (parent === dir) break;
    dir = parent;
  }

  return out;
}

/** The .npmrc files npm reads: the project's from `cwd` upward, the user's, and the global one when it is named. */
function npmrcFiles(cwd: string, env: Env): string[] {
  const global = env.npm_config_globalconfig ?? env.NPM_CONFIG_GLOBALCONFIG;

  return [...upward(cwd, ".npmrc"), userconfigPath(env), ...(global ? [global] : [])];
}

/** The first .npmrc setting among `keys` (or matching `pattern`) that is on, as `file: key=value`. */
function npmrcSetting(files: readonly string[], keys: readonly string[], pattern: RegExp | null): string | null {
  for (const file of files) {
    const text = readText(file);

    if (text === null) continue;

    for (const [k, v] of parseNpmrc(text)) {
      const key = k.toLowerCase();

      if ((keys.includes(key) && isOn(key, v)) || pattern?.test(k)) return `${file}: ${k}=${v}`;
    }
  }

  return null;
}

const PnpmField = z.object({ pnpm: z.object({ supportedArchitectures: z.unknown().optional() }).loose().optional() }).loose();

const PnpmWorkspace = z.object({ supportedArchitectures: z.unknown().optional(), force: z.unknown().optional() }).loose();

/** pnpm's supportedArchitectures in package.json, or supportedArchitectures or force in pnpm-workspace.yaml. */
function pnpmFileSetting(cwd: string): string | null {
  for (const file of upward(cwd, "package.json")) {
    const text = readText(file);

    if (text === null) continue;

    try {
      const pj = PnpmField.safeParse(JSON.parse(text));

      if (pj.success && pj.data.pnpm?.supportedArchitectures !== undefined) return `${file}: pnpm.supportedArchitectures`;
    } catch {
      // an unreadable package.json says nothing about platforms
    }
  }

  for (const file of upward(cwd, "pnpm-workspace.yaml")) {
    const text = readText(file);

    if (text === null) continue;

    try {
      const ws = PnpmWorkspace.safeParse(Bun.YAML.parse(text));

      if (ws.success && ws.data.supportedArchitectures !== undefined) return `${file}: supportedArchitectures`;

      if (ws.success && ws.data.force !== undefined && ws.data.force !== false) return `${file}: force`;
    } catch {
      // an unreadable pnpm-workspace.yaml: pnpm itself would refuse it
    }
  }

  return null;
}

const Bunfig = z.object({ install: z.object({ os: z.unknown().optional(), cpu: z.unknown().optional(), force: z.unknown().optional() }).loose().optional() }).loose();

/** bun's [install] os, cpu or force in a bunfig.toml it reads: the project's, then the user's. */
function bunfigSetting(cwd: string, env: Env): string | null {
  const home = env.HOME ?? homedir();
  const xdg = env.XDG_CONFIG_HOME;

  for (const file of [join(cwd, "bunfig.toml"), ...(xdg ? [join(xdg, ".bunfig.toml")] : []), join(home, ".bunfig.toml")]) {
    const text = readText(file);

    if (text === null) continue;

    try {
      const parsed = Bunfig.safeParse(Bun.TOML.parse(text));
      const install = parsed.success ? parsed.data.install : undefined;

      for (const key of ["os", "cpu", "force"] as const) {
        const value = install?.[key];

        if (value !== undefined && value !== false) return `${file}: install.${key}`;
      }
    } catch {
      // an unreadable bunfig.toml: bun itself would refuse it
    }
  }

  return null;
}

/**
 * Why `pm` may install packages built for another platform than this machine, or null when nothing says it would.
 * npm: npm_config_force, npm_config_os, npm_config_cpu, or force, os or cpu in an .npmrc. pnpm: those, pnpm_config_*,
 * supported-architectures in an .npmrc, pnpm.supportedArchitectures in package.json, and supportedArchitectures or
 * force in pnpm-workspace.yaml. bun: [install] os, cpu or force in bunfig.toml, and the npm_config_* settings. yarn:
 * apm does not read yarn's supportedArchitectures, so it always counts as overridden.
 */
export function platformOverride(input: { pm: Pm; cwd: string; env: Env }): string | null {
  const { pm, cwd, env } = input;

  switch (pm) {
    case "npm":
      return envSetting(env, ["npm_config_"], NPM_KEYS) ?? npmrcSetting(npmrcFiles(cwd, env), NPM_KEYS, null);
    case "pnpm":
      return envSetting(env, ["npm_config_", "pnpm_config_"], [...NPM_KEYS, "supported_architectures"]) ?? npmrcSetting(npmrcFiles(cwd, env), NPM_KEYS, PNPM_ARCH_KEY) ?? pnpmFileSetting(cwd);
    case "bun":
      return envSetting(env, ["npm_config_", "bun_config_"], NPM_KEYS) ?? bunfigSetting(cwd, env);
    case "yarn":
      return "yarn: apm does not read yarn's supportedArchitectures";
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/**
 * The platform to ask the registry about for an install `pm` runs from `cwd`: this machine's, unless a force flag or
 * an os/cpu override is in effect for `pm`, and then "any", so the registry checks every optional package.
 */
export function installTarget(input: { pm: Pm; cwd: string; env: Env; host?: InstallTarget }): TargetChoice {
  const why = platformOverride(input);

  if (why !== null) return { kind: "any", target: ANY_TARGET, why };

  return { kind: "host", target: input.host ?? { os: process.platform, cpu: process.arch } };
}
