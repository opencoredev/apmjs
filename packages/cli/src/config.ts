// Where apm talks to and who it is: registry URL and token, read from the same files npm and bun use.
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import type { Pm } from "./pm.ts";

export const DEFAULT_REGISTRY = "https://registry.apmjs.dev/";

/** `withheld` names the registry APM_TOKEN belongs to when apm talks to a different one and so sends no token. */
export type Config = { registry: string; token: string | null; userconfig: string; withheld: string | null };

function withSlash(u: string): string {
  return u.endsWith("/") ? u : `${u}/`;
}

/** Parses the key=value lines of an .npmrc file. */
export function parseNpmrc(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const i = line.indexOf("=");
    if (i < 0) continue;
    out.set(line.slice(0, i).trim(), line.slice(i + 1).trim());
  }
  return out;
}

function readNpmrc(path: string): Map<string, string> {
  try {
    return existsSync(path) ? parseNpmrc(readFileSync(path, "utf8")) : new Map();
  } catch {
    return new Map();
  }
}

/** The project .npmrc files from `cwd` upward, nearest first, stopping before any user-home/userconfig directory. */
function projectNpmrcs(cwd: string, userDirs: ReadonlySet<string>): string[] {
  const out: string[] = [];
  let dir = cwd;
  for (let i = 0; i < 20; i++) {
    if (userDirs.has(dir)) break;
    const p = join(dir, ".npmrc");
    if (existsSync(p)) out.push(p);
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return out;
}

export function userconfigPath(env: Record<string, string | undefined>): string {
  return env.npm_config_userconfig ?? env.NPM_CONFIG_USERCONFIG ?? join(env.HOME ?? homedir(), ".npmrc");
}

export function authKey(registry: string): string {
  const u = new URL(registry);
  return `//${u.host}${u.pathname}`;
}

/** Same host, path and protocol: a token or a check for one applies to the other. */
export function sameRegistry(a: string, b: string): boolean {
  try {
    return authKey(a) === authKey(b) && new URL(a).protocol === new URL(b).protocol;
  } catch {
    return false;
  }
}

/**
 * The registry APM_TOKEN is issued for: APM_REGISTRY, else `registry=` in the user .npmrc, else the default.
 * A project .npmrc and npm_config_registry never count: both can come from a cloned repo
 * (`npm run` exports project config as npm_config_* variables).
 */
export function tokenRegistry(env: Record<string, string | undefined>): string {
  return withSlash(env.APM_REGISTRY ?? readNpmrc(userconfigPath(env)).get("registry") ?? DEFAULT_REGISTRY);
}

export function loadConfig(cwd: string, env: Record<string, string | undefined>): Config {
  const userconfig = userconfigPath(env);
  const userDirs = new Set<string>([homedir(), dirname(userconfig)]);

  if (env.HOME) userDirs.add(env.HOME);
  const files = [...projectNpmrcs(cwd, userDirs), userconfig].map(readNpmrc);
  const registry = withSlash(env.APM_REGISTRY ?? env.npm_config_registry ?? env.NPM_CONFIG_REGISTRY ?? files.find((f) => f.has("registry"))?.get("registry") ?? DEFAULT_REGISTRY);
  const envToken = env.APM_TOKEN || null;

  if (envToken) {
    const bound = tokenRegistry(env);

    if (sameRegistry(bound, registry)) return { registry, token: envToken, userconfig, withheld: null };

    return { registry, token: fileToken(files, registry, env), userconfig, withheld: bound };
  }

  return { registry, token: fileToken(files, registry, env), userconfig, withheld: null };
}

/** The npm registry, which npm, pnpm and bun install from when nothing names another. */
const NPM_REGISTRY = "https://registry.npmjs.org/";

/** bunfig.toml's `[install] registry`, a URL or `{ url, token }`, read as its URL. */
const BunfigRegistry = z.object({ install: z.object({ registry: z.union([z.string(), z.object({ url: z.string() }).loose().transform((r) => r.url)]) }).loose() }).loose();

/** .yarnrc.yml's `npmRegistryServer` (yarn 2 and later). */
const YarnrcRegistry = z.object({ npmRegistryServer: z.string() }).loose();

/** The registry a bunfig.toml or .yarnrc.yml at `path` names; null when it names none or cannot be read. */
function fileRegistry(path: string, kind: "bunfig" | "yarnrc"): string | null {
  if (!existsSync(path)) return null;

  try {
    const text = readFileSync(path, "utf8");

    switch (kind) {
      case "bunfig": {
        const parsed = BunfigRegistry.safeParse(Bun.TOML.parse(text));

        return parsed.success ? parsed.data.install.registry : null;
      }

      case "yarnrc": {
        const parsed = YarnrcRegistry.safeParse(Bun.YAML.parse(text));

        return parsed.success ? parsed.data.npmRegistryServer : null;
      }

      default: {
        const _exhaustive: never = kind;

        return _exhaustive;
      }
    }
  } catch {
    return null;
  }
}

/**
 * A registry URL as apm prints it: http or https, its host and path only, no user, password, query or fragment (an
 * .npmrc or a variable can carry credentials in any of them). Null for anything else, which apm then does not name.
 */
export function displayRegistry(url: string): string | null {
  try {
    const u = new URL(url);

    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    const shown = `${u.origin}${u.pathname}`;

    return /^[\w\-.:/~%]{1,200}$/.test(shown) ? withSlash(shown) : null;
  } catch {
    return null;
  }
}

/**
 * The default registry `pm` is configured with for the project at `root` when apm passes nothing (a plain install), from
 * the variables and files it reads: for bun, its variables, then bunfig.toml (the project's, then the user's); then
 * npm_config_registry, the project root's .npmrc and the user's (npm reads no .npmrc above the project root); else npm's
 * registry. For yarn, YARN_NPM_REGISTRY_SERVER or .yarnrc.yml's npmRegistryServer, or null: its defaults differ by
 * version. Only for saying where a plain install goes; a scope's own registry and a lockfile's URLs still apply.
 */
export function pmRegistry(input: { pm: Pm; root: string; env: Record<string, string | undefined> }): string | null {
  const { pm, root, env } = input;
  const home = env.HOME ?? homedir();
  const npmrc = [join(root, ".npmrc"), userconfigPath(env)].map(readNpmrc).find((f) => f.has("registry"))?.get("registry") ?? null;
  const fromEnv = env.npm_config_registry ?? env.NPM_CONFIG_REGISTRY ?? null;

  switch (pm) {
    case "bun": {
      const bunfig = [join(root, "bunfig.toml"), join(env.XDG_CONFIG_HOME ?? join(home, ".config"), ".bunfig.toml"), join(home, ".bunfig.toml")].map((p) => fileRegistry(p, "bunfig")).find((r) => r !== null) ?? null;

      return env.BUN_CONFIG_REGISTRY ?? fromEnv ?? bunfig ?? npmrc ?? NPM_REGISTRY;
    }

    case "npm":
    case "pnpm":
      return fromEnv ?? npmrc ?? NPM_REGISTRY;
    case "yarn":
      return env.YARN_NPM_REGISTRY_SERVER ?? fileRegistry(join(root, ".yarnrc.yml"), "yarnrc");
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/** The token .npmrc files hold for exactly this registry host (never one keyed to another host). */
function fileToken(files: Map<string, string>[], registry: string, env: Record<string, string | undefined>): string | null {
  const key = `${authKey(registry)}:_authToken`;
  const host = `//${new URL(registry).host}/:_authToken`;

  for (const f of files) {
    const t = f.get(key) ?? f.get(host);

    if (t) return t.replace(/^\$\{(\w+)\}$/, (_, name: string) => env[name] ?? "") || null;
  }

  return null;
}

/** apm tokens are `apm_` plus base64url. Anything else (a newline above all) must never reach an .npmrc line. */
export function isApmToken(token: string): boolean {
  return /^apm_[A-Za-z0-9_-]{16,256}$/.test(token);
}

/**
 * Writes (or replaces) the auth line for `registry` in the user .npmrc, which npm, pnpm and bun all read.
 * The file holds a token, so it ends up 0600 whatever its mode was, and it is replaced atomically: a temp
 * file in the same directory, made private before the token is written, then renamed over the original.
 */
export function saveToken(userconfig: string, registry: string, token: string): void {
  const key = `${authKey(registry)}:_authToken`;
  // a symlinked .npmrc (dotfiles repos) keeps its link: write next to the real file
  const target = existsSync(userconfig) ? realpathSync(userconfig) : userconfig;
  const lines = existsSync(target) ? readFileSync(target, "utf8").split(/\r?\n/) : [];
  const kept = lines.filter((l) => !l.trim().startsWith(`${key}=`) && l.trim() !== "");
  kept.push(`${key}=${token}`);
  const tmp = join(dirname(target), `.npmrc.${randomBytes(6).toString("hex")}.tmp`);
  try {
    writeFileSync(tmp, "", { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
    writeFileSync(tmp, `${kept.join("\n")}\n`);
    renameSync(tmp, target);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
  chmodSync(target, 0o600);
}
