// What apm hands the package manager it runs: the registry apm checked, pinned so that no config file
// can send a package to another registry, and an environment with no credentials in it.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import { parseNpmrc, sameRegistry, userconfigPath } from "./config.ts";
import type { Pm } from "./pm.ts";

type Env = Record<string, string | undefined>;

/** Env variables that carry a registry credential. npm turns `npm_config_<key>` into config, so `npm_config_//host/:_authToken` is one too. */
const SECRET_KEYS = new Set(["APM_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN", "BUN_CONFIG_TOKEN", "YARN_NPM_AUTH_TOKEN", "YARN_NPM_AUTH_IDENT"]);

export function isSecretEnvKey(key: string): boolean {
  const k = key.toUpperCase();

  if (SECRET_KEYS.has(k)) return true;

  return k.startsWith("NPM_CONFIG_") && /(_AUTHTOKEN|_AUTH|_PASSWORD|:USERNAME|_TOKEN|:CERTFILE|:KEYFILE)$/.test(k);
}

/** The env minus APM_TOKEN and, unless `keepAuth`, every other credential variable. */
export function withoutSecrets(parent: Env, keepAuth = false) {
  const out: Env = {};

  for (const [k, v] of Object.entries(parent)) {
    if (k.toUpperCase() === "APM_TOKEN" || (!keepAuth && isSecretEnvKey(k))) continue;
    out[k] = v;
  }

  return out;
}

/** Registry settings in the environment, which apm replaces with its own. */
function isRegistryEnvKey(key: string): boolean {
  const k = key.toUpperCase();

  return k === "NPM_CONFIG_REGISTRY" || k === "BUN_CONFIG_REGISTRY" || k === "YARN_REGISTRY" || k === "YARN_NPM_REGISTRY_SERVER" || /^NPM_CONFIG_@[^:]+:REGISTRY$/.test(k);
}

/** The scopes ("@alice") among package names. */
export function scopesOf(names: string[]): string[] {
  const out = new Set<string>();

  for (const n of names) {
    const m = /^(@[^/]+)\//.exec(n);

    if (m?.[1]) out.add(m[1]);
  }

  return [...out];
}

/**
 * The child env: the parent env without credentials (install scripts and package binaries see this env),
 * with the registry and every scope in `scopes` pinned to `registry`. `keepAuth` keeps credential variables
 * for `publish <tarball>`, which runs no package code and may need `${NODE_AUTH_TOKEN}` in an .npmrc.
 */
export function childEnv(input: { parent: Env; registry: string; scopes: string[]; keepAuth: boolean }) {
  const out: Env = {};

  for (const [k, v] of Object.entries(withoutSecrets(input.parent, input.keepAuth))) {
    if (!isRegistryEnvKey(k)) out[k] = v;
  }

  out.npm_config_registry = input.registry;
  out.NPM_CONFIG_REGISTRY = input.registry;
  out.BUN_CONFIG_REGISTRY = input.registry;
  out.YARN_REGISTRY = input.registry;
  out.YARN_NPM_REGISTRY_SERVER = input.registry;

  for (const s of input.scopes) out[`npm_config_${s}:registry`] = input.registry;

  return out;
}

/** Command-line registry flags, which beat every config file. Yarn takes none; its env settings above win instead. */
export function registryArgs(pm: Pm, registry: string, scopes: string[]): string[] {
  switch (pm) {
    case "npm":
    case "pnpm":
      return [`--registry=${registry}`, ...scopes.map((s) => `--${s}:registry=${registry}`)];
    case "bun":
      return [`--registry=${registry}`];
    case "yarn":
      return [];
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

export type Override = { scope: string; registry: string; source: string };

function readText(path: string): string | null {
  try {
    return existsSync(path) ? readFileSync(path, "utf8") : null;
  } catch {
    return null;
  }
}

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

// a scope is either a URL or { url, token }
const BunScope = z.union([z.string(), z.object({ url: z.string() }).loose().transform((o) => o.url)]);
const Bunfig = z.object({ install: z.object({ scopes: z.record(z.string(), BunScope).optional() }).loose().optional() }).loose();
const Yarnrc = z.object({ npmScopes: z.record(z.string(), z.object({ npmRegistryServer: z.string().optional() }).loose()).optional() }).loose();

function bunfigScopes(path: string): Override[] {
  const text = readText(path);

  if (text === null) return [];

  try {
    const parsed = Bunfig.safeParse(Bun.TOML.parse(text));

    if (!parsed.success) return [];

    return Object.entries(parsed.data.install?.scopes ?? {}).map(([scope, v]) => ({
      scope: scope.startsWith("@") ? scope : `@${scope}`,
      registry: v,
      source: path,
    }));
  } catch {
    return [];
  }
}

function yarnrcScopes(path: string): Override[] {
  const text = readText(path);

  if (text === null) return [];

  try {
    const parsed = Yarnrc.safeParse(Bun.YAML.parse(text));

    if (!parsed.success) return [];

    const out: Override[] = [];

    for (const [scope, v] of Object.entries(parsed.data.npmScopes ?? {})) {
      if (v.npmRegistryServer) out.push({ scope: `@${scope.replace(/^@/, "")}`, registry: v.npmRegistryServer, source: path });
    }

    return out;
  } catch {
    return [];
  }
}

function npmrcScopes(path: string): Override[] {
  const text = readText(path);

  if (text === null) return [];

  const out: Override[] = [];

  for (const [k, v] of parseNpmrc(text)) {
    const m = /^(@[^:]+):registry$/.exec(k);

    if (m?.[1]) out.push({ scope: m[1].toLowerCase(), registry: v, source: path });
  }

  return out;
}

/**
 * Per-scope registry settings that the package manager would read for `scopes` and that point somewhere
 * other than `registry`: .npmrc files (project, then user), bunfig.toml ([install.scopes]) and .yarnrc.yml (npmScopes).
 */
export function scopeOverrides(input: { cwd: string; env: Env; registry: string; scopes: string[] }): Override[] {
  if (input.scopes.length === 0) return [];

  const home = input.env.HOME ?? homedir();
  const xdg = input.env.XDG_CONFIG_HOME;

  const all: Override[] = [
    ...[...upward(input.cwd, ".npmrc"), userconfigPath(input.env)].flatMap(npmrcScopes),
    ...[join(input.cwd, "bunfig.toml"), ...(xdg ? [join(xdg, ".bunfig.toml")] : []), join(home, ".bunfig.toml")].flatMap(bunfigScopes),
    ...[...upward(input.cwd, ".yarnrc.yml"), join(home, ".yarnrc.yml")].flatMap(yarnrcScopes),
  ];

  const wanted = new Set(input.scopes.map((s) => s.toLowerCase()));

  return all.filter((o) => wanted.has(o.scope.toLowerCase()) && !sameRegistry(o.registry, input.registry));
}
