// Where apm talks to and who it is: registry URL and token, read from the same files npm and bun use.
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DEFAULT_REGISTRY = "https://registry.apmjs.dev/";

/**
 * `withheld` names the registry APM_TOKEN belongs to when apm talks to a different one and so sends no token.
 * `unexpanded` names an .npmrc whose `${VAR}` token apm did not fill in, because a repo chose the registry it would go to.
 */
export type Config = { registry: string; token: string | null; userconfig: string; withheld: string | null; unexpanded: string | null };

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
 * The registry APM_TOKEN is issued for: APM_REGISTRY, else `registry=` in ~/.npmrc, else the default.
 * A project .npmrc, npm_config_registry and npm_config_userconfig never count: all three can come from a cloned repo
 * (`npm run` exports project config, `userconfig=` included, as npm_config_* variables).
 */
export function tokenRegistry(env: Record<string, string | undefined>): string {
  return withSlash(env.APM_REGISTRY ?? readNpmrc(join(env.HOME ?? homedir(), ".npmrc")).get("registry") ?? DEFAULT_REGISTRY);
}

export function loadConfig(cwd: string, env: Record<string, string | undefined>): Config {
  const userconfig = userconfigPath(env);
  const userDirs = new Set<string>([homedir(), dirname(userconfig)]);

  if (env.HOME) userDirs.add(env.HOME);
  const files = [...projectNpmrcs(cwd, userDirs), userconfig].map((path) => ({ path, values: readNpmrc(path) }));
  const registry = withSlash(env.APM_REGISTRY ?? env.npm_config_registry ?? env.NPM_CONFIG_REGISTRY ?? files.find((f) => f.values.has("registry"))?.values.get("registry") ?? DEFAULT_REGISTRY);
  const envToken = env.APM_TOKEN || null;
  const bound = tokenRegistry(env);
  // a registry a repo chose gets `${VAR}` filled in only from ~/.npmrc: a repo's own .npmrc would otherwise name any secret
  const expandFrom = sameRegistry(bound, registry) ? null : join(env.HOME ?? homedir(), ".npmrc");
  const file = fileToken(files, registry, env, expandFrom);

  if (envToken) {
    if (sameRegistry(bound, registry)) return { registry, token: envToken, userconfig, withheld: null, unexpanded: null };

    // a repo's .npmrc can ask for `${APM_TOKEN}` as its own host's token: a withheld token stays withheld
    return { registry, token: file.token === envToken ? null : file.token, userconfig, withheld: bound, unexpanded: file.unexpanded };
  }

  return { registry, token: file.token, userconfig, withheld: null, unexpanded: file.unexpanded };
}

/**
 * A registry as apm prints it: the origin of an http or https URL and nothing else, since an .npmrc or a variable can
 * carry a credential in the user, the path, the query or the fragment. Null for anything else, which apm then does not name.
 */
export function displayRegistry(url: string): string | null {
  try {
    const u = new URL(url);

    return u.protocol === "https:" || u.protocol === "http:" ? `${u.origin}/` : null;
  } catch {
    return null;
  }
}

/** What .npmrc files give for a registry: its token, and the file whose `${VAR}` token was passed over. */
type FileToken = { token: string | null; unexpanded: string | null };

/**
 * The token .npmrc files hold for exactly this registry host (never one keyed to another host). With `expandFrom`, a
 * `${VAR}` token is read only from that file; one in any other file is passed over, and `unexpanded` names it.
 */
function fileToken(files: { path: string; values: Map<string, string> }[], registry: string, env: Record<string, string | undefined>, expandFrom: string | null): FileToken {
  const key = `${authKey(registry)}:_authToken`;
  const host = `//${new URL(registry).host}/:_authToken`;
  let unexpanded: string | null = null;

  for (const f of files) {
    const t = f.values.get(key) ?? f.values.get(host);

    if (!t) continue;
    const variable = /^\$\{(\w+)\}$/.exec(t);

    if (variable === null) return { token: t, unexpanded };

    if (expandFrom !== null && f.path !== expandFrom) {
      unexpanded ??= `${f.path} (\${${variable[1]}})`;
      continue;
    }

    return { token: env[variable[1] ?? ""] || null, unexpanded };
  }

  return { token: null, unexpanded };
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
