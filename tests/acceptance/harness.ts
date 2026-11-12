// Acceptance-test harness: runs the real registry in-process and drives the
// stock `bun` and `npm` clients against it as subprocesses.
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

export const ROOT = join(import.meta.dir, "..", "..");
export const CLI = join(ROOT, "packages", "cli", "src", "main.ts");

export type Registry = {
  url: string; // always ends with "/"
  dataDir: string;
  stop: () => Promise<void>;
};

type RegistryModule = {
  startRegistry: (opts: { dataDir: string; port: number; hostname?: string; now?: () => number; upstream?: string }) => Promise<{
    url: string;
    stop: () => Promise<void>;
  }>;
};

function isRegistryModule(m: unknown): m is RegistryModule {
  return typeof m === "object" && m !== null && "startRegistry" in m && typeof m.startRegistry === "function";
}

export async function startRegistry(opts: { now?: () => number; upstream?: string } = {}): Promise<Registry> {
  const mod: unknown = await import(join(ROOT, "packages", "registry", "src", "index.ts"));
  if (!isRegistryModule(mod)) throw new Error("@apm/registry must export startRegistry");
  const dataDir = mkdtempSync(join(tmpdir(), "apm-reg-"));
  const srv = await mod.startRegistry({ dataDir, port: 0, hostname: "127.0.0.1", ...(opts.now ? { now: opts.now } : {}), ...(opts.upstream ? { upstream: opts.upstream } : {}) });
  const url = srv.url.endsWith("/") ? srv.url : `${srv.url}/`;
  return { url, dataDir, stop: srv.stop };
}

export function hostKey(registryUrl: string): string {
  // "//127.0.0.1:1234/" form used by .npmrc auth lines
  const u = new URL(registryUrl);
  return `//${u.host}${u.pathname}`;
}

/** Creates a user with the legacy npm adduser endpoint and returns its token. */
export async function addUser(reg: Registry, name: string, password = "correct-horse-battery"): Promise<string> {
  const res = await fetch(`${reg.url}-/user/org.couchdb.user:${encodeURIComponent(name)}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ _id: `org.couchdb.user:${name}`, name, password, email: `${name}@example.test`, type: "user", roles: [] }),
  });
  const body: unknown = await res.json();
  if (!res.ok || typeof body !== "object" || body === null || !("token" in body) || typeof body.token !== "string") {
    throw new Error(`adduser failed: ${res.status} ${JSON.stringify(body)}`);
  }
  return body.token;
}

export type PkgSpec = {
  name: string;
  version: string;
  files?: Record<string, string>;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  extra?: Record<string, unknown>;
};

/** A throwaway HOME with npm and bun pointed at the registry. */
export function makeSandbox(reg: Registry, token?: string): { home: string; env: Record<string, string> } {
  const home = mkdtempSync(join(tmpdir(), "apm-home-"));
  const lines = [`registry=${reg.url}`];
  if (token) lines.push(`${hostKey(reg.url)}:_authToken=${token}`);
  writeFileSync(join(home, ".npmrc"), lines.join("\n") + "\n");
  const bunfig = [`[install]`, token ? `registry = { url = "${reg.url}", token = "${token}" }` : `registry = "${reg.url}"`, `[install.cache]`, `dir = "${join(home, ".bun-cache")}"`, ``].join("\n");
  writeFileSync(join(home, ".bunfig.toml"), bunfig);
  const env: Record<string, string> = {
    // repo-pinned tools (pnpm) first: the machine's pnpm may be an npx shim that fetches from the configured registry
    PATH: `${join(ROOT, "node_modules", ".bin")}:${process.env.PATH ?? ""}`,
    HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    npm_config_userconfig: join(home, ".npmrc"),
    npm_config_cache: join(home, ".npm-cache"),
    npm_config_registry: reg.url,
    npm_config_update_notifier: "false",
    npm_config_fund: "false",
    npm_config_audit: "false",
    BUN_INSTALL_CACHE_DIR: join(home, ".bun-cache"),
    NO_COLOR: "1",
    APM_REGISTRY: reg.url,
    ...(token ? { APM_TOKEN: token } : {}),
  };
  return { home, env };
}

/** Writes a package directory, with the project's own .npmrc and bunfig.toml so both clients use the registry. */
export function writePackage(parent: string, spec: PkgSpec, reg: Registry, token?: string): string {
  const dir = mkdtempSync(join(parent, "pkg-"));
  const pkgJson: Record<string, unknown> = {
    name: spec.name,
    version: spec.version,
    main: "index.js",
    license: "MIT",
    ...(spec.scripts ? { scripts: spec.scripts } : {}),
    ...(spec.dependencies ? { dependencies: spec.dependencies } : {}),
    ...(spec.extra ?? {}),
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkgJson, null, 2));
  const files = spec.files ?? { "index.js": `module.exports = ${JSON.stringify(`${spec.name}@${spec.version}`)};\n` };
  for (const [rel, content] of Object.entries(files)) {
    const p = join(dir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  writeProjectConfig(dir, reg, token);
  return dir;
}

export function writeProjectConfig(dir: string, reg: Registry, token?: string): void {
  const lines = [`registry=${reg.url}`];
  if (token) lines.push(`${hostKey(reg.url)}:_authToken=${token}`);
  writeFileSync(join(dir, ".npmrc"), lines.join("\n") + "\n");
  const bunfig = [`[install]`, token ? `registry = { url = "${reg.url}", token = "${token}" }` : `registry = "${reg.url}"`, ``].join("\n");
  writeFileSync(join(dir, "bunfig.toml"), bunfig);
}

/** An empty consumer project that depends on nothing yet. */
export function writeConsumer(parent: string, reg: Registry, token?: string, deps: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(parent, "app-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "consumer-app", version: "1.0.0", private: true, dependencies: deps }, null, 2));
  writeProjectConfig(dir, reg, token);
  return dir;
}

export type RunResult = { code: number; stdout: string; stderr: string; out: string };

export async function run(cmd: string[], opts: { cwd: string; env: Record<string, string>; stdin?: string; timeoutMs?: number }): Promise<RunResult> {
  const proc = Bun.spawn(cmd, {
    cwd: opts.cwd,
    env: opts.env,
    stdin: opts.stdin !== undefined ? new TextEncoder().encode(opts.stdin) : "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const timer = setTimeout(() => proc.kill(), opts.timeoutMs ?? 60_000);
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  clearTimeout(timer);
  return { code, stdout, stderr, out: stdout + stderr };
}

export function apm(args: string[], opts: { cwd: string; env: Record<string, string>; stdin?: string; timeoutMs?: number }): Promise<RunResult> {
  return run(["bun", CLI, ...args], opts);
}

export async function getJson(url: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, init);
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // keep text
  }
  return { status: res.status, body };
}

export function installedVersion(appDir: string, name: string): string | null {
  const p = join(appDir, "node_modules", ...name.split("/"), "package.json");
  if (!existsSync(p)) return null;
  const parsed: unknown = JSON.parse(readFileSync(p, "utf8"));
  if (typeof parsed === "object" && parsed !== null && "version" in parsed && typeof parsed.version === "string") return parsed.version;
  return null;
}

export function encodePkg(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

/** Pulls a nested field from unknown JSON without casts. */
export function dig(v: unknown, ...path: (string | number)[]): unknown {
  let cur: unknown = v;
  for (const k of path) {
    if (typeof cur !== "object" || cur === null) return undefined;
    cur = Reflect.get(cur, k);
  }
  return cur;
}
