// Acceptance-test harness: runs the registry Worker build locally (Miniflare, see worker-registry.ts) and drives
// the stock `bun`, `npm` and `pnpm` clients against it as subprocesses.
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHmac, randomBytes } from "node:crypto";
import { startWorkerRegistry, type WorkerRegistryOptions } from "./worker-registry.ts";

export const ROOT = join(import.meta.dir, "..", "..");
export const CLI = join(ROOT, "packages", "cli", "src", "main.ts");

// ---------- one scratch directory per test process ----------
// Every sandbox, registry data dir and package directory the suites make goes under RUN_DIR (TMPDIR points
// there, so the suites' own mkdtempSync(tmpdir()) calls land in it too), and RUN_DIR is removed when the
// process exits. A run that was killed leaves its directory behind; the next run removes those.
const RUN_PREFIX = "apm-test-";

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);

    return true;
  } catch (e) {
    // EPERM: the process exists but belongs to someone else
    return e instanceof Error && "code" in e && e.code === "EPERM";
  }
}

function sweepDeadRuns(parent: string): void {
  for (const name of readdirSync(parent)) {
    const pid = Number(/^apm-test-(\d+)-/.exec(name)?.[1] ?? Number.NaN);

    if (!Number.isInteger(pid) || pid === process.pid || isAlive(pid)) continue;

    try {
      rmSync(join(parent, name), { recursive: true, force: true });
    } catch {
      // someone else's directory: leave it
    }
  }
}

const parentTmp = tmpdir();

sweepDeadRuns(parentTmp);

export const RUN_DIR = mkdtempSync(join(parentTmp, `${RUN_PREFIX}${process.pid}-`));

process.env.TMPDIR = RUN_DIR;

const removeRunDir = (): void => rmSync(RUN_DIR, { recursive: true, force: true });

process.on("exit", removeRunDir);

// `bun test` ends without firing "exit" (Bun 1.4), so a watcher removes RUN_DIR once this process is gone.
Bun.spawn(["sh", "-c", 'while kill -0 "$1" 2>/dev/null; do sleep 0.3; done; rm -rf -- "$2"', "apm-test-cleanup", String(process.pid), RUN_DIR], {
  stdin: "ignore",
  stdout: "ignore",
  stderr: "ignore",
}).unref();

for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.once(sig, () => {
    removeRunDir();
    process.exit(128 + (sig === "SIGINT" ? 2 : sig === "SIGTERM" ? 15 : 1));
  });
}

export type Registry = {
  url: string; // always ends with "/"
  stop: () => Promise<void>;
  /** Test-only: a token for `user` without any login flow. "publish" goes live at once (the CI trusted-publishing path); "stage" needs approval. */
  mintToken: (input: { user: string; scope: TokenScope }) => Promise<string>;
  /** Test-only: the registry's blob store (R2), to check what was stored and to tamper with it. */
  blobs: { keys: () => Promise<string[]>; put: (key: string, bytes: Uint8Array | string) => Promise<void> };
  /** Test-only: runs one SQL statement against the registry's Postgres database and returns its rows. */
  query: (text: string, params?: readonly unknown[]) => Promise<unknown[]>;
};

export type TokenScope = "publish" | "stage";

export type NamePolicy = "scoped" | "open";

export type GitHubEndpoints = { authorize: string; token: string; user: string; emails: string };

/** AI release review options, as packages/registry/src/review.ts takes them. */
export type ReviewOptions = {
  serviceTokenHash: string;
  admins: readonly string[];
  popularWeekly?: number;
  downloadsUrl?: string;
  leaseMs?: number;
  requestsPerHour?: number;
  maxAttempts?: number;
};

export type StartOptions = {
  now?: () => number;
  upstream?: string;
  /** How long the registry trusts an upstream packument before asking again (default 60s). */
  upstreamTtlMs?: number;
  /** npm's password adduser and password re-auth. On by default here so the older suites keep their meaning; off in production. */
  legacyAuth?: boolean;
  /** "open" lets bare names through (the older suites); "scoped" is production: new names live under your GitHub login. */
  namePolicy?: NamePolicy;
  /** A fake GitHub to sign in through. */
  github?: FakeGitHub;
  /** Turns on the AI review queue and routes. */
  review?: ReviewOptions;
  /** Worker variables to set or override (APM_PUBLIC_URL, APM_ALLOW_LEGACY_IN_PROD, ...). */
  env?: Readonly<Record<string, string>>;
};

export async function startRegistry(opts: StartOptions = {}): Promise<Registry> {
  const options: WorkerRegistryOptions = {
    legacyAuth: opts.legacyAuth ?? true,
    namePolicy: opts.namePolicy ?? "open",
    // Authenticator codes follow the tests' TOTP clock, so a test can ask for a fresh code without waiting 30s.
    totpNow: () => totpClock.now,
    authSecret: `test-only-secret-${randomBytes(24).toString("hex")}`,
  };

  if (opts.now) options.now = opts.now;

  if (opts.upstream) options.upstream = opts.upstream;

  if (opts.upstreamTtlMs !== undefined) options.upstreamTtlMs = opts.upstreamTtlMs;

  if (opts.github) options.github = { clientId: "fake-client-id", clientSecret: "fake-client-secret", endpoints: opts.github.endpoints };

  const env = { ...reviewEnv(opts.review), ...opts.env };

  if (Object.keys(env).length > 0) options.env = env;
  const srv = await startWorkerRegistry(options);

  const url = srv.url.endsWith("/") ? srv.url : `${srv.url}/`;

  return { url, stop: srv.stop, mintToken: srv.mint, blobs: srv.blobs, query: srv.query };
}

/** The Worker variables that turn the AI review on, as the deploy sets them; none when it is off. */
function reviewEnv(r: ReviewOptions | undefined) {
  if (r === undefined) return {};
  const optional = [
    ["APM_REVIEW_POPULAR_WEEKLY", r.popularWeekly],
    ["APM_NPM_DOWNLOADS_URL", r.downloadsUrl],
    ["APM_REVIEW_LEASE_MS", r.leaseMs],
    ["APM_REVIEW_REQUESTS_PER_HOUR", r.requestsPerHour],
    ["APM_REVIEW_MAX_ATTEMPTS", r.maxAttempts],
  ] as const;

  return Object.fromEntries([
    ["APM_REVIEW_TOKEN_HASH", r.serviceTokenHash],
    ["APM_ADMINS", r.admins.join(",")],
    ...optional.flatMap(([key, value]) => (value === undefined ? [] : [[key, String(value)] as const])),
  ]);
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
    ...spec.extra,
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

// ---------- raw publishes, for tests that control every byte ----------
/** The package.json fields raw-publish tests set. */
export type RawManifest = { name: string; version: string; license?: string; main?: string; scripts?: Record<string, string>; dependencies?: Record<string, string> };

function tarHeader(path: string, size: number): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string, off: number, len: number): void => h.set(new TextEncoder().encode(s).subarray(0, len), off);
  put(path, 0, 100);
  put("0000644\0", 100, 8);
  put("0000000\0", 108, 8);
  put("0000000\0", 116, 8);
  put(`${size.toString(8).padStart(11, "0")}\0`, 124, 12);
  put("00000000000\0", 136, 12);
  put("        ", 148, 8);
  put("0", 156, 1);
  put("ustar\0", 257, 6);
  put("00", 263, 2);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);

  return h;
}

/** A gzip'd package tarball: package.json from `manifest` plus `files`. */
export function pkgTgz(manifest: RawManifest, files: Record<string, string> = { "index.js": "module.exports = 1;\n" }): Uint8Array {
  const entries = [{ path: "package.json", data: JSON.stringify(manifest) }, ...Object.entries(files).map(([path, data]) => ({ path, data }))];
  const parts: Uint8Array[] = [];

  for (const f of entries) {
    const data = new TextEncoder().encode(f.data);
    parts.push(tarHeader(`package/${f.path}`, data.length), data, new Uint8Array((512 - (data.length % 512)) % 512));
  }

  parts.push(new Uint8Array(1024));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;

  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }

  return Bun.gzipSync(out);
}

/** A publish request the way npm sends it. `tags` defaults to { latest: version }. */
export async function putPublish(
  reg: Registry,
  token: string,
  manifest: RawManifest,
  opts: { files?: Record<string, string>; tags?: Record<string, string> } = {},
): Promise<{ status: number; body: unknown }> {
  const tgz = pkgTgz(manifest, opts.files);

  const body = {
    _id: manifest.name,
    name: manifest.name,
    "dist-tags": opts.tags ?? { latest: manifest.version },
    versions: { [manifest.version]: manifest },
    _attachments: { [`${manifest.name}-${manifest.version}.tgz`]: { content_type: "application/octet-stream", data: Buffer.from(tgz).toString("base64"), length: tgz.length } },
  };

  return getJson(`${reg.url}${encodePkg(manifest.name)}`, {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
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

// ---------- sign-in: a fake GitHub, a cookie jar, TOTP and the device login ----------

export type FakeGitHub = {
  url: string;
  endpoints: GitHubEndpoints;
  stop: () => Promise<void>;
  /** Renames a GitHub account: the numeric id stays, the login changes. The old login is free for someone else. */
  rename: (from: string, to: string) => void;
};

/**
 * A stand-in for github.com: /login/oauth/authorize signs in whoever the test names with `login=`
 * (default "octocat") and redirects straight back; the token and /user endpoints answer for that login.
 */
export function startFakeGitHub(): FakeGitHub {
  const ids = new Map<string, number>();
  let nextId = 5000;

  const idOf = (login: string): number => {
    const known = ids.get(login);

    if (known !== undefined) return known;
    const id = nextId++;
    ids.set(login, id);

    return id;
  };

  const loginOf = (req: Request): string => (req.headers.get("authorization") ?? "").replace(/^(Bearer|token)\s+gho_/i, "");

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const u = new URL(req.url);

      if (u.pathname === "/login/oauth/authorize") {
        const back = new URL(u.searchParams.get("redirect_uri") ?? "");
        back.searchParams.set("code", `code_${u.searchParams.get("login") ?? "octocat"}`);
        back.searchParams.set("state", u.searchParams.get("state") ?? "");

        return Response.redirect(back.toString(), 302);
      }

      if (u.pathname === "/login/oauth/access_token" && req.method === "POST") {
        const form = new URLSearchParams(await req.text());
        const code = form.get("code") ?? "";

        if (!code.startsWith("code_")) return Response.json({ error: "bad_verification_code" });

        return Response.json({ access_token: `gho_${code.slice(5)}`, token_type: "bearer", scope: "read:user,user:email" });
      }

      const login = loginOf(req);

      if (!login) return Response.json({ message: "Requires authentication" }, { status: 401 });

      if (u.pathname === "/user") return Response.json({ id: idOf(login), login, name: login, email: null, avatar_url: `https://avatars.example.test/${login}` });

      // GitHub verifies each address for one account only, so the address follows the numeric id, not the login.
      if (u.pathname === "/user/emails") return Response.json([{ email: `gh-${idOf(login)}@users.example.test`, primary: true, verified: true }]);

      return Response.json({ message: "Not Found" }, { status: 404 });
    },
  });

  const url = server.url.toString().replace(/\/$/, "");

  return {
    url,
    endpoints: { authorize: `${url}/login/oauth/authorize`, token: `${url}/login/oauth/access_token`, user: `${url}/user`, emails: `${url}/user/emails` },
    stop: () => server.stop(true),
    rename(from, to) {
      const id = idOf(from);
      ids.delete(from);
      ids.set(to, id);
    },
  };
}

/** A browser: a cookie jar plus the Origin header Better Auth checks on state-changing requests. */
export class Browser {
  private jar = new Map<string, string>();
  constructor(readonly reg: Registry) {}

  cookie(): string {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  take(res: Response): void {
    for (const line of res.headers.getSetCookie()) {
      const pair = line.split(";")[0] ?? "";
      const eq = pair.indexOf("=");

      if (eq <= 0) continue;
      const key = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();

      if (value === "" || /max-age=0(;|$)/i.test(line)) this.jar.delete(key);
      else this.jar.set(key, value);
    }
  }

  async fetch(pathOrUrl: string, init: { method?: string; body?: unknown; redirect?: "manual" | "follow"; headers?: Record<string, string> } = {}): Promise<Response> {
    const url = pathOrUrl.startsWith("http") ? pathOrUrl : `${this.reg.url}${pathOrUrl.replace(/^\//, "")}`;

    const res = await fetch(url, {
      method: init.method ?? "GET",
      redirect: init.redirect ?? "manual",
      headers: {
        origin: new URL(this.reg.url).origin,
        cookie: this.cookie(),
        ...(init.body !== undefined ? { "content-type": "application/json" } : {}),
        ...init.headers,
      },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });

    this.take(res);

    return res;
  }

  async json(pathOrUrl: string, init: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<{ status: number; body: unknown }> {
    const res = await this.fetch(pathOrUrl, init);
    const text = await res.text();
    let body: unknown = text;

    try {
      body = JSON.parse(text);
    } catch {
      // keep text
    }

    return { status: res.status, body };
  }
}

/** Signs in with "GitHub" (the fake) the way the website's button does, and returns the signed-in browser. */
export async function signInWithGitHub(reg: Registry, gh: FakeGitHub, login: string): Promise<Browser> {
  const b = new Browser(reg);
  const start = await b.json("api/auth/sign-in/social", { method: "POST", body: { provider: "github", callbackURL: "/", disableRedirect: true } });
  const authorizeUrl = dig(start.body, "url");

  if (start.status !== 200 || typeof authorizeUrl !== "string") throw new Error(`sign-in start failed: ${start.status} ${JSON.stringify(start.body)}`);
  const authorize = new URL(authorizeUrl);

  if (!authorize.toString().startsWith(gh.url)) throw new Error(`sign-in went to ${authorize.origin}, not the fake GitHub`);
  authorize.searchParams.set("login", login);
  const atGitHub = await fetch(authorize, { redirect: "manual" });
  const callback = atGitHub.headers.get("location");

  if (!callback) throw new Error("fake GitHub did not redirect back");
  const done = await b.fetch(callback);

  if (done.status >= 400) throw new Error(`sign-in callback failed: ${done.status} ${await done.text()}`);
  const session = await b.json("api/auth/get-session");

  if (session.status !== 200 || dig(session.body, "user") === undefined) throw new Error(`no session after sign-in: ${JSON.stringify(session.body)}`);

  return b;
}

function base32Decode(text: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";

  for (const ch of text.replace(/=+$/, "").toUpperCase()) {
    const i = alphabet.indexOf(ch);

    if (i < 0) throw new Error(`not base32: ${ch}`);
    bits += i.toString(2).padStart(5, "0");
  }

  const out: number[] = [];

  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));

  return new Uint8Array(out);
}

/** The clock the registry checks authenticator codes against in tests. Starts at real time; each request carries it. */
export const totpClock = { now: Date.now() };
const STEP_MS = 30_000;
const lastStep = new Map<string, number>();

/** RFC 6238 TOTP (SHA-1, 6 digits, 30s) for one time step. */
function codeAt(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = (h[h.length - 1] ?? 0) & 0x0f;

  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/**
 * What an authenticator app shows for this base32 secret, never a code this secret already got from
 * here: the registry accepts each time step once. Uses the current step or the next one (both inside
 * the registry's one-step window) and moves the TOTP clock forward only when both were handed out.
 */
export function totp(secret: string): string {
  const now = Math.floor(totpClock.now / STEP_MS);
  const step = Math.max(now, (lastStep.get(secret) ?? Number.NEGATIVE_INFINITY) + 1);

  if (step > now + 1) totpClock.now += (step - now - 1) * STEP_MS;
  lastStep.set(secret, step);

  return codeAt(secret, step);
}

/** A six-digit code that is not valid for this secret now (nor one step either side). */
export function wrongTotp(secret: string): string {
  const now = Math.floor(totpClock.now / STEP_MS);
  const valid = new Set([now - 1, now, now + 1, now + 2].map((st) => codeAt(secret, st)));

  for (let n = 0; ; n++) {
    const c = String(n).padStart(6, "0");

    if (!valid.has(c)) return c;
  }
}

/** Turns on authenticator-app 2FA for the signed-in account; returns the base32 secret. */
export async function enableTotp(b: Browser): Promise<string> {
  return (await enableTotpWithCodes(b)).secret;
}

/** Turns on authenticator-app 2FA; returns the secret and the recovery codes shown once at setup. */
export async function enableTotpWithCodes(b: Browser): Promise<{ secret: string; recoveryCodes: string[] }> {
  const en = await b.json("api/auth/two-factor/enable", { method: "POST", body: {} });
  const uri = dig(en.body, "totpURI");

  if (en.status !== 200 || typeof uri !== "string") throw new Error(`2FA enable failed: ${en.status} ${JSON.stringify(en.body)}`);
  const secret = new URL(uri).searchParams.get("secret");

  if (!secret) throw new Error("totpURI has no secret");
  const codes = dig(en.body, "backupCodes");
  const recoveryCodes = Array.isArray(codes) ? codes.map(String) : [];
  const v = await b.json("api/auth/two-factor/verify-totp", { method: "POST", body: { code: totp(secret) } });

  if (v.status !== 200) throw new Error(`2FA verify failed: ${v.status} ${JSON.stringify(v.body)}`);

  return { secret, recoveryCodes };
}

/** `apm login`'s device flow, with the signed-in browser approving the code. Returns the CLI token. */
export async function deviceLogin(b: Browser): Promise<{ token: string; username: string }> {
  const reg = b.reg;
  const start = await getJson(`${reg.url}-/apm/v1/login/device`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  const userCode = dig(start.body, "userCode");
  const deviceCode = dig(start.body, "deviceCode");
  const verificationUrl = dig(start.body, "verificationUrl");

  if (start.status !== 200 || typeof userCode !== "string" || typeof deviceCode !== "string" || typeof verificationUrl !== "string") {
    throw new Error(`device login start failed: ${start.status} ${JSON.stringify(start.body)}`);
  }

  const pending = await getJson(`${reg.url}-/apm/v1/login/device/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ deviceCode }) });

  if (pending.status === 200) throw new Error("device token was issued before anyone approved it");
  const claim = await b.json(`api/auth/device?user_code=${encodeURIComponent(userCode)}`);

  if (claim.status !== 200) throw new Error(`device claim failed: ${claim.status} ${JSON.stringify(claim.body)}`);
  const ok = await b.json("api/auth/device/approve", { method: "POST", body: { userCode } });

  if (ok.status !== 200) throw new Error(`device approve failed: ${ok.status} ${JSON.stringify(ok.body)}`);
  await Bun.sleep(1_100); // the CLI polls no faster than the interval
  const done = await getJson(`${reg.url}-/apm/v1/login/device/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ deviceCode }) });
  const token = dig(done.body, "token");
  const username = dig(done.body, "username");

  if (done.status !== 200 || typeof token !== "string" || typeof username !== "string") throw new Error(`device token failed: ${done.status} ${JSON.stringify(done.body)}`);

  return { token, username };
}

/** The approval id in an approval link printed by a publish, or null. */
export function approvalId(output: string): string | null {
  return /\/approve\/([A-Za-z0-9_-]+)/.exec(output)?.[1] ?? null;
}
