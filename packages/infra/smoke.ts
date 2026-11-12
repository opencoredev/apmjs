// Checks a deployed stage the way people use it: stock bun and npm install real npm packages through it, apm add
// refuses a low-score package, a login token stages a publish that goes live only after a TOTP approval, and
// bun audit reads advisories through it. Prints one PASS/FAIL line per check; exits non-zero on any FAIL.
//
//   bun packages/infra/smoke.ts --stage staging
//
// The staged-publish check needs a signed-in person. GitHub sign-in needs a real browser login, so on staging this
// script makes a check identity directly in the stage's database (user "apm-staging-check" with a GitHub account
// row) and signs a session cookie with the stage's AUTH_SECRET. Everything after that runs the deployed code:
// TOTP enrolment, the device login, npm publish, the approval and the install. It never runs against production.
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "pg";
import { z } from "zod";

const ROOT = join(import.meta.dirname, "..", "..");
const SECRETS = process.env.APM_SECRETS_DIR ?? join(homedir(), ".config", "apmjs");
const Stage = z.enum(["staging", "production"]);
const stageAt = process.argv.indexOf("--stage");
const stage = Stage.parse(stageAt > 0 ? process.argv[stageAt + 1] : "staging");
const SUBDOMAIN = process.env.WORKERS_SUBDOMAIN ?? "leoisadev";
const registry = stage === "production" ? "https://registry.apmjs.dev/" : `https://apmjs-registry-${stage}.${SUBDOMAIN}.workers.dev/`;
const web = stage === "production" ? "https://apmjs.dev/" : `https://apmjs-web-${stage}.${SUBDOMAIN}.workers.dev/`;
const work = mkdtempSync(join(tmpdir(), "apm-smoke-"));
const results: { ok: boolean; name: string; detail: string }[] = [];

function record(ok: boolean, name: string, detail: string): void {
  results.push({ ok, name, detail });
  process.stdout.write(`${ok ? "PASS" : "FAIL"}: ${name} (${detail})\n`);
}

async function run(cmd: string[], cwd: string, env: Record<string, string> = {}): Promise<{ code: number; out: string }> {
  const proc = Bun.spawn(cmd, {
    cwd,
    env: { PATH: process.env.PATH ?? "", HOME: work, NO_COLOR: "1", npm_config_cache: join(work, ".npm"), BUN_INSTALL_CACHE_DIR: join(work, ".bun"), ...env },
    stdout: "pipe",
    stderr: "pipe",
  });

  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  return { code, out: stdout + stderr };
}

function project(name: string, files: Record<string, string> = {}): string {
  const dir = join(work, name);
  Bun.spawnSync(["mkdir", "-p", dir]);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", private: true }));
  writeFileSync(join(dir, "bunfig.toml"), `[install]\nregistry = "${registry}"\n`);
  writeFileSync(join(dir, ".npmrc"), `registry=${registry}\n`);

  for (const [file, text] of Object.entries(files)) writeFileSync(join(dir, file), text);

  return dir;
}

function installed(dir: string, name: string): string | null {
  const p = join(dir, "node_modules", ...name.split("/"), "package.json");

  return existsSync(p) ? z.object({ version: z.string() }).parse(JSON.parse(readFileSync(p, "utf8"))).version : null;
}

// ---------- stock clients ----------
async function stockClients(): Promise<void> {
  const b = project("bun-app");
  const bunAdd = await run(["bun", "add", "chalk@5.3.0", "ms"], b);
  record(bunAdd.code === 0 && installed(b, "chalk") === "5.3.0", "bun add of real npm packages through the registry", `exit ${bunAdd.code}, chalk ${installed(b, "chalk")}`);
  const n = project("npm-app");
  const npm = await run(["npm", "install", "--no-audit", "--no-fund", "is-odd@3.0.1"], n);
  const lock = existsSync(join(n, "package-lock.json")) ? readFileSync(join(n, "package-lock.json"), "utf8") : "";
  record(npm.code === 0 && installed(n, "is-odd") === "3.0.1" && lock.includes(registry), "npm install of a real npm package through the registry", `exit ${npm.code}, lockfile resolves to the registry: ${lock.includes(registry)}`);
}

async function apmRefusal(): Promise<void> {
  const dir = project("apm-app");
  const env = { APM_REGISTRY: registry };
  const bad = await run(["bun", join(ROOT, "packages", "cli", "src", "main.ts"), "add", "puppeteer@1.20.0"], dir, env);
  record(bad.code !== 0 && installed(dir, "puppeteer") === null && /below 40/.test(bad.out), "apm add refuses a low-score npm package (puppeteer@1.20.0)", `exit ${bad.code}, installed ${installed(dir, "puppeteer")}`);
  const good = await run(["bun", join(ROOT, "packages", "cli", "src", "main.ts"), "add", "ms"], dir, env);
  record(good.code === 0 && installed(dir, "ms") !== null, "apm add installs a clean npm package (ms)", `exit ${good.code}`);
}

async function bunAudit(): Promise<void> {
  const dir = project("audit-app");
  await run(["bun", "add", "minimist@0.0.8"], dir);
  const audit = await run(["bun", "audit"], dir);
  record(audit.code !== 0 && /minimist/.test(audit.out) && /critical/.test(audit.out), "bun audit reports npm advisories through the registry", `exit ${audit.code}`);
}

// ---------- staged publish and approval ----------
const CHECK = { authUserId: "apm-staging-check", githubId: "990000001", login: "apm-staging-check" } as const;

function totp(secret: string, at: number = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";

  for (const ch of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = new Uint8Array(Math.floor(bits.length / 8)).map((_, i) => parseInt(bits.slice(i * 8, i * 8 + 8), 2));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const offset = (h[h.length - 1] ?? 0) & 0x0f;

  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** The stage's database, the check identity in it, and a fresh signed session for that identity. */
async function checkSession(): Promise<{ cookie: string; done: () => Promise<void> }> {
  const neon = new URL(readFileSync(join(SECRETS, "neon-url"), "utf8").trim());
  neon.pathname = "/apmjs_staging";
  neon.searchParams.set("sslmode", "verify-full");
  const secret = readFileSync(join(SECRETS, `auth-secret-${stage}`), "utf8").trim();
  const db = new Client({ connectionString: neon.toString() });
  await db.connect();
  const now = new Date();
  await db.query(
    `INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt") VALUES ($1, $2, $3, true, $4, $4) ON CONFLICT (id) DO NOTHING`,
    [CHECK.authUserId, "apm staging check", "apm-staging-check@users.noreply.github.com", now],
  );
  await db.query(
    `INSERT INTO account (id, "accountId", "providerId", "userId", "createdAt", "updatedAt") SELECT $1, $2, 'github', $3, $4, $4 WHERE NOT EXISTS (SELECT 1 FROM account WHERE id = $1)`,
    [`${CHECK.authUserId}-github`, CHECK.githubId, CHECK.authUserId, now],
  );
  await db.query(`INSERT INTO github_profiles (github_id, login, updated_at) VALUES ($1, $2, $3) ON CONFLICT (github_id) DO NOTHING`, [CHECK.githubId, CHECK.login, now.getTime()]);
  const token = randomBytes(24).toString("base64url");
  await db.query(`INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "userId") VALUES ($1, $2, $3, $4, $4, $5)`, [
    `smoke-${token.slice(0, 12)}`,
    new Date(now.getTime() + 30 * 60_000),
    token,
    now,
    CHECK.authUserId,
  ]);
  const signature = createHmac("sha256", secret).update(token).digest("base64");
  const value = encodeURIComponent(`${token}.${signature}`);

  return {
    cookie: `__Secure-better-auth.session_token=${value}; better-auth.session_token=${value}`,
    done: async () => {
      await db.query(`DELETE FROM session WHERE token = $1`, [token]);
      await db.end();
    },
  };
}

/** A browser's cookie jar: Better Auth rotates the session cookie (after TOTP verification, for one). */
class Jar {
  private readonly cookies = new Map<string, string>();
  constructor(initial: string) {
    for (const pair of initial.split("; ")) this.set(pair);
  }
  private set(pair: string): void {
    const eq = pair.indexOf("=");

    if (eq > 0) this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
  take(res: Response): void {
    for (const line of res.headers.getSetCookie()) {
      const pair = line.split(";")[0] ?? "";
      const name = pair.slice(0, pair.indexOf("=")).trim();

      if (/max-age=0(;|$)/i.test(line) || pair.endsWith("=")) this.cookies.delete(name);
      else this.set(pair);
    }
  }
  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

async function call(path: string, init: { method?: string; jar?: Jar; body?: unknown; origin?: string } = {}): Promise<{ status: number; body: unknown }> {
  const headers = new Headers({ origin: init.origin ?? new URL(web).origin });

  if (init.jar) headers.set("cookie", init.jar.header());

  if (init.body !== undefined) headers.set("content-type", "application/json");
  const res = await fetch(`${registry}${path}`, { method: init.method ?? "GET", headers, body: init.body === undefined ? undefined : JSON.stringify(init.body) });
  init.jar?.take(res);
  const text = await res.text();
  let body: unknown = text;

  try {
    body = JSON.parse(text);
  } catch {
    // keep text
  }

  return { status: res.status, body };
}

const TotpUri = z.object({ totpURI: z.string() });
const DeviceStart = z.object({ deviceCode: z.string(), userCode: z.string() });
const DeviceToken = z.object({ token: z.string(), username: z.string() });
const AccountView = z.object({ security: z.object({ totp: z.boolean() }) });

async function stagedPublish(): Promise<void> {
  if (stage !== "staging") {
    record(true, "staged publish and approval", "skipped: runs only on staging, where it may create a check identity");

    return;
  }

  const session = await checkSession();
  const jar = new Jar(session.cookie);

  try {
    const totpFile = join(SECRETS, "staging-check-totp");
    const account = AccountView.parse((await call("-/apm/v1/account", { jar })).body);
    let secret = existsSync(totpFile) ? readFileSync(totpFile, "utf8").trim() : null;

    if (!account.security.totp || secret === null) {
      const en = await call("api/auth/two-factor/enable", { method: "POST", jar, body: {} });
      secret = new URL(TotpUri.parse(en.body).totpURI).searchParams.get("secret");

      if (!secret) throw new Error("two-factor/enable returned no secret");
      const v = await call("api/auth/two-factor/verify-totp", { method: "POST", jar, body: { code: totp(secret) } });

      if (v.status !== 200) throw new Error(`verify-totp: ${v.status} ${JSON.stringify(v.body)}`);
      writeFileSync(totpFile, `${secret}\n`, { mode: 0o600 });
    }

    const start = DeviceStart.parse((await call("-/apm/v1/login/device", { method: "POST", body: {} })).body);
    const claim = await call(`api/auth/device?user_code=${encodeURIComponent(start.userCode)}`, { jar });
    const approveDevice = await call("api/auth/device/approve", { method: "POST", jar, body: { userCode: start.userCode } });

    if (claim.status !== 200 || approveDevice.status !== 200) throw new Error(`device approval: ${claim.status}/${approveDevice.status} ${JSON.stringify(approveDevice.body)}`);
    await Bun.sleep(1_200);
    const login = DeviceToken.parse((await call("-/apm/v1/login/device/token", { method: "POST", body: { deviceCode: start.deviceCode } })).body);
    record(login.username === CHECK.login, "apm login's device flow issues a token for the signed-in account", `user ${login.username}`);

    const name = `@${CHECK.login}/smoke-${Date.now().toString(36)}`;
    const pkg = join(work, "publish");
    Bun.spawnSync(["mkdir", "-p", pkg]);
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name, version: "1.0.0", main: "index.js", license: "MIT", description: "apm staging smoke check" }));
    writeFileSync(join(pkg, "index.js"), "module.exports = 'apm staging smoke check';\n");
    writeFileSync(join(pkg, ".npmrc"), `registry=${registry}\n//${new URL(registry).host}/:_authToken=${login.token}\n`);
    const pub = await run(["npm", "publish", "--registry", registry], pkg);
    const id = /\/approve\/([A-Za-z0-9_-]+)/.exec(pub.out)?.[1] ?? null;
    const hidden = await call(`${name.replace("/", "%2F")}`);
    record(pub.code === 0 && id !== null && hidden.status === 404, "npm publish with a login token stages the version and prints the approval link", `exit ${pub.code}, link ${id !== null}, packument ${hidden.status}`);

    if (id === null) return;
    const approved = await call(`-/apm/v1/staged/${id}/approve`, { method: "POST", jar, body: { code: totp(secret) } });
    const live = await call(`${name.replace("/", "%2F")}`);
    record(approved.status === 200 && live.status === 200, "a TOTP approval makes the staged version live", `approve ${approved.status}, packument ${live.status}`);
    const consumer = project("consumer");
    const install = await run(["npm", "install", "--no-audit", "--no-fund", `${name}@1.0.0`], consumer);
    record(install.code === 0 && installed(consumer, name) === "1.0.0", "the approved version installs with npm", `exit ${install.code}`);
  } finally {
    await session.done();
  }
}

process.stdout.write(`smoke: ${stage} registry ${registry}\n`);

await stockClients();

await apmRefusal();

await stagedPublish();

await bunAudit();

rmSync(work, { recursive: true, force: true });

const failed = results.filter((r) => !r.ok).length;

process.stdout.write(`${results.length - failed}/${results.length} passed\n`);

process.exit(failed === 0 ? 0 : 1);
