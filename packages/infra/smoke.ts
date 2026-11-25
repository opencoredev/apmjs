// Checks a deployed stage the way people use it: stock bun and npm install real npm packages through it, apm add
// refuses a low-score package, a login token stages a publish that goes live only after a TOTP approval, and
// bun audit reads advisories through it, and the stage's own CLI install script (/install) installs apm into a fresh
// HOME after checking its SHA-256. The website's explain must answer a large package (next) and refuse a version the OSSF
// malicious-packages feed lists, which the registry must withhold from its packuments and refuse as a tarball, all read
// without installing. Prints one PASS/FAIL line per check; exits non-zero on any FAIL. No package install
// it runs executes a package's install script, and the raw npm and bun installs install committed lockfiles (smoke-commands.ts,
// smoke-fixtures/): what a registry answers never runs code here and cannot add a dependency. That the registry
// resolves versions is checked by reading its metadata, without installing.
//
//   bun packages/infra/smoke.ts --stage staging [--build <id> --subdomain <workers.dev subdomain>]
//
// deploy.ts passes --build (its run's build id) and --subdomain (the account's, as it resolved it). With --build, the
// registry and the website must answer uncached with that build before the behavioural checks and again after them
// (smoke-identity.ts): an old version that still gives the same answers fails the check. Without it, run by hand,
// which version answers is not checked.
//
// The staged-publish check needs a signed-in person. GitHub sign-in needs a real browser login, so on staging this
// script makes a check identity directly in the stage's database (user "apm-staging-check" with a GitHub account
// row) and signs a session cookie with the stage's AUTH_SECRET. Everything after that runs the deployed code:
// TOTP enrolment, the device login, npm publish, the approval and the install. It never runs against production.
// Browser steps go to the website (which forwards them to the registry over a service binding); npm and the
// CLI's steps go to the registry.
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "pg";
import { z } from "zod";
import { apmAdd, bunInstallLocked, metadataProblem, NO_SCRIPTS_ENV, npmCi, PROBE_NAMES, probeFixture, singleLockfile, tarballPath, type Locked, type Probe } from "./smoke-commands.ts";
import { confirmBuild, parseSmokeArgs, smokeTargets } from "./smoke-identity.ts";
import { largeExplain, ossfListed } from "./smoke-probes.ts";
import { installCheck } from "./cli-check.ts";
import { cliLedgerPath } from "./cli-ledger.ts";
import { cliRecordOf, installStep, killRunning, LARGE_PACKAGES, largePackageAnswer, resultLine, smokeTimeouts, spawnBounded, type CheckAnswer } from "./smoke-checks.ts";

const ROOT = join(import.meta.dirname, "..", "..");
const CLI_MAIN = join(ROOT, "packages", "cli", "src", "main.ts");
const SECRETS = process.env.APM_SECRETS_DIR ?? join(homedir(), ".config", "apmjs");
const TIMEOUTS = smokeTimeouts(process.env);
const { stage, build, subdomain } = parseSmokeArgs(process.argv.slice(2));
const { registry, web, docs } = smokeTargets(stage, subdomain);
const work = mkdtempSync(join(tmpdir(), "apm-smoke-"));

// the workspace holds a login token in publish/.npmrc, so it goes however the run ends: a thrown check, an exit or a
// signal; so do the commands still running, whose process groups outlive this one
const removeWork = (): void => rmSync(work, { recursive: true, force: true });

process.on("exit", () => {
  killRunning();
  removeWork();
});

// SIGHUP: an operator's SSH session dropping. SIGKILL cannot be caught; nothing here can clean up after it.
const SIGNAL_EXITS = [["SIGHUP", 129], ["SIGINT", 130], ["SIGQUIT", 131], ["SIGABRT", 134], ["SIGTERM", 143]] as const;

for (const [signal, code] of SIGNAL_EXITS) process.on(signal, () => process.exit(code));

const results: { ok: boolean; name: string; detail: string }[] = [];

function record(ok: boolean, name: string, detail: string): void {
  results.push({ ok, name, detail });
  process.stdout.write(resultLine(ok, name, detail));
}

/** fetch, cut short after TIMEOUTS.httpMs: a hung endpoint fails its check instead of holding the run. */
function bounded(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUTS.httpMs) });
}

/** Runs one check; one that throws (a request cut short, an unreadable answer) fails as itself and the rest still run. */
async function check(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (e) {
    const timedOut = e instanceof Error && e.name === "TimeoutError";

    record(false, name, timedOut ? `no answer within ${TIMEOUTS.httpMs} ms` : `stopped: ${e instanceof Error ? e.message : String(e)}`);
  }
}

async function run(cmd: string[], cwd: string, env: Record<string, string> = {}): Promise<{ code: number; out: string; stdout: string }> {
  const r = await spawnBounded(cmd, { cwd, env: { PATH: process.env.PATH ?? "", HOME: work, NO_COLOR: "1", npm_config_cache: join(work, ".npm"), BUN_INSTALL_CACHE_DIR: join(work, ".bun"), TMPDIR: tmpdir(), ...env, ...NO_SCRIPTS_ENV } }, TIMEOUTS.commandMs);
  const stopped = r.stopped ? `\n(stopped: ${cmd.slice(0, 3).join(" ")} gave no result within ${TIMEOUTS.commandMs} ms)` : "";

  return { code: r.code, out: r.stdout + r.stderr + stopped, stdout: r.stdout };
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

/** A project holding a probe's committed package.json and lockfile, configured for the registry under test. */
function locked(probe: Probe): string {
  return project(probe, probeFixture(probe).files);
}

function installed(dir: string, name: string): string | null {
  const p = join(dir, "node_modules", ...name.split("/"), "package.json");

  return existsSync(p) ? z.object({ version: z.string() }).parse(JSON.parse(readFileSync(p, "utf8"))).version : null;
}

// ---------- which version answers ----------
/** How long the check before the behavioural ones waits for the new versions to take the traffic. */
const TAKEOVER_MS = 120_000;

/** Both Workers that run code answer with this run's build: `wait` before the checks, no waiting after them. */
async function identity(when: "before" | "after"): Promise<void> {
  if (build === null) {
    if (when === "before") process.stdout.write("which version answers: not checked (no --build)\n");

    return;
  }

  for (const [name, url] of [["the registry", `${registry}-/ping`], ["the website", `${web}api/build`]] as const) {
    const r = await confirmBuild({ name, url, expected: build, consecutive: 3, deadlineMs: when === "before" ? TAKEOVER_MS : 0 });

    record(r.ok, `${name} answers with this run's build ${when} the checks`, r.detail);
  }
}

// ---------- the CLI's install ----------
/**
 * The documented install, `curl -fsSL <site>/install | sh`, into a fresh HOME (cli-check.ts): it must install, the
 * installed apm must print the version, and the fingerprint the script printed must be the installed file's SHA-256 and
 * the one the version's SHA256SUMS lists. A stage with no CLI release yet answers /install with 404 and a sentence
 * saying so; that passes only while this machine's CLI release record (cli-ledger.ts) exists, parses, and has no release for the
 * stage (smoke-checks.ts, installStep).
 */
async function cliInstall(): Promise<void> {
  const site = web.replace(/\/$/, "");
  const res = await bounded(`${site}/install`, { method: "HEAD" });
  const step = installStep({ status: res.status, stage, readRecord: () => cliRecordOf(stage, cliLedgerPath()) });

  if (step.kind !== "install") {
    record(step.kind === "skip", "the CLI install script", step.detail);

    return;
  }

  const r = await installCheck(site, TIMEOUTS);

  record(r.ok, `curl -fsSL ${site}/install | sh installs apm and checks its SHA-256`, r.detail);
}

// ---------- docs ----------
async function docsSite(): Promise<void> {
  const home = await bounded(docs, { redirect: "manual" });
  const text = await home.text();
  record(home.status === 200 && text.includes("apm documentation"), "the docs site serves its home page", `HTTP ${home.status}`);
  // assets-only Worker with drop-trailing-slash: a page answers at its own path, without a redirect
  const page = await bounded(`${docs}quickstart`, { redirect: "manual" });
  record(page.status === 200, "a docs page answers without a redirect", `/quickstart HTTP ${page.status}`);
}

// ---------- stock clients ----------
async function stockClients(): Promise<void> {
  const b = locked("bun-app");
  const added = await run(bunInstallLocked(registry), b);
  record(added.code === 0 && installed(b, "chalk") === "5.3.0" && installed(b, "ms") === "2.1.3", "bun install of a locked project of real npm packages (chalk 5.3.0, ms 2.1.3) through the registry", `exit ${added.code}, chalk ${installed(b, "chalk")}, ms ${installed(b, "ms")}`);
  const n = locked("npm-app");
  const npm = await run(npmCi(registry), n);
  record(npm.code === 0 && installed(n, "is-odd") === "3.0.1" && installed(n, "is-number") === "6.0.0", "npm ci of a locked project of a real npm package (is-odd 3.0.1) through the registry", `exit ${npm.code}, is-odd ${installed(n, "is-odd")}, is-number ${installed(n, "is-number")}`);
}

/** The registry's install metadata for a package (what npm and bun resolve from): its status and parsed JSON body. */
async function installMetadata(name: string): Promise<{ status: number; body: unknown }> {
  const res = await bounded(`${registry}${name.replace("/", "%2F")}`, { headers: { accept: "application/vnd.npm.install-v1+json" } });

  return { status: res.status, body: res.status === 200 ? await res.json().catch(() => null) : null };
}

/**
 * Resolution through the registry, without installing: for every version the probes lock, the registry's install
 * metadata lists it with exactly the lockfile's integrity and dependency edges, advertises its tarball at exactly the
 * URL the locked installs fetch, and names as latest a version it lists (metadataProblem). A registry that resolves
 * wrongly fails here; the locked installs never resolve.
 */
async function resolution(): Promise<void> {
  const all = new Map<string, Locked>();

  for (const probe of PROBE_NAMES) for (const l of probeFixture(probe).locked) all.set(`${l.name}@${l.version}`, l);
  const wrong: string[] = [];

  for (const l of all.values()) {
    const problem = metadataProblem({ registry, ...(await installMetadata(l.name)), locked: l, latest: "listed" });

    if (problem !== null) wrong.push(problem);
  }

  record(wrong.length === 0, "the registry resolves every locked version to the lockfile's integrity, tarball URL and dependencies, and latest is a listed version (metadata only, nothing installed)", wrong.length === 0 ? `${all.size} versions` : wrong.join("; "));
}

// ---------- install verdicts and the OSSF feed (smoke-probes.ts) ----------
async function verdictProbes(): Promise<void> {
  // the probes bound each read themselves; APM_SMOKE_HTTP_TIMEOUT_MS bounds it too, as it does every other request here
  const deps = { fetch: (url: string, init: { headers: Record<string, string>; signal: AbortSignal }) => fetch(url, { ...init, signal: AbortSignal.any([init.signal, AbortSignal.timeout(TIMEOUTS.httpMs)]) }), registry, web };

  for (const c of [await largeExplain(deps), ...(await ossfListed(deps))]) record(c.ok, c.name, c.detail);
}

/**
 * The package check agents read (GET /api/explain) for packages whose check walks a very large tree. Issue #1: next
 * and firebase answered "unknown" for over 90 minutes while small packages, the only ones the monitors asked about,
 * answered. Each must be a real verdict with a version; next is checked by largeExplain (smoke-probes.ts).
 */
async function largePackages(): Promise<void> {
  for (const name of LARGE_PACKAGES) {
    let answer: CheckAnswer;

    try {
      const res = await bounded(`${web}api/explain?package=${encodeURIComponent(name)}`, { headers: { accept: "application/json", "cache-control": "no-cache" } });

      answer = largePackageAnswer({ name, status: res.status, body: await res.json().catch(() => null) });
    } catch (e) {
      answer = { ok: false, detail: `${name}: ${e instanceof Error && e.name === "TimeoutError" ? `no answer within ${TIMEOUTS.httpMs} ms` : e instanceof Error ? e.message : String(e)}` };
    }

    record(answer.ok, `the package check gives a very large package (${name}) a real verdict, not unknown`, answer.detail);
  }
}

/**
 * What apm add says about a version it flags, by what the registry knows of it. By default each is a warning and the
 * install goes ahead (the owner's warn-not-block policy, 2026-11); with --strict each is a refusal. Null when the
 * output shows none of them.
 */
const WARNINGS = [
  ["scored below the floor", /under the floor of 40/],
  ["incomplete", /could not fully analyse it/],
  ["not scored yet", /not scored yet/],
  ["cannot be scored", /apm cannot score this version/],
] as const;

const REFUSALS = [
  ["scored below the floor", /below 40/],
  ["still being analysed", /is still being analysed, try again in a minute/],
  ["cannot be scored", /apm cannot score this version/],
] as const;

function matchOf(list: readonly (readonly [string, RegExp])[], out: string): string | null {
  return list.find(([, re]) => re.test(out))?.[0] ?? null;
}

/** A failed check's whole CLI output, indented under its FAIL line, so a failure says what apm printed. */
function transcript(ok: boolean, out: string): void {
  if (ok) return;
  process.stdout.write(`${out.trimEnd().split("\n").map((l) => `    | ${l}`).join("\n")}\n`);
}

/**
 * The low-score package the warn path installs: three 0.187.0. Its analysis is incomplete (its largest files are past
 * what apm reads), so it scores under 40 on every run; it has no dependencies and no install scripts, and it was
 * published weeks ago. puppeteer 1.20.0, the check's first target, brings in a tree of dependencies, so whenever one of them
 * publishes (ws 6.2.7 did, 7 hours before a run) its warnings include the cooldown's, beside the score's (before the
 * review of 2fbf383 the cooldown refused the install in every mode, and the check failed on it). Its install script
 * also downloads Chromium.
 */
const LOW_SCORE = { name: "three", version: "0.187.0" } as const;

// Anonymous: a version not scored yet is queued, and the registry waits for the queue (about 20 s) before it answers.
// A cold analysis can take longer than that, or end in an outcome that is not a score, so any of the warnings (and,
// with --strict, any of the refusals) passes, and the detail says which, and how long each took.
async function apmWarning(): Promise<void> {
  const env = { APM_REGISTRY: registry };
  const spec = `${LOW_SCORE.name}@${LOW_SCORE.version}`;
  const dir = project("apm-app");
  const t0 = Date.now();
  const warned = await run(apmAdd(CLI_MAIN, spec), dir, env);
  const warning = /WARNING/.test(warned.out) ? matchOf(WARNINGS, warned.out) : null;
  const warnedOk = warned.code === 0 && installed(dir, LOW_SCORE.name) === LOW_SCORE.version && warning !== null;

  record(warnedOk, `apm add warns about a low-score npm package (${spec}) and installs it`, `exit ${warned.code}, installed ${installed(dir, LOW_SCORE.name)}, warned as ${warning ?? "nothing apm says"}, ${((Date.now() - t0) / 1000).toFixed(1)} s`);
  transcript(warnedOk, warned.out);
  const strictDir = project("apm-strict-app");
  const t1 = Date.now();
  const bad = await run(apmAdd(CLI_MAIN, spec, ["--strict"]), strictDir, env);
  const refusal = matchOf(REFUSALS, bad.out);
  const refusedOk = bad.code !== 0 && installed(strictDir, LOW_SCORE.name) === null && refusal !== null;

  record(refusedOk, "apm add --strict refuses it", `exit ${bad.code}, installed ${installed(strictDir, LOW_SCORE.name)}, refused as ${refusal ?? "nothing apm says"}, ${((Date.now() - t1) / 1000).toFixed(1)} s`);
  transcript(refusedOk, bad.out);
  const t2 = Date.now();
  const good = await run(apmAdd(CLI_MAIN, "ms"), dir, env);
  const goodOk = good.code === 0 && installed(dir, "ms") !== null;

  record(goodOk, "apm add installs a clean npm package (ms)", `exit ${good.code}, ${((Date.now() - t2) / 1000).toFixed(1)} s`);
  transcript(goodOk, good.out);
}

/**
 * bun audit of a locked project holding a version with known advisories. The audit reads what is installed, so the
 * locked install must pass first (review of 96f0ba7, finding 5): a failed install fails this check instead of
 * leaving the audit to read nothing.
 */
async function bunAudit(): Promise<void> {
  const dir = locked("audit-app");
  const want = probeFixture("audit-app").locked;
  const add = await run(bunInstallLocked(registry), dir);
  const got = want.map((l) => `${l.name} ${installed(dir, l.name)}`);
  const installOk = add.code === 0 && want.every((l) => installed(dir, l.name) === l.version);

  record(installOk, "bun install of the locked audit project (minimist 0.0.8) through the registry", `exit ${add.code}, ${got.join(", ")}`);
  transcript(installOk, add.out);

  if (!installOk) {
    record(false, "bun audit reports npm advisories through the registry", "not run: the audit project did not install");

    return;
  }

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
  const db = new Client({ connectionString: neon.toString(), connectionTimeoutMillis: TIMEOUTS.httpMs, query_timeout: TIMEOUTS.httpMs });
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

/** A request the way a browser (to the website) or the CLI (to the registry) sends it. */
async function call(path: string, init: { method?: string; jar?: Jar; body?: unknown; origin?: string; via?: "web" | "registry" } = {}): Promise<{ status: number; body: unknown }> {
  const headers = new Headers({ origin: init.origin ?? new URL(web).origin });

  if (init.jar) headers.set("cookie", init.jar.header());

  if (init.body !== undefined) headers.set("content-type", "application/json");
  const res = await bounded(`${init.via === "registry" ? registry : web}${path}`, { method: init.method ?? "GET", headers, body: init.body === undefined ? undefined : JSON.stringify(init.body) });
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
const Packed = z.tuple([z.object({ filename: z.string(), integrity: z.string() })]);
const DeviceStart = z.object({ deviceCode: z.string(), userCode: z.string() });
const DeviceToken = z.object({ token: z.string(), username: z.string() });
const AccountView = z.object({ security: z.object({ totp: z.boolean() }) });

/**
 * The sign-in code is loaded only when a request needs it (registry auth-engine.ts, its own module beside the entry):
 * a deploy missing it still answers installs, so a signed-out session read, which loads it, is checked on every stage.
 */
async function signInLoads(): Promise<void> {
  const res = await bounded(`${web}api/auth/get-session`, { headers: { accept: "application/json", "cache-control": "no-cache" } });
  const text = await res.text();

  record(res.status === 200 && text.trim() === "null", "the sign-in code loads: a signed-out session read answers null", `HTTP ${res.status}, ${text.trim().slice(0, 40)}`);
}

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

    const start = DeviceStart.parse((await call("-/apm/v1/login/device", { method: "POST", body: {}, via: "registry" })).body);
    const claim = await call(`api/auth/device?user_code=${encodeURIComponent(start.userCode)}`, { jar });
    const approveDevice = await call("api/auth/device/approve", { method: "POST", jar, body: { userCode: start.userCode } });

    if (claim.status !== 200 || approveDevice.status !== 200) throw new Error(`device approval: ${claim.status}/${approveDevice.status} ${JSON.stringify(approveDevice.body)}`);
    await Bun.sleep(1_200);
    const login = DeviceToken.parse((await call("-/apm/v1/login/device/token", { method: "POST", body: { deviceCode: start.deviceCode }, via: "registry" })).body);
    record(login.username === CHECK.login, "apm login's device flow issues a token for the signed-in account", `user ${login.username}`);

    const name = `@${CHECK.login}/smoke-${Date.now().toString(36)}`;
    const pkg = join(work, "publish");
    Bun.spawnSync(["mkdir", "-p", pkg]);
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name, version: "1.0.0", main: "index.js", license: "MIT", description: "apm staging smoke check" }));
    writeFileSync(join(pkg, "index.js"), "module.exports = 'apm staging smoke check';\n");
    writeFileSync(join(pkg, ".npmrc"), `registry=${registry}\n//${new URL(registry).host}/:_authToken=${login.token}\n`);
    // packed here first, so the consumer's lockfile holds the integrity of the bytes this script made, not one the
    // registry reports
    const packed = await run(["npm", "pack", "--json", "--pack-destination", work], pkg);
    const tarball = Packed.parse(JSON.parse(packed.stdout))[0];
    const pub = await run(["npm", "publish", join(work, tarball.filename), "--registry", registry], pkg);
    const id = /\/approve\/([A-Za-z0-9_-]+)/.exec(pub.out)?.[1] ?? null;
    const hidden = await call(`${name.replace("/", "%2F")}`, { via: "registry" });
    record(pub.code === 0 && id !== null && hidden.status === 404, "npm publish with a login token stages the version and prints the approval link", `exit ${pub.code}, link ${id !== null}, packument ${hidden.status}`);

    if (id === null) return;
    const approved = await call(`-/apm/v1/staged/${id}/approve`, { method: "POST", jar, body: { code: totp(secret) } });
    // live means installable as published (review of 96f0ba7, finding 4): the approved version is listed with the
    // integrity of the tarball this check packed, at the tarball URL an install fetches, and latest names it
    // the package this check packed declares no dependencies
    const expected: Locked = { name, version: "1.0.0", integrity: tarball.integrity, edges: { installs: {}, peers: {} } };
    const live = metadataProblem({ registry, ...(await installMetadata(name)), locked: expected, latest: "this" });
    record(approved.status === 200 && live === null, "a TOTP approval makes the staged version live, as packed and tagged latest", `approve ${approved.status}, ${live ?? "metadata matches"}`);
    const lockfile = singleLockfile("consumer", { ...expected, resolved: `${registry}${tarballPath(name, "1.0.0")}` });
    const consumer = project("consumer", { "package.json": JSON.stringify({ name: "consumer", version: "1.0.0", private: true, dependencies: { [name]: "1.0.0" } }), "package-lock.json": lockfile });
    const install = await run(npmCi(registry), consumer);
    record(install.code === 0 && installed(consumer, name) === "1.0.0", "the approved version installs with npm (npm ci, the integrity of the tarball this check packed)", `exit ${install.code}`);
  } finally {
    await session.done();
  }
}

async function concurrentPages(): Promise<void> {
  for (const [label, base] of [["the home page", web], ["a package page (react)", `${web}package/react`]] as const) {
    const results = await Promise.all(
      Array.from({ length: 16 }, async (_, i) => {
        const res = await bounded(`${base}?smoke=${i}`, { headers: { "accept-encoding": "identity" } });
        const html = await res.text();

        return { ok: res.status === 200 && html.trimEnd().endsWith("</html>") && /<title>[^<]+<\/title>/.test(html), status: res.status, bytes: html.length };
      }),
    );

    const bad = results.filter((r) => !r.ok);

    record(bad.length === 0, `${label} finishes every render under 16 concurrent requests`, bad.length === 0 ? "16/16 complete HTML" : `${bad.length}/16 cut off (${bad.slice(0, 3).map((b) => `HTTP ${b.status} ${b.bytes}B`).join(", ")})`);
  }
}

process.stdout.write(`smoke: ${stage} registry ${registry}\n`);

await identity("before");

await check("the docs site", docsSite);

await check("the CLI install script", cliInstall);

await check("stock clients install through the registry", stockClients);

await check("the registry resolves locked versions", resolution);

await check("explain verdicts and the OSSF feed", verdictProbes);

await check("the package check for very large packages", largePackages);

await check("apm add warns and --strict refuses", apmWarning);

await check("the sign-in code loads", signInLoads);

await check("staged publish and approval", stagedPublish);

await check("bun audit reads advisories", bunAudit);

await check("pages finish under concurrent requests", concurrentPages);

await identity("after");

const failed = results.filter((r) => !r.ok).length;

process.stdout.write(`${results.length - failed}/${results.length} passed\n`);

process.exit(failed === 0 ? 0 : 1);
