// Spec (launch-readiness review of 5b4544c): one test per finding, each reproduced against the real
// registry, the apm CLI and the stock bun, npm and pnpm clients. Payloads are inert stand-ins: install
// scripts write a marker file, "network" calls go to example.invalid, and secrets are fake strings.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  startRegistry,
  startFakeGitHub,
  signInWithGitHub,
  enableTotp,
  deviceLogin,
  totp,
  addUser,
  makeSandbox,
  writeConsumer,
  putPublish,
  run,
  apm,
  getJson,
  hostKey,
  encodePkg,
  dig,
  ROOT,
  type Registry,
  type FakeGitHub,
  type Browser,
  type RawManifest,
} from "./harness";
import { scanPackages } from "../../packages/bun-scanner/src/index.ts";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const PASSWORD = "correct-horse-battery";
let clock = Date.parse("2026-11-01T00:00:00Z");
let work: string;

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), "apm-launch-"));
});

async function publishOk(reg: Registry, token: string, manifest: RawManifest, opts: Parameters<typeof putPublish>[3] = {}): Promise<void> {
  const r = await putPublish(reg, token, { license: "MIT", main: "index.js", ...manifest }, opts);

  if (r.status !== 201) throw new Error(`publish ${manifest.name}@${manifest.version}: ${r.status} ${JSON.stringify(r.body)}`);
}

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

function bearer(method: string, body: Json, token: string): RequestInit {
  return { method, headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) };
}

/** Every file under `dir` (symlinks not followed) whose text contains `needle`. */
function filesContaining(dir: string, needle: string): string[] {
  const out: string[] = [];

  const walk = (d: string): void => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const st = lstatSync(p);

      if (st.isSymbolicLink()) continue;

      if (st.isDirectory()) walk(p);
      else if (st.size < 1_000_000 && readFileSync(p, "utf8").includes(needle)) out.push(p);
    }
  };

  if (existsSync(dir)) walk(dir);

  return out;
}

// ---------- blocker 1: the whole installed tree comes from the registry apm checked ----------
describe("blocker 1: transitive dependencies install only from the registry apm checked", () => {
  type Pm = "bun" | "npm" | "pnpm";

  let reg: Registry;
  let other: Registry;
  let token: string;

  // the leaf's install script leaves a marker naming the copy that ran
  const leafFiles = (tag: string) => ({
    "index.js": `module.exports = '${tag}_BYTES';\n`,
    "post.js": `require('fs').writeFileSync(require('path').join(process.env.APM_TEST_MARKS, 'leaf-${tag}'), 'ran');\n`,
  });

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    other = await startRegistry({ now: () => clock });
    token = await addUser(reg, "artifactuser", PASSWORD);
    const otherToken = await addUser(other, "artifactuser", PASSWORD);
    const leaf: RawManifest = { name: "@artifactuser/leaf", version: "1.0.0", scripts: { postinstall: "node post.js" } };

    await publishOk(reg, token, leaf, { files: leafFiles("CHECKED") });
    await publishOk(other, otherToken, leaf, { files: leafFiles("UNCHECKED") });
    await publishOk(reg, token, { name: "root-artifact-demo", version: "1.0.0", dependencies: { "@artifactuser/leaf": "1.0.0" } });
    clock += 10 * DAY;
  });
  afterAll(async () => {
    await reg?.stop();
    await other?.stop();
  });

  /** A consumer that lets the leaf's install script run under bun and pnpm too, as a project that trusts it would. */
  function consumer() {
    const sb = makeSandbox(reg, token);
    const app = writeConsumer(work, reg, token);
    const marks = mkdtempSync(join(work, "marks-"));

    writeFileSync(
      join(app, "package.json"),
      JSON.stringify({ name: "consumer-app", version: "1.0.0", private: true, dependencies: {}, trustedDependencies: ["@artifactuser/leaf"], pnpm: { onlyBuiltDependencies: ["@artifactuser/leaf"] } }),
    );

    return { app, marks, env: { ...sb.env, APM_TEST_MARKS: marks, npm_config_store_dir: join(sb.home, ".pnpm-store") } };
  }

  const npmrc = (scoped: boolean): string => `registry=${reg.url}\n${hostKey(reg.url)}:_authToken=${token}\n${scoped ? `@artifactuser:registry=${other.url}\n` : ""}`;

  async function scopeOfDependencyCase(pm: Pm): Promise<void> {
    const { app, marks, env } = consumer();

    writeFileSync(join(app, ".npmrc"), npmrc(true));
    const r = await apm(["add", "root-artifact-demo", "--pm", pm], { cwd: app, env });

    expect(readdirSync(marks), r.out).not.toContain("leaf-UNCHECKED");
    expect(filesContaining(join(app, "node_modules"), "UNCHECKED_BYTES"), r.out).toEqual([]);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toContain("@artifactuser");
    expect(r.out).toContain(other.url);
  }

  async function lockedDependencyCase(pm: Pm): Promise<void> {
    const { app, marks, env } = consumer();

    // a lockfile committed by someone whose config sent @artifactuser to the other registry
    writeFileSync(join(app, ".npmrc"), npmrc(true));
    const first = await run([pm, pm === "npm" ? "install" : "add", "--ignore-scripts", "root-artifact-demo@1.0.0"], { cwd: app, env });

    expect(first.code, first.out).toBe(0);
    writeFileSync(join(app, ".npmrc"), npmrc(false));
    rmSync(join(app, "node_modules"), { recursive: true, force: true });
    const r = await apm(["add", "root-artifact-demo@1.0.0", "--pm", pm], { cwd: app, env });

    expect(readdirSync(marks), r.out).not.toContain("leaf-UNCHECKED");
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toContain("@artifactuser/leaf@1.0.0");
    expect(filesContaining(join(app, "node_modules"), "UNCHECKED_BYTES"), r.out).toEqual([]);
  }

  async function cleanTreeCase(pm: Pm): Promise<void> {
    const { app, marks, env } = consumer();
    const r = await apm(["add", "root-artifact-demo", "--pm", pm], { cwd: app, env });

    expect(r.code, r.out).toBe(0);
    expect(filesContaining(join(app, "node_modules"), "CHECKED_BYTES").length, r.out).toBeGreaterThan(0);
    // install scripts still run, after the tree is verified
    expect(readdirSync(marks), r.out).toContain("leaf-CHECKED");
  }

  test("a project .npmrc sending a dependency's scope to another registry is refused (bun)", () => scopeOfDependencyCase("bun"));
  test("a project .npmrc sending a dependency's scope to another registry is refused (npm)", () => scopeOfDependencyCase("npm"));
  test("a project .npmrc sending a dependency's scope to another registry is refused (pnpm)", () => scopeOfDependencyCase("pnpm"));
  test("a lockfile pinning a dependency to another registry's bytes is refused before its scripts run (bun)", () => lockedDependencyCase("bun"));
  test("a lockfile pinning a dependency to another registry's bytes is refused before its scripts run (npm)", () => lockedDependencyCase("npm"));
  test("a lockfile pinning a dependency to another registry's bytes is refused before its scripts run (pnpm)", () => lockedDependencyCase("pnpm"));
  test("a clean tree installs and its install scripts still run (bun)", () => cleanTreeCase("bun"));
  test("a clean tree installs and its install scripts still run (npm)", () => cleanTreeCase("npm"));
  test("a clean tree installs and its install scripts still run (pnpm)", () => cleanTreeCase("pnpm"));

  test("the architecture note explains how apm binds and verifies the tree", () => {
    const doc = readFileSync(join(ROOT, "docs", "ARCHITECTURE.md"), "utf8");

    expect(doc).toMatch(/--ignore-scripts/);
    expect(doc).toMatch(/integrity/);
  });
});

// ---------- blocker 2: the strict bun scanner checks prereleases ----------
describe("blocker 2: the bun scanner checks prerelease versions", () => {
  let reg: Registry;

  type ScanInput = Parameters<typeof scanPackages>[0];

  const scan = (input: ScanInput): ReturnType<typeof scanPackages> => scanPackages(input);

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    const alice = await addUser(reg, "alice", PASSWORD);

    await publishOk(reg, alice, { name: "revoked-prerelease-probe", version: "1.0.0-beta.1" }, { tags: { next: "1.0.0-beta.1" } });
    const rv = await getJson(`${reg.url}-/apm/v1/revoke`, bearer("POST", { name: "revoked-prerelease-probe", version: "1.0.0-beta.1", reason: "probe", password: PASSWORD }, alice));

    if (rv.status !== 200) throw new Error(`revoke: ${rv.status} ${JSON.stringify(rv.body)}`);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("a revoked prerelease is reported as fatal in strict mode", async () => {
    const warnings: string[] = [];
    const tarball = `${reg.url}revoked-prerelease-probe/-/revoked-prerelease-probe-1.0.0-beta.1.tgz`;

    const advisories = await scan({
      packages: [{ name: "revoked-prerelease-probe", version: "1.0.0-beta.1", tarball, requestedRange: "next" }],
      env: { APM_REGISTRY: reg.url, APM_SCANNER_STRICT: "1" },
      cwd: work,
      warn: (l) => warnings.push(l),
    });

    expect(JSON.stringify(advisories), warnings.join("\n")).toContain("revoked-prerelease-probe");
    expect(JSON.stringify(advisories)).toContain("fatal");
  });

  test("a version the scanner cannot send to the registry is reported, and strict mode cancels", async () => {
    const warnings: string[] = [];

    const input = (strict: boolean): ScanInput => ({
      packages: [{ name: "git-dep", version: "github:someone/git-dep#abc123", tarball: "https://codeload.example.invalid/x.tgz", requestedRange: "github:someone/git-dep" }],
      env: strict ? { APM_REGISTRY: reg.url, APM_SCANNER_STRICT: "1" } : { APM_REGISTRY: reg.url },
      cwd: work,
      warn: (l) => warnings.push(l),
    });

    await scan(input(false));
    expect(warnings.join("\n")).toContain("git-dep");
    let threw = false;

    try {
      await scan(input(true));
    } catch {
      threw = true;
    }

    expect(threw).toBe(true);
  });
});

// ---------- blocker 3: review decisions need a website session and a fresh factor ----------
describe("blocker 3: tokens have no review-admin powers", () => {
  const SERVICE = "svc_launch_review_service_token_0123456789";
  let gh: FakeGitHub;
  let reg: Registry;
  let admin: Browser;
  let secret: string;
  let stageToken: string;
  let publishToken: string;

  beforeAll(async () => {
    gh = startFakeGitHub();
    reg = await startRegistry({ now: () => clock, github: gh, review: { serviceTokenHash: createHash("sha256").update(SERVICE).digest("hex"), admins: ["rev-admin"] } });
    admin = await signInWithGitHub(reg, gh, "rev-admin");
    secret = await enableTotp(admin);
    stageToken = (await deviceLogin(admin)).token;
    publishToken = await reg.mintToken({ user: "rev-admin", scope: "publish" });
  });
  afterAll(async () => {
    await reg?.stop();
    await gh?.stop();
  });

  const decision = { name: "some-pkg", version: "1.0.0", digest: "sha512-x", decision: "dismiss", note: "" };

  test("an admin's staging or publish token cannot read the queue or decide", async () => {
    for (const t of [stageToken, publishToken]) {
      expect((await getJson(`${reg.url}-/apm/v1/review-admin/queue`, { headers: { authorization: `Bearer ${t}` } })).status).toBe(403);
      expect((await getJson(`${reg.url}-/apm/v1/review-admin/decide`, bearer("POST", decision, t))).status).toBe(403);
    }
  });

  test("on the website a decision needs a fresh code as well as the session", async () => {
    expect((await admin.json("-/apm/v1/review-admin/queue")).status).toBe(200);
    expect((await admin.json("-/apm/v1/review-admin/decide", { method: "POST", body: decision })).status).toBe(401);
    // with the code it gets past the check: there is no such review
    expect((await admin.json("-/apm/v1/review-admin/decide", { method: "POST", body: { ...decision, code: totp(secret) } })).status).toBe(404);
  });
});

// ---------- blocker 4: staged uploads: atomic quotas, metadata counted, payloads purged ----------
describe("blocker 4: staged-upload quotas are atomic and rejected uploads are purged", () => {
  let gh: FakeGitHub;
  let slow: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let b: Browser;
  let stage: string;

  beforeAll(async () => {
    gh = startFakeGitHub();
    // an npm that takes a while to say "no such package", so concurrent uploads overlap in the publish check
    slow = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch() {
        await Bun.sleep(300);

        return Response.json({ error: "Not found" }, { status: 404 });
      },
    });
    reg = await startRegistry({ now: () => clock, github: gh, upstream: slow.url.toString() });
    b = await signInWithGitHub(reg, gh, "quota-user");
    await enableTotp(b);
    stage = (await deviceLogin(b)).token;
  });
  afterAll(async () => {
    await reg?.stop();
    await slow?.stop(true);
    await gh?.stop();
  });

  const stageOne = (name: string, version: string, extra: Partial<RawManifest> = {}): Promise<{ status: number; body: unknown }> =>
    putPublish(reg, stage, { name, version, license: "MIT", main: "index.js", ...extra });

  async function pendingOf(name: string): Promise<number> {
    const r = await b.json("-/apm/v1/staged");
    const staged = dig(r.body, "staged");

    return Array.isArray(staged) ? staged.filter((s) => dig(s, "package") === name).length : -1;
  }

  test("concurrent uploads cannot go past the per-package limit", async () => {
    for (let i = 0; i < 4; i++) expect((await stageOne("@quota-user/race", `1.0.${i}`)).status).toBe(202);
    // each names a dependency nobody asked npm about yet, so both wait on the slow npm after the quota check
    const both = await Promise.all([stageOne("@quota-user/race", "1.0.4", { dependencies: { "slow-dep-four": "1.0.0" } }), stageOne("@quota-user/race", "1.0.5", { dependencies: { "slow-dep-five": "1.0.0" } })]);

    expect(both.map((r) => r.status).sort()).toEqual([202, 429]);
    expect(await pendingOf("@quota-user/race")).toBe(5);
  });

  test("concurrent first uploads of one version get one approval, not two", async () => {
    const both = await Promise.all([stageOne("@quota-user/dup", "1.0.0"), stageOne("@quota-user/dup", "1.0.0")]);

    expect(both.map((r) => r.status).sort()).toEqual([202, 409]);
    expect(await pendingOf("@quota-user/dup")).toBe(1);
  });

  test("a staged readme over 1 MB is refused", async () => {
    const r = await putPublish(reg, stage, { name: "@quota-user/huge-readme", version: "1.0.0", license: "MIT", main: "index.js", readme: "x".repeat(1_100_000) });

    expect(r.status, JSON.stringify(r.body).slice(0, 300)).toBe(413);
  });

  test("a rejected or expired upload keeps an audit row but not its readme, manifest or score", async () => {
    const readme = `# purge me\n${"r".repeat(4096)}\n`;
    const rejected = await stageOne("@quota-user/purge", "1.0.0", { readme });
    const rejectedId = dig(rejected.body, "id");

    expect(rejected.status).toBe(202);
    expect((await b.json(`-/apm/v1/staged/${String(rejectedId)}/reject`, { method: "POST", body: {} })).status).toBe(200);
    const expiring = await stageOne("@quota-user/purge", "1.0.1", { readme });
    const expiringId = dig(expiring.body, "id");

    expect(expiring.status).toBe(202);
    clock += 25 * HOUR;
    await reg.sweep(); // the cron expires uploads past their deadline

    for (const id of [rejectedId, expiringId]) {
      const [row] = await reg.query("SELECT status, readme, manifest::text AS manifest, score, integrity FROM staged WHERE id = $1", [String(id)]);

      expect(dig(row, "status")).toMatch(/rejected|expired/);
      expect(dig(row, "readme")).toBeNull();
      expect(dig(row, "score")).toBeNull();
      expect(String(dig(row, "manifest")).length).toBeLessThan(100);
      expect(String(dig(row, "integrity"))).toMatch(/^sha512-/);
    }
  });
});

// ---------- blocker 5: website confirmations name every parameter of the command ----------
describe("blocker 5: a confirmed command authorizes only those exact parameters", () => {
  let gh: FakeGitHub;
  let reg: Registry;
  let b: Browser;
  let secret: string;
  let stage: string;
  const sinceA = () => new Date(clock - 2 * HOUR).toISOString();
  const sinceB = () => new Date(clock - 20 * DAY).toISOString();

  beforeAll(async () => {
    gh = startFakeGitHub();
    reg = await startRegistry({ now: () => clock, github: gh });
    b = await signInWithGitHub(reg, gh, "confirm-user");
    secret = await enableTotp(b);
    stage = (await deviceLogin(b)).token;
    const direct = await reg.mintToken({ user: "confirm-user", scope: "publish" });

    await publishOk(reg, direct, { name: "@confirm-user/inc", version: "1.0.0" });
    await publishOk(reg, direct, { name: "@confirm-user/dep", version: "1.0.0" });
    clock += HOUR;
  });
  afterAll(async () => {
    await reg?.stop();
    await gh?.stop();
  });

  type Command = { kind: "deprecate"; name: string; changes: { version: string; message: string | null }[] } | { kind: "incident"; since: string; dryRun: boolean };

  async function confirm(command: Command): Promise<void> {
    const r = await b.json("-/apm/v1/verify", { method: "POST", body: { command, code: totp(secret) } });

    expect(r.status, JSON.stringify(r.body)).toBe(200);
  }

  /** 200 while the version installs, 404 once it is revoked. */
  const versionStatus = async (name: string): Promise<number> => (await getJson(`${reg.url}${encodePkg(name)}/1.0.0`)).status;

  test("deprecate: a confirmation for one message does not authorize another", async () => {
    await confirm({ kind: "deprecate", name: "@confirm-user/dep", changes: [{ version: "1.0.0", message: "use 2.x" }] });

    const put = (message: string): Promise<{ status: number; body: unknown }> =>
      getJson(
        `${reg.url}${encodePkg("@confirm-user/dep")}`,
        bearer("PUT", { _id: "@confirm-user/dep", name: "@confirm-user/dep", versions: { "1.0.0": { name: "@confirm-user/dep", version: "1.0.0", deprecated: message } } }, stage),
      );

    const swapped = await put("install @evil/replacement instead");

    expect(swapped.status).toBe(401);
    expect(JSON.stringify(swapped.body)).toContain("install @evil/replacement instead");
    expect(dig((await getJson(`${reg.url}${encodePkg("@confirm-user/dep")}/1.0.0`)).body, "deprecated")).toBeUndefined();
    expect((await put("use 2.x")).status).toBe(200);
    expect(dig((await getJson(`${reg.url}${encodePkg("@confirm-user/dep")}/1.0.0`)).body, "deprecated")).toBe("use 2.x");
  });

  test("incident: a dry-run confirmation for one time range authorizes neither a real run nor another range", async () => {
    await confirm({ kind: "incident", since: sinceA(), dryRun: true });
    const incident = (since: string, dryRun: boolean): Promise<{ status: number; body: unknown }> => getJson(`${reg.url}-/apm/v1/incident`, bearer("POST", { since, dryRun }, stage));
    const otherRange = await incident(sinceB(), false);

    expect(otherRange.status).toBe(401);
    expect(JSON.stringify(otherRange.body)).toContain(sinceB());
    expect(await versionStatus("@confirm-user/inc")).toBe(200);
    expect((await incident(sinceA(), false)).status).toBe(401);
    expect(await versionStatus("@confirm-user/inc")).toBe(200);
    const preview = await incident(sinceA(), true);

    expect(preview.status, JSON.stringify(preview.body)).toBe(200);
    expect(dig(preview.body, "dryRun")).toBe(true);
    await confirm({ kind: "incident", since: sinceA(), dryRun: false });
    expect((await incident(sinceA(), false)).status).toBe(200);
    expect(await versionStatus("@confirm-user/inc")).toBe(404);
  });
});

// ---------- blocker 6: comments cannot hide code from the scorer ----------
describe("blocker 6: comment handling does not hide executable code", () => {
  let reg: Registry;
  let alice: string;
  let n = 0;

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  async function signalsOf(code: string): Promise<string[]> {
    const r = await putPublish(reg, alice, { name: `comment-probe-${++n}`, version: "1.0.0", license: "MIT", main: "index.js" }, { files: { "index.js": code } });

    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const signals = dig(r.body, "score", "signals");

    return Array.isArray(signals) ? signals.map((s) => String(dig(s, "id"))) : [];
  }

  test("a closed /* comment */ in front of code does not hide it", async () => {
    expect(await signalsOf("/* ordinary comment */ const b = process.binding('spawn_sync');\n")).toContain("shell-exec");
    expect(await signalsOf("/* ordinary comment */ require('dns').lookup('example.invalid', () => {});\n")).toContain("network");
    expect(await signalsOf("/* ordinary comment */ const e = (0, eval)('1');\n")).toContain("eval");
  });

  test("200 commented examples do not use up the search and hide a later call", async () => {
    const docs = Array.from({ length: 220 }, (_, i) => `// example ${i}: new EventSource(url)\n`).join("");

    expect(await signalsOf(`${docs}module.exports = new EventSource('https://example.invalid/stream');\n`)).toContain("network");
  });

  test("code inside a string that looks like a comment opener is still read", async () => {
    expect(await signalsOf("const s = '/*'; require('dns').lookup('example.invalid', () => {}); const t = '*/';\n")).toContain("network");
  });

  test("an example in a real comment counts as apm-score-v3 counted it (apm-score-v9: String(fn) gives comments back)", async () => {
    expect(await signalsOf("/**\n * Usage:\n *   const es = new EventSource(url);\n */\nmodule.exports = 1;\n")).toContain("network");
  });
});

// ---------- 7: password failures are counted under concurrency ----------
describe("7: concurrent wrong passwords are all counted", () => {
  let reg: Registry;

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("12 wrong passwords sent at once lock the account", async () => {
    await addUser(reg, "racer", PASSWORD);

    const login = (password: string): Promise<{ status: number; body: unknown }> =>
      getJson(`${reg.url}-/user/org.couchdb.user:racer`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ _id: "org.couchdb.user:racer", name: "racer", password, type: "user", roles: [] }) });

    const wrong = await Promise.all(Array.from({ length: 12 }, (_, i) => login(`wrong-${i}-password`)));

    expect(wrong.every((r) => r.status === 401 || r.status === 429)).toBe(true);
    expect((await login(PASSWORD)).status).toBe(429);
  });
});

// ---------- 9 and the secret rules: the publish-time secret scan ----------
describe("9 and score 14: the secret scan reads every file and knows more secret shapes", () => {
  let reg: Registry;
  let alice: string;
  let n = 0;
  // assembled at run time so the test source holds no secret-shaped literal
  const fakeNpmToken = `npm_${"Z".repeat(36)}`;

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  const publishFiles = (files: Record<string, string>): Promise<{ status: number; body: unknown }> =>
    putPublish(reg, alice, { name: `secret-probe-${++n}`, version: "1.0.0", license: "MIT", main: "index.js" }, { files: { "index.js": "module.exports = 1;\n", ...files } });

  test("a NUL byte early in a file does not hide a token later in it", async () => {
    const r = await publishFiles({ "lib/data.js": `/*\0*/\nmodule.exports = '${fakeNpmToken}';\n` });

    expect(r.status, JSON.stringify(r.body)).toBe(422);
  });

  test("basic-auth .npmrc lines are secrets", async () => {
    expect((await publishFiles({ ".npmrc": "//registry.example.invalid/:_auth=Ym9iOnNlY3JldA==\n" })).status).toBe(422);
    expect((await publishFiles({ ".npmrc": "//registry.example.invalid/:username=bob\n//registry.example.invalid/:_password=c2VjcmV0\n" })).status).toBe(422);
  });

  test("Slack and Discord webhook URLs are secrets", async () => {
    expect((await publishFiles({ "settings.js": `module.exports = 'https://hooks.slack.com/services/T0000/B0000/${"x".repeat(24)}';\n` })).status).toBe(422);
    expect((await publishFiles({ "settings.js": `module.exports = 'https://discord.com/api/webhooks/123456789/${"y".repeat(40)}';\n` })).status).toBe(422);
  });

  test("key stores and other private-key formats are secrets", async () => {
    expect((await publishFiles({ "cert.p12": "0\u0082 binary keystore stand-in" })).status).toBe(422);
    expect((await publishFiles({ "deploy.ppk": "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\nAAAA\n" })).status).toBe(422);
    expect((await publishFiles({ "key.txt": "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nAAAA\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n" })).status).toBe(422);
  });
});

// ---------- score 15: one entry-point collector ----------
describe("score 15: missing exports and module targets are refused", () => {
  let reg: Registry;
  let alice: string;

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("an exports target that is not in the tarball is refused", async () => {
    const r = await putPublish(reg, alice, { name: "broken-exports", version: "1.0.0", license: "MIT", main: "index.js", exports: { ".": { import: "./dist/index.mjs", require: "./index.js" } } });

    expect(r.status, JSON.stringify(r.body)).toBe(422);
    expect(JSON.stringify(r.body)).toContain("dist/index.mjs");
  });

  test("a module target that is not in the tarball is refused", async () => {
    const r = await putPublish(reg, alice, { name: "broken-module", version: "1.0.0", license: "MIT", main: "index.js", module: "./esm/index.mjs" });

    expect(r.status, JSON.stringify(r.body)).toBe(422);
  });

  test("exports and module targets that exist publish", async () => {
    const r = await putPublish(
      reg,
      alice,
      { name: "whole-exports", version: "1.0.0", license: "MIT", main: "index.js", module: "./esm/index.mjs", exports: { ".": { import: "./esm/index.mjs", require: "./index.js" }, "./package.json": "./package.json" } },
      { files: { "index.js": "module.exports = 1;\n", "esm/index.mjs": "export default 1;\n" } },
    );

    expect(r.status, JSON.stringify(r.body)).toBe(201);
  });
});

// ---------- routes 3: the docs say what a fresh revoke does ----------
describe("routes 3: README and docs describe the fresh-version revoke as it works", () => {
  test("neither promises a pending window for depended-on fresh versions", () => {
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    const docs = readFileSync(join(ROOT, "apps", "web", "app", "docs", "page.tsx"), "utf8");

    for (const text of [readme, docs]) {
      expect(text).not.toMatch(/old or depended-on versions/);
      expect(text).not.toMatch(/with no dependents is revoked at once/);
      expect(text).toMatch(/under 72 hours old is revoked at once, even when other packages depend on it/);
    }
  });
});

// ---------- per-user answers say so to every cache ----------
describe("the registry marks per-user answers private, no-store", () => {
  let gh: FakeGitHub;
  let reg: Registry;
  // the operator's debug token; the Worker holds only its sha256, as the deploy sets it
  const DEBUG_TOKEN = "debug-token-for-the-timing-test";

  beforeAll(async () => {
    gh = startFakeGitHub();
    reg = await startRegistry({ now: () => clock, github: gh, env: { APM_DEBUG_TOKEN_HASH: createHash("sha256").update(DEBUG_TOKEN).digest("hex") } });
  });
  afterAll(async () => {
    await reg?.stop();
    await gh?.stop();
  });

  test("account, staged, whoami and session answers are private, no-store", async () => {
    const b = await signInWithGitHub(reg, gh, "cache-user");
    const token = await deviceLogin(b);

    for (const path of ["-/apm/v1/account", "-/apm/v1/staged", "api/auth/get-session"]) {
      const res = await b.fetch(path);

      expect(res.headers.get("cache-control"), path).toBe("private, no-store");
      expect(res.headers.get("vary") ?? "", path).toMatch(/Cookie/);
    }

    const who = await fetch(`${reg.url}-/whoami`, { headers: { authorization: `Bearer ${token.token}` } });

    expect(who.headers.get("cache-control")).toBe("private, no-store");
    expect(who.headers.get("vary") ?? "").toMatch(/Authorization/);
  });

  const TIMED = [
    ["HEAD", "-/apm/v1/packages/timing-missing"],
    ["GET", "-/apm/v1/packages/timing-missing"],
    ["GET", "-/apm/v1/score/timing-missing/1.0.0"],
    ["GET", "-/apm/v1/readme/timing-missing/1.0.0"],
  ] as const;

  const timingOf = async (method: string, path: string, headers: Record<string, string> = {}): Promise<string> => {
    const res = await fetch(`${reg.url}${path}`, { method, headers });
    await res.body?.cancel();

    return res.headers.get("server-timing") ?? "";
  };

  test("the package page's reads send anyone only the database's time and the total; account answers send none", async () => {
    for (const [method, path] of TIMED) {
      // no query count, no npm or cache metric, whole milliseconds: a wrong debug token, a signed-in token or none
      const callers: Record<string, string>[] = [{}, { "x-apm-debug": "not-the-token" }, { "x-apm-debug": "" }, { authorization: "Bearer npm_not_a_debug_token" }];

      for (const headers of callers) {
        expect(await timingOf(method, path, headers), `${method} ${path} ${JSON.stringify(headers)}`).toMatch(/^db;dur=\d+, total;dur=\d+$/);
      }
    }

    const account = await fetch(`${reg.url}-/apm/v1/account`);
    await account.body?.cancel();

    expect(account.headers.get("server-timing")).toBeNull();
  });

  test("the operator's debug token in x-apm-debug gets every metric with its count", async () => {
    for (const [method, path] of TIMED) {
      // every one reads the package row, so the database's time is named, and the whole answer's
      expect(await timingOf(method, path, { "x-apm-debug": DEBUG_TOKEN }), `${method} ${path}`).toMatch(/^db;dur=[\d.]+;desc="\d+"(, [a-z-]+;dur=[\d.]+;desc="\d+")*, total;dur=[\d.]+$/);
    }

    // the debug token opens nothing else: an account answer still has no timing
    const account = await fetch(`${reg.url}-/apm/v1/account`, { headers: { "x-apm-debug": DEBUG_TOKEN } });
    await account.body?.cancel();

    expect(account.headers.get("server-timing")).toBeNull();
  });
});
