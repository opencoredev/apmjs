// Spec: sign-in, GitHub-scoped names and publish approval.
// - Accounts come from GitHub (or Vercel) sign-in through Better Auth; the apm scope is the GitHub login, lowercased.
// - New packages are scoped to the publisher's GitHub login. Bare names mean the npm package. A scope that exists
//   on npm is reserved unless the publisher's GitHub login is that scope.
// - A login token (apm login's device flow, or a stock bun/npm publish with it) only stages a version: stored, not
//   served, with an approval link in the notice both clients print. A person approves it with a passkey or TOTP.
//   Staged versions expire after 24h. Publishing needs a passkey or 2FA on the account.
// - With legacyAuth off (production), npm's password adduser creates nothing, and revoke needs a fresh second factor.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  startRegistry,
  startFakeGitHub,
  signInWithGitHub,
  enableTotp,
  deviceLogin,
  totp,
  wrongTotp,
  approvalId,
  makeSandbox,
  writePackage,
  writeConsumer,
  run,
  apm,
  CLI,
  getJson,
  installedVersion,
  encodePkg,
  dig,
  type Registry,
  type FakeGitHub,
  type Browser,
} from "./harness";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
let clock = Date.parse("2026-03-01T00:00:00Z");
let gh: FakeGitHub;
let npmFake: ReturnType<typeof Bun.serve>;
let reg: Registry;
let work: string;
let octo: Browser;
let octoSecret: string;
let octoToken: string;

/** npm stand-in: the scopes @acme and @beta exist there; no packages resolve. */
function startFakeNpm(): ReturnType<typeof Bun.serve> {
  return Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const p = new URL(req.url).pathname;
      if (p === "/-/org/acme/package") return Response.json({ "@acme/widget": "write" });
      if (p === "/-/org/beta/package") return Response.json({ "@beta/gadget": "write" });
      if (p.startsWith("/-/org/")) return Response.json({ error: "Scope not found" }, { status: 404 });
      if (p === "/-/v1/search") return Response.json({ objects: [], total: 0, time: new Date().toUTCString() });
      return Response.json({ error: "Not found" }, { status: 404 });
    },
  });
}

async function publishWith(tool: "bun" | "npm", name: string, version: string, token: string): Promise<{ code: number; out: string }> {
  const sb = makeSandbox(reg, token);
  const dir = writePackage(work, { name, version }, reg, token);
  const r = await run(tool === "bun" ? ["bun", "publish"] : ["npm", "publish"], { cwd: dir, env: sb.env });
  return { code: r.code, out: r.out };
}

async function packumentStatus(name: string): Promise<{ status: number; body: unknown }> {
  return getJson(`${reg.url}${encodePkg(name)}`);
}

async function approve(b: Browser, id: string, code?: string): Promise<{ status: number; body: unknown }> {
  return b.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: code === undefined ? {} : { code } });
}

/** Stages name@version with the device token and returns the approval id from what bun printed. */
async function stage(name: string, version: string): Promise<string> {
  const r = await publishWith("bun", name, version, octoToken);
  expect(r.code, r.out).toBe(0);
  const id = approvalId(r.out);
  expect(id, `bun publish should print the approval link:\n${r.out}`).not.toBeNull();
  return id ?? "";
}

beforeAll(async () => {
  gh = startFakeGitHub();
  npmFake = startFakeNpm();
  reg = await startRegistry({ now: () => clock, legacyAuth: false, namePolicy: "scoped", github: gh, upstream: npmFake.url.toString() });
  work = mkdtempSync(join(tmpdir(), "apm-auth-"));
  octo = await signInWithGitHub(reg, gh, "Octo-Cat");
  octoSecret = await enableTotp(octo);
  octoToken = (await deviceLogin(octo)).token;
});
afterAll(async () => {
  await reg?.stop();
  await gh?.stop();
  await npmFake?.stop(true);
});

describe("sign-in", () => {
  test("GitHub sign-in through OAuth creates an account whose scope is the GitHub login, lowercased", async () => {
    const b = await signInWithGitHub(reg, gh, "Mona-Lisa");
    const me = await b.json("-/apm/v1/account");
    expect(me.status, JSON.stringify(me.body)).toBe(200);
    expect(dig(me.body, "scope")).toBe("mona-lisa");
    expect(dig(me.body, "github")).toBe("Mona-Lisa");
    expect(JSON.stringify(dig(me.body, "linked"))).toContain("github");
    expect(dig(me.body, "security", "totp")).toBe(false);

    const anon = await getJson(`${reg.url}-/apm/v1/account`);
    expect(anon.status).toBe(401);
  });

  test("legacy adduser is refused when legacyAuth is off, and makes no account", async () => {
    const put = (password: string) =>
      getJson(`${reg.url}-/user/org.couchdb.user:mallory`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ _id: "org.couchdb.user:mallory", name: "mallory", password, email: "m@example.test", type: "user", roles: [] }),
      });
    const first = await put("a-long-enough-password");
    expect(first.status).toBeGreaterThanOrEqual(400);
    expect(first.status).toBeLessThan(500);
    expect(String(dig(first.body, "error"))).toMatch(/apm login/);
    expect(dig(first.body, "token")).toBeUndefined();
    // a second try with the same password would log in if the first had made the account
    const second = await put("a-long-enough-password");
    expect(dig(second.body, "token")).toBeUndefined();
  });
});

describe("names", () => {
  test("publishing a bare new name is refused with a clear message naming your scope", async () => {
    const r = await publishWith("bun", "plain-new-lib", "1.0.0", octoToken);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("@octo-cat/plain-new-lib");
    expect(r.out).toMatch(/npm/);
    expect((await packumentStatus("plain-new-lib")).status).toBe(404);
  });

  test("publishing under someone else's scope is refused", async () => {
    const r = await publishWith("bun", "@someone-else/lib", "1.0.0", octoToken);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("@octo-cat");
    expect((await packumentStatus("@someone-else/lib")).status).toBe(404);
  });

  test("a scope that exists on npm is refused unless the publisher's GitHub login is that scope", async () => {
    // "acme" is a name on this registry but not a verified GitHub login
    const unverified = reg.mintToken({ user: "acme", scope: "publish" });
    const r = await publishWith("bun", "@acme/fresh", "1.0.0", unverified);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/@acme/);
    expect(r.out).toMatch(/npm/);
    expect((await packumentStatus("@acme/fresh")).status).toBe(404);

    // the GitHub account "beta" owns @beta here even though @beta exists on npm
    const beta = await signInWithGitHub(reg, gh, "beta");
    const me = await beta.json("-/apm/v1/account");
    expect(dig(me.body, "scope")).toBe("beta");
    const verified = reg.mintToken({ user: "beta", scope: "publish" });
    const ok = await publishWith("bun", "@beta/fresh", "1.0.0", verified);
    expect(ok.code, ok.out).toBe(0);
    expect(dig((await packumentStatus("@beta/fresh")).body, "dist-tags", "latest")).toBe("1.0.0");
  });
});

describe("publish approval", () => {
  test("device login yields a token that can only stage: npm publish stores the version, prints the link, serves nothing", async () => {
    const who = await getJson(`${reg.url}-/whoami`, { headers: { authorization: `Bearer ${octoToken}` } });
    expect(dig(who.body, "username")).toBe("octo-cat");

    const r = await publishWith("npm", "@octo-cat/agent-lib", "1.0.0", octoToken);
    expect(r.code, r.out).toBe(0);
    const id = approvalId(r.out);
    expect(id, `npm publish should print the approval link:\n${r.out}`).not.toBeNull();
    expect(r.out).toMatch(/approv/i);
    expect((await packumentStatus("@octo-cat/agent-lib")).status).toBe(404);

    const staged = await octo.json(`-/apm/v1/staged/${id}`);
    expect(staged.status, JSON.stringify(staged.body)).toBe(200);
    expect(dig(staged.body, "package")).toBe("@octo-cat/agent-lib");
    expect(dig(staged.body, "version")).toBe("1.0.0");
    expect(dig(staged.body, "publisher")).toBe("octo-cat");
    expect(JSON.stringify(dig(staged.body, "files"))).toContain("package.json");
  });

  test("a staged version is not served or installable until a person approves it", async () => {
    const id = await stage("@octo-cat/staged-lib", "1.0.0");
    expect((await packumentStatus("@octo-cat/staged-lib")).status).toBe(404);
    const tgz = await getJson(`${reg.url}@octo-cat/staged-lib/-/staged-lib-1.0.0.tgz`);
    expect(tgz.status).toBe(404);
    const sb = makeSandbox(reg);
    const app = writeConsumer(work, reg, undefined, { "@octo-cat/staged-lib": "1.0.0" });
    const before = await run(["bun", "install"], { cwd: app, env: sb.env });
    expect(before.code).not.toBe(0);

    const ok = await approve(octo, id, totp(octoSecret));
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(dig((await packumentStatus("@octo-cat/staged-lib")).body, "dist-tags", "latest")).toBe("1.0.0");
    const app2 = writeConsumer(work, reg, undefined, { "@octo-cat/staged-lib": "1.0.0" });
    const after = await run(["bun", "install"], { cwd: app2, env: makeSandbox(reg).env });
    expect(after.code, after.out).toBe(0);
    expect(installedVersion(app2, "@octo-cat/staged-lib")).toBe("1.0.0");
  });

  test("approval without a TOTP code fails, a wrong code fails, a valid code succeeds", async () => {
    const id = await stage("@octo-cat/needs-2fa", "1.0.0");
    const none = await approve(octo, id);
    expect(none.status).toBe(401);
    const wrong = await approve(octo, id, wrongTotp(octoSecret));
    expect(wrong.status).toBe(401);
    expect((await packumentStatus("@octo-cat/needs-2fa")).status).toBe(404);

    // a stranger who is signed in cannot approve it either, even with their own valid code
    const stranger = await signInWithGitHub(reg, gh, "stranger");
    const strangerSecret = await enableTotp(stranger);
    const theirs = await approve(stranger, id, totp(strangerSecret));
    expect(theirs.status).toBe(403);

    const ok = await approve(octo, id, totp(octoSecret));
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(dig((await packumentStatus("@octo-cat/needs-2fa")).body, "versions", "1.0.0", "version")).toBe("1.0.0");
  });

  test("a staged version expires after 24h and can no longer be approved", async () => {
    const id = await stage("@octo-cat/too-late", "1.0.0");
    clock += 24 * HOUR + MINUTE;
    const late = await approve(octo, id, totp(octoSecret));
    expect(late.status).toBe(410);
    expect((await packumentStatus("@octo-cat/too-late")).status).toBe(404);
    const listed = await octo.json("-/apm/v1/staged");
    expect(JSON.stringify(listed.body)).not.toContain(id);
  });

  test("an account without a passkey or 2FA cannot stage a publish", async () => {
    const b = await signInWithGitHub(reg, gh, "no-factor");
    const { token } = await deviceLogin(b);
    const r = await publishWith("bun", "@no-factor/lib", "1.0.0", token);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/2FA|passkey/);
    expect(approvalId(r.out)).toBeNull();
  });
});

describe("second factor for destructive actions", () => {
  test("revoke needs a fresh second factor: a token alone fails, --otp works, and a website confirmation covers that one command for 10 minutes", async () => {
    for (const v of ["1.0.0", "1.0.1", "1.0.2"]) {
      const id = await stage("@octo-cat/revokable", v);
      const ok = await approve(octo, id, totp(octoSecret));
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    }
    const revoke = (version: string, extra: Record<string, unknown> = {}) =>
      getJson(`${reg.url}-/apm/v1/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${octoToken}` },
        body: JSON.stringify({ name: "@octo-cat/revokable", version, reason: "test revoke", ...extra }),
      });

    const confirm = (version: string) =>
      octo.json("-/apm/v1/verify", { method: "POST", body: { code: totp(octoSecret), command: { kind: "revoke", name: "@octo-cat/revokable", version } } });

    const bare = await revoke("1.0.0");
    expect(bare.status).toBe(401);
    expect(String(dig(bare.body, "error"))).toMatch(/otp|passkey|second factor/i);
    // the refusal links to a page that confirms exactly this command
    expect(String(dig(bare.body, "error"))).toContain("account?confirm=");
    // passwords are not a second factor once legacyAuth is off
    expect((await revoke("1.0.0", { password: "anything-at-all" })).status).toBe(401);
    expect((await revoke("1.0.0", { otp: wrongTotp(octoSecret) })).status).toBe(401);
    const withOtp = await revoke("1.0.0", { otp: totp(octoSecret) });
    expect(withOtp.status, JSON.stringify(withOtp.body)).toBe(200);
    expect(dig(withOtp.body, "status")).toBe("revoked");

    // confirming a command on the website lets the CLI run that command once within 10 minutes
    const check = await confirm("1.0.1");
    expect(check.status, JSON.stringify(check.body)).toBe(200);
    expect(String(dig(check.body, "command"))).toBe("apm revoke @octo-cat/revokable@1.0.1");
    clock += 11 * MINUTE;
    expect((await revoke("1.0.1")).status).toBe(401);
    expect((await confirm("1.0.1")).status).toBe(200);
    clock += 2 * MINUTE;
    expect((await revoke("1.0.2")).status).toBe(401);
    const fresh = await revoke("1.0.1");
    expect(fresh.status, JSON.stringify(fresh.body)).toBe(200);
  });
});

describe("apm CLI", () => {
  test("apm login prints a URL and a code, waits for the browser to approve, and saves a token that stages", async () => {
    const sb = makeSandbox(reg);
    const proc = Bun.spawn(["bun", CLI, "login", "--no-browser"], { cwd: sb.home, env: sb.env, stdout: "pipe", stderr: "pipe", stdin: "ignore" });
    const timer = setTimeout(() => proc.kill(), 60_000);
    const reader = proc.stdout.getReader();
    let printed = "";
    let userCode: string | null = null;
    while (userCode === null) {
      const chunk = await reader.read();
      if (chunk.done) break;
      printed += new TextDecoder().decode(chunk.value);
      if (printed.includes("/device")) userCode = /code[^A-Z0-9]*([A-Z0-9]{4}-?[A-Z0-9]{4})/.exec(printed)?.[1] ?? null;
    }
    expect(printed).toMatch(/https?:\/\/\S+\/device/);
    expect(userCode, printed).not.toBeNull();
    const code = (userCode ?? "").replace("-", "");
    expect((await octo.json(`api/auth/device?user_code=${code}`)).status).toBe(200);
    expect((await octo.json("api/auth/device/approve", { method: "POST", body: { userCode: code } })).status).toBe(200);
    const rest = await new Response(new ReadableStream({ pull: async (c) => { const x = await reader.read(); if (x.done) c.close(); else c.enqueue(x.value); } })).text();
    const exit = await proc.exited;
    clearTimeout(timer);
    const out = printed + rest + (await new Response(proc.stderr).text());
    expect(exit, out).toBe(0);
    expect(out).toContain("octo-cat");
    const npmrc = readFileSync(join(sb.home, ".npmrc"), "utf8");
    expect(npmrc).toMatch(/_authToken=apm_/);
    const who = await apm(["whoami"], { cwd: sb.home, env: sb.env });
    expect(who.out).toContain("octo-cat");
  });

  test("apm publish with a login token prints the approval link and says the version is not live yet", async () => {
    const sb = makeSandbox(reg, octoToken);
    const dir = writePackage(work, { name: "@octo-cat/via-apm", version: "1.0.0" }, reg, octoToken);
    const r = await apm(["publish", "--pm", "bun"], { cwd: dir, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(approvalId(r.out)).not.toBeNull();
    expect(r.out).toMatch(/not live|waiting for approval|approve/i);
    expect((await packumentStatus("@octo-cat/via-apm")).status).toBe(404);
  });
});
