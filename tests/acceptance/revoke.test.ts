// Spec: a maintainer can pull a bad version at any time, in one step, and stock clients notice.
// States: deprecated (advisory), yanked (hidden from new resolution, lockfiles keep working),
// revoked (malicious: hidden, tarball refused, critical advisory for audit).
// Safeguards (council round 1): revoke, restore and incident need the account password, not just a
// bearer token. Revoking a version older than 72h or with dependents yanks it at once and turns into a
// full revoke after 24h or when a second owner confirms. Incident has a preview and a 30-day window.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, getJson, installedVersion, dig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const PASSWORD = "correct-horse-battery";
let clock = Date.parse("2026-01-01T00:00:00Z");
let reg: Registry;
let alice: string;
let bob: string;
let work: string;
let lockedApp: string;
let lockedNpmApp: string;

async function publish(name: string, version: string, token: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(reg, token);
  const d = writePackage(work, { name, version, ...extra }, reg, token);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`publish ${name}@${version} failed: ${r.out}`);
}

function api(path: string, token: string | null, body: unknown): Promise<{ status: number; body: unknown }> {
  return getJson(`${reg.url}-/apm/v1/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice", PASSWORD);
  bob = await addUser(reg, "bob", PASSWORD);
  work = mkdtempSync(join(tmpdir(), "apm-revoke-"));
  for (const v of ["1.0.0", "1.1.0", "1.2.0"]) {
    await publish("yankee", v, alice);
    clock += DAY;
  }
  for (const v of ["2.0.0", "2.0.1"]) {
    await publish("hacked-lib", v, alice);
    clock += DAY;
  }
  const sb = makeSandbox(reg, alice);
  lockedApp = writeConsumer(work, reg, alice, { "hacked-lib": "2.0.1" });
  const i1 = await run(["bun", "install"], { cwd: lockedApp, env: sb.env });
  if (i1.code !== 0) throw new Error(i1.out);
  lockedNpmApp = writeConsumer(work, reg, alice, { "hacked-lib": "2.0.1" });
  const i2 = await run(["npm", "install"], { cwd: lockedNpmApp, env: sb.env });
  if (i2.code !== 0) throw new Error(i2.out);
});
afterAll(async () => {
  await reg?.stop();
});

describe("yank", () => {
  test("a yanked version disappears from new resolution but an existing lockfile still installs from a cold cache", async () => {
    const sb = makeSandbox(reg, alice);
    const locked = writeConsumer(work, reg, alice, { yankee: "^1.0.0" });
    const first = await run(["bun", "install"], { cwd: locked, env: sb.env });
    expect(first.code, first.out).toBe(0);
    expect(installedVersion(locked, "yankee")).toBe("1.2.0");

    const y = await api("yank", alice, { name: "yankee", version: "1.2.0", reason: "broke ESM import" });
    expect(y.status, JSON.stringify(y.body)).toBe(200);

    const { body } = await getJson(`${reg.url}yankee`);
    expect(dig(body, "versions", "1.2.0")).toBeUndefined();
    expect(dig(body, "dist-tags", "latest")).toBe("1.1.0");

    const fresh = writeConsumer(work, reg, alice, { yankee: "^1.0.0" });
    const r = await run(["bun", "install"], { cwd: fresh, env: makeSandbox(reg, alice).env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(fresh, "yankee")).toBe("1.1.0");

    // the old lockfile still installs 1.2.0 with an empty cache and no node_modules
    rmSync(join(locked, "node_modules"), { recursive: true, force: true });
    const cold = makeSandbox(reg, alice);
    const again = await run(["bun", "install", "--frozen-lockfile"], { cwd: locked, env: cold.env });
    expect(again.code, again.out).toBe(0);
    expect(installedVersion(locked, "yankee")).toBe("1.2.0");
  });

  test("unyank restores the version", async () => {
    const u = await api("unyank", alice, { name: "yankee", version: "1.2.0" });
    expect(u.status, JSON.stringify(u.body)).toBe(200);
    const { body } = await getJson(`${reg.url}yankee`);
    expect(dig(body, "versions", "1.2.0", "version")).toBe("1.2.0");
  });

  test("only an owner can yank", async () => {
    const r = await api("yank", bob, { name: "yankee", version: "1.1.0", reason: "nope" });
    expect(r.status).toBe(403);
    const anon = await api("yank", null, { name: "yankee", version: "1.1.0", reason: "nope" });
    expect(anon.status).toBe(401);
  });
});

describe("revoke", () => {
  test("a bearer token alone cannot revoke: the account password is required", async () => {
    const r = await api("revoke", alice, { name: "hacked-lib", version: "2.0.1", reason: "test" });
    expect(r.status).toBe(401);
    expect(JSON.stringify(r.body).toLowerCase()).toContain("password");
    const wrong = await api("revoke", alice, { name: "hacked-lib", version: "2.0.1", reason: "test", password: "wrong-password" });
    expect(wrong.status).toBe(401);
  });

  test("revoking an old version with dependents yanks it at once and becomes a 410 after 24 hours", async () => {
    clock += 120 * DAY;
    await publish("depends-on-hacked", "1.0.0", bob, { dependencies: { "hacked-lib": "^2.0.0" } });
    const r = await api("revoke", alice, { name: "hacked-lib", version: "2.0.1", reason: "maintainer token stolen; malicious postinstall", password: PASSWORD });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(dig(r.body, "status")).toBe("revoke-pending");
    // hidden from new installs immediately
    const { body } = await getJson(`${reg.url}hacked-lib`);
    expect(dig(body, "versions", "2.0.1")).toBeUndefined();
    expect(dig(body, "dist-tags", "latest")).toBe("2.0.0");
    // lockfiles keep working during the pending window
    expect((await fetch(`${reg.url}hacked-lib/-/hacked-lib-2.0.1.tgz`)).status).toBe(200);
    clock += 25 * HOUR;
    const tgz = await fetch(`${reg.url}hacked-lib/-/hacked-lib-2.0.1.tgz`);
    expect(tgz.status).toBe(410);
    expect(await tgz.text()).toContain("malicious postinstall");
  });

  test("npm shows the owner's reason when a lockfile asks for a revoked tarball", async () => {
    const reason = "maintainer token stolen; malicious postinstall";
    const tgz = await getJson(`${reg.url}hacked-lib/-/hacked-lib-2.0.1.tgz`);

    expect(tgz.status).toBe(410);
    // npm prints a refused download's `error` and nothing else from the body
    expect(dig(tgz.body, "error")).toBe(`hacked-lib@2.0.1 was revoked by its owner: ${reason}`);
    expect(dig(tgz.body, "revokeReason")).toBe(reason);

    // the app locked to 2.0.1 before the revoke, installed again from its lockfile with an empty cache
    const app = mkdtempSync(join(work, "app-ci-"));

    for (const f of ["package.json", "package-lock.json", ".npmrc"]) copyFileSync(join(lockedNpmApp, f), join(app, f));
    const sb = makeSandbox(reg, alice);
    const ci = await run(["npm", "ci"], { cwd: app, env: sb.env });

    expect(ci.code, ci.out).not.toBe(0);
    expect(ci.out).toContain(reason);
  });

  test("a second owner's confirmation makes a pending revoke final at once", async () => {
    await publish("shared-lib", "1.0.0", alice);
    const add = await api("owners", alice, { name: "shared-lib", user: "bob", password: PASSWORD });
    expect(add.status, JSON.stringify(add.body)).toBe(200);
    clock += 5 * DAY;
    const r = await api("revoke", alice, { name: "shared-lib", version: "1.0.0", reason: "bad build", password: PASSWORD });
    expect(dig(r.body, "status")).toBe("revoke-pending");
    expect((await fetch(`${reg.url}shared-lib/-/shared-lib-1.0.0.tgz`)).status).toBe(200);
    const c = await api("revoke", bob, { name: "shared-lib", version: "1.0.0", reason: "confirm", password: PASSWORD });
    expect(c.status, JSON.stringify(c.body)).toBe(200);
    expect(dig(c.body, "status")).toBe("revoked");
    expect((await fetch(`${reg.url}shared-lib/-/shared-lib-1.0.0.tgz`)).status).toBe(410);
  });

  test("the bulk advisory endpoint reports revoked versions as critical", async () => {
    const r = await getJson(`${reg.url}-/npm/v1/security/advisories/bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ "hacked-lib": ["2.0.0", "2.0.1"], yankee: ["1.0.0"] }),
    });
    expect(r.status).toBe(200);
    const list = dig(r.body, "hacked-lib");
    expect(Array.isArray(list)).toBe(true);
    expect(JSON.stringify(list)).toContain("critical");
    expect(JSON.stringify(list)).toContain("revoked");
    expect(String(dig(r.body, "hacked-lib", 0, "vulnerable_versions"))).toContain("2.0.1");
    expect(Bun.semver.satisfies("2.0.0", String(dig(r.body, "hacked-lib", 0, "vulnerable_versions")))).toBe(false);
  });

  test("the bulk advisory endpoint accepts gzip bodies like npm and bun send", async () => {
    const gz = Bun.gzipSync(new TextEncoder().encode(JSON.stringify({ "hacked-lib": ["2.0.1"] })));
    const r = await getJson(`${reg.url}-/npm/v1/security/advisories/bulk`, {
      method: "POST",
      headers: { "content-type": "application/json", "content-encoding": "gzip" },
      body: gz,
    });
    expect(r.status).toBe(200);
    expect(JSON.stringify(r.body)).toContain("critical");
  });

  test("bun audit and npm audit flag an app that installed the version before it was revoked", async () => {
    const sb = makeSandbox(reg, alice);
    const audit = await run(["bun", "audit"], { cwd: lockedApp, env: sb.env });
    expect(audit.code, audit.out).not.toBe(0);
    expect(audit.out).toContain("hacked-lib");
    expect(audit.out.toLowerCase()).toContain("critical");
    const npmAudit = await run(["npm", "audit", "--json"], { cwd: lockedNpmApp, env: { ...sb.env, npm_config_audit: "true" } });
    expect(npmAudit.code, npmAudit.out).not.toBe(0);
    expect(npmAudit.stdout).toContain("hacked-lib");
  });

  test("a revoked version number can never be published again", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "hacked-lib", version: "2.0.1", files: { "index.js": "module.exports = 'clean';\n" } }, reg, alice);
    const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
  });

  test("a mistaken revoke can be downgraded to a yank by an owner, and the log shows it", async () => {
    const r = await api("restore", alice, { name: "shared-lib", version: "1.0.0", reason: "revoked by mistake", password: PASSWORD });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(dig(r.body, "status")).toBe("yanked");
    expect((await fetch(`${reg.url}shared-lib/-/shared-lib-1.0.0.tgz`)).status).toBe(200);
  });

  test("the package's public audit log records who revoked what and why", async () => {
    const { status, body } = await getJson(`${reg.url}-/apm/v1/packages/hacked-lib/events`);
    expect(status).toBe(200);
    const text = JSON.stringify(body);
    expect(text).toContain("revoke");
    expect(text).toContain("alice");
    expect(text).toContain("maintainer token stolen");
    const shared = JSON.stringify((await getJson(`${reg.url}-/apm/v1/packages/shared-lib/events`)).body);
    expect(shared).toContain("restore");
    expect(shared).toContain("revoked by mistake");
  });
});

describe("incident: my account was hacked", () => {
  test("incident needs the password, rejects windows over 30 days, and previews before acting", async () => {
    const noPw = await api("incident", bob, { since: new Date(clock - DAY).toISOString(), reason: "phished" });
    expect(noPw.status).toBe(401);
    const tooOld = await api("incident", bob, { since: new Date(clock - 45 * DAY).toISOString(), reason: "phished", password: PASSWORD });
    expect(tooOld.status).toBe(400);
  });

  test("one call revokes every token and every version published since a time", async () => {
    const t0 = clock;
    clock += DAY;
    await publish("victim-a", "1.0.0", bob);
    await publish("victim-b", "3.0.0", bob);
    const before = await getJson(`${reg.url}-/whoami`, { headers: { authorization: `Bearer ${bob}` } });
    expect(before.status).toBe(200);

    const preview = await api("incident", bob, { since: new Date(t0).toISOString(), reason: "phished", password: PASSWORD, dryRun: true });
    expect(preview.status, JSON.stringify(preview.body)).toBe(200);
    expect(JSON.stringify(dig(preview.body, "revoked"))).toContain("victim-a@1.0.0");
    expect((await fetch(`${reg.url}victim-a/-/victim-a-1.0.0.tgz`)).status).toBe(200);

    const r = await api("incident", bob, { since: new Date(t0).toISOString(), reason: "phished", password: PASSWORD });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(JSON.stringify(dig(r.body, "revoked"))).toContain("victim-a@1.0.0");
    expect(JSON.stringify(dig(r.body, "revoked"))).toContain("victim-b@3.0.0");
    expect(JSON.stringify(dig(r.body, "revoked"))).not.toContain("depends-on-hacked");
    expect(Number(dig(r.body, "tokensRevoked"))).toBeGreaterThanOrEqual(1);

    const after = await getJson(`${reg.url}-/whoami`, { headers: { authorization: `Bearer ${bob}` } });
    expect(after.status).toBe(401);
    const tgz = await fetch(`${reg.url}victim-a/-/victim-a-1.0.0.tgz`);
    expect(tgz.status).toBe(410);
  });
});
