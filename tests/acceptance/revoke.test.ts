// Spec: a maintainer can pull a bad version at any time, in one step, and stock clients notice.
// States: deprecated (advisory), yanked (hidden from new resolution, lockfiles keep working),
// revoked (malicious: hidden, tarball refused, critical advisory for audit).
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, getJson, installedVersion, dig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
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
  alice = await addUser(reg, "alice");
  bob = await addUser(reg, "bob");
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
  test("a yanked version disappears from new resolution but lockfiles still install", async () => {
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
    const r = await run(["bun", "install"], { cwd: fresh, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(fresh, "yankee")).toBe("1.1.0");

    // the tarball is still served for existing lockfiles
    const tgz = await fetch(`${reg.url}yankee/-/yankee-1.2.0.tgz`);
    expect(tgz.status).toBe(200);
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
  test("revoke works months after publish with dependents, refuses the tarball and moves latest back", async () => {
    clock += 120 * DAY;
    await publish("depends-on-hacked", "1.0.0", bob, { dependencies: { "hacked-lib": "^2.0.0" } });
    const r = await api("revoke", alice, { name: "hacked-lib", version: "2.0.1", reason: "maintainer token stolen; malicious postinstall" });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const tgz = await fetch(`${reg.url}hacked-lib/-/hacked-lib-2.0.1.tgz`);
    expect(tgz.status).toBe(410);
    expect(await tgz.text()).toContain("malicious postinstall");
    const { body } = await getJson(`${reg.url}hacked-lib`);
    expect(dig(body, "versions", "2.0.1")).toBeUndefined();
    expect(dig(body, "dist-tags", "latest")).toBe("2.0.0");
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

  test("the package's public audit log records who revoked what and why", async () => {
    const { status, body } = await getJson(`${reg.url}-/apm/v1/packages/hacked-lib/events`);
    expect(status).toBe(200);
    const text = JSON.stringify(body);
    expect(text).toContain("revoke");
    expect(text).toContain("alice");
    expect(text).toContain("maintainer token stolen");
  });
});

describe("incident: my account was hacked", () => {
  test("one call revokes every token and every version published since a time", async () => {
    const t0 = clock;
    clock += DAY;
    await publish("victim-a", "1.0.0", bob);
    await publish("victim-b", "3.0.0", bob);
    const before = await getJson(`${reg.url}-/whoami`, { headers: { authorization: `Bearer ${bob}` } });
    expect(before.status).toBe(200);

    const r = await api("incident", bob, { since: new Date(t0).toISOString(), reason: "phished" });
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
