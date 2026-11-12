// Spec: stock bun and npm clients work against the registry unmodified.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, getJson, installedVersion, encodePkg, dig, type Registry } from "./harness";

let reg: Registry;
let alice: string;
let bob: string;
let work: string;

beforeAll(async () => {
  reg = await startRegistry();
  alice = await addUser(reg, "alice");
  bob = await addUser(reg, "bob");
  work = mkdtempSync(join(tmpdir(), "apm-proto-"));
});
afterAll(async () => {
  await reg?.stop();
});

describe("protocol: bun client", () => {
  test("bun publish creates a packument with tarball, shasum and integrity", async () => {
    const sb = makeSandbox(reg, alice);
    const dir = writePackage(work, { name: "left-padder", version: "1.0.0" }, reg, alice);
    const r = await run(["bun", "publish"], { cwd: dir, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const { status, body } = await getJson(`${reg.url}left-padder`);
    expect(status).toBe(200);
    expect(dig(body, "name")).toBe("left-padder");
    expect(dig(body, "dist-tags", "latest")).toBe("1.0.0");
    expect(String(dig(body, "versions", "1.0.0", "dist", "tarball"))).toStartWith(reg.url);
    expect(String(dig(body, "versions", "1.0.0", "dist", "integrity"))).toStartWith("sha512-");
    expect(String(dig(body, "versions", "1.0.0", "dist", "shasum"))).toMatch(/^[0-9a-f]{40}$/);
    expect(typeof dig(body, "time", "1.0.0")).toBe("string");
  });

  test("bun install resolves a caret range to the newest match", async () => {
    const sb = makeSandbox(reg, alice);
    for (const v of ["1.1.0", "1.2.0", "2.0.0"]) {
      const d = writePackage(work, { name: "ranged", version: v }, reg, alice);
      const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
      expect(r.code, r.out).toBe(0);
    }
    const app = writeConsumer(work, reg, alice, { ranged: "^1.0.0" });
    const r = await run(["bun", "install"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "ranged")).toBe("1.2.0");
  });

  test("scoped packages publish and install with bun", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "@alice/util", version: "0.1.0", extra: { publishConfig: { access: "public" } } }, reg, alice);
    const p = await run(["bun", "publish"], { cwd: d, env: sb.env });
    expect(p.code, p.out).toBe(0);
    const app = writeConsumer(work, reg, alice, { "@alice/util": "0.1.0" });
    const r = await run(["bun", "install"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "@alice/util")).toBe("0.1.0");
  });

  test("abbreviated packument is served for the install Accept header", async () => {
    const res = await fetch(`${reg.url}left-padder`, { headers: { accept: "application/vnd.npm.install-v1+json" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toContain("application/vnd.npm.install-v1+json");
    const body: unknown = await res.json();
    expect(typeof dig(body, "modified")).toBe("string");
    expect(dig(body, "versions", "1.0.0", "dist", "tarball")).toBeTruthy();
    expect(dig(body, "versions", "1.0.0", "readme")).toBeUndefined();
  });

  test("unknown package is a 404", async () => {
    const { status } = await getJson(`${reg.url}definitely-not-here-xyz`);
    expect(status).toBe(404);
  });
});

describe("protocol: npm client", () => {
  test("npm publish and npm install", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "npm-made", version: "3.1.4" }, reg, alice);
    const p = await run(["npm", "publish"], { cwd: d, env: sb.env });
    expect(p.code, p.out).toBe(0);
    const app = writeConsumer(work, reg, alice, { "npm-made": "^3.0.0" });
    const r = await run(["npm", "install"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "npm-made")).toBe("3.1.4");
  });

  test("npm whoami returns the token's user", async () => {
    const sb = makeSandbox(reg, bob);
    const r = await run(["npm", "whoami"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.stdout.trim()).toBe("bob");
  });

  test("npm view reads versions", async () => {
    const sb = makeSandbox(reg);
    const r = await run(["npm", "view", "ranged", "versions", "--json"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual(["1.1.0", "1.2.0", "2.0.0"]);
  });

  test("npm dist-tag add and ls", async () => {
    const sb = makeSandbox(reg, alice);
    const add = await run(["npm", "dist-tag", "add", "ranged@1.2.0", "stable"], { cwd: sb.home, env: sb.env });
    expect(add.code, add.out).toBe(0);
    const { body } = await getJson(`${reg.url}ranged`);
    expect(dig(body, "dist-tags", "stable")).toBe("1.2.0");
    expect(dig(body, "dist-tags", "latest")).toBe("2.0.0");
  });

  test("npm deprecate marks a version deprecated", async () => {
    const sb = makeSandbox(reg, alice);
    const r = await run(["npm", "deprecate", "ranged@1.1.0", "use 1.2.0"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const { body } = await getJson(`${reg.url}ranged`);
    expect(dig(body, "versions", "1.1.0", "deprecated")).toBe("use 1.2.0");
    expect(dig(body, "versions", "1.2.0", "deprecated")).toBeUndefined();
  });

  test("npm search finds published packages", async () => {
    const sb = makeSandbox(reg);
    const r = await run(["npm", "search", "--json", "padder"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const results: unknown = JSON.parse(r.stdout);
    expect(Array.isArray(results)).toBe(true);
    expect(JSON.stringify(results)).toContain("left-padder");
  });
});

describe("protocol: authorization", () => {
  test("publishing without a token is rejected", async () => {
    const sb = makeSandbox(reg);
    const d = writePackage(work, { name: "anon-pkg", version: "1.0.0" }, reg);
    const r = await run(["npm", "publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
    const { status } = await getJson(`${reg.url}anon-pkg`);
    expect(status).toBe(404);
  });

  test("a different user cannot publish over someone else's package", async () => {
    const sb = makeSandbox(reg, bob);
    const d = writePackage(work, { name: "left-padder", version: "9.9.9" }, reg, bob);
    const r = await run(["npm", "publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
    const { body } = await getJson(`${reg.url}left-padder`);
    expect(dig(body, "versions", "9.9.9")).toBeUndefined();
  });

  test("republishing an existing version is refused", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "left-padder", version: "1.0.0", files: { "index.js": "module.exports = 'different';\n" } }, reg, alice);
    const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
  });

  test("scoped name reachable with encoded slash", async () => {
    const { status, body } = await getJson(`${reg.url}${encodePkg("@alice/util")}`);
    expect(status).toBe(200);
    expect(dig(body, "name")).toBe("@alice/util");
  });
});
