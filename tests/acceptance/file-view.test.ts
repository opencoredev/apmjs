// Spec (council round 3): every evidence citation opens the cited file. The registry returns one file of a
// published version as text, from the verified tarball, looked up in the parsed entry list; files over 1 MB and
// binary files are named, not sent; answers are cached in the blob store by tarball digest and path.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { startRegistry, addUser, putPublish, getJson, dig, type Registry } from "./harness";

let clock = Date.parse("2026-08-01T00:00:00Z");
let upstream: Registry;
let reg: Registry;

const SETUP = "const fs = require('fs');\n// read the token\nconst t = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');\nmodule.exports = t;\n";
const BIG = `${"// filler line for the size cap\n".repeat(36_000)}`;
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0xff, 0xfe, 0x80, 0x81]);

function fileUrl(r: Registry, name: string, version: string, path: string): string {
  return `${r.url}-/apm/v1/file/${name}/${version}?path=${encodeURIComponent(path)}`;
}

beforeAll(async () => {
  upstream = await startRegistry({ now: () => clock });
  await addUser(upstream, "upbob");
  const upToken = await upstream.mintToken({ user: "upbob", scope: "publish" });
  const up = await putPublish(upstream, upToken, { name: "up-files", version: "2.0.0", license: "MIT", main: "index.js" }, { files: { "index.js": "module.exports = 'from upstream';\n", "lib/setup.js": SETUP } });

  if (up.status !== 201 && up.status !== 200) throw new Error(`upstream publish failed: ${JSON.stringify(up.body)}`);

  reg = await startRegistry({ now: () => clock, upstream: upstream.url });
  await addUser(reg, "alice");
  const token = await reg.mintToken({ user: "alice", scope: "publish" });

  const local = await putPublish(
    reg,
    token,
    { name: "viewme", version: "1.0.0", license: "MIT", main: "index.js" },
    { files: { "index.js": "module.exports = require('./lib/setup.js');\n", "lib/setup.js": SETUP, "big.js": BIG, "logo.png": PNG } },
  );

  if (local.status !== 201 && local.status !== 200) throw new Error(`publish failed: ${JSON.stringify(local.body)}`);
  clock += 2 * 24 * 60 * 60 * 1000;
});

afterAll(async () => {
  await reg?.stop();
  await upstream?.stop();
});

describe("file view", () => {
  test("returns a local version's file as text, with its size", async () => {
    const { status, body } = await getJson(fileUrl(reg, "viewme", "1.0.0", "lib/setup.js"));
    expect(status).toBe(200);
    expect(dig(body, "kind")).toBe("text");
    expect(dig(body, "text")).toBe(SETUP);
    expect(dig(body, "size")).toBe(new TextEncoder().encode(SETUP).length);
    expect(dig(body, "path")).toBe("lib/setup.js");
  });

  test("returns an upstream version's file, fetched and verified through the proxy", async () => {
    const { status, body } = await getJson(fileUrl(reg, "up-files", "2.0.0", "lib/setup.js"));
    expect(status).toBe(200);
    expect(dig(body, "kind")).toBe("text");
    expect(dig(body, "text")).toBe(SETUP);
  });

  test("a path that isn't in the tarball is a 404, and path tricks name nothing", async () => {
    for (const path of ["lib/nope.js", "../package.json", "lib/../index.js", "/index.js", "./index.js", "package/index.js", "LIB/SETUP.JS"]) {
      const { status, body } = await getJson(fileUrl(reg, "viewme", "1.0.0", path));
      expect(status, path).toBe(404);
      expect(String(dig(body, "error"))).toContain("has no file");
    }
  });

  test("an unknown version or package is a 404, and a missing path parameter is a 400", async () => {
    expect((await getJson(fileUrl(reg, "viewme", "9.9.9", "index.js"))).status).toBe(404);
    expect((await getJson(fileUrl(reg, "nobody-has-this", "1.0.0", "index.js"))).status).toBe(404);
    expect((await getJson(`${reg.url}-/apm/v1/file/viewme/1.0.0`)).status).toBe(400);
  });

  test("a file over 1 MB is named with its size and not sent", async () => {
    const { status, body } = await getJson(fileUrl(reg, "viewme", "1.0.0", "big.js"));
    expect(status).toBe(200);
    expect(dig(body, "kind")).toBe("too-large");
    expect(dig(body, "size")).toBe(BIG.length);
    expect(dig(body, "limit")).toBe(1024 * 1024);
    expect(dig(body, "text")).toBeUndefined();
  });

  test("a binary file says so and sends no bytes", async () => {
    const { status, body } = await getJson(fileUrl(reg, "viewme", "1.0.0", "logo.png"));
    expect(status).toBe(200);
    expect(dig(body, "kind")).toBe("binary");
    expect(dig(body, "size")).toBe(PNG.length);
    expect(dig(body, "text")).toBeUndefined();
  });

  test("answers are cached in the blob store by tarball digest and path", async () => {
    const keys = (await reg.blobs.keys()).filter((k) => k.startsWith("files/"));
    const index = keys.find((k) => k.endsWith("/index.json"));
    expect(index).toMatch(/^files\/sha512-[0-9a-f]{128}\/index\.json$/);
    const dir = String(index).slice(0, -"index.json".length);
    // the cached answer for lib/setup.js is what the next request serves
    const cached = keys.find((k) => k.startsWith(dir) && !k.endsWith("/index.json"));
    expect(cached).toBeDefined();
    const path = "lib/setup.js";
    const key = `${dir}${new Bun.CryptoHasher("sha256").update(path).digest("hex")}.json`;
    expect(keys).toContain(key);
    await reg.blobs.put(key, JSON.stringify({ kind: "text", text: "served from the cache\n" }));
    const { body } = await getJson(fileUrl(reg, "viewme", "1.0.0", path));
    expect(dig(body, "text")).toBe("served from the cache\n");
  });

  test("HEAD answers with the status and no body", async () => {
    const res = await fetch(fileUrl(reg, "viewme", "1.0.0", "index.js"), { method: "HEAD" });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("");
    expect((await fetch(fileUrl(reg, "viewme", "1.0.0", "nope.js"), { method: "HEAD" })).status).toBe(404);
  });
});
