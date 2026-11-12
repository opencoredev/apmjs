// Spec (council round 3): every evidence citation opens the cited file. The registry returns one file of a
// published version as text, from the verified tarball, looked up in the parsed entry list; files over 1 MB and
// binary files are named, not sent; answers are cached in the blob store by tarball digest and path.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { z } from "zod";
import { startRegistry, addUser, putPublish, getJson, dig, type Registry } from "./harness";

let clock = Date.parse("2026-08-01T00:00:00Z");
let upstream: Registry;
let reg: Registry;
let aliceToken: string;
const PASSWORD = "correct-horse-battery";

const SETUP = "const fs = require('fs');\n// read the token\nconst t = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');\nmodule.exports = t;\n";
const BIG = `${"// filler line for the size cap\n".repeat(36_000)}`;

// a 1.6 MB bundle: numbered lines, a credential read at line 25134 and a 50 KB minified line at 7 whose
// 4096-byte cut falls inside a two-byte character
const HUGE_LINES = 40_000;
const CITED = "const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');";
const MINIFIED = `${"a".repeat(4095)}é${"b".repeat(50_000)}`;
const HUGE = `${Array.from({ length: HUGE_LINES }, (_, i) => (i + 1 === 25_134 ? CITED : i + 1 === 7 ? MINIFIED : `// bundle line ${i + 1} with some padding text`)).join("\n")}\n`;
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0xff, 0xfe, 0x80, 0x81]);

function fileUrl(r: Registry, name: string, version: string, path: string): string {
  return `${r.url}-/apm/v1/file/${name}/${version}?path=${encodeURIComponent(path)}`;
}

function excerptUrl(input: { name?: string; version?: string; path: string; line: number | string; context?: number | string }): string {
  const context = input.context === undefined ? "" : `&context=${input.context}`;

  return `${fileUrl(reg, input.name ?? "viewme", input.version ?? "1.0.0", input.path)}&line=${input.line}${context}`;
}

const Lines = z.object({ lines: z.array(z.object({ n: z.number(), text: z.string(), truncated: z.object({ bytes: z.number() }).nullable() })) });

/** The lines of an excerpt answer, parsed. */
function linesOf(answer: { body: unknown }) {
  return Lines.parse(answer.body).lines;
}

beforeAll(async () => {
  upstream = await startRegistry({ now: () => clock });
  await addUser(upstream, "upbob");
  const upToken = await upstream.mintToken({ user: "upbob", scope: "publish" });
  const up = await putPublish(upstream, upToken, { name: "up-files", version: "2.0.0", license: "MIT", main: "index.js" }, { files: { "index.js": "module.exports = 'from upstream';\n", "lib/setup.js": SETUP } });

  if (up.status !== 201 && up.status !== 200) throw new Error(`upstream publish failed: ${JSON.stringify(up.body)}`);

  reg = await startRegistry({ now: () => clock, upstream: upstream.url });
  aliceToken = await addUser(reg, "alice", PASSWORD);
  const token = await reg.mintToken({ user: "alice", scope: "publish" });

  const local = await putPublish(
    reg,
    token,
    { name: "viewme", version: "1.0.0", license: "MIT", main: "index.js" },
    {
      files: {
        "index.js": "module.exports = require('./lib/setup.js');\n",
        "lib/setup.js": SETUP,
        "big.js": BIG,
        "logo.png": PNG,
        "dist/node/chunks/node.js": HUGE,
        "crlf.txt": "a\r\nb\n",
        "empty.txt": "",
      },
    },
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

describe("excerpts of a file of any size", () => {
  test("lines around a cited line of a file over 1 MB, with their real numbers", async () => {
    const { status, body } = await getJson(excerptUrl({ path: "dist/node/chunks/node.js", line: 25_134, context: 3 }));
    expect(status, JSON.stringify(body)).toBe(200);
    expect(dig(body, "kind")).toBe("excerpt");
    expect(dig(body, "size")).toBe(new TextEncoder().encode(HUGE).length);
    expect(dig(body, "totalLines")).toBe(HUGE_LINES);
    expect([dig(body, "line"), dig(body, "from"), dig(body, "to")]).toEqual([25_134, 25_131, 25_137]);
    const lines = linesOf({ body });
    expect(lines.map((l) => l.n)).toEqual([25_131, 25_132, 25_133, 25_134, 25_135, 25_136, 25_137]);
    expect(lines[3]?.text).toBe(CITED);
    expect(lines[2]?.text).toBe("// bundle line 25133 with some padding text");
    // the whole-file view still refuses it
    expect(dig((await getJson(fileUrl(reg, "viewme", "1.0.0", "dist/node/chunks/node.js"))).body, "kind")).toBe("too-large");
  });

  test("20 lines each side by default, clamped at the file's ends", async () => {
    expect(linesOf(await getJson(excerptUrl({ path: "dist/node/chunks/node.js", line: 25_134 })))).toHaveLength(41);
    const start = (await getJson(excerptUrl({ path: "dist/node/chunks/node.js", line: 2, context: 5 }))).body;
    expect([dig(start, "from"), dig(start, "to")]).toEqual([1, 7]);
    const end = (await getJson(excerptUrl({ path: "dist/node/chunks/node.js", line: HUGE_LINES, context: 2 }))).body;
    expect(linesOf({ body: end }).map((l) => l.n)).toEqual([HUGE_LINES - 2, HUGE_LINES - 1, HUGE_LINES]);
  });

  test("a line past the end is a 416 that says how many lines there are", async () => {
    const { status, body } = await getJson(excerptUrl({ path: "dist/node/chunks/node.js", line: HUGE_LINES + 1 }));
    expect(status).toBe(416);
    expect(dig(body, "lines")).toBe(HUGE_LINES);
    expect(String(dig(body, "error"))).toContain("40000 lines");
  });

  test("bad line and context values are a 400", async () => {
    for (const q of ["&line=0", "&line=-3", "&line=1.5", "&line=abc", "&line=", "&line=5&context=101", "&line=5&context=-1", "&context=5"]) {
      const { status } = await getJson(`${fileUrl(reg, "viewme", "1.0.0", "dist/node/chunks/node.js")}${q}`);
      expect(status, q).toBe(400);
    }
  });

  test("a huge minified line is cut at 4096 bytes on a character boundary and says how long it is", async () => {
    const lines = linesOf(await getJson(excerptUrl({ path: "dist/node/chunks/node.js", line: 7, context: 1 })));
    const line = lines.find((l) => l.n === 7);
    expect(line?.truncated).toEqual({ bytes: new TextEncoder().encode(MINIFIED).length });
    // the "é" straddles byte 4096, so the cut drops it rather than splitting it
    expect(line?.text).toBe("a".repeat(4095));
    expect(lines.find((l) => l.n === 6)?.truncated).toBeNull();
  });

  test("a path that isn't in the tarball is a 404, and path tricks name nothing", async () => {
    for (const path of ["dist/node/chunks/nope.js", "../package.json", "dist/node/../node/chunks/node.js", "DIST/NODE/CHUNKS/NODE.JS"]) {
      const { status, body } = await getJson(excerptUrl({ path, line: 1 }));
      expect(status, path).toBe(404);
      expect(String(dig(body, "error"))).toContain("has no file");
    }
  });

  test("small files, CRLF and empty files number lines the way the scorer does", async () => {
    const setup = linesOf(await getJson(excerptUrl({ path: "lib/setup.js", line: 3, context: 0 })));
    expect(setup).toEqual([{ n: 3, text: "const t = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');", truncated: null }]);
    const crlf = (await getJson(excerptUrl({ path: "crlf.txt", line: 1, context: 5 }))).body;
    expect(dig(crlf, "totalLines")).toBe(2);
    expect(linesOf({ body: crlf }).map((l) => l.text)).toEqual(["a\r", "b"]);
    const empty = (await getJson(excerptUrl({ path: "empty.txt", line: 1 }))).body;
    expect([dig(empty, "totalLines"), linesOf({ body: empty })]).toEqual([1, [{ n: 1, text: "", truncated: null }]]);
  });

  test("a binary file says so and sends no lines", async () => {
    const { status, body } = await getJson(excerptUrl({ path: "logo.png", line: 1 }));
    expect(status).toBe(200);
    expect(dig(body, "kind")).toBe("binary");
    expect(dig(body, "lines")).toBeUndefined();
  });

  test("an upstream version's large-file excerpt is fetched and verified through the proxy", async () => {
    const { status, body } = await getJson(excerptUrl({ name: "up-files", version: "2.0.0", path: "lib/setup.js", line: 2, context: 0 }));
    expect(status).toBe(200);
    expect(linesOf({ body })[0]?.text).toBe("// read the token");
  });

  test("excerpts are cached by tarball digest, path and block of lines", async () => {
    const dir = (await reg.blobs.keys()).find((k) => k.endsWith("/index.json") && k.startsWith("files/"));
    const hash = new Bun.CryptoHasher("sha256").update("dist/node/chunks/node.js").digest("hex");
    const prefix = `${String(dir).slice(0, -"index.json".length)}${hash}`;
    const keys = await reg.blobs.keys();
    // every request above landed in blocks 0, 251 and 399, never in a key per range asked for
    const blocks = keys.filter((k) => k.startsWith(`${prefix}.b`)).map((k) => Number(k.split("-").at(-1)?.replace(".json", "")));
    expect(blocks.sort((a, b) => a - b)).toEqual([0, 251, 399]);
    expect(keys).toContain(`${prefix}.lines.json`);
    const block = keys.find((k) => k.startsWith(`${prefix}.b`) && k.endsWith("-251.json"));
    const lines = Array.from({ length: 100 }, (_, i) => ({ n: 25_101 + i, text: `cached ${25_101 + i}`, truncated: null }));
    await reg.blobs.put(String(block), JSON.stringify({ lines }));
    expect(linesOf(await getJson(excerptUrl({ path: "dist/node/chunks/node.js", line: 25_134, context: 0 })))[0]?.text).toBe("cached 25134");
  });
});

describe("readme from the tarball", () => {
  let token: string;

  beforeAll(async () => {
    token = await reg.mintToken({ user: "alice", scope: "publish" });

    const pub = async (name: string, files: Record<string, string>, extra: Partial<Parameters<typeof putPublish>[2]> = {}) => {
      const r = await putPublish(reg, token, { name, version: "1.0.0", license: "MIT", main: "index.js", ...extra }, { files: { "index.js": "module.exports = 1;\n", ...files } });

      if (r.status !== 201 && r.status !== 200) throw new Error(`publish ${name} failed: ${JSON.stringify(r.body)}`);
    };

    await pub("readme-order", { "README.txt": "plain text", README: "no extension", "readme.md": "# lower-case markdown", "docs/README.md": "# nested" });
    await pub("readme-plain", { "README.txt": "plain text", README: "# no extension" });
    await pub("readme-none", { "README.txt": "plain text only", "docs/README.md": "# nested only" });
    await pub("readme-links", { "README.md": "# links" }, { homepage: "https://example.com/home", bugs: { url: "https://github.com/acme/links/issues" }, repository: "github:acme/links" });
    await pub("revoke-files", { "README.md": "# soon gone" });
  });

  const readme = (name: string) => getJson(`${reg.url}-/apm/v1/readme/${name}/1.0.0`);

  test("picks a markdown README at the package root first, the way npm does", async () => {
    const { status, body } = await readme("readme-order");
    expect(status).toBe(200);
    expect([dig(body, "kind"), dig(body, "path"), dig(body, "text")]).toEqual(["text", "readme.md", "# lower-case markdown"]);
  });

  test("falls back to a file named README, and to nothing for README.txt alone or a nested README", async () => {
    expect(dig((await readme("readme-plain")).body, "path")).toBe("README");
    const none = await readme("readme-none");
    expect(none.status).toBe(404);
    expect(String(dig(none.body, "error"))).toContain("no readme");
  });

  test("the package answer names the latest version's homepage and issue tracker", async () => {
    const { body } = await getJson(`${reg.url}-/apm/v1/packages/readme-links`);
    expect(dig(body, "homepage")).toBe("https://example.com/home");
    expect(dig(body, "bugs")).toBe("https://github.com/acme/links/issues");
    expect(dig(body, "repository", "url")).toBe("github:acme/links");
    const bare = (await getJson(`${reg.url}-/apm/v1/packages/readme-none`)).body;
    expect([dig(bare, "homepage"), dig(bare, "bugs")]).toEqual([null, null]);
  });

  test("a revoked version answers 410 for its readme, its excerpts and its files", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${aliceToken}` },
      body: JSON.stringify({ name: "revoke-files", version: "1.0.0", reason: "bad build", password: PASSWORD }),
    });

    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(dig(r.body, "status")).toBe("revoked");
    expect((await readme("revoke-files")).status).toBe(410);
    expect((await getJson(excerptUrl({ name: "revoke-files", path: "README.md", line: 1 }))).status).toBe(410);
    expect((await getJson(fileUrl(reg, "revoke-files", "1.0.0", "README.md"))).status).toBe(410);
  });
});
