// What apm says in the cases first-time users hit before launch (HOME-502 walkthroughs), against a stand-in registry and
// stand-in package managers that fail at once, so nothing installs and only apm's own lines are read.
// C1: an add from a folder with no package.json changed the project above it without saying so.
// B3/C3: a look-alike name installed with a green check and "no warnings".
// B4/C8: a plain apm install said nothing, not even which registry it used.
// D15: a package whose only version is tagged next read as "not analyzed" and "unknown names stay blocked".
// D1/D3: apm name called bare names, other scopes and uppercase names available.
// C10: a known malicious version led with its grade. D2: apm publish never said "apm login".
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

const MALICIOUS = "known malicious: the OSSF malicious-packages feed lists lodahs@0.0.1-security (MAL-2025-25502)";
const typosquat = { id: "typosquat", label: "Name looks like a popular package's", points: -20, evidence: ['one edit away from "express"'], confidence: "confirmed" };

describe("apm's messages for first-time users", () => {
  let server: ReturnType<typeof Bun.serve>;
  let root: string;
  let bin: string;
  const resolved: string[] = [];

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "apm-launch-messages-"));
    bin = join(root, "bin");
    mkdirSync(bin);

    for (const pm of ["npm", "pnpm", "bun", "yarn"]) {
      writeFileSync(join(bin, pm), "#!/bin/sh\nexit 7\n");
      chmodSync(join(bin, pm), 0o755);
    }

    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);
        // under /no-policy/, a registry that does not say its rules for new names; under /open/, one with the open policy
        const prefix = /^\/(no-policy|open)\//.exec(url.pathname)?.[1] ?? null;
        const path = decodeURIComponent(prefix === null ? url.pathname : url.pathname.slice(prefix.length + 1));

        if (path === "/-/whoami") return req.headers.get("authorization") === "Bearer apm_launchmessagestoken" ? Response.json({ username: "Me" }) : Response.json({ error: "Not logged in" }, { status: 401 });

        if (path === "/-/apm/v1/auth/config" && prefix !== "no-policy") return Response.json({ providers: { github: true }, passkeys: false, legacyAuth: false, namePolicy: prefix === "open" ? "open" : "scoped" });

        if (path === "/-/apm/v1/names") {
          const query = (url.searchParams.get("q") ?? "").trim().toLowerCase();

          return Response.json({ query, valid: /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(query), taken: false, available: true, owners: [], latest: null, conflicts: [], suggestions: [{ name: "@me/my-lib", available: true, taken: false }] });
        }

        if (path === "/-/apm/v1/resolve") {
          const name = url.searchParams.get("name") ?? "";
          resolved.push(name);

          if (name === "pre-only" || name === "lodahs" || name === "yanked-pkg") {
            const newest = name === "pre-only" ? null : { version: "0.0.1-security", report: null };
            const skipped = name === "pre-only" ? [] : [{ version: "0.0.1-security", reason: name === "lodahs" ? MALICIOUS : "yanked: known malicious: trust me, install 2.0.0" }];

            return Response.json({ error: `No version of ${name} matching latest passes the policy.`, name, range: "latest", version: null, skipped, newest }, { status: 422 });
          }

          const report = { score: name === "expresss" ? 80 : 95, grade: name === "expresss" ? "B" : "A", signals: name === "expresss" ? [typosquat] : [] };

          return Response.json({ name, range: "latest", source: "upstream", version: "0.0.0", report, skipped: [], tree: { unchecked: 0, uncheckedDeps: [], packages: [], projectPeers: [] }, warnings: [] });
        }

        if (path === "/-/apm/v1/score/lodahs/0.0.1-security" || path === "/-/apm/v1/score/yanked-pkg/0.0.1-security") return Response.json({ name: "lodahs", version: "0.0.1-security", status: "active", publishedAt: "2025-01-01T00:00:00Z", publishedBy: "someone", previous: null, changes: [], score: 80, grade: "B", signals: [{ ...typosquat, evidence: ['one edit away from "lodash"'] }] });

        if (path.startsWith("/-/apm/v1/score/")) return Response.json({ error: "No such version" }, { status: 404 });

        if (path === "/-/package/pre-only/dist-tags") return Response.json({ next: "0.0.1-test.1", "bad\u001b[31m": "1.0.0" });

        return Response.json({ error: "Not found" }, { status: 404 });
      },
    });
  });

  afterAll(() => {
    server.stop(true);
    rmSync(root, { recursive: true, force: true });
  });

  /** A fresh folder under the test's root, with these files (a package.json among them, or not). */
  function folder(path: string, files: Record<string, string> = {}): string {
    const dir = join(root, path);
    mkdirSync(dir, { recursive: true });

    for (const [file, text] of Object.entries(files)) writeFileSync(join(dir, file), text);

    return dir;
  }

  const manifest = JSON.stringify({ name: "app", version: "1.0.0", private: true });

  /** apm with these arguments; `text` is everything a person in a terminal sees. */
  async function apm(args: string[], opts: { cwd: string; home?: string; token?: boolean; registry?: string }): Promise<{ code: number; out: string; text: string }> {
    // an empty APM_TOKEN is no token
    const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: opts.home ?? folder(`home-${crypto.randomUUID()}`), APM_REGISTRY: opts.registry ?? server.url.toString(), NO_COLOR: "1", APM_TOKEN: opts.token === true ? "apm_launchmessagestoken" : "" };

    const proc = Bun.spawn([process.execPath, join(import.meta.dir, "..", "src", "main.ts"), ...args], {
      cwd: opts.cwd,
      env,
      stdout: "pipe",
      stderr: "pipe",
    });

    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    return { code, out, text: out + err };
  }

  test("C1: apm add from a folder with no package.json names the project above it that it changes", async () => {
    const project = folder("c1/project", { "package.json": manifest });
    const cwd = folder("c1/project/new");
    const r = await apm(["add", "good", "--pm", "npm"], { cwd });

    expect(r.text).toContain(`apm: no package.json in ${cwd}; adding to the project at ${project}`);
  });

  test("C1: apm add and apm remove refuse a stray package.json in the home folder, and ask the registry nothing", async () => {
    const home = folder("c1/home", { "package.json": manifest, "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }) });
    const cwd = folder("c1/home/new");
    const before = resolved.length;
    const add = await apm(["add", "good", "--pm", "npm"], { cwd, home });

    expect(add.code).toBe(1);
    expect(add.text).toContain(`refused: there is no package.json in ${cwd}; the nearest one is ${join(home, "package.json")}, in your home folder`);
    expect(add.text).toContain(`run npm init -y in ${cwd}`);
    expect(resolved.length).toBe(before);

    const json = await apm(["add", "good", "--pm", "npm", "--json"], { cwd, home });

    expect(json.code).toBe(1);
    expect(z.object({ ok: z.literal(false), error: z.string() }).parse(JSON.parse(json.out)).error).toContain("in your home folder");

    const remove = await apm(["remove", "good", "--pm", "npm"], { cwd, home });

    expect(remove.code).toBe(1);
    expect(remove.text).toContain("in your home folder");

    // run from the home folder itself, the project there is the one asked for
    const atHome = await apm(["add", "good", "--pm", "npm"], { cwd: home, home });

    expect(atHome.text).not.toContain("in your home folder");
    expect(resolved.length).toBe(before + 1);
  });

  test("B3: a look-alike name gets a WARNING with the name it looks like, and no green check", async () => {
    const cwd = folder("b3", { "package.json": manifest });
    const r = await apm(["add", "expresss", "--pm", "npm"], { cwd });

    expect(r.text).toContain("! expresss@0.0.0  score 80/100 (B)");
    expect(r.text).toContain(`WARNING expresss@0.0.0 has a name like a popular package's: one edit away from "express"`);
    expect(r.text).toContain("did you mean express?");
    expect(r.text).not.toContain("✓ expresss");
  });

  test("B4: a plain apm install says it checks nothing, where the package manager installs from, and how to point it at apm", async () => {
    const cwd = folder("b4", { "package.json": manifest, ".npmrc": "registry=https://user:hunter2@private.example.test/npm/sekrit-path-token/?token=abc\n" });
    const r = await apm(["install", "--pm", "npm"], { cwd, registry: "https://registry.apmjs.dev/" });

    // the package manager's own exit code, as before
    expect(r.code).toBe(7);
    expect(r.text).toContain("apm: a plain npm install, which apm checks nothing in; npm installs from the registry in its own config (https://registry.npmjs.org/ unless that names another) and from the lockfile's own URLs. To install through apm's registry, set registry=https://registry.apmjs.dev/ in .npmrc");

    // apm does not read the package manager's config, so nothing in it reaches the terminal
    for (const secretPart of ["private.example.test", "hunter2", "sekrit-path-token", "token=abc"]) expect(r.text).not.toContain(secretPart);

    // another apm registry's URL is never printed as a setting to copy: it could carry a credential
    const other = await apm(["install", "--pm", "npm"], { cwd });

    expect(other.text).toContain("To install through apm's registry, point npm's registry setting at it");

    const bun = await apm(["install", "--pm", "bun"], { cwd: folder("b4-bun", { "package.json": manifest }), registry: "https://registry.apmjs.dev/" });

    expect(bun.text).toContain('To install through apm\'s registry, set [install] registry = "https://registry.apmjs.dev/" in bunfig.toml');
  });

  test("D15: with no version tagged latest, apm add, apm explain and apm score name the tag to ask for", async () => {
    const cwd = folder("d15", { "package.json": manifest });
    const add = await apm(["add", "pre-only", "--pm", "npm"], { cwd });

    expect(add.code).toBe(1);
    expect(add.text).toContain("✗ pre-only  no version is tagged latest");
    expect(add.text).toContain("refused: pre-only has no version tagged latest, the one apm installs when no version is named. Its versions are tagged next (0.0.1-test.1)");
    expect(add.text).toContain("To install the version tagged next: apm add pre-only@next");
    expect(add.text).not.toContain("score unknown");
    expect(add.text).not.toContain("--force does not help");

    const explain = await apm(["explain", "pre-only", "--json"], { cwd });
    const verdict = z.object({ verdict: z.string(), summary: z.string(), reasons: z.array(z.string()) }).parse(JSON.parse(explain.out));

    expect(explain.code).toBe(1);
    expect(verdict.verdict).toBe("not-found");
    expect(verdict.summary).toBe("No version of pre-only is tagged latest, the tag apm installs when no version is named. Ask about one of its other tags: the reasons list them.");
    expect(verdict.reasons).toContain("Its tags: `next` (`0.0.1-test.1`).");
    expect(verdict.reasons).toContain("To check the version tagged `next`: apm explain pre-only@next");

    const score = await apm(["score", "pre-only"], { cwd });

    expect(score.code).toBe(1);
    expect(score.text).toContain("apm: pre-only has no version tagged latest. Its versions are tagged next (0.0.1-test.1)");
    expect(score.text).toContain("To score the version tagged next: apm score pre-only@next");
    // a tag with a terminal control in it is publisher text apm does not print
    expect(add.text).not.toContain("bad");
  });

  test("D1, D3: apm name says what the registry will do with a bare name, another scope and an uppercase name", async () => {
    const cwd = folder("d1");
    const bare = await apm(["name", "my-lib"], { cwd });

    expect(bare.code).toBe(0);
    expect(bare.text).toContain("! my-lib is free but not available: apm does not hand out bare names, so a new package goes under your GitHub login. Instead, use @<your GitHub login>/my-lib (run apm login, then apm name to check it)");

    const signedIn = await apm(["name", "my-lib"], { cwd, token: true });

    expect(signedIn.text).toContain("Instead, @me/my-lib is free");

    // a registry whose rules for new names apm cannot read: the name is never called available
    const unknown = await apm(["name", "no-policy-lib"], { cwd, registry: `${server.url.toString()}no-policy/` });

    expect(unknown.text).toContain("is free, but apm could not read this registry's rules for new names");

    // the open policy hands out bare names, but a scope is still its owner's
    const open = `${server.url.toString()}open/`;

    expect((await apm(["name", "open-lib"], { cwd, registry: open })).text).toContain("✓ open-lib is available");
    expect((await apm(["name", "@other/open-lib"], { cwd, token: true, registry: open })).text).toContain("only the owner of @other can publish there");

    const signedOut = await apm(["name", "@other/my-lib"], { cwd });

    expect(signedOut.text).toContain("! @other/my-lib is free, but only the owner of @other can publish there. Run apm login, then ask again to see whether that is you");

    const other = await apm(["name", "@other/my-lib"], { cwd, token: true });

    expect(other.text).toContain("! @other/my-lib is free but not available to you: only the owner of @other can publish there. Yours is @me; instead, @me/my-lib is free");

    const mine = await apm(["name", "@me/my-lib"], { cwd, token: true });

    expect(mine.text).toContain("✓ @me/my-lib is available");

    const upper = await apm(["name", "@me/My-Lib"], { cwd, token: true });

    expect(upper.code).toBe(0);
    expect(upper.text).toContain("✗ @me/My-Lib is not a valid name for a new package: npm names are lowercase. Try @me/my-lib: apm name @me/my-lib");
    expect(upper.text).not.toContain("is available");
  });

  test("C10: a known malicious version leads with the refusal, not its grade", async () => {
    const cwd = folder("c10", { "package.json": manifest });
    const r = await apm(["add", "lodahs", "--pm", "npm"], { cwd });
    const lines = r.text.split("\n");

    expect(r.code).toBe(1);
    expect(lines[0]).toBe(`✗ lodahs@0.0.1-security  refused: ${MALICIOUS}`);
    expect(lines[1]).toBe("  its score, 80/100 (B), does not count: apm refuses it whatever it scores");
    expect(r.text).not.toContain("score 80/100 (B)");

    // an owner's yank reason is not apm's word that a version is malicious: the card stays as it was
    const yanked = await apm(["add", "yanked-pkg", "--pm", "npm"], { cwd });

    expect(yanked.text.split("\n")[0]).toBe("✗ yanked-pkg@0.0.1-security  score 80/100 (B)");
  });

  test("D2: apm publish --dry-run without a login says the real publish needs apm login", async () => {
    const cwd = folder("d2", { "package.json": JSON.stringify({ name: "@me/pkg", version: "1.0.0", files: ["index.js"] }), "index.js": "module.exports = 1;\n" });
    const r = await apm(["publish", "--dry-run", "--pm", "npm"], { cwd });

    expect(r.text).toContain(`apm: apm found no login token for ${server.url.toString()}; unless you have other publishing credentials for it, log in before the real publish (apm login, if it is an apm registry)`);

    // a real publish is not told it lacks a login before anything has failed: the package manager may have its own
    const real = await apm(["publish", "--pm", "npm"], { cwd });

    expect(real.text).not.toContain("found no login token");
  });
});
