// apm add for a newcomer (HOME-638): a look-alike that apm explain calls review-first was installed with "ok": true and no
// warnings even under --strict; a gitignored .npmrc left clones and CI on npm without a word; an `npm init -y` project
// got bun. Against a stand-in registry and stand-in package managers that record their runs and fail at once.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { detectPm } from "../src/pm.ts";

const typosquat = { id: "typosquat", label: "Name looks like a popular package's", points: -20, evidence: ['one edit away from "lodash"'], confidence: "confirmed" };

const AddJson = z.object({
  ok: z.boolean(),
  pm: z.string(),
  packages: z.array(z.object({ name: z.string(), blocked: z.boolean(), reason: z.string().nullable(), warnings: z.array(z.object({ kind: z.string(), name: z.string(), version: z.string(), text: z.string() }).loose()) }).loose()),
});

describe("apm add for a newcomer", () => {
  let server: ReturnType<typeof Bun.serve>;
  let root: string;
  let bin: string;
  const ran = (): string => (existsSync(join(root, "ran.log")) ? readFileSync(join(root, "ran.log"), "utf8") : "");

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "apm-add-newcomer-"));
    // a .git at the root keeps every lookup upward (lockfile, packageManager, bunfig) inside the test's folders
    mkdirSync(join(root, ".git"));
    bin = join(root, "bin");
    mkdirSync(bin);

    for (const pm of ["npm", "pnpm", "bun", "yarn"]) {
      writeFileSync(join(bin, pm), `#!/bin/sh\necho ${pm} "$@" >> "$RAN_LOG"\nexit 7\n`);
      chmodSync(join(bin, pm), 0o755);
    }

    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);

        if (url.pathname === "/-/apm/v1/resolve") {
          const name = url.searchParams.get("name") ?? "";
          const report = { scorer: "apm-score-v11", coverage: { kind: "complete" }, score: name === "loadsh" ? 75 : 95, grade: name === "loadsh" ? "B" : "A", signals: name === "loadsh" ? [typosquat] : [] };

          return Response.json({ name, range: "latest", source: "upstream", version: "1.0.0", report, skipped: [], tree: { unchecked: 0, uncheckedDeps: [], packages: [], projectPeers: [], risks: [], reviews: { kind: "off" } }, warnings: [] });
        }

        return Response.json({ error: "Not found" }, { status: 404 });
      },
    });
  });

  afterAll(() => {
    server.stop(true);
    rmSync(root, { recursive: true, force: true });
  });

  function folder(path: string, files: Record<string, string> = {}): string {
    const dir = join(root, path);

    mkdirSync(dir, { recursive: true });

    for (const [file, text] of Object.entries(files)) writeFileSync(join(dir, file), text);

    return dir;
  }

  const manifest = JSON.stringify({ name: "app", version: "1.0.0", private: true });

  async function apm(args: string[], opts: { cwd: string; path?: string; strictEnv?: true }): Promise<{ code: number; out: string; text: string }> {
    rmSync(join(root, "ran.log"), { force: true });
    const env = { ...(opts.strictEnv ? { APM_STRICT: "1" } : {}), PATH: opts.path ?? `${bin}:/usr/bin:/bin`, TMPDIR: root, HOME: folder(`home-${crypto.randomUUID()}`), APM_REGISTRY: server.url.toString(), NO_COLOR: "1", APM_TOKEN: "", RAN_LOG: join(root, "ran.log") };
    const proc = Bun.spawn([process.execPath, join(import.meta.dir, "..", "src", "main.ts"), ...args], { cwd: opts.cwd, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    return { code, out, text: out + err };
  }

  test("a package apm explain calls review-first is a warning in --json, and the add goes on without --strict", async () => {
    const cwd = folder("rf-default", { "package.json": manifest });
    const r = await apm(["add", "loadsh", "--pm", "npm", "--json"], { cwd });
    const doc = AddJson.parse(JSON.parse(r.out));
    const [pkg] = doc.packages;

    expect(pkg?.blocked).toBe(false);
    expect(pkg?.warnings.map((w) => w.kind)).toEqual(["review-first"]);
    expect(pkg?.warnings[0]?.text).toContain("Review loadsh@1.0.0 before installing: apm found a risk signal in it: Name looks like a popular package's");
    expect(r.text).toContain("apm explain calls loadsh@1.0.0 review-first, and apm add installs it anyway. To refuse it instead, run with --strict");
    // the package manager was started (and failed, as the stand-in does): the add went ahead
    expect(ran()).toContain("npm install --package-lock-only");
    expect(r.code).toBe(7);
  });

  test("--strict refuses a review-first package before anything runs: exit 1, ok false, nothing changed", async () => {
    const cwd = folder("rf-strict", { "package.json": manifest });
    const r = await apm(["add", "--strict", "--json", "loadsh", "--pm", "npm"], { cwd });
    const doc = AddJson.parse(JSON.parse(r.out));
    const [pkg] = doc.packages;

    expect(r.code).toBe(1);
    expect(doc.ok).toBe(false);
    expect(pkg?.blocked).toBe(true);
    expect(pkg?.reason).toBe("loadsh@1.0.0: strict mode refuses what apm explain calls review-first");
    expect(pkg?.warnings.map((w) => w.kind)).toEqual(["review-first"]);
    expect(r.text).toContain("refused: loadsh@1.0.0: strict mode refuses what apm explain calls review-first");
    expect(r.text).toContain("apm explain loadsh says why; to install with a warning instead, run apm add without --strict.");
    expect(r.text).not.toContain("--force does not help");
    expect(ran()).toBe("");
    expect(readFileSync(join(cwd, "package.json"), "utf8")).toBe(manifest);
    expect(existsSync(join(cwd, "package-lock.json"))).toBe(false);
  });

  test("APM_STRICT=1 refuses it the same way, and a package explain would install is not held", async () => {
    const cwd = folder("rf-clean", { "package.json": manifest });
    const held = await apm(["add", "--json", "loadsh", "--pm", "npm"], { cwd, strictEnv: true });

    expect(held.code).toBe(1);
    expect(AddJson.parse(JSON.parse(held.out)).ok).toBe(false);
    expect(ran()).toBe("");

    const clean = await apm(["add", "--strict", "--json", "good", "--pm", "npm"], { cwd });
    const [pkg] = AddJson.parse(JSON.parse(clean.out)).packages;

    expect(pkg?.blocked).toBe(false);
    expect(pkg?.warnings).toEqual([]);
    expect(clean.text).not.toContain("review-first");
    expect(ran()).toContain("npm install --package-lock-only");
  });

  test("a gitignored .npmrc that points installs at apm gets one warning; a committed one, no repository or no git gets none", async () => {
    const npmrc = `registry=${server.url.toString()}\n`;
    // the test root's .git is an empty folder, not a repository: git check-ignore fails, and apm says nothing
    const notRepo = folder("gi/not-a-repo", { "package.json": manifest, ".npmrc": npmrc, ".gitignore": ".npmrc\n" });
    const outside = await apm(["add", "good", "--pm", "npm"], { cwd: notRepo });

    expect(outside.text).not.toContain("git ignores");
    expect(outside.text).toContain("npm install --package-lock-only");

    const repo = folder("gi/repo", { "package.json": manifest, ".npmrc": npmrc, ".gitignore": ".npmrc\n" });
    const git = (args: string[], cwd: string): void => void Bun.spawnSync(["git", ...args], { cwd, stdout: "ignore", stderr: "ignore" });

    rmSync(join(repo, ".git"), { recursive: true, force: true });
    git(["init", "-q"], repo);
    const ignored = await apm(["add", "good", "--pm", "npm"], { cwd: repo });

    expect(ignored.text).toContain("apm: git ignores .npmrc, which points installs at apm's registry, so clones and CI will not install through apm until it is committed (keep any token out of it)");

    // without git on PATH, apm says nothing about it and goes on
    const noGit = await apm(["add", "good", "--pm", "npm"], { cwd: repo, path: bin });

    expect(noGit.text).not.toContain("git ignores");
    expect(noGit.text).toContain("npm install --package-lock-only");

    // a committed .npmrc is tracked, so git does not report it as ignored
    git(["add", "-f", ".npmrc"], repo);
    const tracked = await apm(["add", "good", "--pm", "npm"], { cwd: repo });

    expect(tracked.text).not.toContain("git ignores");

    // another registry in an ignored .npmrc is not apm's to warn about
    const other = folder("gi/other", { "package.json": manifest, ".npmrc": "registry=https://registry.npmjs.org/\n", ".gitignore": ".npmrc\n" });

    git(["init", "-q"], other);
    expect((await apm(["add", "good", "--pm", "npm"], { cwd: other })).text).not.toContain("git ignores");
  });

  test("a gitignored bunfig.toml or .yarnrc.yml with apm's registry is named too", async () => {
    const registry = server.url.toString();
    const repo = folder("gi/bun", { "package.json": manifest, "bunfig.toml": `[install]\nregistry = "${registry}"\n`, ".yarnrc.yml": `npmRegistryServer: "${registry}"\n`, ".gitignore": "bunfig.toml\n.yarnrc.yml\n" });

    Bun.spawnSync(["git", "init", "-q"], { cwd: repo, stdout: "ignore", stderr: "ignore" });
    const r = await apm(["add", "good", "--pm", "npm"], { cwd: repo });

    expect(r.text).toContain("apm: git ignores bunfig.toml,");
    expect(r.text).toContain("apm: git ignores .yarnrc.yml,");
  });

  test("an npm init -y project (package.json, no lockfile, packageManager or bunfig) is added with npm, not bun", async () => {
    const cwd = folder("pm/npm-init", { "package.json": manifest });
    const r = await apm(["add", "good"], { cwd });

    expect(r.text).toContain("(npm: default for a project with no lockfile or packageManager;");
    expect(ran()).toStartWith("npm install --package-lock-only");
    expect(ran()).not.toContain("bun ");
  });
});

describe("detectPm", () => {
  let root: string;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "apm-detect-pm-"));
    mkdirSync(join(root, ".git"));
  });

  afterAll(() => rmSync(root, { recursive: true, force: true }));

  function project(name: string, files: Record<string, string>): string {
    const dir = join(root, name);

    mkdirSync(dir);

    for (const [file, text] of Object.entries(files)) writeFileSync(join(dir, file), text);

    return dir;
  }

  const manifest = JSON.stringify({ name: "app", version: "1.0.0" });

  test("a package.json alone means npm", () => {
    expect(detectPm(project("plain", { "package.json": manifest }), null).pm).toBe("npm");
  });

  test("bun.lock, bun.lockb, bunfig.toml and packageManager bun keep bun", () => {
    expect(detectPm(project("lock", { "package.json": manifest, "bun.lock": "{}" }), null)).toEqual({ pm: "bun", why: "bun.lock" });
    expect(detectPm(project("lockb", { "package.json": manifest, "bun.lockb": "" }), null)).toEqual({ pm: "bun", why: "bun.lockb" });
    expect(detectPm(project("bunfig", { "package.json": manifest, "bunfig.toml": "[install]\n" }), null)).toEqual({ pm: "bun", why: "bunfig.toml" });
    expect(detectPm(project("field", { "package.json": JSON.stringify({ name: "app", packageManager: "bun@1.4.4" }) }), null).pm).toBe("bun");
  });

  test("another lockfile, packageManager and --pm still win", () => {
    expect(detectPm(project("pnpm", { "package.json": manifest, "pnpm-lock.yaml": "", "bunfig.toml": "" }), null).pm).toBe("pnpm");
    expect(detectPm(project("yarn-field", { "package.json": JSON.stringify({ name: "app", packageManager: "yarn@4.0.0" }), "bunfig.toml": "" }), null).pm).toBe("yarn");
    expect(detectPm(project("flag", { "package.json": manifest }), "bun")).toEqual({ pm: "bun", why: "--pm flag" });
  });
});
