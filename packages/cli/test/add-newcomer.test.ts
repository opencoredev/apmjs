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
  packages: z.array(z.object({ name: z.string(), blocked: z.boolean(), reason: z.string().nullable(), warnings: z.array(z.object({ kind: z.string(), name: z.string(), version: z.string(), text: z.string(), reasons: z.array(z.string()), via: z.array(z.string()) }).loose()) }).loose()),
});

/** The registry's answer for name@range: a scored version, fresh or not, or nothing in range. */
function resolveAnswer(name: string, range: string): Response {
  const report = (score: number, signals: unknown[]) => ({ scorer: "apm-score-v11", coverage: { kind: "complete" }, score, grade: score >= 75 ? "A" : "F", signals });

  const ok = (version: string, score: number, signals: unknown[], fresh: boolean) =>
    Response.json({
      name,
      range,
      source: "upstream",
      version,
      report: report(score, signals),
      skipped: [],
      tree: { unchecked: 0, uncheckedDeps: [], packages: [], projectPeers: [], risks: [], reviews: { kind: "off" } },
      warnings: fresh ? [{ name, version, kind: "cooldown", score, grade: "A", text: "published 2h ago, inside apm's 24-hour cooldown", reasons: [], url: "", via: [] }] : [],
    });

  const none = () => Response.json({ error: `No version of ${name} matching ${range} passes the policy.`, name, range, version: null, skipped: [] }, { status: 422 });

  switch (name) {
    case "loadsh":
    case "noreview":
      return ok("1.0.0", 75, [typosquat], false);
    case "lowscore":
      return ok("1.0.0", 30, [], false);
    case "fresh":
      // an exact pin of the only version, inside the cooldown: nothing older to pick
      return range.startsWith("<") || range.includes(" <") ? none() : ok("1.0.0", 95, [], true);
    case "fresh-older":
      // the newest is inside the cooldown; the one before it is past it and clean
      return range.includes("<2.0.0") ? ok("1.0.0", 95, [], false) : ok("2.0.0", 95, [], true);
    case "fresh-risky":
      // the newest, inside the cooldown, is the look-alike; the older one past it is clean
      return range.includes("<2.0.0") ? ok("1.0.0", 95, [], false) : ok("2.0.0", 75, [typosquat], true);
    case "older-risky":
      // the newest, inside the cooldown, is clean; the older one past it is the look-alike
      return range.includes("<2.0.0") ? ok("1.0.0", 75, [typosquat], false) : ok("2.0.0", 95, [], true);
    default:
      return ok("1.0.0", 95, [], false);
  }
}

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
      writeFileSync(join(bin, pm), `#!/bin/sh\n[ "$1" = --version ] && echo 4.5.0 && exit 0\necho ${pm} "$@" >> "$RAN_LOG"\nexit 7\n`);
      chmodSync(join(bin, pm), 0o755);
    }

    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);

        if (url.pathname === "/-/apm/v1/resolve") return resolveAnswer(url.searchParams.get("name") ?? "", url.searchParams.get("range") ?? "latest");

        if (url.pathname.startsWith("/-/apm/v1/review/noreview/")) return Response.json({ error: "unavailable" }, { status: 503 });

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

  /** The environment apm runs with here: APM_REGISTRY and APM_STRICT only when a test asks for them. */
  type AddEnv = { PATH: string; TMPDIR: string; HOME: string; NO_COLOR: string; APM_TOKEN: string; RAN_LOG: string; APM_REGISTRY?: string; APM_STRICT?: string };

  /** apm in `cwd`; `registry: "npmrc"` leaves APM_REGISTRY unset, so the project's .npmrc names the registry. */
  async function apm(args: string[], opts: { cwd: string; path?: string; strictEnv?: true; registry?: "npmrc" }): Promise<{ code: number; out: string; text: string }> {
    rmSync(join(root, "ran.log"), { force: true });
    const env: AddEnv = { PATH: opts.path ?? `${bin}:/usr/bin:/bin`, TMPDIR: root, HOME: folder(`home-${crypto.randomUUID()}`), NO_COLOR: "1", APM_TOKEN: "", RAN_LOG: join(root, "ran.log") };

    if (opts.registry !== "npmrc") env.APM_REGISTRY = server.url.toString();

    if (opts.strictEnv) env.APM_STRICT = "1";
    const proc = Bun.spawn([process.execPath, join(import.meta.dir, "..", "src", "main.ts"), ...args], { cwd: opts.cwd, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    return { code, out, text: out + err };
  }

  const kinds = (out: string): string[] => AddJson.parse(JSON.parse(out)).packages.flatMap((p) => p.warnings.map((w) => w.kind));

  test("a package apm explain calls review-first is a warning in --json, and the add goes on without --strict", async () => {
    const cwd = folder("rf-default", { "package.json": manifest });
    const r = await apm(["add", "loadsh", "--pm", "npm", "--json"], { cwd });
    const [pkg] = AddJson.parse(JSON.parse(r.out)).packages;

    expect(pkg?.blocked).toBe(false);
    expect(pkg?.warnings).toEqual([
      {
        kind: "review-first",
        name: "loadsh",
        version: "1.0.0",
        score: 75,
        grade: "A",
        text: "Review loadsh@1.0.0 before installing: apm found a risk signal in it: Name looks like a popular package's. It passes apm's install policy and scores 75/100 (A). No AI review: this registry runs none.",
        reasons: ["Name looks like a popular package's (-20 points).", "This registry runs no AI review."],
        url: null,
        via: [],
      },
    ]);
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
    expect(kinds(r.out)).toEqual(["review-first"]);
    expect(r.text).toContain("refused: loadsh@1.0.0: strict mode refuses what apm explain calls review-first");
    expect(r.text).toContain("Nothing was changed. apm explain says why:\n  apm explain loadsh@1.0.0\nTo install with a warning instead, run apm add without --strict.");
    expect(r.text).not.toContain("--force does not help");
    expect(ran()).toBe("");
    expect(readFileSync(join(cwd, "package.json"), "utf8")).toBe(manifest);
    expect(existsSync(join(cwd, "package-lock.json"))).toBe(false);
  });

  test("APM_STRICT=1 refuses it the same way and says to unset it; a package explain would install is not held", async () => {
    const cwd = folder("rf-clean", { "package.json": manifest });
    const held = await apm(["add", "--json", "loadsh", "--pm", "npm"], { cwd, strictEnv: true });

    expect(held.code).toBe(1);
    expect(AddJson.parse(JSON.parse(held.out)).ok).toBe(false);
    expect(held.text).toContain("run apm add with APM_STRICT unset and without --strict");
    expect(ran()).toBe("");

    const clean = await apm(["add", "--strict", "--json", "good", "--pm", "npm"], { cwd });

    expect(kinds(clean.out)).toEqual([]);
    expect(clean.text).not.toContain("review-first");
    expect(ran()).toContain("npm install --package-lock-only");
  });

  test("the floor the add asks for is the one explain weighs: --force and --floor lift a low score, the default holds it", async () => {
    const cwd = folder("rf-floor", { "package.json": manifest });
    const held = await apm(["add", "--strict", "--json", "lowscore", "--pm", "npm"], { cwd });

    expect(held.code).toBe(1);
    expect(AddJson.parse(JSON.parse(held.out)).packages[0]?.warnings[0]?.text).toContain("under apm's floor of 40");

    for (const flags of [["--force"], ["--floor", "20"]]) {
      const r = await apm(["add", "--strict", "--json", ...flags, "lowscore", "--pm", "npm"], { cwd });

      expect(kinds(r.out), flags.join(" ")).toEqual([]);
      expect(ran()).toContain("npm install --package-lock-only");
    }
  });

  test("a fresh version with nothing older in range is review-first as in explain; one with an older clean version is not", async () => {
    const cwd = folder("rf-fresh", { "package.json": manifest });
    const pinned = await apm(["add", "--json", "fresh@1.0.0", "--pm", "npm"], { cwd });

    expect(kinds(pinned.out)).toEqual(["cooldown", "review-first"]);
    expect(pinned.text).toContain("it was published inside apm's 24-hour cooldown and no older version in range is past it");

    const older = await apm(["add", "--json", "fresh-older", "--pm", "npm"], { cwd });

    expect(kinds(older.out)).toEqual(["cooldown"]);
  });

  test("the verdict is always on the version apm add installs, never on the older one explain would pick", async () => {
    const cwd = folder("rf-which", { "package.json": manifest });
    const risky = await apm(["add", "--json", "fresh-risky", "--pm", "npm"], { cwd });
    const [pkg] = AddJson.parse(JSON.parse(risky.out)).packages;

    expect(pkg?.warnings.map((w) => `${w.kind} ${w.version}`)).toEqual(["cooldown 2.0.0", "review-first 2.0.0"]);
    expect(pkg?.warnings[1]?.text).toStartWith("Review fresh-risky@2.0.0 before installing: apm found a risk signal in it");
    expect(ran()).toContain("fresh-risky@2.0.0");

    const clean = await apm(["add", "--json", "older-risky", "--pm", "npm"], { cwd });

    expect(kinds(clean.out)).toEqual(["cooldown"]);
    expect(ran()).toContain("older-risky@2.0.0");
  });

  test("an AI review apm cannot read leaves explain at unknown: the add's own checks decide, as before", async () => {
    const cwd = folder("rf-unknown", { "package.json": manifest });
    const strict = await apm(["add", "--strict", "--json", "noreview", "--pm", "npm"], { cwd });

    expect(kinds(strict.out)).toEqual([]);
    expect(ran()).toContain("npm install --package-lock-only");
  });

  const git = (args: string[], cwd: string): void => void Bun.spawnSync(["git", ...args], { cwd, stdout: "ignore", stderr: "ignore" });

  test("a gitignored .npmrc that apm takes the registry from gets one warning; tracked, shadowed or no repository gets none", async () => {
    const npmrc = `registry=${server.url.toString()}\n`;
    // the test root's .git is an empty folder, not a repository: git says it is not a work tree, and apm says nothing
    const notRepo = folder("gi/not-a-repo", { "package.json": manifest, ".npmrc": npmrc, ".gitignore": ".npmrc\n" });
    const outside = await apm(["add", "good", "--pm", "npm"], { cwd: notRepo, registry: "npmrc" });

    expect(outside.text).not.toContain("git ignores");
    expect(outside.text).toContain("npm install --package-lock-only");

    const repo = folder("gi/repo", { "package.json": manifest, ".npmrc": npmrc, ".gitignore": ".npmrc\n" });

    git(["init", "-q"], repo);
    const ignored = await apm(["add", "good", "--pm", "npm"], { cwd: repo, registry: "npmrc" });

    expect(ignored.text).toContain("apm: git ignores .npmrc, which points installs at apm's registry, so clones and CI will not install through apm until it is committed (keep any token out of it)");

    // APM_REGISTRY names the registry: the .npmrc is not what this add relies on
    expect((await apm(["add", "good", "--pm", "npm"], { cwd: repo })).text).not.toContain("git ignores");

    // without git on PATH, apm says nothing about it and goes on
    const noGit = await apm(["add", "good", "--pm", "npm"], { cwd: repo, path: bin, registry: "npmrc" });

    expect(noGit.text).not.toContain("git ignores");
    expect(noGit.text).toContain("npm install --package-lock-only");

    // a git that cannot start is no git
    const broken = folder("gi/broken-bin");

    writeFileSync(join(broken, "git"), "#!/no/such/interpreter\n");
    chmodSync(join(broken, "git"), 0o755);
    const brokenGit = await apm(["add", "good", "--pm", "npm"], { cwd: repo, path: `${broken}:${bin}`, registry: "npmrc" });

    expect(brokenGit.text).not.toContain("git ignores");
    expect(brokenGit.text).toContain("npm install --package-lock-only");

    // a committed .npmrc is tracked, so git does not report it as ignored
    git(["add", "-f", ".npmrc"], repo);
    expect((await apm(["add", "good", "--pm", "npm"], { cwd: repo, registry: "npmrc" })).text).not.toContain("git ignores");
  });

  test("an ignored .npmrc above a nested project, where apm takes the registry from, is named by its path", async () => {
    const top = folder("gi/parent", { ".npmrc": `registry=${server.url.toString()}\n`, ".gitignore": ".npmrc\n" });
    const nested = folder("gi/parent/apps/web", { "package.json": manifest });

    git(["init", "-q"], top);
    const r = await apm(["add", "good", "--pm", "npm"], { cwd: nested, registry: "npmrc" });

    expect(r.text).toContain(`apm: git ignores ${join("..", "..", ".npmrc")}, which points installs at apm's registry`);
  });

  test("a gitignored bunfig.toml or .yarnrc.yml with apm's registry is named only for the package manager that reads it", async () => {
    const registry = server.url.toString();
    const repo = folder("gi/native", { "package.json": JSON.stringify({ name: "app", version: "1.0.0", private: true, packageManager: "yarn@4.5.0" }), "bunfig.toml": `[install]\nregistry = "${registry}"\n`, ".yarnrc.yml": `npmRegistryServer: "${registry}"\n`, ".gitignore": "bunfig.toml\n.yarnrc.yml\n" });

    git(["init", "-q"], repo);
    const bun = await apm(["add", "good", "--pm", "bun"], { cwd: repo });

    expect(bun.text).toContain("apm: git ignores bunfig.toml,");
    expect(bun.text).not.toContain(".yarnrc.yml");

    const yarn = await apm(["add", "good", "--pm", "yarn"], { cwd: repo });

    expect(yarn.text).toContain("apm: git ignores .yarnrc.yml,");
    expect(yarn.text).not.toContain("git ignores bunfig.toml");

    expect((await apm(["add", "good", "--pm", "npm"], { cwd: repo })).text).not.toContain("git ignores");

    // yarn 1 does not read .yarnrc.yml: with yarn 1's lockfile and no packageManager, no word about it
    const classic = folder("gi/yarn-classic", { "package.json": manifest, "yarn.lock": "# yarn lockfile v1\n", ".yarnrc.yml": `npmRegistryServer: "${registry}"\n`, ".gitignore": ".yarnrc.yml\n" });

    git(["init", "-q"], classic);
    expect((await apm(["add", "good", "--pm", "yarn"], { cwd: classic })).text).not.toContain("git ignores");

    // a yarnPath in .yarnrc.yml is yarn 2 or later, lockfile or not
    const berry = folder("gi/yarn-path", { "package.json": manifest, ".yarnrc.yml": `yarnPath: .yarn/releases/yarn-4.5.0.cjs\nnpmRegistryServer: "${registry}"\n`, ".gitignore": ".yarnrc.yml\n" });

    git(["init", "-q"], berry);
    expect((await apm(["add", "good", "--pm", "yarn"], { cwd: berry })).text).toContain("apm: git ignores .yarnrc.yml,");
  });

  test("a bun workspace member's own gitignored bunfig.toml is named", async () => {
    const registry = server.url.toString();
    const repo = folder("gi/bun-ws", { "package.json": JSON.stringify({ name: "ws", private: true, workspaces: ["packages/*"] }), ".gitignore": "bunfig.toml\n" });
    const member = folder("gi/bun-ws/packages/app", { "package.json": manifest, "bunfig.toml": `[install]\nregistry = "${registry}"\n` });

    git(["init", "-q"], repo);
    const r = await apm(["add", "good", "--pm", "bun"], { cwd: member });

    expect(r.text).toContain("apm: git ignores bunfig.toml,");
  });

  test("an npm init -y project still gets bun when it is installed (held for launch), and the reason says how to use npm", async () => {
    const cwd = folder("pm/npm-init", { "package.json": manifest });
    const r = await apm(["add", "good"], { cwd });

    expect(r.text).toContain("(bun: default (bun is installed; no lockfile or packageManager names another, so pass --pm npm to use npm);");
  });
});

describe("detectPm", () => {
  let root: string;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "apm-detect-pm-"));
    mkdirSync(join(root, ".git"));
  });

  afterAll(() => rmSync(root, { recursive: true, force: true }));

  test("lockfiles, packageManager and --pm still win over the default", () => {
    const project = (name: string, files: Record<string, string>): string => {
      const dir = join(root, name);

      mkdirSync(dir);

      for (const [file, text] of Object.entries(files)) writeFileSync(join(dir, file), text);

      return dir;
    };

    const manifest = JSON.stringify({ name: "app", version: "1.0.0" });

    expect(detectPm(project("npm-lock", { "package.json": manifest, "package-lock.json": "{}" }), null)).toEqual({ pm: "npm", why: "package-lock.json" });
    expect(detectPm(project("yarn-field", { "package.json": JSON.stringify({ name: "app", packageManager: "yarn@4.0.0" }) }), null).pm).toBe("yarn");
    expect(detectPm(project("flag", { "package.json": manifest }), "npm")).toEqual({ pm: "npm", why: "--pm flag" });
  });
});
