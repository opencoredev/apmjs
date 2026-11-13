// Spec (review of a2227d1): apm add and apm x are lockfile first. The package manager computes the add's lockfile in a
// directory of apm's own, apm checks every package of it at its exact version and integrity, and a refusal ends there:
// the project's package.json, lockfile and node_modules are byte-identical afterwards, whatever the project looked like
// (dirty, a workspace, no lockfile, an upgrade). Only a lockfile that passes is written back, installed with every
// script held back, verified, and then has its install scripts run, for the packages it installed.
//
// Real npm, pnpm and bun against the real registry. The registry's resolve walk predicts leaf@1.1.0 (old, clean); the
// package managers keep or pin leaf@1.0.0, published an hour ago. Payloads are inert: install scripts write a marker.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { treeHash } from "../../packages/cli/test/fixtures/tree-hash.ts";
import { addUser, apm, getJson, makeSandbox, run, startRegistry, writePackage, writeProjectConfig, type Registry } from "./harness";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const PASSWORD = "correct-horse-battery";
let clock = Date.parse("2026-10-01T00:00:00Z");
let reg: Registry;
let alice: string;
let work: string;

type Pm = "npm" | "pnpm" | "bun";

const PMS: readonly Pm[] = ["npm", "pnpm", "bun"];

async function publish(spec: Parameters<typeof writePackage>[1]): Promise<void> {
  const sb = makeSandbox(reg, alice);
  const d = writePackage(work, spec, reg, alice);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });

  if (r.code !== 0) throw new Error(`publish ${spec.name}@${spec.version}: ${r.out}`);
}

/** A package whose install script leaves a marker named `mark`, so a test can tell which scripts ran. */
const marked = (mark: string, files: Record<string, string> = {}) => ({ scripts: { postinstall: "node mark.js" }, files: { "index.js": "module.exports = 1;\n", "mark.js": `require('fs').writeFileSync(require('path').join(process.env.APM_TEST_MARKS, '${mark}'), 'ran');\n`, ...files } });

/** Every package with an install script: trusted (bun) and allowed to build (pnpm 10), so a test sees each script that runs. */
const BUILT = ["transitive-root", "rtransitive-root", "peer-root", "override-root", "unlocked-plugin", "up", "nest-old", "nest-new", "nleaf", "ws-root"];

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice", PASSWORD);
  work = mkdtempSync(join(tmpdir(), "apm-lockfirst-"));

  // old and clean: what the walk predicts
  for (const prefix of ["", "r"]) {
    await publish({ name: `${prefix}leaf`, version: "1.1.0" });
    await publish({ name: `${prefix}transitive-root`, version: "1.0.0", dependencies: { [`${prefix}leaf`]: "^1.0.0" }, ...marked(`${prefix}transitive-root`) });
  }

  await publish({ name: "plugin", version: "1.0.0", extra: { peerDependencies: { leaf: "^1.0.0" } } });
  await publish({ name: "peer-root", version: "1.0.0", dependencies: { plugin: "1.0.0" }, ...marked("peer-root") });
  await publish({ name: "override-root", version: "1.0.0", dependencies: { leaf: "^1.0.0" }, ...marked("override-root") });
  await publish({ name: "otherhost", version: "2.0.0" });
  await publish({ name: "unlocked-plugin", version: "1.0.0", extra: { peerDependencies: { otherhost: ">=1.0.0" } }, ...marked("unlocked-plugin") });
  // an upgrade: up@1.0.0 needs nothing, up@2.0.0 needs leaf ^1.0.0 (which the project's lockfile holds at the fresh 1.0.0)
  await publish({ name: "up", version: "1.0.0", ...marked("up1") });
  await publish({ name: "up", version: "2.0.0", dependencies: { leaf: "^1.0.0" }, ...marked("up2") });
  // nested versions: nest-old keeps nleaf@1.0.0 at the top, nest-new brings nleaf@2.0.0 nested under it
  await publish({ name: "nleaf", version: "1.0.0", ...marked("nleaf1") });
  await publish({ name: "nleaf", version: "2.0.0", ...marked("nleaf2") });
  await publish({ name: "nest-old", version: "1.0.0", dependencies: { nleaf: "^1.0.0" } });
  await publish({ name: "nest-new", version: "1.0.0", dependencies: { nleaf: "^2.0.0" }, ...marked("nest-new") });
  // apm x: a tool whose binary runs its dependency's binary, found on PATH
  await publish({ name: "helper-bin", version: "1.0.0", extra: { bin: { "helper-say": "say.js" } }, files: { "index.js": "module.exports = 1;\n", "say.js": "#!/usr/bin/env node\nconsole.log('helper says ' + process.argv.slice(2).join(' '));\n" } });
  // a project's devDependency, and a package it shares with the production graph
  await publish({ name: "devtool", version: "1.0.0", dependencies: { nleaf: "^1.0.0" } });
  await publish({ name: "xtool", version: "1.0.0", dependencies: { "helper-bin": "1.0.0" }, extra: { bin: { xtool: "cli.js" } }, files: { "index.js": "module.exports = 1;\n", "cli.js": "#!/usr/bin/env node\nrequire('child_process').execFileSync('helper-say', process.argv.slice(2), { stdio: 'inherit' });\n" } });
  clock += 10 * DAY;
  // an hour old: inside the 24-hour cooldown, and what the package managers below install
  await publish({ name: "leaf", version: "1.0.0" });
  await publish({ name: "existing", version: "1.0.0", dependencies: { leaf: "1.0.0" } });
  await publish({ name: "otherhost", version: "1.0.0" });
  await publish({ name: "rleaf", version: "1.0.0" });
  await publish({ name: "rexisting", version: "1.0.0", dependencies: { rleaf: "1.0.0" } });
  clock += HOUR;
});

afterAll(async () => {
  await reg?.stop();
});

const LOCKFILE: Record<Pm, string> = { npm: "package-lock.json", pnpm: "pnpm-lock.yaml", bun: "bun.lock" };

const Json = z.object({
  ok: z.boolean(),
  installed: z
    .object({ checked: z.number(), refused: z.boolean(), touched: z.boolean(), stage: z.string(), blocked: z.array(z.object({ name: z.string(), version: z.string() })), warnings: z.array(z.object({ name: z.string(), version: z.string(), kind: z.string() })) })
    .nullish(),
});

type Project = { root: string; app: string; env: Record<string, string>; marks: string; read: (file: string) => string | null; hash: () => ReturnType<typeof treeHash> };

/** package.json fields a test project sets besides its dependencies. */
type ProjectFields = { overrides?: Record<string, string>; resolutions?: Record<string, string>; pnpm?: { overrides: Record<string, string> }; dirty?: boolean; devDependencies?: Record<string, string> };

/**
 * A project with `deps`, installed by `pm` itself when `install` is set (scripts on, then the markers cleared, so a test
 * sees only what apm runs). `workspace`: the project is packages/app in a workspace whose root holds the lockfile.
 */
async function project(input: { pm: Pm; deps: Record<string, string>; extra?: ProjectFields; install: boolean; workspace?: boolean }): Promise<Project> {
  const sb = makeSandbox(reg, alice);
  const root = mkdtempSync(join(work, "app-"));
  const app = input.workspace ? join(root, "packages", "app") : root;
  const marks = mkdtempSync(join(work, "marks-"));
  const env = { ...sb.env, APM_TEST_MARKS: marks, npm_config_store_dir: join(sb.home, ".pnpm-store"), TMPDIR: tmpdir() };
  const trust = { trustedDependencies: BUILT, pnpm: { onlyBuiltDependencies: BUILT, ...input.extra?.pnpm } };

  mkdirSync(app, { recursive: true });
  writeProjectConfig(root, reg, alice);

  if (input.workspace) {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "ws-top", version: "1.0.0", private: true, workspaces: ["packages/*"], ...trust }, null, 2));
    writeFileSync(join(root, "pnpm-workspace.yaml"), `packages:\n  - packages/*\nonlyBuiltDependencies:\n${BUILT.map((b) => `  - ${b}`).join("\n")}\n`);
    mkdirSync(join(root, "packages", "other"), { recursive: true });
    writeFileSync(join(root, "packages", "other", "package.json"), JSON.stringify({ name: "other-member", version: "1.0.0", dependencies: { "nest-old": "1.0.0" } }, null, 2));
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "app-member", version: "1.0.0", dependencies: input.deps }, null, 2));
  } else {
    const { dirty: _dirty, ...extra } = input.extra ?? {};

    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "consumer-app", version: "1.0.0", private: true, dependencies: input.deps, ...trust, ...extra, pnpm: trust.pnpm }, null, 2));
  }

  if (input.install) {
    const r = await run([input.pm, "install"], { cwd: root, env });

    if (r.code !== 0) throw new Error(`${input.pm} install: ${r.out}`);

    for (const m of readdirSync(marks)) rmSync(join(marks, m));
  }

  const read = (f: string): string | null => (existsSync(join(root, f)) ? readFileSync(join(root, f), "utf8") : null);

  return { root, app, env, marks, read, hash: () => treeHash(root) };
}

/** apm add from the project's directory, its JSON answer, and which install scripts ran. */
async function add(p: Project, args: string[]) {
  const r = await apm(["add", ...args, "--json"], { cwd: p.app, env: p.env, timeoutMs: 120_000 });
  let json: z.infer<typeof Json>;

  try {
    json = Json.parse(JSON.parse(r.stdout));
  } catch {
    throw new Error(`no JSON answer:\n${r.out}`);
  }

  return { ...r, json, ran: readdirSync(p.marks).sort() };
}

/** A refused add: exit 1, no script, nothing written, and the whole project tree byte-identical. */
function expectUntouched(r: Awaited<ReturnType<typeof add>>, before: ReturnType<typeof treeHash>, after: ReturnType<typeof treeHash>): void {
  expect(r.code, r.out).toBe(1);
  expect(r.ran, r.out).toEqual([]);
  expect(r.json.installed?.touched ?? false, r.out).toBe(false);
  expect(after.lines, r.out).toEqual(before.lines);
  expect(after.hash).toBe(before.hash);
}

describe.each(PMS)("apm add with the real %s: a refusal leaves the project byte-identical", (pm) => {
  test("transitive lockfile pin: strict refuses the fresh leaf the lockfile keeps", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true });
    const before = p.hash();
    const r = await add(p, ["transitive-root", "--pm", pm, "--strict"]);

    expect(r.out).toContain("the early check read 1.1.0, the lockfile holds 1.0.0");
    expect(r.json.installed?.warnings.filter((w) => w.name === "leaf").map((w) => `${w.version}:${w.kind}`), r.out).toEqual(["1.0.0:cooldown"]);
    expect(r.out).toContain("before installing anything");
    expectUntouched(r, before, p.hash());
  });

  test("a dirty project with a patch in node_modules", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true });
    // a hand patch inside an installed package, and an edit to package.json nobody installed yet
    const leafDir = pm === "pnpm" ? join(p.root, "node_modules", ".pnpm", "leaf@1.0.0", "node_modules", "leaf") : join(p.root, "node_modules", "leaf");

    writeFileSync(join(leafDir, "index.js"), "module.exports = 'patched by hand';\n");
    const pkg = z.record(z.string(), z.unknown()).parse(JSON.parse(readFileSync(join(p.root, "package.json"), "utf8")));

    writeFileSync(join(p.root, "package.json"), JSON.stringify({ ...pkg, description: "edited, not installed" }, null, 2));
    const before = p.hash();
    const r = await add(p, ["transitive-root", "--pm", pm, "--strict"]);

    expectUntouched(r, before, p.hash());
    expect(readFileSync(join(leafDir, "index.js"), "utf8")).toBe("module.exports = 'patched by hand';\n");
  });

  test("a workspace: the add from packages/app checks the root lockfile and leaves every member as it was", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true, workspace: true });
    const before = p.hash();
    const r = await add(p, ["transitive-root", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toContain("leaf@1.0.0");
    expectUntouched(r, before, p.hash());
  });

  test("no lockfile: the check uses the otherhost@1.0.0 package.json pins, not the newest in range", async () => {
    const p = await project({ pm, deps: { otherhost: "1.0.0" }, install: false });
    const before = p.hash();
    const r = await add(p, ["unlocked-plugin", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toEqual(["otherhost@1.0.0"]);
    expectUntouched(r, before, p.hash());
    expect(p.read(LOCKFILE[pm])).toBeNull();
    expect(existsSync(join(p.root, "node_modules"))).toBe(false);
  });

  test("an existing dependency upgraded: up@1.0.0 stays, with its lockfile entry and its directory", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0", up: "1.0.0" }, install: true });
    const before = p.hash();
    const r = await add(p, ["up@2.0.0", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toContain("leaf@1.0.0");
    expectUntouched(r, before, p.hash());
  });

  test("overrides: strict refuses the leaf@1.0.0 the project's override installs", async () => {
    const extra = { overrides: { leaf: "1.0.0" }, resolutions: { leaf: "1.0.0" }, pnpm: { overrides: { leaf: "1.0.0" } } };
    const p = await project({ pm, deps: {}, extra, install: false });
    const before = p.hash();
    const r = await add(p, ["override-root", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toEqual(["leaf@1.0.0"]);
    expectUntouched(r, before, p.hash());
  });

  test("nested peer: strict refuses the fresh leaf that meets plugin's peer below peer-root", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true });
    const before = p.hash();
    const r = await add(p, ["peer-root", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toContain("leaf@1.0.0");
    expectUntouched(r, before, p.hash());
  });
});

describe.each(PMS)("apm add with the real %s: an add that passes", (pm) => {
  test("the default mode warns about leaf@1.0.0, writes the checked files, and runs only transitive-root's script", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true });
    const r = await add(p, ["transitive-root", "--pm", pm]);

    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/WARNING leaf@1\.0\.0 .*cooldown/);
    expect(r.json.installed?.stage).toBe("done");
    expect(r.json.installed?.touched).toBe(true);
    expect(r.ran, r.out).toEqual(["transitive-root"]);
    expect(p.read(LOCKFILE[pm])).toContain("transitive-root");
    expect(existsSync(join(p.root, "node_modules", "transitive-root", "package.json")), r.out).toBe(true);
  });

  test("nested nleaf@1.0.0 beside nleaf@2.0.0: scripts run for what this add installed, never the untouched nested copy", async () => {
    const p = await project({ pm, deps: { "nest-old": "1.0.0" }, install: true });
    const r = await add(p, ["nest-new", "--pm", pm]);

    expect(r.code, r.out).toBe(0);
    // every script that ran is a package of the checked lockfile, and the ones this add installed ran. npm and pnpm nest
    // nleaf@2.0.0 and leave nleaf@1.0.0 where it was, so its script does not run again; bun hoists nleaf@2.0.0 and moves
    // nleaf@1.0.0 under nest-old, a fresh copy whose script runs again (it is checked: it is in the lockfile)
    expect(r.ran, r.out).toEqual(pm === "bun" ? ["nest-new", "nleaf1", "nleaf2"] : ["nest-new", "nleaf2"]);
    expect(r.json.installed?.checked, r.out).toBe(4);
  });

  test("a workspace: the member's package.json and the root lockfile change, nothing else", async () => {
    const p = await project({ pm, deps: { "nest-old": "1.0.0" }, install: true, workspace: true });
    const top = p.read("package.json");
    const other = p.read("packages/other/package.json");
    const r = await add(p, ["nest-new", "--pm", pm]);

    expect(r.code, r.out).toBe(0);
    expect(p.read("packages/app/package.json")).toContain("nest-new");
    expect(p.read(LOCKFILE[pm])).toContain("nest-new");
    expect(p.read("package.json")).toBe(top);
    expect(p.read("packages/other/package.json")).toBe(other);
    // the workspace's own members, bound to their folders, names and versions, are the project's source: no warning
    expect(r.json.installed?.warnings.filter((w) => w.name === "other-member" || w.name === "app-member"), r.out).toEqual([]);
    expect(r.ran, r.out).toEqual(["nest-new", "nleaf2"]);
  });

  test("a workspace in strict mode: the declared members are trusted, so a clean add passes (review of 2a098b1)", async () => {
    const p = await project({ pm, deps: { "nest-old": "1.0.0" }, install: true, workspace: true });
    const r = await add(p, ["nest-new", "--pm", pm, "--strict"]);

    // on 2a098b1: refused, because app-member and other-member are not from a registry
    expect(r.code, r.out).toBe(0);
    expect(r.json.installed?.warnings, r.out).toEqual([]);
    expect(r.ran, r.out).toEqual(["nest-new", "nleaf2"]);
  });
});

describe("npm-shrinkwrap.json beats package-lock.json (real npm)", () => {
  test("the check reads the shrinkwrap npm installs from, and an add writes only that file", async () => {
    const p = await project({ pm: "npm", deps: { existing: "1.0.0" }, install: true });
    const shrink = p.read("package-lock.json") ?? "";
    // a stale package-lock.json npm ignores: it pins leaf@1.1.0, the clean version, with that version's real integrity
    const Doc = z.object({ versions: z.record(z.string(), z.object({ dist: z.object({ integrity: z.string(), tarball: z.string() }) })) });
    const leaf = Doc.parse((await getJson(`${reg.url}leaf`)).body).versions["1.1.0"];
    const Lock = z.object({ packages: z.record(z.string(), z.record(z.string(), z.unknown())) }).loose();
    const lock = Lock.parse(JSON.parse(shrink));

    lock.packages["node_modules/leaf"] = { version: "1.1.0", resolved: leaf?.dist.tarball, integrity: leaf?.dist.integrity };
    lock.packages["node_modules/existing"] = { ...lock.packages["node_modules/existing"], dependencies: { leaf: "^1.0.0" } };
    const stale = JSON.stringify(lock, null, 2);

    writeFileSync(join(p.root, "npm-shrinkwrap.json"), shrink);
    writeFileSync(join(p.root, "package-lock.json"), stale);
    const before = p.hash();
    const strict = await add(p, ["transitive-root", "--pm", "npm", "--strict"]);

    expect(strict.out).toContain("in the npm-shrinkwrap.json npm computed");
    expect(strict.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), strict.out).toContain("leaf@1.0.0");
    expectUntouched(strict, before, p.hash());

    const ok = await add(p, ["transitive-root", "--pm", "npm"]);

    expect(ok.code, ok.out).toBe(0);
    expect(p.read("npm-shrinkwrap.json")).toContain("node_modules/transitive-root");
    expect(p.read("package-lock.json")).toBe(stale);
  });
});

describe("a revoked transitive version the lockfile pins (real npm)", () => {
  test("is refused in the default mode, with nothing installed, run or written", async () => {
    const p = await project({ pm: "npm", deps: { rexisting: "1.0.0" }, install: true });

    const revoke = await getJson(`${reg.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ name: "rleaf", version: "1.0.0", reason: "compromised", password: PASSWORD }),
    });

    expect(revoke.status, JSON.stringify(revoke.body)).toBe(200);
    const before = p.hash();
    const r = await add(p, ["rtransitive-root", "--pm", "npm"]);

    expect(r.json.installed?.blocked.map((b) => `${b.name}@${b.version}`), r.out).toEqual(["rleaf@1.0.0"]);
    expect(r.out).toContain("refused: rleaf@1.0.0: rleaf@1.0.0 was revoked by its maintainer: compromised");
    expect(r.out).toContain("apm changed nothing");
    expectUntouched(r, before, p.hash());
  });
});

describe.each(PMS)("apm x with the real %s", (pm) => {
  test("the checked installation's helper binaries are on PATH, ahead of the caller's", async () => {
    const sb = makeSandbox(reg, alice);
    const cwd = mkdtempSync(join(work, "x-"));
    const fake = mkdtempSync(join(work, "fakebin-"));

    // an unrelated helper-say earlier on the caller's PATH must not be the one that runs
    writeFileSync(join(fake, "helper-say"), "#!/bin/sh\necho impostor\n", { mode: 0o755 });
    const r = await apm(["x", "--pm", pm, "xtool", "from-apm-x"], { cwd, env: { ...sb.env, TMPDIR: tmpdir(), PATH: `${fake}:${sb.env.PATH ?? ""}` }, timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("helper says from-apm-x");
    expect(r.out).not.toContain("impostor");
    // its directory is gone: nothing of apm-x is left under TMPDIR
    expect(readdirSync(tmpdir()).filter((d) => d.startsWith("apm-x-")), r.out).toEqual([]);
  });
});

// Review of 2b7767f, finding 3: a production install leaves devDependencies out, and apm add must accept that it did
describe.each(PMS)("apm add with the real %s: a production install", (pm) => {
  const asks: Record<Pm, { env: Record<string, string>; args: string[] }[]> = {
    npm: [
      { env: { npm_config_omit: "dev" }, args: [] },
      { env: {}, args: ["--omit=dev"] },
    ],
    pnpm: [{ env: { npm_config_production: "true" }, args: [] }],
    bun: [{ env: {}, args: ["--production"] }],
  };

  for (const ask of asks[pm]) {
    test(`${Object.entries(ask.env).map(([k, v]) => `${k}=${v}`).join(" ") || ask.args.join(" ")}: the add passes, its devDependency is not installed, the shared nleaf stays (on 2b7767f: refused after the write)`, async () => {
      const p = await project({ pm, deps: { "nest-old": "1.0.0" }, extra: { devDependencies: { devtool: "1.0.0" } }, install: true });
      const r = await add({ ...p, env: { ...p.env, ...ask.env } }, ["up@1.0.0", "--pm", pm, ...ask.args]);

      expect(r.code, r.out).toBe(0);
      expect(r.json.installed?.stage, r.out).toBe("done");
      expect(r.out).toContain("leaves devDependencies out of this install");
      expect(p.read("package.json")).toContain('"up"');

      // npm and pnpm remove the devDependency they no longer install; bun leaves what is there
      if (pm !== "bun") expect(existsSync(join(p.root, "node_modules", "devtool")), r.out).toBe(false);
      // nleaf, which nest-old needs too, stays (pnpm keeps a package no folder lists directly in its store)
      expect(existsSync(join(p.root, "node_modules", ...(pm === "pnpm" ? [".pnpm", "nleaf@1.0.0", "node_modules"] : []), "nleaf", "package.json")), r.out).toBe(true);
    });
  }
});
