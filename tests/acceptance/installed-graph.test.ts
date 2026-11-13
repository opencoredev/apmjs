// Spec (review of 16fc8b5, findings 1 to 3): apm add checks the graph the package manager really installed, every
// package at its exact version, before any install script runs. The registry's resolve walk predicts leaf@1.1.0 (old,
// clean); the real npm, pnpm and bun installs below reuse or pin leaf@1.0.0, published an hour ago. Strict mode
// refuses it and puts the project back, the default mode warns about it, and a revoked version refuses in every mode.
// Payloads are inert: the install scripts write a marker file.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { addUser, apm, getJson, makeSandbox, run, startRegistry, writeConsumer, writePackage, type Registry } from "./harness";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const PASSWORD = "correct-horse-battery";
let clock = Date.parse("2026-10-01T00:00:00Z");
let reg: Registry;
let alice: string;
let work: string;

type Pm = "npm" | "pnpm" | "bun";

async function publish(spec: Parameters<typeof writePackage>[1]): Promise<void> {
  const sb = makeSandbox(reg, alice);
  const d = writePackage(work, spec, reg, alice);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });

  if (r.code !== 0) throw new Error(`publish ${spec.name}@${spec.version}: ${r.out}`);
}

/** A package whose install script leaves a marker named after it, so a test can tell whether any script ran. */
const marked = (name: string) => ({ scripts: { postinstall: "node mark.js" }, files: { "index.js": "module.exports = 1;\n", "mark.js": `require('fs').writeFileSync(require('path').join(process.env.APM_TEST_MARKS, '${name}'), 'ran');\n` } });

const ROOTS = ["transitive-root", "rtransitive-root", "peer-root", "override-root", "unlocked-plugin"];

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice", PASSWORD);
  work = mkdtempSync(join(tmpdir(), "apm-graph-"));

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

const Json = z.object({ ok: z.boolean(), installed: z.object({ refused: z.boolean(), blocked: z.array(z.object({ name: z.string(), version: z.string() })), warnings: z.array(z.object({ name: z.string(), version: z.string(), kind: z.string() })) }).nullish() });

type Project = { app: string; env: Record<string, string>; marks: string; before: { pkg: string | null; lock: string | null }; read: (file: string) => string | null };

/** A project with `deps` (and `extra` package.json fields), installed by `pm` itself when `install` is set, scripts off. */
/** package.json fields a test project sets besides its dependencies. */
type ProjectFields = { overrides?: Record<string, string>; resolutions?: Record<string, string>; pnpm?: { overrides: Record<string, string>; onlyBuiltDependencies: string[] } };

async function project(input: { pm: Pm; deps: Record<string, string>; extra?: ProjectFields; install: boolean }): Promise<Project> {
  const sb = makeSandbox(reg, alice);
  const app = writeConsumer(work, reg, alice, input.deps);
  const marks = mkdtempSync(join(work, "marks-"));
  const env = { ...sb.env, APM_TEST_MARKS: marks, npm_config_store_dir: join(sb.home, ".pnpm-store") };
  const pkg = { name: "consumer-app", version: "1.0.0", private: true, dependencies: input.deps, trustedDependencies: ROOTS, pnpm: { onlyBuiltDependencies: ROOTS }, ...input.extra };

  writeFileSync(join(app, "package.json"), JSON.stringify(pkg, null, 2));

  if (input.install) {
    const r = await run([input.pm, "install", "--ignore-scripts"], { cwd: app, env });

    if (r.code !== 0) throw new Error(`${input.pm} install: ${r.out}`);
  }

  const read = (f: string): string | null => (existsSync(join(app, f)) ? readFileSync(join(app, f), "utf8") : null);

  return { app, env, marks, before: { pkg: read("package.json"), lock: read(LOCKFILE[input.pm]) }, read };
}

/** apm add, its JSON answer, and which install scripts ran. */
async function add(p: Project, args: string[]) {
  const r = await apm(["add", ...args, "--json"], { cwd: p.app, env: p.env, timeoutMs: 120_000 });
  let json: z.infer<typeof Json>;

  try {
    json = Json.parse(JSON.parse(r.stdout));
  } catch {
    throw new Error(`no JSON answer:\n${r.out}`);
  }

  return { ...r, json, ran: readdirSync(p.marks) };
}

describe.each(["npm", "pnpm", "bun"] as const)("apm add with the real %s", (pm) => {
  test("transitive lockfile pin: strict refuses the fresh leaf the package manager kept, runs no script and puts the project back", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true });
    const r = await add(p, ["transitive-root", "--pm", pm, "--strict"]);
    const leaf = r.json.installed?.warnings.filter((w) => w.name === "leaf").map((w) => `${w.version}:${w.kind}`);

    expect(r.out).toContain("the early check read 1.1.0");
    expect(leaf, r.out).toEqual(["1.0.0:cooldown"]);
    expect(r.code, r.out).toBe(1);
    expect(r.ran, r.out).toEqual([]);
    expect(p.read("package.json")).toBe(p.before.pkg);
    expect(p.read(LOCKFILE[pm])).toBe(p.before.lock);
    expect(existsSync(join(p.app, "node_modules", "transitive-root")), r.out).toBe(false);
    expect(existsSync(join(p.app, "node_modules", "existing")), r.out).toBe(true);
  });

  test("transitive lockfile pin: the default mode warns about leaf@1.0.0, then runs the scripts", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true });
    const r = await add(p, ["transitive-root", "--pm", pm]);

    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/WARNING leaf@1\.0\.0 .*cooldown/);
    expect(r.out).toContain("apm: checked the");
    expect(r.ran, r.out).toEqual(["transitive-root"]);
  });

  test("nested peer: strict refuses the fresh leaf that meets plugin's peer below peer-root", async () => {
    const p = await project({ pm, deps: { existing: "1.0.0" }, install: true });
    const r = await add(p, ["peer-root", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toContain("leaf@1.0.0");
    expect(r.code, r.out).toBe(1);
    expect(r.ran, r.out).toEqual([]);
    expect(p.read(LOCKFILE[pm])).toBe(p.before.lock);
  });

  test("overrides: strict refuses the leaf@1.0.0 the project's override installs", async () => {
    const extra = { overrides: { leaf: "1.0.0" }, resolutions: { leaf: "1.0.0" }, pnpm: { overrides: { leaf: "1.0.0" }, onlyBuiltDependencies: ROOTS } };
    const p = await project({ pm, deps: {}, extra, install: false });
    const r = await add(p, ["override-root", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toEqual(["leaf@1.0.0"]);
    expect(r.code, r.out).toBe(1);
    expect(r.ran, r.out).toEqual([]);
    expect(p.read("package.json")).toBe(p.before.pkg);
    expect(existsSync(join(p.app, "node_modules")), r.out).toBe(false);
  });

  test("no lockfile: the check uses the otherhost@1.0.0 package.json pins, not the newest in range", async () => {
    const p = await project({ pm, deps: { otherhost: "1.0.0" }, install: false });
    const r = await add(p, ["unlocked-plugin", "--pm", pm, "--strict"]);

    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`), r.out).toEqual(["otherhost@1.0.0"]);
    expect(r.code, r.out).toBe(1);
    expect(r.ran, r.out).toEqual([]);
    expect(p.read("package.json")).toBe(p.before.pkg);
    expect(p.read(LOCKFILE[pm])).toBeNull();
    expect(existsSync(join(p.app, "node_modules")), r.out).toBe(false);
  });
});

describe("a revoked transitive version the lockfile pins (real npm)", () => {
  test("is refused in the default mode, with no script run and the project put back", async () => {
    const p = await project({ pm: "npm", deps: { rexisting: "1.0.0" }, install: true });

    const revoke = await getJson(`${reg.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ name: "rleaf", version: "1.0.0", reason: "compromised", password: PASSWORD }),
    });

    expect(revoke.status, JSON.stringify(revoke.body)).toBe(200);
    const r = await add(p, ["rtransitive-root", "--pm", "npm"]);

    expect(r.json.installed?.blocked.map((b) => `${b.name}@${b.version}`), r.out).toEqual(["rleaf@1.0.0"]);
    expect(r.out).toContain("refused: rleaf@1.0.0: rleaf@1.0.0 was revoked by its maintainer: compromised");
    expect(r.code, r.out).toBe(1);
    expect(r.ran, r.out).toEqual([]);
    expect(p.read("package.json")).toBe(p.before.pkg);
    expect(p.read("package-lock.json")).toBe(p.before.lock);
    expect(existsSync(join(p.app, "node_modules", "rtransitive-root")), r.out).toBe(false);
    expect(r.out).toContain("No install script ran");
  });
});
