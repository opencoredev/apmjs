// Review of 2b7767f, findings 1, 3 and 4, with the real package managers: npm and pnpm install local tarballs offline
// (no registry, no network), and the check after the install reads what they wrote. a and b each depend on their own
// leaf tarball (1.0.0 and 2.0.0), and the project has a devDependency.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installedPackages } from "../src/audit.ts";
import { devGroup, releaseOmission } from "../src/groups.ts";
import { readLock, type LockPm } from "../src/lockfile.ts";
import { verifyInstall } from "../src/verify.ts";
import { npmAnswer, OMISSION_CASES, type OmissionCase } from "./fixtures/omission-cases.ts";

const PNPM = join(import.meta.dir, "..", "..", "..", "node_modules", ".bin", "pnpm");
let base: string;
let home: string;
const tgz: Record<string, string> = {};

/** The environment every real package manager here runs in: no network settings, caches under `home`. */
const shEnv = (env: Record<string, string>) => ({ PATH: process.env.PATH ?? "", HOME: home, npm_config_cache: join(home, ".npm"), npm_config_store_dir: join(home, ".pnpm-store"), npm_config_audit: "false", npm_config_fund: "false", npm_config_update_notifier: "false", ...env });

async function sh(cmd: string[], cwd: string, env: Record<string, string> = {}): Promise<string> {
  const proc = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe", env: shEnv(env) });
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  if (code !== 0) throw new Error(`${cmd.join(" ")} exited ${code}:\n${out}${err}`);

  return out + err;
}

/** A package tarball in `base`, as `npm pack` lays it out, and its file: spec. */
async function pack(name: string, version: string, fields: { dependencies?: Record<string, string>; scripts?: Record<string, string> } = {}): Promise<string> {
  const src = join(base, "src", `${name}-${version}`, "package");

  mkdirSync(src, { recursive: true });
  writeFileSync(join(src, "package.json"), JSON.stringify({ name, version, ...fields }));
  writeFileSync(join(src, "index.js"), `module.exports = ${JSON.stringify(`${name}@${version}`)};\n`);
  // an install script leaves a marker named after the package in $MARKS
  writeFileSync(join(src, "mark.js"), `require("fs").writeFileSync(require("path").join(process.env.MARKS, ${JSON.stringify(name)}), "ran");\n`);
  const file = join(base, `${name}-${version}.tgz`);

  await sh(["tar", "czf", file, "-C", join(base, "src", `${name}-${version}`), "package"], base);

  return `file:${file}`;
}

beforeAll(async () => {
  base = realpathSync(mkdtempSync(join(tmpdir(), "apm-real-layouts-")));
  home = join(base, "home");
  mkdirSync(home);
  tgz.leaf1 = await pack("leaf", "1.0.0");
  tgz.leaf2 = await pack("leaf", "2.0.0");
  tgz.a = await pack("a", "1.0.0", { dependencies: { leaf: tgz.leaf1 } });
  tgz.b = await pack("b", "1.0.0", { dependencies: { leaf: tgz.leaf2 } });
  tgz.devonly = await pack("devonly", "1.0.0");
  tgz.tool = await pack("tool", "1.0.0", { scripts: { postinstall: "node mark.js" } });
  tgz.devscript = await pack("devscript", "1.0.0", { scripts: { postinstall: "node mark.js" } });
});

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

let n = 0;

function project(): string {
  const dir = join(base, `p${++n}`, "project");

  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", private: true, dependencies: { a: tgz.a, b: tgz.b }, devDependencies: { devonly: tgz.devonly } }));

  return dir;
}

function verify(input: { pm: LockPm; root: string; omitDev: boolean }) {
  const file = input.pm === "npm" ? "package-lock.json" : "pnpm-lock.yaml";
  const read = readLock({ pm: input.pm, path: join(input.root, file), cwd: input.root });

  if (read.kind !== "read") throw new Error(JSON.stringify(read));

  return verifyInstall({ pm: input.pm, root: input.root, lockfile: file, checked: new Uint8Array(readFileSync(join(input.root, file))), nodes: read.nodes, importers: read.importers, members: [], before: [], omitted: { dev: input.omitDev } });
}

describe("finding 4: real pnpm, file-tarball dependencies with their own file-tarball dependencies", () => {
  for (const [layout, args] of [
    ["isolated", ["--node-linker=isolated"]],
    ["hoisted", ["--node-linker=hoisted"]],
    ["shamefully hoisted", ["--shamefully-hoist"]],
  ] as const) {
    test(`${layout}: verified, both leaf versions placed (on 2b7767f: leaf@1.0.0 and leaf@2.0.0 refused as not in the lockfile)`, async () => {
      const root = project();

      await sh([PNPM, "install", "--offline", "--ignore-scripts", ...args], root);
      const r = verify({ pm: "pnpm", root, omitDev: false });

      expect(r.problems).toEqual([]);
      expect(r.kind).toBe("verified");
      expect([...new Set(r.placed.map((p) => `${p.name}@${p.version}`))].toSorted()).toEqual(["a@1.0.0", "b@1.0.0", "devonly@1.0.0", "leaf@1.0.0", "leaf@2.0.0"]);
    }, 60_000);
  }
});

// Review of efef668, finding 5: strict mode refuses any package directory apm could not read. Every ordinary pnpm
// layout, including the hoisted linker and a virtual store outside the project (whose .pnpm holds only lock.yaml),
// reads whole: nothing unread, so strict passes when everything is checked.
describe("finding 5 of efef668: real pnpm layouts leave nothing unread", () => {
  test("a virtual store outside the project is part of what is installed, so an old copy there is not taken for a new one", async () => {
    const root = project();

    await sh([PNPM, "install", "--offline", "--ignore-scripts", "--virtual-store-dir=../outer-store"], root);
    const disk = installedPackages(root);

    expect(disk.unchecked).toEqual([]);
    expect(disk.found.filter((f) => f.path.startsWith("../outer-store/")).map((f) => `${f.name}@${f.version}`).toSorted()).toEqual(["a@1.0.0", "b@1.0.0", "devonly@1.0.0", "leaf@1.0.0", "leaf@2.0.0"]);
  }, 60_000);

  for (const [layout, args] of [
    ["isolated", []],
    ["hoisted", ["--node-linker=hoisted"]],
    ["shamefully hoisted", ["--shamefully-hoist"]],
    ["external virtual store", ["--virtual-store-dir=../shared-store"]],
    ["hoisted, external virtual store", ["--node-linker=hoisted", "--virtual-store-dir=../shared-store"]],
    ["hoisted, production", ["--node-linker=hoisted", "--prod"]],
    ["external virtual store, production", ["--virtual-store-dir=../shared-store", "--prod"]],
  ] as const) {
    test(`${layout}: verified with no unread directory (on efef668: node_modules/.pnpm, unknown package store layout, for every hoisted or external one)`, async () => {
      const root = project();

      await sh([PNPM, "install", "--offline", "--ignore-scripts", ...args], root);
      const r = verify({ pm: "pnpm", root, omitDev: args.join(" ").includes("--prod") });

      expect(r.problems).toEqual([]);
      expect(r.unreadable).toEqual([]);
      expect(r.kind).toBe("verified");
    }, 60_000);
  }
});

describe("finding 1: real pnpm with its virtual store outside the project", () => {
  test("the install is verified; a's leaf swapped for b's inside the external store is a mismatch (on 2b7767f: verified)", async () => {
    const root = project();

    await sh([PNPM, "install", "--offline", "--ignore-scripts", "--virtual-store-dir=../shared-store"], root);
    expect(verify({ pm: "pnpm", root, omitDev: false }).problems).toEqual([]);

    // a's own leaf link, inside the store outside the project, pointed at leaf@2.0.0
    const store = join(root, "..", "shared-store");
    const aDir = [...new Bun.Glob("a@*/node_modules").scanSync({ cwd: store, onlyFiles: false })][0] ?? "";
    const bDir = [...new Bun.Glob("leaf@*2.0.0*/node_modules/leaf").scanSync({ cwd: store, onlyFiles: false })][0] ?? "";

    expect(existsSync(join(store, aDir, "leaf"))).toBe(true);
    rmSync(join(store, aDir, "leaf"));
    symlinkSync(join(store, bDir), join(store, aDir, "leaf"));
    const r = verify({ pm: "pnpm", root, omitDev: false });

    expect(r.kind).toBe("mismatch");
    expect(r.problems.some((p) => p.includes("resolves leaf to leaf@2.0.0")), JSON.stringify(r.problems)).toBe(true);
  }, 60_000);
});

describe("finding 3: real npm, a production install", () => {
  for (const [how, args, env] of [
    ["--omit=dev", ["--omit=dev"], {}],
    ["npm_config_omit=dev", [], { npm_config_omit: "dev" }],
  ] as const) {
    test(`${how}: apm reads the omission and verifies the install (on 2b7767f: refused, devonly@1.0.0 not installed)`, async () => {
      const root = project();

      await sh(["npm", "install", "--package-lock-only", "--ignore-scripts", "--offline"], root);
      await sh(["npm", "install", "--ignore-scripts", "--offline", ...args], root, env);
      expect(existsSync(join(root, "node_modules", "devonly"))).toBe(false);
      const group = devGroup({ pm: "npm", root, env: { HOME: home, ...env }, production: args.length > 0 });

      expect(group.kind).toBe("omit");
      expect(verify({ pm: "npm", root, omitDev: group.kind === "omit" }).problems).toEqual([]);
      // the same tree, checked as a full install, is missing the devDependency
      expect(verify({ pm: "npm", root, omitDev: false }).problems).toContain("devonly (devonly@1.0.0), which your project needs, is not installed");
    }, 60_000);
  }
});

// Review of efef668, finding 3: every setting in the table, installed by real npm and pnpm (offline, scripts off).
// apm's reading of each (groups.test.ts holds it to the same table) is what the package manager did.
describe("finding 3 of efef668: real npm and pnpm leave devDependencies out exactly as the table says", () => {
  for (const pm of ["npm", "pnpm"] as const) {
    test(`${pm}: every case`, async () => {
      // one lockfile, computed with no settings, which each case installs frozen (at the same depth: pnpm records
      // the tarballs' paths relative to the project)
      const seed = join(base, `omission-seed-${pm}`, "project");

      mkdirSync(seed, { recursive: true });
      writeFileSync(join(seed, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", private: true, dependencies: { a: tgz.a }, devDependencies: { devonly: tgz.devonly } }));
      await sh(pm === "npm" ? ["npm", "install", "--package-lock-only", "--ignore-scripts", "--offline"] : [PNPM, "install", "--lockfile-only", "--offline"], seed);
      const lockName = pm === "npm" ? "package-lock.json" : "pnpm-lock.yaml";
      const lock = readFileSync(join(seed, lockName), "utf8");
      const wrong: string[] = [];
      // the table's npm column for the npm on PATH: 9.2 type-checks its settings, 9.3 on does not
      const [major = 0, minor = 0] = (await sh(["npm", "--version"], seed)).trim().split(".").map(Number);
      const expected = (c: OmissionCase): string => (pm === "npm" ? npmAnswer(c, { major, minor }) : c.pnpm);

      const one = async (c: OmissionCase, i: number): Promise<void> => {
        const root = join(base, `omission-${pm}-${i}`, "project");
        const caseHome = join(base, `omission-${pm}-${i}`, "home");

        mkdirSync(root, { recursive: true });
        mkdirSync(caseHome, { recursive: true });
        writeFileSync(join(root, "package.json"), readFileSync(join(seed, "package.json")));
        writeFileSync(join(root, lockName), lock);

        if (c.npmrc !== undefined) writeFileSync(join(root, ".npmrc"), c.npmrc);

        if (c.user !== undefined) writeFileSync(join(caseHome, ".npmrc"), c.user);

        if (c.global !== undefined) writeFileSync(join(caseHome, "global-npmrc"), c.global);
        // the global config is a file of the case's own, there or not
        const env = { npm_config_globalconfig: join(caseHome, "global-npmrc"), ...c.env, HOME: caseHome };

        await sh(pm === "npm" ? ["npm", "ci", "--ignore-scripts", "--offline"] : [PNPM, "install", "--frozen-lockfile", "--ignore-scripts", "--offline"], root, env);
        const did = existsSync(join(root, "node_modules", "devonly")) ? "include" : "omit";
        const apm = devGroup({ pm, root, env: shEnv(env), production: false }).kind;

        if (did !== expected(c) || apm !== did) wrong.push(`${c.name}: ${pm} ${did}d, the table says ${expected(c)}, apm says ${apm}`);
      };

      // four at a time
      const queue = OMISSION_CASES.map((c, i) => [c, i] as const);

      await Promise.all(
        Array.from({ length: 4 }, async () => {
          for (let next = queue.shift(); next !== undefined; next = queue.shift()) await one(...next);
        }),
      );
      expect(wrong).toEqual([]);
    }, 240_000);
  }
});

// Review of a24c6aa, finding 1: a [section] header with whitespace after it is a section to npm 11 (ini 6) and a key to
// Debian's npm 9.2 (ini 3), so no table answer holds for every npm. Each case is installed with the npm on PATH and
// apm must agree with what it did; pnpm 10 reads the header as a key. Run once with npm 11 first on PATH as well.
describe("finding 1 of a24c6aa: section headers followed by whitespace, as the npm on PATH and pnpm read them", () => {
  const cases = [
    { npmrc: "[section] \nproduction=true\n", pnpm: "omit" },
    { npmrc: "omit=dev\n[section] \nproduction=false\n", pnpm: "include" },
    { npmrc: "[section]\t\nonly=prod\n", pnpm: "omit" },
  ] as const;

  for (const pm of ["npm", "pnpm"] as const) {
    test(`${pm}: apm reads each as the install did`, async () => {
      const wrong: string[] = [];

      for (const [i, c] of cases.entries()) {
        const root = join(base, `sections-${pm}-${i}`, "project");
        const caseHome = join(base, `sections-${pm}-${i}`, "home");

        mkdirSync(root, { recursive: true });
        mkdirSync(caseHome, { recursive: true });
        writeFileSync(join(root, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", private: true, dependencies: { a: tgz.a }, devDependencies: { devonly: tgz.devonly } }));
        writeFileSync(join(root, ".npmrc"), c.npmrc);
        const env = { npm_config_globalconfig: join(caseHome, "global-npmrc"), HOME: caseHome };

        await sh(pm === "npm" ? ["npm", "install", "--ignore-scripts", "--offline"] : [PNPM, "install", "--ignore-scripts", "--offline"], root, env);
        const did = existsSync(join(root, "node_modules", "devonly")) ? "include" : "omit";
        const apm = devGroup({ pm, root, env: shEnv(env), production: false }).kind;

        if (apm !== did || (pm === "pnpm" && did !== c.pnpm)) wrong.push(`${JSON.stringify(c.npmrc)}: ${pm} ${did}d, apm says ${apm}`);
      }

      expect(wrong).toEqual([]);
    }, 120_000);
  }
});

// Review of efef668, finding 1: after a production install with scripts held, the command that runs tool's script
// (bun installs the removed tool again; pnpm and npm rebuild it) is told the omission too. Without it, bun's second
// install put devscript back and ran its install script.
describe("finding 1 of efef668: releasing held scripts keeps a production install's omission", () => {
  for (const pm of ["bun", "pnpm", "npm"] as const) {
    test(`${pm}: tool's script runs, devscript is neither installed nor run (on efef668, bun: devscript installed and its script ran)`, async () => {
      const root = join(base, `release-${pm}`, "project");
      const marks = join(base, `release-${pm}`, "marks");
      const env = { MARKS: marks };
      const omit = { kind: "omit", why: "test" } as const;
      const release = releaseOmission(pm, omit);

      mkdirSync(root, { recursive: true });
      mkdirSync(marks, { recursive: true });
      writeFileSync(join(root, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", private: true, dependencies: { tool: tgz.tool }, devDependencies: { devscript: tgz.devscript }, trustedDependencies: ["tool", "devscript"], pnpm: { onlyBuiltDependencies: ["tool", "devscript"] } }));

      switch (pm) {
        case "bun":
          await sh(["bun", "install", "--lockfile-only"], root, env);
          await sh(["bun", "install", "--frozen-lockfile", "--production", "--ignore-scripts"], root, env);
          // apm removes what it releases, and bun installs it again with scripts on
          rmSync(join(root, "node_modules", "tool"), { recursive: true });
          await sh(["bun", "install", "--frozen-lockfile", ...release.args], root, { ...env, ...release.env });
          break;
        case "pnpm":
          await sh([PNPM, "install", "--lockfile-only", "--offline"], root, env);
          await sh([PNPM, "install", "--frozen-lockfile", "--prod", "--ignore-scripts", "--offline"], root, env);
          await sh([PNPM, "rebuild", "tool@1.0.0", ...release.args], root, { ...env, ...release.env });
          break;
        case "npm":
          await sh(["npm", "install", "--package-lock-only", "--ignore-scripts", "--offline"], root, env);
          await sh(["npm", "ci", "--omit=dev", "--ignore-scripts", "--offline"], root, env);
          await sh(["npm", "rebuild", ...release.args, join(root, "node_modules", "tool")], root, { ...env, ...release.env });
          break;
        default: {
          const _exhaustive: never = pm;

          throw new Error(`unknown ${String(_exhaustive)}`);
        }
      }

      expect(existsSync(join(marks, "tool"))).toBe(true);
      expect(existsSync(join(marks, "devscript"))).toBe(false);
      expect(existsSync(join(root, "node_modules", "devscript"))).toBe(false);
    }, 60_000);
  }
});
