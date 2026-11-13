// Review of 2b7767f, findings 1, 3 and 4, with the real package managers: npm and pnpm install local tarballs offline
// (no registry, no network), and the check after the install reads what they wrote. a and b each depend on their own
// leaf tarball (1.0.0 and 2.0.0), and the project has a devDependency.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { devGroup } from "../src/groups.ts";
import { readLock, type LockPm } from "../src/lockfile.ts";
import { verifyInstall } from "../src/verify.ts";

const PNPM = join(import.meta.dir, "..", "..", "..", "node_modules", ".bin", "pnpm");
let base: string;
let home: string;
const tgz: Record<string, string> = {};

async function sh(cmd: string[], cwd: string, env: Record<string, string> = {}): Promise<string> {
  const proc = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe", env: { PATH: process.env.PATH ?? "", HOME: home, npm_config_cache: join(home, ".npm"), npm_config_store_dir: join(home, ".pnpm-store"), npm_config_audit: "false", npm_config_fund: "false", npm_config_update_notifier: "false", ...env } });
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  if (code !== 0) throw new Error(`${cmd.join(" ")} exited ${code}:\n${out}${err}`);

  return out + err;
}

/** A package tarball in `base`, as `npm pack` lays it out, and its file: spec. */
async function pack(name: string, version: string, fields: { dependencies?: Record<string, string> } = {}): Promise<string> {
  const src = join(base, "src", `${name}-${version}`, "package");

  mkdirSync(src, { recursive: true });
  writeFileSync(join(src, "package.json"), JSON.stringify({ name, version, ...fields }));
  writeFileSync(join(src, "index.js"), `module.exports = ${JSON.stringify(`${name}@${version}`)};\n`);
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
