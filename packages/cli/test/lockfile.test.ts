// Launch review blocker 1: apm reads the subtree under the added packages from each lockfile format.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bunKeyNames, lockedTree, type LockPm } from "../src/lockfile.ts";

const dirs: string[] = [];

afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function project(file: string, text: string): string {
  const dir = mkdtempSync(join(tmpdir(), "apm-lock-unit-"));

  dirs.push(dir);
  writeFileSync(join(dir, file), text);

  return dir;
}

function under(input: { pm: LockPm; cwd: string; roots: string[] }): string[] {
  const r = lockedTree({ cwd: input.cwd, pm: input.pm, roots: { kind: "under", names: input.roots } });

  if (r.kind !== "read") throw new Error(`lockfile not read: ${r.kind}`);

  return r.nodes.map((n) => `${n.name}@${n.version} ${n.integrity ?? "-"}`).sort();
}

describe("npm package-lock.json", () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { root: "1.0.0", other: "1.0.0" } },
      "node_modules/root": { version: "1.0.0", integrity: "sha512-root", dependencies: { "@s/leaf": "^2.0.0", shared: "1.0.0" } },
      "node_modules/root/node_modules/@s/leaf": { version: "2.0.0", integrity: "sha512-nested-leaf", dependencies: { shared: "1.0.0" } },
      "node_modules/@s/leaf": { version: "1.0.0", integrity: "sha512-top-leaf" },
      "node_modules/shared": { version: "1.0.0", integrity: "sha512-shared" },
      "node_modules/alias": { name: "real-pkg", version: "3.0.0", integrity: "sha512-real" },
      "node_modules/other": { version: "1.0.0", integrity: "sha512-other", dependencies: { alias: "npm:real-pkg@3.0.0" } },
    },
  };

  test("follows node's lookup: the nested copy first, then the top", () => {
    expect(under({ pm: "npm", cwd: project("package-lock.json", JSON.stringify(lock)), roots: ["root"] })).toEqual(["@s/leaf@2.0.0 sha512-nested-leaf", "root@1.0.0 sha512-root", "shared@1.0.0 sha512-shared"]);
  });

  test("an alias is read as the package it installs", () => {
    expect(under({ pm: "npm", cwd: project("package-lock.json", JSON.stringify(lock)), roots: ["other"] })).toEqual(["other@1.0.0 sha512-other", "real-pkg@3.0.0 sha512-real"]);
  });
});

describe("bun.lock", () => {
  const lock = `{
    "lockfileVersion": 1,
    "workspaces": { "": { "dependencies": { "root": "1.0.0" } } },
    "packages": {
      "root": ["root@1.0.0", "", { "dependencies": { "@s/leaf": "^2.0.0" } }, "sha512-root"],
      "@s/leaf": ["@s/leaf@1.0.0", "", {}, "sha512-top-leaf"],
      "root/@s/leaf": ["@s/leaf@2.0.0", "https://elsewhere.invalid/leaf-2.0.0.tgz", { "hasInstallScript": true, "dependencies": { "gitdep": "github:x/y" } }, "sha512-nested-leaf"],
      "gitdep": ["gitdep@github:x/y#abc", { "dependencies": {} }, "abc"],
    },
  }`;

  test("nested keys are install paths, and git entries are kept without an integrity", () => {
    expect(under({ pm: "bun", cwd: project("bun.lock", lock), roots: ["root"] })).toEqual(["@s/leaf@2.0.0 sha512-nested-leaf", "gitdep@github:x/y#abc -", "root@1.0.0 sha512-root"]);
    expect(bunKeyNames("root/@s/leaf/x")).toEqual(["root", "@s/leaf", "x"]);
  });
});

describe("pnpm-lock.yaml v9", () => {
  const lock = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      root:
        specifier: 1.0.0
        version: 1.0.0(peer@1.0.0)
      unrelated:
        specifier: 1.0.0
        version: 1.0.0
packages:
  root@1.0.0:
    resolution: {integrity: sha512-root}
  '@s/leaf@2.0.0':
    resolution: {integrity: sha512-leaf}
  real-pkg@3.0.0:
    resolution: {integrity: sha512-real}
  peer@1.0.0:
    resolution: {integrity: sha512-peer}
  unrelated@1.0.0:
    resolution: {integrity: sha512-unrelated}
snapshots:
  root@1.0.0(peer@1.0.0):
    dependencies:
      '@s/leaf': 2.0.0
      alias: real-pkg@3.0.0
      peer: 1.0.0
  '@s/leaf@2.0.0': {}
  real-pkg@3.0.0: {}
  peer@1.0.0: {}
  unrelated@1.0.0: {}
`;

  test("peer suffixes and aliases resolve to their packages, and only the subtree is read", () => {
    expect(under({ pm: "pnpm", cwd: project("pnpm-lock.yaml", lock), roots: ["root"] })).toEqual(["@s/leaf@2.0.0 sha512-leaf", "peer@1.0.0 sha512-peer", "real-pkg@3.0.0 sha512-real", "root@1.0.0 sha512-root"]);
  });
});
