// Launch review blocker 1: apm reads the subtree under the added packages from each lockfile format.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bunKeyNames, lockedTree, projectPins, type LockPm } from "../src/lockfile.ts";

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

// review of 1924692, finding 1: a peer the project provides is checked at the version its lockfile pins
describe("the project's own pins (projectPins)", () => {
  const pins = (input: { pm: "npm" | "pnpm" | "bun" | "yarn"; cwd: string; names: string[] }) => Object.fromEntries(projectPins(input));

  test("npm: a registry entry is pinned; an alias, a git entry and a workspace link are unknown; an unlisted name is left out", () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { host: "^1.0.0", alias: "npm:real-pkg@3.0.0", gitdep: "github:x/y", ws: "file:../ws" } },
        "node_modules/host": { version: "1.0.0", resolved: "https://registry.npmjs.org/host/-/host-1.0.0.tgz", integrity: "sha512-host" },
        "node_modules/alias": { name: "real-pkg", version: "3.0.0", integrity: "sha512-real" },
        "node_modules/gitdep": { version: "2.0.0", resolved: "git+ssh://git@github.com/x/y.git#abc" },
        "node_modules/ws": { resolved: "../ws", link: true },
      },
    };

    const cwd = project("package-lock.json", JSON.stringify(lock));

    expect(pins({ pm: "npm", cwd, names: ["host", "alias", "gitdep", "ws", "absent"] })).toEqual({
      host: { kind: "pinned", version: "1.0.0" },
      alias: { kind: "unknown", why: "alias installs real-pkg, an alias" },
      gitdep: { kind: "unknown", why: "gitdep is not installed from a registry (git+ssh://git@github.com/x/y.git#abc)" },
      ws: { kind: "unknown", why: "ws is not installed from a registry (link:../ws)" },
    });
  });

  test("pnpm: the importer's version, without its peer suffix; an alias is unknown", () => {
    const lock = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      host:
        specifier: ^1.0.0
        version: 1.0.0(peer@1.0.0)
      alias:
        specifier: npm:real-pkg@3.0.0
        version: real-pkg@3.0.0
packages:
  host@1.0.0:
    resolution: {integrity: sha512-host}
  real-pkg@3.0.0:
    resolution: {integrity: sha512-real}
snapshots:
  host@1.0.0(peer@1.0.0): {}
  real-pkg@3.0.0: {}
`;

    expect(pins({ pm: "pnpm", cwd: project("pnpm-lock.yaml", lock), names: ["host", "alias", "absent"] })).toEqual({ host: { kind: "pinned", version: "1.0.0" }, alias: { kind: "unknown", why: "alias installs real-pkg, an alias" } });
  });

  test("bun: the top-level entry's version; a git entry is unknown", () => {
    const lock = `{
      "lockfileVersion": 1,
      "workspaces": { "": { "dependencies": { "host": "^1.0.0", "gitdep": "github:x/y" } } },
      "packages": {
        "host": ["host@1.0.0", "", {}, "sha512-host"],
        "host/inner": ["inner@1.0.0", "", {}, "sha512-inner"],
        "gitdep": ["gitdep@github:x/y#abc", { "dependencies": {} }, "abc"],
      },
    }`;

    expect(pins({ pm: "bun", cwd: project("bun.lock", lock), names: ["host", "gitdep", "inner"] })).toEqual({ host: { kind: "pinned", version: "1.0.0" }, gitdep: { kind: "unknown", why: "gitdep is not installed from a registry (github:x/y#abc)" } });
  });

  test("no lockfile: nothing is pinned, so the package manager installs the newest in range", () => {
    expect(pins({ pm: "npm", cwd: project("package.json", "{}"), names: ["host"] })).toEqual({});
    expect(pins({ pm: "yarn", cwd: project("package.json", "{}"), names: ["host"] })).toEqual({});
  });

  test("a yarn.lock, or a lockfile apm cannot parse, makes every name unknown", () => {
    const yarn = project("yarn.lock", "host@^1.0.0:\n  version \"1.0.0\"\n");

    expect(pins({ pm: "yarn", cwd: yarn, names: ["host"] })).toEqual({ host: { kind: "unknown", why: `apm cannot read ${join(yarn, "yarn.lock")}` } });
    const broken = project("package-lock.json", "{ not json");

    expect(pins({ pm: "npm", cwd: broken, names: ["host"] }).host?.kind).toBe("unknown");
  });
});
