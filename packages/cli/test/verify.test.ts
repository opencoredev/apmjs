// Review of 2a098b1: what the check after a frozen install accepts. Each case lays node_modules by hand, as npm, pnpm or
// bun lay it (pnpm's .pnpm store with its links, npm's nested and workspace paths), reads a real lockfile text with
// readLock, and asks verifyInstall. On 2a098b1 the verifier compared a set of name@versions: every case marked so
// returned "verified".
import { afterAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { installedPackages } from "../src/audit.ts";
import { readLock, type LockPm } from "../src/lockfile.ts";
import { removeInstalled, verifyInstall } from "../src/verify.ts";

/** A JSON value, as the fixtures' package.json fields and lockfiles hold. */
type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

const base = mkdtempSync(join(tmpdir(), "apm-verify-"));

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

let n = 0;

/** A fresh project directory. */
const project = (): string => {
  const dir = join(base, `p${++n}`);

  mkdirSync(dir, { recursive: true });

  return realpathSync(dir);
};

/** A package directory with its package.json (`extra`: more fields). */
function pkg(dir: string, name: string, version: string, extra: Record<string, Json> = {}): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version, ...extra }));
}

/** A symlink at `at` to `target` (relative, as the package managers write them). */
function link(at: string, target: string): void {
  mkdirSync(dirname(at), { recursive: true });
  symlinkSync(target, at);
}

const sha = (s: string): string => `sha512-${s}`;

/** verifyInstall on `root` with the lockfile `file` holding `text`. `before`: what node_modules held before the install. */
function verify(input: { pm: LockPm; root: string; file: string; text: string; members?: { dir: string; name: string; version: string }[]; before?: ReturnType<typeof installedPackages>["found"] }) {
  writeFileSync(join(input.root, input.file), input.text);
  const read = readLock({ pm: input.pm, path: join(input.root, input.file), cwd: input.root });

  if (read.kind !== "read") throw new Error(`fixture lockfile unreadable: ${JSON.stringify(read)}`);

  return verifyInstall({ pm: input.pm, root: input.root, lockfile: input.file, checked: new Uint8Array(readFileSync(join(input.root, input.file))), nodes: read.nodes, importers: read.importers, members: input.members ?? [], before: input.before ?? [] });
}

const npmLock = (packages: Record<string, Json>): string => JSON.stringify({ name: "p", lockfileVersion: 3, requires: true, packages: { "": { name: "p", version: "1.0.0" }, ...packages } });

describe("npm: every lockfile path holds its locked version (finding 3)", () => {
  const workspace = (leafInMember: string) =>
    npmLock({
      "": { name: "p", version: "1.0.0", workspaces: ["packages/*"], dependencies: { leaf: "1.0.0" } },
      "node_modules/app": { resolved: "packages/app", link: true },
      "node_modules/leaf": { version: "1.0.0", resolved: "https://r.test/leaf/-/leaf-1.0.0.tgz", integrity: sha("one") },
      "packages/app": { name: "app", version: "1.0.0", dependencies: { leaf: "2.0.0" } },
      "packages/app/node_modules/leaf": { version: leafInMember, resolved: `https://r.test/leaf/-/leaf-${leafInMember}.tgz`, integrity: sha("two") },
    });

  test("a workspace member's own node_modules holding another version than the lockfile's is a mismatch (on 2a098b1: verified)", () => {
    const root = project();

    pkg(join(root, "node_modules", "leaf"), "leaf", "1.0.0");
    pkg(join(root, "packages", "app"), "app", "1.0.0");
    pkg(join(root, "packages", "app", "node_modules", "leaf"), "leaf", "1.0.0");
    link(join(root, "node_modules", "app"), "../packages/app");
    const r = verify({ pm: "npm", root, file: "package-lock.json", text: workspace("2.0.0"), members: [{ dir: "packages/app", name: "app", version: "1.0.0" }] });

    expect(r.kind).toBe("mismatch");
    expect(r.problems).toContain("packages/app resolves leaf to leaf@1.0.0 (packages/app/node_modules/leaf), but the checked lockfile locks leaf@2.0.0 there");
  });

  test("the same layout at the locked versions is verified", () => {
    const root = project();

    pkg(join(root, "node_modules", "leaf"), "leaf", "1.0.0");
    pkg(join(root, "packages", "app"), "app", "1.0.0");
    pkg(join(root, "packages", "app", "node_modules", "leaf"), "leaf", "2.0.0");
    link(join(root, "node_modules", "app"), "../packages/app");
    const r = verify({ pm: "npm", root, file: "package-lock.json", text: workspace("2.0.0"), members: [{ dir: "packages/app", name: "app", version: "1.0.0" }] });

    expect(r.problems).toEqual([]);
    expect(r.kind).toBe("verified");
  });

  test("npm's own record of the integrity it installed at a path must be the checked one", () => {
    const root = project();
    const lock = npmLock({ "": { name: "p", dependencies: { leaf: "1.0.0" } }, "node_modules/leaf": { version: "1.0.0", resolved: "https://r.test/leaf/-/leaf-1.0.0.tgz", integrity: sha("checked") } });

    pkg(join(root, "node_modules", "leaf"), "leaf", "1.0.0");
    writeFileSync(join(root, "node_modules", ".package-lock.json"), JSON.stringify({ name: "p", lockfileVersion: 3, packages: { "node_modules/leaf": { version: "1.0.0", integrity: sha("other") } } }));
    const r = verify({ pm: "npm", root, file: "package-lock.json", text: lock });

    expect(r.problems).toEqual(["node_modules/leaf: npm recorded installing sha512-other there, not the checked sha512-checked"]);
  });
});

describe("missing packages and package directories apm cannot read (finding 4)", () => {
  test("a required package that is not installed is a mismatch (on 2a098b1: verified)", () => {
    const root = project();
    const lock = npmLock({ "": { name: "p", dependencies: { required: "1.0.0" } }, "node_modules/required": { version: "1.0.0", resolved: "https://r.test/required/-/required-1.0.0.tgz", integrity: sha("r") } });

    mkdirSync(join(root, "node_modules"));
    const r = verify({ pm: "npm", root, file: "package-lock.json", text: lock });

    expect(r.kind).toBe("mismatch");
    expect(r.problems).toContain("required (required@1.0.0), which your project needs, is not installed");
  });

  test("an optional package for another platform may be missing", () => {
    const root = project();

    const lock = npmLock({
      "": { name: "p", dependencies: { withopt: "1.0.0" } },
      "node_modules/withopt": { version: "1.0.0", resolved: "https://r.test/withopt/-/withopt-1.0.0.tgz", integrity: sha("w"), optionalDependencies: { optx: "1.0.0" } },
      "node_modules/optx": { version: "1.0.0", resolved: "https://r.test/optx/-/optx-1.0.0.tgz", integrity: sha("o"), optional: true, os: ["win32"] },
    });

    pkg(join(root, "node_modules", "withopt"), "withopt", "1.0.0");
    expect(verify({ pm: "npm", root, file: "package-lock.json", text: lock }).kind).toBe("verified");
  });

  test("a package directory with code but no package.json, and one that cannot be listed, are unreadable, never an empty inventory (on 2a098b1: unreadable [])", () => {
    const root = project();

    mkdirSync(join(root, "node_modules", "unknown"), { recursive: true });
    writeFileSync(join(root, "node_modules", "unknown", "index.js"), "// unknown bytes\n");
    mkdirSync(join(root, "node_modules", "@locked"), { recursive: true });
    chmodSync(join(root, "node_modules", "@locked"), 0o000);

    try {
      const r = verify({ pm: "npm", root, file: "package-lock.json", text: npmLock({}) });

      expect(r.unreadable.map((u) => `${u.id}: ${u.reason}`).toSorted()).toEqual(["node_modules/@locked: could not be listed (EACCES)", "node_modules/unknown: no package.json"]);
    } finally {
      chmodSync(join(root, "node_modules", "@locked"), 0o755);
    }
  });
});

describe("packages outside the lockfile (finding 3)", () => {
  const lock = npmLock({ "": { name: "p", dependencies: { leaf: "1.0.0" } }, "node_modules/leaf": { version: "1.0.0", resolved: "https://r.test/leaf/-/leaf-1.0.0.tgz", integrity: sha("l") } });

  const lay = (root: string): void => {
    pkg(join(root, "node_modules", "leaf"), "leaf", "1.0.0");
    // a second copy of an allowed name@version, where the lockfile puts nothing
    pkg(join(root, "node_modules", "leaf", "node_modules", "leaf"), "leaf", "1.0.0");
  };

  test("an extra copy of a locked name@version the install put there is a mismatch (on 2a098b1: it disappeared into the set)", () => {
    const root = project();

    lay(root);
    const r = verify({ pm: "npm", root, file: "package-lock.json", text: lock });

    expect(r.problems).toEqual(["node_modules holds a package the checked lockfile does not: leaf@1.0.0"]);
  });

  test("one that was there before the install is reported as extraneous, for the caller to warn about (strict refuses it)", () => {
    const root = project();

    lay(root);
    const before = installedPackages(root).found;
    const r = verify({ pm: "npm", root, file: "package-lock.json", text: lock, before });

    expect(r.kind).toBe("verified");
    expect(r.extraneous).toEqual([{ path: "node_modules/leaf/node_modules/leaf", name: "leaf", version: "1.0.0" }]);
  });
});

/** pnpm's lockfile, as JSON (which YAML reads). */
const pnpmLock = (doc: { importers: Record<string, Json>; packages: Record<string, Json>; snapshots: Record<string, Json> }): string => JSON.stringify({ lockfileVersion: "9.0", ...doc });

/** A package in pnpm's store, node_modules/.pnpm/<dir>/node_modules/<name>. */
const stored = (root: string, dir: string, name: string, version: string, extra: Record<string, Json> = {}): string => {
  const at = join(root, "node_modules", ".pnpm", dir, "node_modules", name);

  pkg(at, name, version, extra);

  return at;
};

describe("pnpm: each dependency link points at the locked version (finding 3)", () => {
  const leafLock = pnpmLock({
    importers: { ".": { dependencies: { leaf: { specifier: "2.0.0", version: "2.0.0" } } } },
    packages: { "leaf@1.0.0": { resolution: { integrity: sha("1") } }, "leaf@2.0.0": { resolution: { integrity: sha("2") } } },
    snapshots: { "leaf@1.0.0": {}, "leaf@2.0.0": {} },
  });

  test("a top-level link to leaf@1.0.0 where the importer locks 2.0.0 is a mismatch (on 2a098b1: verified, both versions being allowed)", () => {
    const root = project();

    stored(root, "leaf@1.0.0", "leaf", "1.0.0");
    stored(root, "leaf@2.0.0", "leaf", "2.0.0");
    link(join(root, "node_modules", "leaf"), ".pnpm/leaf@1.0.0/node_modules/leaf");
    const r = verify({ pm: "pnpm", root, file: "pnpm-lock.yaml", text: leafLock });

    expect(r.problems).toContain("your project resolves leaf to leaf@1.0.0 (node_modules/.pnpm/leaf@1.0.0/node_modules/leaf), but the checked lockfile locks leaf@2.0.0 there");
  });

  const peerLock = pnpmLock({
    importers: { ".": { dependencies: { plug: { specifier: "1.0.0", version: "1.0.0(host@2.0.0)" }, host: { specifier: "2.0.0", version: "2.0.0" } } } },
    packages: { "plug@1.0.0": { resolution: { integrity: sha("p") } }, "host@1.0.0": { resolution: { integrity: sha("h1") } }, "host@2.0.0": { resolution: { integrity: sha("h2") } } },
    snapshots: { "plug@1.0.0(host@2.0.0)": { dependencies: { host: "2.0.0" } }, "host@1.0.0": {}, "host@2.0.0": {} },
  });

  const layPeers = (root: string, peer: string): void => {
    stored(root, "plug@1.0.0_host@2.0.0", "plug", "1.0.0");
    stored(root, "host@1.0.0", "host", "1.0.0");
    stored(root, "host@2.0.0", "host", "2.0.0");
    link(join(root, "node_modules", ".pnpm", "plug@1.0.0_host@2.0.0", "node_modules", "host"), `../../host@${peer}/node_modules/host`);
    link(join(root, "node_modules", "plug"), ".pnpm/plug@1.0.0_host@2.0.0/node_modules/plug");
    link(join(root, "node_modules", "host"), ".pnpm/host@2.0.0/node_modules/host");
  };

  test("a package's peer linked to another version than its snapshot's is a mismatch", () => {
    const root = project();

    layPeers(root, "1.0.0");
    const r = verify({ pm: "pnpm", root, file: "pnpm-lock.yaml", text: peerLock, before: [{ path: "node_modules/.pnpm/host@1.0.0/node_modules/host", name: "host", version: "1.0.0" }] });

    expect(r.problems).toContain("plug@1.0.0 (node_modules/.pnpm/plug@1.0.0_host@2.0.0/node_modules/plug) resolves host to host@1.0.0 (node_modules/.pnpm/host@1.0.0/node_modules/host), but the checked lockfile locks host@2.0.0 there");
  });

  test("the store laid as the lockfile locks it is verified, with every package placed where it is", () => {
    const root = project();

    layPeers(root, "2.0.0");
    const r = verify({ pm: "pnpm", root, file: "pnpm-lock.yaml", text: peerLock, before: [{ path: "node_modules/.pnpm/host@1.0.0/node_modules/host", name: "host", version: "1.0.0" }] });

    expect(r.problems).toEqual([]);
    expect(r.placed.map((p) => p.path).toSorted()).toEqual(["node_modules/.pnpm/host@2.0.0/node_modules/host", "node_modules/.pnpm/plug@1.0.0_host@2.0.0/node_modules/plug"]);
    // a store directory left from before, outside the lockfile, is extraneous
    expect(r.extraneous.map((f) => f.path)).toEqual(["node_modules/.pnpm/host@1.0.0/node_modules/host"]);
  });
});

describe("pnpm: a bundled dependency is inside its parent's tarball (finding 8)", () => {
  const lock = pnpmLock({
    importers: { ".": { dependencies: { "bundle-root": { specifier: "1.0.0", version: "1.0.0" } } } },
    packages: { "bundle-root@1.0.0": { resolution: { integrity: sha("b") } } },
    snapshots: { "bundle-root@1.0.0": {} },
  });

  const lay = (root: string, declares: boolean): void => {
    const at = stored(root, "bundle-root@1.0.0", "bundle-root", "1.0.0", declares ? { bundleDependencies: ["leaf"] } : {});

    pkg(join(at, "node_modules", "leaf"), "leaf", "1.0.0");
    link(join(root, "node_modules", "bundle-root"), ".pnpm/bundle-root@1.0.0/node_modules/bundle-root");
  };

  test("a package the parent's bundleDependencies name is embedded, for the caller to check its state (on 2a098b1: refused as a package the lockfile does not hold)", () => {
    const root = project();

    lay(root, true);
    const r = verify({ pm: "pnpm", root, file: "pnpm-lock.yaml", text: lock });

    expect(r.kind).toBe("verified");
    expect(r.embedded).toEqual([{ name: "leaf", version: "1.0.0", path: "node_modules/.pnpm/bundle-root@1.0.0/node_modules/bundle-root/node_modules/leaf", under: "bundle-root@1.0.0" }]);
  });

  test("one its parent does not bundle is no bundle: not the checked lockfile", () => {
    const root = project();

    lay(root, false);
    expect(verify({ pm: "pnpm", root, file: "pnpm-lock.yaml", text: lock }).problems).toEqual(["node_modules holds a package the checked lockfile does not: leaf@1.0.0"]);
  });
});

describe("bun: a local dependency is found by where the lockfile resolves it, not by its source spec (finding 7)", () => {
  test("a file: tarball dependency with an install script is placed, with the version its package.json holds", () => {
    const root = project();
    const lock = JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "p", dependencies: { "local-leaf": "file:../local-leaf-1.0.0.tgz" } } }, packages: { "local-leaf": ["local-leaf@file:../local-leaf-1.0.0.tgz", { hasInstallScript: true }] } });

    pkg(join(root, "node_modules", "local-leaf"), "local-leaf", "1.0.0", { scripts: { postinstall: "node mark.js" } });
    const r = verify({ pm: "bun", root, file: "bun.lock", text: lock });

    expect(r.problems).toEqual([]);
    // on 2a098b1: no directory matched "file:../local-leaf-1.0.0.tgz", so its script was held forever
    expect(r.placed).toEqual([{ key: "local-leaf", path: "node_modules/local-leaf", name: "local-leaf", version: "1.0.0", scripts: true }]);
  });
});

describe("removing a directory for bun to install again (finding 5)", () => {
  test("node_modules linked to a directory outside the project: nothing is removed, and that directory is untouched (on 2a098b1: deleted)", () => {
    const root = project();
    const external = project();

    pkg(join(external, "leaf"), "leaf", "1.0.0");
    writeFileSync(join(external, "leaf", "USER-PATCH"), "keep");
    symlinkSync(external, join(root, "node_modules"));
    const r = removeInstalled({ root, members: [], path: "node_modules/leaf" });

    expect(r.kind).toBe("refused");
    expect(readFileSync(join(external, "leaf", "USER-PATCH"), "utf8")).toBe("keep");
    expect(existsSync(join(external, "leaf", "package.json"))).toBe(true);
  });

  test("a path through a link inside node_modules is refused; a real directory inside it is removed", () => {
    const root = project();
    const external = project();

    pkg(join(external, "shared"), "shared", "1.0.0");
    link(join(root, "node_modules", "via"), external);
    pkg(join(root, "node_modules", "own"), "own", "1.0.0");

    expect(removeInstalled({ root, members: [], path: "node_modules/via/shared" }).kind).toBe("refused");
    expect(existsSync(join(external, "shared", "package.json"))).toBe(true);
    expect(removeInstalled({ root, members: [], path: "node_modules/own" })).toEqual({ kind: "removed" });
    expect(existsSync(join(root, "node_modules", "own"))).toBe(false);
  });

  test("outside node_modules (a workspace folder) is refused", () => {
    const root = project();

    pkg(join(root, "packages", "app"), "app", "1.0.0");
    mkdirSync(join(root, "node_modules"));
    expect(removeInstalled({ root, members: ["packages/app"], path: "packages/app" }).kind).toBe("refused");
    expect(existsSync(join(root, "packages", "app", "package.json"))).toBe(true);
  });
});
