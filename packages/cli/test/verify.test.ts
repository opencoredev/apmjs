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
import { pnpmRebuildable, removeInstalled, verifyInstall, type Placed } from "../src/verify.ts";

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
function verify(input: { pm: LockPm; root: string; file: string; text: string; members?: { dir: string; name: string; version: string }[]; before?: ReturnType<typeof installedPackages>["found"]; omitDev?: boolean; host?: { os: string; cpu: string } }) {
  writeFileSync(join(input.root, input.file), input.text);
  const read = readLock({ pm: input.pm, path: join(input.root, input.file), cwd: input.root });

  if (read.kind !== "read") throw new Error(`fixture lockfile unreadable: ${JSON.stringify(read)}`);

  return verifyInstall({ pm: input.pm, root: input.root, lockfile: input.file, checked: new Uint8Array(readFileSync(join(input.root, input.file))), nodes: read.nodes, importers: read.importers, members: input.members ?? [], before: input.before ?? [], omitted: { dev: input.omitDev === true }, host: input.host });
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

describe("optional dependencies the package manager left out", () => {
  test("bun: an optional dependency with no os or cpu of its own, and what only it needs, may both be missing (apm add next on staging)", () => {
    const root = project();

    const lock = JSON.stringify({
      lockfileVersion: 1,
      workspaces: { "": { name: "p", dependencies: { sharp: "0.35.5" } } },
      packages: {
        sharp: ["sharp@0.35.5", "", { dependencies: { colour: "^1.1.0" }, optionalDependencies: { "sharp-wasm32": "0.35.5" } }, "sha512-s"],
        colour: ["colour@1.1.0", "", {}, "sha512-c"],
        "sharp-wasm32": ["sharp-wasm32@0.35.5", "", { dependencies: { "emnapi-runtime": "^1.11.3" } }, "sha512-w"],
        "emnapi-runtime": ["emnapi-runtime@1.11.3", "", {}, "sha512-e"],
      },
    });

    pkg(join(root, "node_modules", "sharp"), "sharp", "0.35.5");
    pkg(join(root, "node_modules", "colour"), "colour", "1.1.0");
    const r = verify({ pm: "bun", root, file: "bun.lock", text: lock });

    expect(r.problems).toEqual([]);
    rmSync(join(root, "node_modules", "colour"), { recursive: true });
    // a required dependency of an installed package is still required
    expect(verify({ pm: "bun", root, file: "bun.lock", text: lock }).problems).toEqual(["colour (colour@1.1.0), which sharp@0.35.5 (node_modules/sharp) needs, is not installed"]);
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

// ---------- review of 2b7767f ----------

describe("finding 1: a store outside the project is walked like one inside it", () => {
  const lock = pnpmLock({
    importers: { ".": { dependencies: { a: { specifier: "1.0.0", version: "1.0.0" } } } },
    packages: { "a@1.0.0": { resolution: { integrity: sha("a") } }, "leaf@2.0.0": { resolution: { integrity: sha("leaf") } } },
    snapshots: { "a@1.0.0": { dependencies: { leaf: "2.0.0" } }, "leaf@2.0.0": {} },
  });

  /** node_modules/.pnpm a link to a store outside the project (or a store inside it), a@1.0.0 there, its leaf at `leaf`. */
  const lay = (input: { external: boolean; leaf: string }): string => {
    const root = project();
    const store = input.external ? join(base, `store${++n}`) : join(root, "node_modules", ".pnpm");
    const a = join(store, "a@1.0.0", "node_modules", "a");

    pkg(a, "a", "1.0.0");
    pkg(join(store, `leaf@${input.leaf}`, "node_modules", "leaf"), "leaf", input.leaf);
    link(join(store, "a@1.0.0", "node_modules", "leaf"), `../../leaf@${input.leaf}/node_modules/leaf`);
    mkdirSync(join(root, "node_modules"), { recursive: true });

    if (input.external) symlinkSync(store, join(root, "node_modules", ".pnpm"));
    link(join(root, "node_modules", "a"), ".pnpm/a@1.0.0/node_modules/a");

    return root;
  };

  for (const external of [false, true]) {
    test(`${external ? "external" : "internal"} store: a's leaf at 9.9.9 where the lockfile locks 2.0.0 is a mismatch${external ? " (on 2b7767f: verified, the walk stopped at the project's edge)" : ""}`, () => {
      const r = verify({ pm: "pnpm", root: lay({ external, leaf: "9.9.9" }), file: "pnpm-lock.yaml", text: lock });

      expect(r.kind).toBe("mismatch");
      expect(r.problems.some((p) => p.includes("resolves leaf to leaf@9.9.9") && p.includes("locks leaf@2.0.0 there")), JSON.stringify(r.problems)).toBe(true);
    });

    test(`${external ? "external" : "internal"} store laid as locked: verified, the store's packages placed`, () => {
      const r = verify({ pm: "pnpm", root: lay({ external, leaf: "2.0.0" }), file: "pnpm-lock.yaml", text: lock });

      expect(r.problems).toEqual([]);
      expect(r.kind).toBe("verified");
      expect(r.placed.map((p) => `${p.name}@${p.version}`).toSorted()).toEqual(["a@1.0.0", "leaf@2.0.0"]);
    });
  }

  test("a required dependency missing in the external store is a mismatch", () => {
    const root = lay({ external: true, leaf: "2.0.0" });
    const store = realpathSync(join(root, "node_modules", ".pnpm"));

    rmSync(join(store, "a@1.0.0", "node_modules", "leaf"));
    const r = verify({ pm: "pnpm", root, file: "pnpm-lock.yaml", text: lock });

    expect(r.kind).toBe("mismatch");
    expect(r.problems.some((p) => p.startsWith("leaf (leaf@2.0.0), which a@1.0.0"))).toBe(true);
  });
});

describe("finding 2: a platform is no optionality", () => {
  const host = { os: "linux", cpu: "x64" };

  const pnpm = (os: string) =>
    pnpmLock({
      importers: { ".": { dependencies: { native: { specifier: "1.0.0", version: "1.0.0" } } } },
      packages: { "native@1.0.0": { resolution: { integrity: sha("n") }, os: [os], cpu: ["x64"] } },
      snapshots: { "native@1.0.0": {} },
    });

  const bun = (os: string) => JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "p", dependencies: { native: "1.0.0" } } }, packages: { native: ["native@1.0.0", "", { os: [os], cpu: ["x64"] }, sha("n")] } });

  for (const pm of ["pnpm", "bun"] as const) {
    const file = pm === "pnpm" ? "pnpm-lock.yaml" : "bun.lock";
    const text = pm === "pnpm" ? pnpm : bun;

    test(`${pm}: a required dependency built for this platform that is not installed is a mismatch (on 2b7767f: verified)`, () => {
      const root = project();

      mkdirSync(join(root, "node_modules"));
      const r = verify({ pm, root, file, text: text("linux"), host });

      expect(r.kind).toBe("mismatch");
      expect(r.problems).toContain("native (native@1.0.0), which your project needs, is not installed");
    });

    test(`${pm}: one built for another platform may be missing, as the package manager skips it`, () => {
      const root = project();

      mkdirSync(join(root, "node_modules"));
      expect(verify({ pm, root, file, text: text("darwin"), host }).kind).toBe("verified");
    });
  }

  test("npm's !os exclusions: a package excluded on this platform may be missing, one only excluded elsewhere may not", () => {
    const lock = (os: string) => npmLock({ "": { name: "p", dependencies: { native: "1.0.0" } }, "node_modules/native": { version: "1.0.0", resolved: "https://r.test/native/-/native-1.0.0.tgz", integrity: sha("n"), os: [os] } });
    const a = project();
    const b = project();

    mkdirSync(join(a, "node_modules"));
    mkdirSync(join(b, "node_modules"));
    expect(verify({ pm: "npm", root: a, file: "package-lock.json", text: lock("!linux"), host }).kind).toBe("verified");
    expect(verify({ pm: "npm", root: b, file: "package-lock.json", text: lock("!win32"), host }).kind).toBe("mismatch");
  });
});

describe("finding 3: a production install leaves devDependencies out", () => {
  // devonly is the project's devDependency and needs shared; prod is a dependency and needs shared too
  const npm = npmLock({
    "": { name: "p", dependencies: { prod: "1.0.0" }, devDependencies: { devonly: "1.0.0" } },
    "node_modules/prod": { version: "1.0.0", resolved: "https://r.test/prod/-/prod-1.0.0.tgz", integrity: sha("p"), dependencies: { shared: "1.0.0" } },
    "node_modules/shared": { version: "1.0.0", resolved: "https://r.test/shared/-/shared-1.0.0.tgz", integrity: sha("s") },
    "node_modules/devonly": { version: "1.0.0", resolved: "https://r.test/devonly/-/devonly-1.0.0.tgz", integrity: sha("d"), dev: true, dependencies: { shared: "1.0.0" } },
  });

  const lay = (input: { shared: boolean }): string => {
    const root = project();

    pkg(join(root, "node_modules", "prod"), "prod", "1.0.0");

    if (input.shared) pkg(join(root, "node_modules", "shared"), "shared", "1.0.0");

    return root;
  };

  test("npm --omit=dev: the devDependency is not installed, and that is what was asked (on 2b7767f: a mismatch)", () => {
    const r = verify({ pm: "npm", root: lay({ shared: true }), file: "package-lock.json", text: npm, omitDev: true });

    expect(r.problems).toEqual([]);
    expect(r.kind).toBe("verified");
  });

  test("without the omission, the same tree is missing a devDependency", () => {
    const r = verify({ pm: "npm", root: lay({ shared: true }), file: "package-lock.json", text: npm, omitDev: false });

    expect(r.problems).toContain("devonly (devonly@1.0.0), which your project needs, is not installed");
  });

  test("a production dependency the dev graph shares stays required", () => {
    const r = verify({ pm: "npm", root: lay({ shared: false }), file: "package-lock.json", text: npm, omitDev: true });

    expect(r.problems).toContain("shared (shared@1.0.0), which prod@1.0.0 (node_modules/prod) needs, is not installed");
  });

  test("a devDependency that is installed anyway must still be the locked version", () => {
    const root = lay({ shared: true });

    pkg(join(root, "node_modules", "devonly"), "devonly", "6.6.6");
    expect(verify({ pm: "npm", root, file: "package-lock.json", text: npm, omitDev: true }).kind).toBe("mismatch");
  });

  test("pnpm --prod and bun --production: an importer's devDependency may be missing", () => {
    const pnpm = pnpmLock({
      importers: { ".": { dependencies: { prod: { specifier: "1.0.0", version: "1.0.0" } }, devDependencies: { devonly: { specifier: "1.0.0", version: "1.0.0" } } } },
      packages: { "prod@1.0.0": { resolution: { integrity: sha("p") } }, "devonly@1.0.0": { resolution: { integrity: sha("d") } } },
      snapshots: { "prod@1.0.0": {}, "devonly@1.0.0": {} },
    });

    const bun = JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "p", dependencies: { prod: "1.0.0" }, devDependencies: { devonly: "1.0.0" } } }, packages: { prod: ["prod@1.0.0", "", {}, sha("p")], devonly: ["devonly@1.0.0", "", {}, sha("d")] } });
    const p1 = project();
    const p2 = project();

    link(join(p1, "node_modules", "prod"), ".pnpm/prod@1.0.0/node_modules/prod");
    stored(p1, "prod@1.0.0", "prod", "1.0.0");
    pkg(join(p2, "node_modules", "prod"), "prod", "1.0.0");
    expect(verify({ pm: "pnpm", root: p1, file: "pnpm-lock.yaml", text: pnpm, omitDev: true }).problems).toEqual([]);
    expect(verify({ pm: "pnpm", root: p1, file: "pnpm-lock.yaml", text: pnpm, omitDev: false }).kind).toBe("mismatch");
    expect(verify({ pm: "bun", root: p2, file: "bun.lock", text: bun, omitDev: true }).problems).toEqual([]);
    expect(verify({ pm: "bun", root: p2, file: "bun.lock", text: bun, omitDev: false }).kind).toBe("mismatch");
  });
});

describe("finding 4: pnpm file-tarball dependencies keep their edges", () => {
  // the lockfile real pnpm 10 writes for a and b tarballs that depend on two leaf tarballs (the review's layout)
  const lock = pnpmLock({
    importers: { ".": { dependencies: { a: { specifier: "file:/abs/a-1.0.0.tgz", version: "file:../a-1.0.0.tgz" }, b: { specifier: "file:/abs/b-1.0.0.tgz", version: "file:../b-1.0.0.tgz" } } } },
    packages: {
      "a@file:../a-1.0.0.tgz": { resolution: { integrity: sha("a"), tarball: "file:../a-1.0.0.tgz" }, version: "1.0.0" },
      "b@file:../b-1.0.0.tgz": { resolution: { integrity: sha("b"), tarball: "file:../b-1.0.0.tgz" }, version: "1.0.0" },
      "leaf@file:../leaf-1.0.0.tgz": { resolution: { integrity: sha("l1"), tarball: "file:../leaf-1.0.0.tgz" }, version: "1.0.0" },
      "leaf@file:../leaf-2.0.0.tgz": { resolution: { integrity: sha("l2"), tarball: "file:../leaf-2.0.0.tgz" }, version: "2.0.0" },
    },
    snapshots: { "a@file:../a-1.0.0.tgz": { dependencies: { leaf: "file:../leaf-1.0.0.tgz" } }, "b@file:../b-1.0.0.tgz": { dependencies: { leaf: "file:../leaf-2.0.0.tgz" } }, "leaf@file:../leaf-1.0.0.tgz": {}, "leaf@file:../leaf-2.0.0.tgz": {} },
  });

  /** pnpm's isolated layout: a store directory per tarball, named as pnpm names it. */
  const lay = (input: { leafUnderB: string }): string => {
    const root = project();
    const dir = (id: string): string => id.replace("file:../", "file+..+");

    stored(root, dir("a@file:../a-1.0.0.tgz"), "a", "1.0.0");
    stored(root, dir("b@file:../b-1.0.0.tgz"), "b", "1.0.0");
    stored(root, dir("leaf@file:../leaf-1.0.0.tgz"), "leaf", "1.0.0");
    stored(root, dir("leaf@file:../leaf-2.0.0.tgz"), "leaf", "2.0.0");
    link(join(root, "node_modules", ".pnpm", dir("a@file:../a-1.0.0.tgz"), "node_modules", "leaf"), `../../${dir("leaf@file:../leaf-1.0.0.tgz")}/node_modules/leaf`);
    link(join(root, "node_modules", ".pnpm", dir("b@file:../b-1.0.0.tgz"), "node_modules", "leaf"), `../../${dir(`leaf@file:../leaf-${input.leafUnderB}.tgz`)}/node_modules/leaf`);
    link(join(root, "node_modules", "a"), `.pnpm/${dir("a@file:../a-1.0.0.tgz")}/node_modules/a`);
    link(join(root, "node_modules", "b"), `.pnpm/${dir("b@file:../b-1.0.0.tgz")}/node_modules/b`);

    return root;
  };

  test("the snapshot's file: references resolve to their lock keys, each node kept once with its edges (on 2b7767f: the edges were dropped)", () => {
    const root = project();

    writeFileSync(join(root, "pnpm-lock.yaml"), lock);
    const read = readLock({ pm: "pnpm", path: join(root, "pnpm-lock.yaml"), cwd: root });

    if (read.kind !== "read") throw new Error(read.kind);
    expect(read.nodes.find((x) => x.key === "a@file:../a-1.0.0.tgz")?.deps).toEqual([{ name: "leaf", key: "leaf@file:../leaf-1.0.0.tgz", optional: false, dev: false }]);
    expect(read.nodes.filter((x) => x.key === "a@file:../a-1.0.0.tgz")).toHaveLength(1);
    expect(read.nodes.find((x) => x.key === "a@file:../a-1.0.0.tgz")?.origin).toEqual({ kind: "file", source: "file:../a-1.0.0.tgz" });
  });

  test("the isolated layout pnpm installs is verified (on 2b7767f: leaf@1.0.0 and leaf@2.0.0 refused as packages the lockfile does not hold)", () => {
    const r = verify({ pm: "pnpm", root: lay({ leafUnderB: "2.0.0" }), file: "pnpm-lock.yaml", text: lock });

    expect(r.problems).toEqual([]);
    expect(r.placed.map((p) => `${p.name}@${p.version}`).toSorted()).toEqual(["a@1.0.0", "b@1.0.0", "leaf@1.0.0", "leaf@2.0.0"]);
  });

  test("b linked to the other leaf tarball is a mismatch", () => {
    const r = verify({ pm: "pnpm", root: lay({ leafUnderB: "1.0.0" }), file: "pnpm-lock.yaml", text: lock });

    expect(r.kind).toBe("mismatch");
  });
});

describe("finding 5: pnpm rebuild reaches every copy of a version", () => {
  const placed = (path: string, version: string): Placed => ({ key: `leaf@${version}`, path, name: "leaf", version, scripts: true });

  test("a version whose every copy is fresh is rebuilt; one with an older copy is held (on 2b7767f: rebuilt, running the old copy's script again)", () => {
    const fresh = [placed("node_modules/.pnpm/leaf@1.0.0_peer@2.0.0/node_modules/leaf", "1.0.0"), placed("node_modules/.pnpm/leaf@2.0.0/node_modules/leaf", "2.0.0")];
    const installed = [...fresh, { path: "node_modules/.pnpm/leaf@1.0.0_peer@1.0.0/node_modules/leaf", name: "leaf", version: "1.0.0" }];

    expect(pnpmRebuildable({ fresh, installed })).toEqual({ specs: ["leaf@2.0.0"], held: ["leaf@1.0.0"] });
  });

  test("a local package is rebuilt by name, so any other copy of that name holds it", () => {
    const fresh = [{ key: "tool@file:x", path: "node_modules/.pnpm/tool@file+x/node_modules/tool", name: "tool", version: "file:x", scripts: true }];

    expect(pnpmRebuildable({ fresh, installed: [...fresh, { path: "node_modules/.pnpm/tool@1.0.0/node_modules/tool", name: "tool", version: "1.0.0" }] })).toEqual({ specs: [], held: ["tool"] });
    expect(pnpmRebuildable({ fresh, installed: fresh })).toEqual({ specs: ["tool"], held: [] });
  });
});
