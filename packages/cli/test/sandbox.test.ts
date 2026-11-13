// Review of a2227d1, finding 12: cleanup followed a symlink out of the project and deleted there. apm's only deletion
// now is of its own temporary directories: made fresh under TMPDIR, and removed without following a symlink out.
// Its only writes to a project are package.json and the lockfile, each replaced in one rename.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { isOwnTemp, makeTemp, removeTemp, writeAtomic } from "../src/sandbox.ts";
import { projectLayout, staysInside } from "../src/project.ts";

let outside: string;
let scratch: string;
const savedTmp = process.env.TMPDIR;

beforeAll(() => {
  outside = mkdtempSync(join(tmpdir(), "apm-sandbox-outside-"));
  scratch = mkdtempSync(join(tmpdir(), "apm-sandbox-tmp-"));
  process.env.TMPDIR = scratch;
});

afterAll(() => {
  process.env.TMPDIR = savedTmp;
  rmSync(outside, { recursive: true, force: true });
  rmSync(scratch, { recursive: true, force: true });
});

describe("temporary directories", () => {
  test("are made under TMPDIR's real path, private, with apm's prefix", () => {
    const dir = makeTemp("add");

    expect(dirname(dir)).toBe(realpathSync(scratch));
    expect(dir).toContain("apm-add-");
    expect(lstatSync(dir).mode & 0o777).toBe(0o700);
    removeTemp(dir);
    expect(existsSync(dir)).toBe(false);
  });

  test("removal never follows a symlink out: what the links point at survives", () => {
    const dir = makeTemp("add");
    const victim = join(outside, "store", "leaf");

    mkdirSync(victim, { recursive: true });
    writeFileSync(join(victim, "package.json"), "{}");
    // the shapes that bit a2227d1: a .pnpm store link, a scoped directory link, and a plain link to a package
    mkdirSync(join(dir, "node_modules", "@scope"), { recursive: true });
    symlinkSync(join(outside, "store"), join(dir, "node_modules", ".pnpm"));
    symlinkSync(join(outside, "store"), join(dir, "node_modules", "@scope", "pkg"));
    symlinkSync(victim, join(dir, "node_modules", "leaf"));
    removeTemp(dir);

    expect(existsSync(dir)).toBe(false);
    expect(readFileSync(join(victim, "package.json"), "utf8")).toBe("{}");
  });

  test("anything that is not one of apm's own temporary directories is left alone", () => {
    const notOurs = mkdtempSync(join(outside, "apm-add-"));
    const link = join(realpathSync(scratch), "apm-add-link");

    symlinkSync(notOurs, link);
    const unprefixed = mkdtempSync(join(realpathSync(scratch), "other-"));

    // removeTemp takes only a TempDir, which only this guard makes; it asks again before it removes
    for (const d of [notOurs, link, unprefixed, outside]) expect(isOwnTemp(d)).toBe(false);
  });
});

// review of 2a098b1, finding 15: the umask must not take permission bits from the file a write replaces
test("writeAtomic keeps a group-writable file's mode under umask 0022 (on 2a098b1: 0664 became 0644)", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "apm-mode-")));
  const file = join(dir, "package.json");
  const old = process.umask(0o022);

  try {
    writeFileSync(file, "{}");
    chmodSync(file, 0o664);
    writeAtomic(file, new TextEncoder().encode('{"new":true}'));

    expect(lstatSync(file).mode & 0o777).toBe(0o664);
    expect(readFileSync(file, "utf8")).toBe('{"new":true}');
  } finally {
    process.umask(old);
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("the writes to a project", () => {
  test("replace the file whole in one rename, keeping its mode, and leave nothing beside it", () => {
    const dir = mkdtempSync(join(outside, "project-"));

    writeFileSync(join(dir, "package.json"), "old", { mode: 0o640 });
    writeAtomic(join(dir, "package.json"), new TextEncoder().encode("new"));

    expect(readFileSync(join(dir, "package.json"), "utf8")).toBe("new");
    expect(lstatSync(join(dir, "package.json")).mode & 0o777).toBe(0o640);
    expect([...new Bun.Glob("*").scanSync({ cwd: dir, dot: true })]).toEqual(["package.json"]);
  });
});

describe("what apm copies", () => {
  test("relative paths that leave the project are never copied", () => {
    expect(staysInside("patches/leaf.patch")).toBe(true);
    expect(staysInside("../outside.patch")).toBe(false);
    expect(staysInside("/etc/passwd")).toBe(false);
    expect(staysInside("a/../../b")).toBe(false);
  });

  test("a workspace: the root's manifest, lockfile and config, every member's manifest, and in-project patch files only", () => {
    const root = mkdtempSync(join(outside, "ws-"));

    mkdirSync(join(root, "packages", "a"), { recursive: true });
    mkdirSync(join(root, "packages", "b"), { recursive: true });
    mkdirSync(join(root, "packages", "a", "node_modules", "dep"), { recursive: true });
    mkdirSync(join(root, "patches"));
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "top", workspaces: ["packages/*"], patchedDependencies: { "leaf@1.0.0": "patches/leaf.patch", "evil@1.0.0": "../outside.patch" } }));
    writeFileSync(join(root, "patches", "leaf.patch"), "");
    writeFileSync(join(root, "bun.lock"), "{}");
    writeFileSync(join(root, "bunfig.toml"), "");
    writeFileSync(join(root, "packages", "a", "package.json"), JSON.stringify({ name: "a", version: "1.0.0" }));
    writeFileSync(join(root, "packages", "b", "package.json"), JSON.stringify({ name: "b", version: "2.0.0" }));
    writeFileSync(join(root, "packages", "a", "node_modules", "dep", "package.json"), "{}");
    writeFileSync(join(root, "packages", "a", "src.ts"), "secret source");

    const r = projectLayout({ cwd: join(root, "packages", "a"), pm: "bun" });

    expect(r.kind).toBe("ok");

    if (r.kind !== "ok") return;
    expect(r.layout.root).toBe(root);
    expect(r.layout.member).toBe("packages/a");
    expect(r.layout.copy.sort()).toEqual(["bun.lock", "bunfig.toml", "package.json", "packages/a/package.json", "packages/b/package.json", "patches/leaf.patch"]);
    expect(r.layout.members).toEqual([
      { dir: "packages/a", name: "a", version: "1.0.0" },
      { dir: "packages/b", name: "b", version: "2.0.0" },
    ]);
  });

  test("npm: npm-shrinkwrap.json is the lockfile when both are there", () => {
    const root = mkdtempSync(join(outside, "shrink-"));

    writeFileSync(join(root, "package.json"), "{}");
    writeFileSync(join(root, "package-lock.json"), "{}");
    writeFileSync(join(root, "npm-shrinkwrap.json"), "{}");
    const r = projectLayout({ cwd: root, pm: "npm" });

    expect(r.kind === "ok" ? [r.layout.lockfile, r.layout.copy.includes("package-lock.json")] : null).toEqual(["npm-shrinkwrap.json", false]);
  });
});
