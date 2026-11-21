// The smoke check of a deployed stage installs from a registry whose answers are untrusted, so no install it runs may
// execute a package's code (smoke-commands.ts). --ignore-scripts is not enough: npm still runs a git dependency's
// `prepare` (review of 4a9c8fb, finding 1; the reproducer is below). So smoke's raw npm and bun installs install
// committed lockfiles, frozen: a registry can serve the locked bytes or fail the install, never add a dependency.
//
// Real npm and bun against a local stand-in registry that can lie: metadata that adds a git dependency, a tarball
// swapped for one that depends on a git repository (with metadata to match), or a redirect to another host for the
// bytes. The git repository's prepare and the package's postinstall only write marker files.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { apmAdd, bunInstallLocked, InstallMetadata, lockedEntries, metadataProblem, type Locked, NO_SCRIPTS, NO_SCRIPTS_ENV, NPM_HOST, npmCi, PROBE_NAMES, PROBES, probeFixture, singleLockfile, tarballPath } from "../smoke-commands.ts";

const SMOKE = readFileSync(join(import.meta.dirname, "..", "smoke.ts"), "utf8");

describe("the smoke check's install commands", () => {
  test("every builder runs no install script, and the raw installs are frozen installs of a lockfile", () => {
    expect(npmCi("https://r.test/")).toEqual(["npm", "ci", NO_SCRIPTS, "--no-audit", "--no-fund", "--registry=https://r.test/", "--replace-registry-host=npmjs"]);
    expect(bunInstallLocked("https://r.test/")).toEqual(["bun", "install", "--frozen-lockfile", NO_SCRIPTS, "--registry=https://r.test/"]);
    expect(apmAdd("/cli/main.ts", "three@0.187.0", ["--strict"])).toEqual(["bun", "/cli/main.ts", "add", "three@0.187.0", NO_SCRIPTS, "--strict"]);
    expect(NO_SCRIPTS).toBe("--ignore-scripts");
    expect(NO_SCRIPTS_ENV).toEqual({ npm_config_ignore_scripts: "true", APM_IGNORE_SCRIPTS: "1" });
    expect(tarballPath("@a/b", "1.0.0")).toBe("@a/b/-/b-1.0.0.tgz");
  });

  test("smoke.ts runs every install through them, and every command it runs gets the no-scripts environment", () => {
    // each command smoke runs is a literal array or a builder call passed to run(...)
    const literal = [...SMOKE.matchAll(/\brun\(\[([^\]]*)\]/g)].map((m) => m[1] ?? "");
    const verbs = /"(add|install|i|ci|update|upgrade|rebuild|x|exec|dlx)"/;

    expect(literal.length).toBeGreaterThan(0);

    for (const args of literal) expect(args, `smoke.ts runs ${args} without a no-scripts builder`).not.toMatch(verbs);
    // two stock installs, three apm adds, the audit fixture's install and the staging consumer's
    expect([...SMOKE.matchAll(/\brun\((bunInstallLocked|npmCi|apmAdd)\(/g)].map((m) => m[1])).toEqual(["bunInstallLocked", "npmCi", "apmAdd", "apmAdd", "apmAdd", "bunInstallLocked", "npmCi"]);
    // run() spreads NO_SCRIPTS_ENV last, so no caller's env turns scripts back on
    expect(SMOKE).toMatch(/TMPDIR: tmpdir\(\), \.\.\.env, \.\.\.NO_SCRIPTS_ENV \}/);
    expect(SMOKE).not.toMatch(/Bun\.spawn(Sync)?\(\[\s*"(bun|npm|pnpm|yarn|npx|bunx)"/);
  });

  test("no install result is thrown away: every command smoke.ts runs is kept and checked (review of 96f0ba7, finding 5)", () => {
    expect(SMOKE).not.toMatch(/^\s*await run\(/m);
    // the audit runs only after its locked install passed, and that install is a check of its own
    const audit = SMOKE.slice(SMOKE.indexOf("async function bunAudit"), SMOKE.indexOf("// ---------- staged publish"));

    expect(audit).toContain("const add = await run(bunInstallLocked(registry), dir);");
    expect(audit).toMatch(/record\(installOk, "bun install of the locked audit project/);
    expect(audit.indexOf("if (!installOk)")).toBeLessThan(audit.indexOf('run(["bun", "audit"]'));
  });

  test("smoke.ts checks install metadata exactly, for the probes and for the approved staged version (review of 96f0ba7, finding 4)", () => {
    expect(SMOKE).not.toContain("startsWith(registry)");
    expect(SMOKE).toContain('metadataProblem({ registry, ...(await installMetadata(l.name)), locked: l, latest: "listed" })');
    expect(SMOKE).toContain('metadataProblem({ registry, ...(await installMetadata(name)), locked: expected, latest: "this" })');
    expect(SMOKE).not.toMatch(/live\.status === 200/);
  });

  test.each(PROBE_NAMES)("the committed %s fixture pins only exact registry versions, each with an integrity", (probe) => {
    const { files, locked } = probeFixture(probe);

    expect(locked.length).toBeGreaterThan(0);
    expect(Object.keys(files).sort()).toEqual(["package.json", PROBES[probe].lockfile].sort());

    for (const l of locked) expect(l.integrity).toMatch(/^sha512-/);
  });

  test("the fixture check refuses a git, remote or unpinned entry, and one with no integrity", () => {
    const manifest = JSON.stringify({ name: "p", version: "1.0.0", private: true, dependencies: { a: "1.0.0" } });
    const npm = (entry: { version: string; resolved: string; integrity?: string }) => JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { a: "1.0.0" } }, "node_modules/a": entry } });
    const sri = `sha512-${"A".repeat(86)}==`;

    const none = { installs: {}, peers: {} };

    expect(lockedEntries("npm", manifest, npm({ version: "1.0.0", resolved: `${NPM_HOST}a/-/a-1.0.0.tgz`, integrity: sri }))).toEqual([{ name: "a", version: "1.0.0", integrity: sri, edges: none }]);
    expect(() => lockedEntries("npm", manifest, npm({ version: "1.0.0", resolved: "git+ssh://git@github.com/x/a.git#abc", integrity: sri }))).toThrow("not its registry tarball");
    expect(() => lockedEntries("npm", manifest, npm({ version: "1.0.0", resolved: "https://evil.test/a-1.0.0.tgz", integrity: sri }))).toThrow("not its registry tarball");
    expect(() => lockedEntries("npm", manifest, npm({ version: "1.0.0", resolved: `${NPM_HOST}a/-/a-1.0.0.tgz` }))).toThrow("sha512 integrity");
    expect(() => lockedEntries("npm", JSON.stringify({ name: "p", version: "1.0.0", private: true, dependencies: { a: "^1.0.0" } }), npm({ version: "1.0.0", resolved: `${NPM_HOST}a/-/a-1.0.0.tgz`, integrity: sri }))).toThrow();
    const bun = (entry: unknown[]) => JSON.stringify({ workspaces: { "": { dependencies: { a: "1.0.0" } } }, packages: { a: entry } });

    expect(lockedEntries("bun", manifest, bun(["a@1.0.0", "", {}, sri]))).toEqual([{ name: "a", version: "1.0.0", integrity: sri, edges: none }]);
    expect(() => lockedEntries("bun", manifest, bun(["a@github:x/a#abc", {}, "abc"]))).toThrow();
    expect(() => lockedEntries("bun", manifest, bun(["a@1.0.0", "https://evil.test/a-1.0.0.tgz", {}, sri]))).toThrow();
  });
});

// ---------- real npm and bun against a local registry that can lie ----------
type Mode = "honest" | "git-in-metadata" | "swapped-tarball" | "redirect";

let dir: string;
let marks: string;
let gitUrl: string;
let server: ReturnType<typeof Bun.serve>;
let url: string;
let mode: Mode = "honest";
const fetched: string[] = [];

type Built = { name: string; version: string; tgz: Uint8Array<ArrayBuffer>; integrity: string; deps: Record<string, string> };

const built = new Map<string, Built>();

const sri = (bytes: Uint8Array): string => `sha512-${createHash("sha512").update(bytes).digest("base64")}`;

function env(extra: Record<string, string> = {}) {
  // a fresh cache every run: every tarball is fetched, so the log and the server see it
  const cache = mkdtempSync(join(dir, "cache-"));

  return { PATH: process.env.PATH ?? "", HOME: dir, TMPDIR: dir, npm_config_cache: join(cache, "npm"), BUN_INSTALL_CACHE_DIR: join(cache, "bun"), npm_config_update_notifier: "false", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", ...extra };
}

/** Runs a command (async: the stand-in registry answers from this same process). */
async function sh(cmd: string[], cwd: string, extra: Record<string, string> = {}): Promise<{ code: number; out: string }> {
  const proc = Bun.spawn(cmd, { cwd, env: env(extra), stdout: "pipe", stderr: "pipe", stdin: "ignore" });
  const timer = setTimeout(() => proc.kill(), 120_000);
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  clearTimeout(timer);

  return { code, out: out + err };
}

/** A package directory packed to a tarball: its bytes and integrity. */
async function pack(name: string, version: string, deps: Record<string, string>, scripts: Record<string, string> = {}): Promise<Built> {
  const src = mkdtempSync(join(dir, `src-${name}-`));

  writeFileSync(join(src, "package.json"), JSON.stringify({ name, version, main: "index.js", dependencies: deps, scripts }));
  writeFileSync(join(src, "index.js"), "module.exports = 1;\n");
  writeFileSync(join(src, "mark.js"), `require("node:fs").writeFileSync(require("node:path").join(${JSON.stringify(marks)}, ${JSON.stringify(name)} + "-" + process.env.npm_lifecycle_event + "-" + process.pid), "ran");\n`);
  const r = await sh(["npm", "pack", "--ignore-scripts", "--pack-destination", src], src);

  if (r.code !== 0) throw new Error(`npm pack ${name}: ${r.out}`);
  const tgz = new Uint8Array(readFileSync(join(src, `${name}-${version}.tgz`)));

  return { name, version, tgz, integrity: sri(tgz), deps };
}

/** What the stand-in serves for a name in the current mode. */
function served(name: string): Built | undefined {
  const honest = built.get(name);

  if (honest === undefined) return undefined;

  if (name === "okpkg" && mode === "git-in-metadata") return { ...honest, deps: { gitdep: gitUrl } };

  if (name === "okpkg" && mode === "swapped-tarball") return built.get("okpkg-swapped");

  return honest;
}

function packument(b: Built) {
  return { name: b.name, "dist-tags": { latest: b.version }, versions: { [b.version]: { name: b.name, version: b.version, dependencies: b.deps, dist: { tarball: `${url}${tarballPath(b.name, b.version)}`, integrity: b.integrity } } } };
}

async function gitFixture(): Promise<string> {
  const repo = join(dir, "gitdep");

  mkdirSync(repo);
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "gitdep", version: "1.0.0", main: "index.js", scripts: { prepare: "node mark.js" } }));
  writeFileSync(join(repo, "mark.js"), `require("node:fs").writeFileSync(require("node:path").join(${JSON.stringify(marks)}, "gitdep-prepare-" + process.pid), "ran");\n`);
  writeFileSync(join(repo, "index.js"), "module.exports = 1;\n");

  for (const args of [["init", "-q", "-b", "main"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-qm", "fixture"]]) {
    const r = await sh(["git", ...args], repo);

    if (r.code !== 0) throw new Error(`git ${args.join(" ")}: ${r.out}`);
  }

  return `git+file://${repo}`;
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "smoke-commands-"));
  marks = mkdtempSync(join(dir, "marks-"));
  gitUrl = await gitFixture();
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(req) {
      const path = decodeURIComponent(new URL(req.url).pathname.slice(1));
      const cdn = path.startsWith("cdn/");
      const tar = /^(?:cdn\/)?(@[^/]+\/[^/]+|[^/@][^/]*)\/-\/[^/]+-(\d+\.\d+\.\d+)\.tgz$/.exec(path);

      if (tar) {
        const b = served(tar[1] ?? "");

        if (b === undefined || b.version !== tar[2]) return new Response("not found", { status: 404 });
        fetched.push(path);

        if (mode === "redirect" && !cdn) return Response.redirect(`${url}cdn/${path}`, 302);

        return new Response(b.tgz, { headers: { "content-type": "application/octet-stream" } });
      }

      const b = served(path);

      return b === undefined ? new Response("{}", { status: 404 }) : Response.json(packument(b));
    },
  });
  url = `http://127.0.0.1:${server.port}/`;
  // okpkg: what a probe locks (its postinstall would leave a marker); its swapped tarball depends on the git repository
  const ok = await pack("okpkg", "1.0.0", {}, { postinstall: "node mark.js" });

  built.set("okpkg", ok);
  built.set("okpkg-swapped", { ...(await pack("okpkg", "1.0.0", { gitdep: gitUrl }, { postinstall: "node mark.js" })), name: "okpkg" });
  // the reviewer's reproducer: a registry package whose dependency is the git repository
  built.set("evil", await pack("evil", "1.0.0", { gitdep: gitUrl }));
}, 60_000);

afterAll(() => {
  server?.stop(true);
  rmSync(dir, { recursive: true, force: true });
});

const ran = (): string[] => readdirSync(marks).sort();

function reset(m: Mode): void {
  mode = m;
  fetched.length = 0;

  for (const f of readdirSync(marks)) rmSync(join(marks, f));
}

/** A project for the stand-in registry, with these files. */
function project(name: string, files: Record<string, string>): string {
  const p = mkdtempSync(join(dir, `${name}-`));

  writeFileSync(join(p, ".npmrc"), `registry=${url}\n`);
  writeFileSync(join(p, "bunfig.toml"), `[install]\nregistry = "${url}"\n`);

  for (const [f, text] of Object.entries(files)) writeFileSync(join(p, f), text);

  return p;
}

const MANIFEST = JSON.stringify({ name: "probe", version: "1.0.0", private: true, dependencies: { okpkg: "1.0.0" } });

/** A probe's committed lockfile for okpkg@1.0.0, written as smoke's are: npm's names registry.npmjs.org, bun's the default registry. */
function lockfile(pm: "npm" | "bun"): string {
  const ok = built.get("okpkg");

  if (ok === undefined) throw new Error("okpkg was not built");

  if (pm === "npm") return singleLockfile("probe", { name: "okpkg", version: "1.0.0", integrity: ok.integrity, resolved: `${NPM_HOST}${tarballPath("okpkg", "1.0.0")}` });

  return JSON.stringify({ lockfileVersion: 1, configVersion: 1, workspaces: { "": { name: "probe", dependencies: { okpkg: "1.0.0" } } }, packages: { okpkg: ["okpkg@1.0.0", "", {}, ok.integrity] } }, null, 2);
}

function installedVersion(p: string, name: string): string | null {
  const f = join(p, "node_modules", name, "package.json");

  return existsSync(f) ? z.object({ version: z.string() }).parse(JSON.parse(readFileSync(f, "utf8"))).version : null;
}

const NPM_MAJOR = Number(Bun.spawnSync(["npm", "--version"], { stdout: "pipe" }).stdout.toString("utf8").trim().split(".")[0] ?? "0");

describe("the reproducer (review of 4a9c8fb, finding 1)", () => {
  test("npm install --ignore-scripts of a registry package with a git dependency installs it (and runs prepare on npm < 11)", async () => {
    reset("honest");
    const p = project("npm-raw", { "package.json": JSON.stringify({ name: "raw", version: "1.0.0", private: true }) });
    const r = await sh(["npm", "install", NO_SCRIPTS, "--no-audit", "--no-fund", "evil@1.0.0"], p, NO_SCRIPTS_ENV);

    expect(r.code, r.out).toBe(0);
    expect(existsSync(join(p, "node_modules", "gitdep", "package.json")), r.out).toBe(true);

    const prepares = ran().filter((m) => m.startsWith("gitdep-prepare-"));

    if (NPM_MAJOR < 11) expect(prepares.length, r.out).toBeGreaterThan(0);
    else expect(prepares, r.out).toEqual([]);
  });

  test("bun add --ignore-scripts of it does not run the prepare (bun 1.4): bun is not affected, and smoke's bun installs are locked all the same", async () => {
    reset("honest");
    const p = project("bun-raw", { "package.json": JSON.stringify({ name: "raw", version: "1.0.0", private: true, trustedDependencies: ["gitdep"] }) });
    const r = await sh(["bun", "add", NO_SCRIPTS, "evil@1.0.0"], p, NO_SCRIPTS_ENV);

    expect(r.code, r.out).toBe(0);
    expect(existsSync(join(p, "node_modules", "gitdep", "package.json")), r.out).toBe(true);
    expect(ran(), r.out).toEqual([]);
  });
});

describe("metadataProblem (review of 96f0ba7, finding 4)", () => {
  const R = "https://registry.example.test/";
  const sri = `sha512-${"A".repeat(86)}==`;
  const other = `sha512-${"B".repeat(86)}==`;
  const locked: Locked = { name: "a", version: "1.0.0", integrity: sri, edges: { installs: {}, peers: {} } };

  const doc = (over: { tarball?: string; integrity?: string; latest?: string | null; version?: string; also?: string[]; deps?: Record<string, string> } = {}) => {
    const tags: Record<string, string> = over.latest === null ? {} : { latest: over.latest ?? "1.0.0" };
    const others = Object.fromEntries((over.also ?? []).map((v) => [v, { dist: { tarball: `${R}a/-/a-${v}.tgz`, integrity: other } }]));

    return {
      "dist-tags": tags,
      versions: { ...others, [over.version ?? "1.0.0"]: { dist: { tarball: over.tarball ?? `${R}a/-/a-1.0.0.tgz`, integrity: over.integrity ?? sri }, dependencies: over.deps } },
    } satisfies z.input<typeof InstallMetadata>;
  };

  const check = (body: z.input<typeof InstallMetadata> | { versions: never[] } | null, opts: { status?: number; latest?: "listed" | "this"; locked?: typeof locked } = {}) =>
    metadataProblem({ registry: R, status: opts.status ?? 200, body, locked: opts.locked ?? locked, latest: opts.latest ?? "listed" });

  test("metadata that installs as the lockfile does passes, a scoped one at its canonical path too", () => {
    expect(check(doc())).toBeNull();
    expect(check(doc({ latest: "2.0.0", also: ["2.0.0"] }))).toBeNull();
    const scoped: Locked = { name: "@s/b", version: "1.0.0", integrity: sri, edges: { installs: {}, peers: {} } };

    expect(check({ "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { dist: { tarball: `${R}@s/b/-/b-1.0.0.tgz`, integrity: sri } } } }, { locked: scoped, latest: "this" })).toBeNull();
  });

  test("a tarball on the registry but not at the URL the locked install fetches fails (before: any same-prefix URL passed)", () => {
    for (const tarball of [`${R}a/-/a-1.0.1.tgz`, `${R}evil/-/a-1.0.0.tgz`, `${R}a/-/a-1.0.0.tgz?x=1`, `${R}a/-/a-1.0.0.tgz/`, `${R}%61/-/a-1.0.0.tgz`]) {
      expect(check(doc({ tarball })), tarball).toContain(`tarball ${tarball}, not ${R}a/-/a-1.0.0.tgz`);
    }

    expect(check(doc({ tarball: "https://elsewhere.test/a/-/a-1.0.0.tgz" }))).toContain("not https://registry.example.test/a/-/a-1.0.0.tgz");
  });

  test("another integrity, a missing version, no latest, an unreadable body or a non-200 answer fails", () => {
    expect(check(doc({ integrity: other }))).toContain("not the lockfile's");
    expect(check(doc({ version: "1.0.1", latest: "1.0.1" }))).toBe("a@1.0.0: missing");
    expect(check(doc({ latest: null }))).toBe("a: no latest dist-tag");
    expect(check({ versions: [] })).toBe("a: unreadable metadata");
    expect(check(null, { status: 404 })).toBe("a: HTTP 404");
  });

  // review of e83dc4b, finding 4: latest could name a version that does not exist, and dependency edges were not read
  test("latest must name a version the metadata lists", () => {
    expect(check(doc({ latest: "9.9.9" }))).toBe("a: latest names 9.9.9, which the metadata does not list");
    expect(check(doc({ latest: "constructor" }))).toBe("a: latest names constructor, which the metadata does not list");
  });

  const required = (range: string) => ({ range, kind: "required" as const });
  const optional = (range: string) => ({ range, kind: "optional" as const });

  /** doc() with these edge fields on 1.0.0. */
  const withFields = (fields: Omit<z.input<typeof InstallMetadata>["versions"][string], "dist">) => {
    const body = doc();
    const v = body.versions["1.0.0"];

    if (v === undefined) throw new Error("no 1.0.0");

    return { ...body, versions: { "1.0.0": { ...v, ...fields } } };
  };

  test("each locked version must declare exactly the lockfile's dependency edges", () => {
    const withDep: Locked = { ...locked, edges: { installs: { b: required("^1.0.0") }, peers: {} } };

    expect(check(doc({ deps: { b: "^1.0.0" } }), { locked: withDep })).toBeNull();
    expect(check(doc(), { locked: withDep })).toBe('a@1.0.0: dependencies {}, not the lockfile\'s {"b":["^1.0.0","required"]}');
    expect(check(doc({ deps: { b: "^2.0.0" } }), { locked: withDep })).toContain('dependencies {"b":["^2.0.0","required"]}');
    expect(check(doc({ deps: { b: "^1.0.0", c: "1.0.0" } }), { locked: withDep })).toContain("not the lockfile's");
    expect(check(doc({ deps: { b: "^1.0.0" } }))).toBe('a@1.0.0: dependencies {"b":["^1.0.0","required"]}, not the lockfile\'s {}');
    expect(check(withFields({ peerDependencies: { react: "*" } }))).toBe('a@1.0.0: peerDependencies {"react":["*","required"]}, not the lockfile\'s {}');
  });

  // review of ae21a19, finding 3: the edge's kind was not compared, only its range
  test("a required dependency reclassified as optional at the same range fails, and the other way round", () => {
    const req: Locked = { ...locked, edges: { installs: { b: required("^1.0.0") }, peers: {} } };
    const opt: Locked = { ...locked, edges: { installs: { b: optional("^1.0.0") }, peers: {} } };
    // npm lists an optional dependency in both fields; either way it is one optional edge
    const inBoth = withFields({ dependencies: { b: "^1.0.0" }, optionalDependencies: { b: "^1.0.0" } });
    const onlyOptional = withFields({ optionalDependencies: { b: "^1.0.0" } });

    for (const body of [inBoth, onlyOptional]) {
      expect(check(body, { locked: req })).toBe('a@1.0.0: dependencies {"b":["^1.0.0","optional"]}, not the lockfile\'s {"b":["^1.0.0","required"]}');
      expect(check(body, { locked: opt })).toBeNull();
    }

    expect(check(doc({ deps: { b: "^1.0.0" } }), { locked: opt })).toContain("not the lockfile's");
    // the optionalDependencies range is the edge's range, as in npm
    expect(check(withFields({ dependencies: { b: "^1.0.0" }, optionalDependencies: { b: "^2.0.0" } }), { locked: opt })).toContain('dependencies {"b":["^2.0.0","optional"]}');
  });

  test("a required peer and an optional peer at the same range differ", () => {
    const req: Locked = { ...locked, edges: { installs: {}, peers: { react: required("*") } } };
    const opt: Locked = { ...locked, edges: { installs: {}, peers: { react: optional("*") } } };
    const plain = withFields({ peerDependencies: { react: "*" } });
    const optionalPeer = withFields({ peerDependencies: { react: "*" }, peerDependenciesMeta: { react: { optional: true } } });

    expect(check(plain, { locked: req })).toBeNull();
    expect(check(optionalPeer, { locked: opt })).toBeNull();
    expect(check(optionalPeer, { locked: req })).toBe('a@1.0.0: peerDependencies {"react":["*","optional"]}, not the lockfile\'s {"react":["*","required"]}');
    expect(check(plain, { locked: opt })).toBe('a@1.0.0: peerDependencies {"react":["*","required"]}, not the lockfile\'s {"react":["*","optional"]}');
    expect(check(withFields({ peerDependencies: { react: "*" }, peerDependenciesMeta: { react: { optional: false } } }), { locked: opt })).toContain("not the lockfile's");
  });

  test("the lockfiles record each edge's kind: npm's fields and peerDependenciesMeta, bun's optionalPeers", () => {
    const manifest = JSON.stringify({ name: "p", version: "1.0.0", private: true, dependencies: { a: "1.0.0" } });
    const entry = { version: "1.0.0", resolved: `${NPM_HOST}a/-/a-1.0.0.tgz`, integrity: sri };

    const fields = {
      dependencies: { b: "^1.0.0", c: "^1.0.0" },
      optionalDependencies: { b: "^1.0.0" },
      peerDependencies: { react: "*", vue: "*" },
      peerDependenciesMeta: { vue: { optional: true } },
    };

    const want = { installs: { b: optional("^1.0.0"), c: required("^1.0.0") }, peers: { react: required("*"), vue: optional("*") } };

    const npm = JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { a: "1.0.0" } }, "node_modules/a": { ...entry, ...fields } } });

    expect(lockedEntries("npm", manifest, npm).map((l) => l.edges)).toEqual([want]);

    const meta = { dependencies: { c: "^1.0.0" }, optionalDependencies: { b: "^1.0.0" }, peerDependencies: { react: "*", vue: "*" }, optionalPeers: ["vue"] };
    const bun = JSON.stringify({ workspaces: { "": { dependencies: { a: "1.0.0" } } }, packages: { a: ["a@1.0.0", "", meta, sri] } });

    expect(lockedEntries("bun", manifest, bun).map((l) => l.edges)).toEqual([want]);

    // the metadata npm and bun would read for that version passes against both
    for (const pm of ["npm", "bun"] as const) {
      const [l] = lockedEntries(pm, manifest, pm === "npm" ? npm : bun);

      if (l === undefined) throw new Error("no entry");

      expect(check(withFields(fields), { locked: l })).toBeNull();
    }
  });

  test("the committed npm-app fixture: metadata that drops is-odd's is-number dependency is refused", () => {
    const isOdd = probeFixture("npm-app").locked.find((l) => l.name === "is-odd");

    if (isOdd === undefined) throw new Error("npm-app does not lock is-odd");

    expect(isOdd.edges).toEqual({ installs: { "is-number": { range: "^6.0.0", kind: "required" } }, peers: {} });

    const meta = (deps: Record<string, string> | undefined) => ({
      "dist-tags": { latest: "3.0.1" },
      versions: { "3.0.1": { dist: { tarball: `${R}is-odd/-/is-odd-3.0.1.tgz`, integrity: isOdd.integrity }, dependencies: deps } },
    });

    expect(metadataProblem({ registry: R, status: 200, body: meta({ "is-number": "^6.0.0" }), locked: isOdd, latest: "listed" })).toBeNull();
    expect(metadataProblem({ registry: R, status: 200, body: meta(undefined), locked: isOdd, latest: "listed" })).toContain("dependencies {}, not the lockfile's");
  });

  test("the committed bun fixtures record their (empty) edges", () => {
    for (const probe of ["bun-app", "audit-app"] as const) for (const l of probeFixture(probe).locked) expect(l.edges, `${l.name}`).toEqual({ installs: {}, peers: {} });
  });

  test('latest "this": a just-published version must be the one latest names', () => {
    expect(check(doc(), { latest: "this" })).toBeNull();
    expect(check(doc({ latest: "0.9.0" }), { latest: "this" })).toBe("a: latest is 0.9.0, not 1.0.0");
  });
});

describe.each(["npm", "bun"] as const)("%s: smoke's locked install", (pm) => {
  const files = () => ({ "package.json": MANIFEST, [pm === "npm" ? "package-lock.json" : "bun.lock"]: lockfile(pm) });
  const install = (p: string, extra: Record<string, string> = {}) => sh(pm === "npm" ? npmCi(url) : bunInstallLocked(url), p, { ...NO_SCRIPTS_ENV, ...extra });

  test("the test's lockfile passes the same check as the committed ones", () => {
    expect(lockedEntries(pm, MANIFEST, lockfile(pm)).map((l) => `${l.name}@${l.version}`)).toEqual(["okpkg@1.0.0"]);
  });

  test("an honest registry: the locked version installs from it, fetched from the registry, and its postinstall does not run", async () => {
    reset("honest");
    const p = project(`${pm}-honest`, files());
    const r = await install(p);

    expect(r.code, r.out).toBe(0);
    expect(installedVersion(p, "okpkg")).toBe("1.0.0");
    // npm's lockfile names registry.npmjs.org and bun's the default registry: both fetched from the registry under test
    expect(fetched).toEqual(["okpkg/-/okpkg-1.0.0.tgz"]);
    expect(ran(), r.out).toEqual([]);
  });

  test("a registry that redirects the tarball elsewhere (as production does to npm's CDN): the install follows it and checks the bytes", async () => {
    reset("redirect");
    const p = project(`${pm}-redirect`, files());
    const r = await install(p);

    expect(r.code, r.out).toBe(0);
    expect(installedVersion(p, "okpkg")).toBe("1.0.0");
    expect(fetched).toEqual(["okpkg/-/okpkg-1.0.0.tgz", "cdn/okpkg/-/okpkg-1.0.0.tgz"]);
  });

  test("metadata that adds a git dependency: the lockfile decides, so the git repository is never fetched and no prepare runs", async () => {
    reset("git-in-metadata");
    const p = project(`${pm}-meta`, files());
    const r = await install(p);

    expect(r.code, r.out).toBe(0);
    expect(installedVersion(p, "okpkg")).toBe("1.0.0");
    expect(existsSync(join(p, "node_modules", "gitdep")), r.out).toBe(false);
    expect(ran(), r.out).toEqual([]);
  });

  test("a tarball swapped for one that depends on the git repository: refused on integrity, nothing of it installed, no prepare runs", async () => {
    reset("swapped-tarball");
    const p = project(`${pm}-swapped`, files());
    // npm retries a tarball that fails its integrity, with backoff: once is enough here
    const r = await install(p, { npm_config_fetch_retries: "0" });

    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(pm === "npm" ? /EINTEGRITY/ : /[Ii]ntegrity/);
    expect(existsSync(join(p, "node_modules", "gitdep")), r.out).toBe(false);
    expect(ran(), r.out).toEqual([]);
  });

  test("the raw install it replaced, against the same swapped registry, runs the git repository's prepare (npm) or installs it (bun)", async () => {
    reset("swapped-tarball");
    const p = project(`${pm}-swapped-raw`, { "package.json": JSON.stringify({ name: "raw", version: "1.0.0", private: true }) });
    const r = await sh(pm === "npm" ? ["npm", "install", NO_SCRIPTS, "--no-audit", "--no-fund", "okpkg@1.0.0"] : ["bun", "add", NO_SCRIPTS, "okpkg@1.0.0"], p, NO_SCRIPTS_ENV);

    expect(r.code, r.out).toBe(0);
    expect(existsSync(join(p, "node_modules", "gitdep", "package.json")), r.out).toBe(true);

    if (pm === "npm") {
      const prepares = ran().filter((m) => m.startsWith("gitdep-prepare-"));

      if (NPM_MAJOR < 11) expect(prepares.length, r.out).toBeGreaterThan(0);
      else expect(prepares, r.out).toEqual([]);
    }
  });
});

test("the staging consumer: a scoped package packed as smoke packs it installs with npm ci from singleLockfile, and a swapped tarball is refused", async () => {
  const name = "@check/smoke-x";
  const src = mkdtempSync(join(dir, "scoped-"));

  writeFileSync(join(src, "package.json"), JSON.stringify({ name, version: "1.0.0", main: "index.js", license: "MIT" }));
  writeFileSync(join(src, "index.js"), "module.exports = 'smoke';\n");
  const packed = await sh(["npm", "pack", "--json", "--silent", "--pack-destination", src], src, NO_SCRIPTS_ENV);
  const tarball = z.array(z.object({ filename: z.string(), integrity: z.string() })).length(1).parse(JSON.parse(packed.out))[0];

  if (tarball === undefined) throw new Error("npm pack wrote nothing");
  const tgz = new Uint8Array(readFileSync(join(src, tarball.filename)));

  expect(sri(tgz)).toBe(tarball.integrity);
  built.set(name, { name, version: "1.0.0", tgz, integrity: tarball.integrity, deps: {} });
  const lock = singleLockfile("consumer", { name, version: "1.0.0", integrity: tarball.integrity, resolved: `${url}${tarballPath(name, "1.0.0")}` });
  const files = { "package.json": JSON.stringify({ name: "consumer", version: "1.0.0", private: true, dependencies: { [name]: "1.0.0" } }), "package-lock.json": lock };

  reset("honest");
  const p = project("consumer", files);
  const r = await sh(npmCi(url), p, NO_SCRIPTS_ENV);

  expect(r.code, r.out).toBe(0);
  expect(z.object({ version: z.string() }).parse(JSON.parse(readFileSync(join(p, "node_modules", "@check", "smoke-x", "package.json"), "utf8"))).version).toBe("1.0.0");
  expect(fetched).toEqual(["@check/smoke-x/-/smoke-x-1.0.0.tgz"]);
  // the registry serving other bytes for it fails the install
  built.set(name, { name, version: "1.0.0", tgz: built.get("okpkg-swapped")?.tgz ?? new Uint8Array(), integrity: tarball.integrity, deps: {} });
  const q = project("consumer-swapped", files);
  const bad = await sh(npmCi(url), q, { ...NO_SCRIPTS_ENV, npm_config_fetch_retries: "0" });

  expect(bad.code, bad.out).not.toBe(0);
  expect(bad.out).toMatch(/EINTEGRITY/);
  expect(ran(), bad.out).toEqual([]);
});
