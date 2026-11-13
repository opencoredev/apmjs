// What a package manager locked: every node of a lockfile, each with where it comes from (a registry, git, a file, a
// link or the project's own workspace). apm add and apm x check the lockfile the package manager computes, in a
// directory of its own, before anything is installed (see docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked").
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix, relative } from "node:path";
import { z } from "zod";
import type { Pm } from "./pm.ts";

export type Locked = { integrity: string | null; resolved: string | null };

/**
 * Where a lockfile entry's bytes come from. `registry`: a registry tarball, which the scan checks by name, version and
 * integrity. The others keep what the lockfile says (`source`): no registry can check them, so they warn and strict
 * mode refuses them. `workspace`: a folder of the project; `dir`, its path from the lockfile's directory when the
 * lockfile names one, and `version`, the version the lockfile records for it (null when it records none), which bind
 * it to a declared workspace member (review of 2a098b1, strict workspaces).
 */
export type Origin = { kind: "registry" } | { kind: "git" | "file" | "link" | "tarball"; source: string } | { kind: "workspace"; source: string; dir: string | null; version: string | null };

/**
 * A dependency edge of the lockfile: the name the dependent asks for (an alias is its own name), the key of the node
 * the lockfile resolves it to (null when the lockfile holds none, as for a link to a folder outside it), whether it
 * may be missing (an optional dependency or an optional peer), and whether it is a folder's devDependency (`dev`),
 * which a production install leaves out (review of 2b7767f, finding 3).
 */
export type LockDep = { name: string; key: string | null; optional: boolean; dev: boolean };

/**
 * The platforms a package is built for, as its lockfile entry names them (npm's form: a list, `!name` excluding one).
 * An empty list allows every platform.
 */
export type Supports = { os: readonly string[]; cpu: readonly string[] };

/**
 * One installed package as the lockfile records it. `key` is the lockfile's own id for it (npm and bun: its install
 * path). `version`: the version or source it is locked at (a registry version, or a file:, git or link locator).
 * `installedVersion`: the version its package.json must hold, when the lockfile records one (a registry version, or
 * the manifest version npm and pnpm record for a tarball or git entry), kept apart from the locator (review of
 * 2b7767f, finding 4). `platform`: the entry names the os or cpu it is built for, and `supports` which (null when it names none).
 * `bundled`: it ships inside its parent's tarball (npm's inBundle), so the parent's score covers its bytes and it has
 * no artifact of its own. `optional`: the lockfile says the package manager may leave it out (it is only reached
 * through optional edges). A platform is no optionality: a package built for this platform that a required edge
 * reaches must be installed (review of 2b7767f, finding 2). `deps`: its dependency edges.
 */
export type LockNode = { key: string; name: string; version: string; installedVersion: string | null; integrity: string | null; resolved: string | null; hasInstallScript: boolean; platform: boolean; supports: Supports | null; origin: Origin; bundled: boolean; optional: boolean; deps: LockDep[] };

/** A project folder the lockfile installs dependencies for: the root ("") or a workspace member, by its path. */
export type LockImporter = { dir: string; deps: LockDep[] };

/** An os or cpu field: a list, or (bun) one name, read as a list. */
const Platforms = z
  .union([z.array(z.string()), z.string().transform((one) => [one])])
  .optional()
  .catch(undefined);

type PlatformFields = { os?: string[] | undefined; cpu?: string[] | undefined };

const hasPlatform = (e: PlatformFields): boolean => e.os !== undefined || e.cpu !== undefined;

/** The platforms an entry names, or null when it names none. */
const supportsOf = (e: PlatformFields): Supports | null => (hasPlatform(e) ? { os: e.os ?? [], cpu: e.cpu ?? [] } : null);

/** Whether `value` (this machine's os or cpu) is in a list of the lockfile's form: none listed, or listed and not excluded. */
function allows(list: readonly string[], value: string): boolean {
  if (list.includes(`!${value}`)) return false;
  const wanted = list.filter((x) => !x.startsWith("!"));

  return wanted.length === 0 || wanted.includes(value);
}

/** Whether a package built for `supports` installs on this machine (`host`: its os and cpu, as Node names them). */
export function supportsHost(supports: Supports | null, host: { os: string; cpu: string }): boolean {
  return supports === null || (allows(supports.os, host.os) && allows(supports.cpu, host.cpu));
}

/** The nodes of a lockfile and the folders it installs for, or why apm could not read them. */
export type LockRead = { kind: "read"; path: string; nodes: LockNode[]; importers: LockImporter[] } | { kind: "missing" } | { kind: "unreadable"; path: string; reason: string };

/** What a lockfile's parse gives: its nodes and the folders it installs for. */
type Parsed = { nodes: LockNode[]; importers: LockImporter[] };

export type LockPm = Exclude<Pm, "yarn">;

/**
 * The lockfiles each package manager reads, in its order of precedence: npm uses npm-shrinkwrap.json over
 * package-lock.json when both are there (review of a2227d1, finding 2).
 */
export const LOCKFILES: Record<LockPm, readonly [string, ...string[]]> = {
  bun: ["bun.lock"],
  npm: ["npm-shrinkwrap.json", "package-lock.json"],
  pnpm: ["pnpm-lock.yaml"],
};

// What each package manager keeps in node_modules when the project lockfile is turned off (read for projectPins only).
const HIDDEN_LOCKFILES: Record<LockPm, string[]> = {
  bun: [],
  npm: [join("node_modules", ".package-lock.json")],
  pnpm: [join("node_modules", ".pnpm", "lock.yaml")],
};

export function isLockPm(pm: Pm): pm is LockPm {
  return pm !== "yarn";
}

/** The lockfile `pm` reads in `dir` itself, by precedence, or null. */
export function lockfileIn(dir: string, pm: LockPm): string | null {
  for (const f of LOCKFILES[pm]) if (existsSync(join(dir, f))) return join(dir, f);

  return null;
}

/** The nearest lockfile for `pm` from `cwd` upward, or null. */
export function findLockfile(cwd: string, pm: LockPm): string | null {
  let dir = cwd;

  for (let i = 0; i < 20; i++) {
    const hit = lockfileIn(dir, pm);

    if (hit !== null) return hit;
    const parent = dirname(dir);

    if (parent === dir) return null;
    dir = parent;
  }

  return null;
}

/** "@scope/name@1.2.3" -> name and the rest. Scoped names keep their leading "@". */
function splitId(id: string): { name: string; spec: string } | null {
  const at = id.indexOf("@", id.startsWith("@") ? 1 : 0);

  if (at <= 0) return null;

  return { name: id.slice(0, at), spec: id.slice(at + 1) };
}

/** A plain semver version (what a registry serves), not a git, file, link or workspace spec. */
export function isRegistryVersion(v: string): boolean {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(v);
}

/** A registry tarball URL: `<registry>/<name>/-/<file>.tgz`. A tarball anywhere else is not a registry's. */
const REGISTRY_TARBALL = /^https?:\/\/[^\s]+\/-\/[^/\s]+\.tgz$/;

const GIT = /^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:)/;

/** A folder path the lockfile names, relative to its directory, kept only when it stays inside it. */
function folderOf(path: string): string | null {
  const n = posix.normalize(path.replace(/^\.\//, ""));

  return n === "." || n === ".." || n.startsWith("../") || posix.isAbsolute(n) ? null : n.replace(/\/+$/, "");
}

/** The origin of a spec or resolved location that is not a plain registry version. */
function originOf(source: string): Origin {
  if (GIT.test(source) || /^https?:\/\/codeload\.github\.com\//.test(source)) return { kind: "git", source };

  if (source.startsWith("workspace:")) return { kind: "workspace", source, dir: folderOf(source.slice("workspace:".length)), version: null };

  if (source.startsWith("link:") || source.startsWith("portal:")) return { kind: "link", source };

  if (source.startsWith("file:")) return { kind: "file", source };

  if (/^https?:\/\//.test(source)) return { kind: "tarball", source };

  // a path, as npm records a link's target
  return { kind: "link", source };
}

const DepMap = z.record(z.string(), z.string());

/**
 * Which nodes to read: those under the named top-level packages, only the named top-level packages themselves (`top`,
 * where each node's key is the name it was asked for, so an alias maps back to it), or every node in the lockfile.
 */
export type Roots = { kind: "under"; names: string[] } | { kind: "top"; names: string[] } | { kind: "all" };

/** Breadth-first walk from the roots over `edges`, each key visited once. */
function walk(input: { roots: string[]; edges: (key: string) => string[] }): string[] {
  const seen = new Set<string>();
  const queue = [...input.roots];

  for (let i = 0; i < queue.length; i++) {
    const k = queue[i];

    if (k === undefined || seen.has(k)) continue;
    seen.add(k);
    queue.push(...input.edges(k));
  }

  return [...seen];
}

// ---------- npm: package-lock.json and npm-shrinkwrap.json v2/v3 ----------
const NpmEntry = z
  .object({
    name: z.string().optional(),
    version: z.string().optional(),
    resolved: z.string().optional(),
    integrity: z.string().optional(),
    link: z.boolean().optional(),
    inBundle: z.boolean().optional(),
    hasInstallScript: z.boolean().optional(),
    dependencies: DepMap.optional(),
    optionalDependencies: DepMap.optional(),
    peerDependencies: DepMap.optional(),
    peerDependenciesMeta: z.record(z.string(), z.object({ optional: z.boolean().optional() }).loose()).optional().catch(undefined),
    devDependencies: DepMap.optional(),
    optional: z.boolean().optional(),
    devOptional: z.boolean().optional(),
    os: Platforms,
    cpu: Platforms,
  })
  .loose();

type NpmPackages = Record<string, z.infer<typeof NpmEntry>>;

const NpmLock = z.object({ lockfileVersion: z.number().min(2, "lockfileVersion 1 has no packages section; run npm install once to upgrade it"), packages: z.record(z.string(), NpmEntry) }).loose();

/** An entry under node_modules (an installed package), not a folder of the project (a workspace or a link's target). */
const isInstallPath = (key: string): boolean => key.startsWith("node_modules/") || key.includes("/node_modules/");

/** Where an npm entry's bytes come from: its `resolved`, not its version (review of a2227d1, finding 4). */
function npmOrigin(key: string, e: z.infer<typeof NpmEntry>): Origin {
  // a folder of the project (a workspace member, a link's target inside it), or a link's target outside it
  if (!isInstallPath(key)) return folderOf(key) === null ? { kind: "link", source: key } : { kind: "workspace", source: key, dir: folderOf(key), version: e.version ?? null };

  if (e.link === true) return originOf(`link:${e.resolved ?? ""}`);
  const resolved = e.resolved;

  if (resolved !== undefined && !REGISTRY_TARBALL.test(resolved)) return originOf(resolved);

  if (e.version === undefined || !isRegistryVersion(e.version)) return originOf(resolved ?? e.version ?? key);

  return { kind: "registry" };
}

function npmGraph(text: string, from: string, roots: Roots): Parsed {
  const { packages } = NpmLock.parse(JSON.parse(text));

  // node's lookup: <dir>/node_modules/<dep>, then each parent package's node_modules, then the top
  const resolve = (base: string, dep: string): string | null => {
    let dir = base;

    for (;;) {
      const candidate = dir === "" ? `node_modules/${dep}` : `${dir}/node_modules/${dep}`;

      if (packages[candidate]) return candidate;

      if (dir === "") return null;
      const i = dir.lastIndexOf("/node_modules/");

      dir = i < 0 ? "" : dir.slice(0, i);
    }
  };

  // the node a dependency resolves to: a link stands for its target, when the lockfile holds it
  const target = (key: string | null): string | null => {
    const e = key === null ? undefined : packages[key];

    return e?.link === true && e.resolved !== undefined && packages[e.resolved] ? e.resolved : key;
  };

  const depsOf = (key: string, opts: { dev: boolean }): LockDep[] => {
    const e = packages[key];

    if (!e) return [];
    const optional = new Set([...Object.keys(e.optionalDependencies ?? {}), ...Object.entries(e.peerDependenciesMeta ?? {}).flatMap(([n, m]) => (m.optional === true ? [n] : []))]);
    const prod = new Set([...Object.keys(e.dependencies ?? {}), ...Object.keys(e.optionalDependencies ?? {}), ...Object.keys(e.peerDependencies ?? {})]);
    const dev = opts.dev ? Object.keys(e.devDependencies ?? {}) : [];
    const names = [...new Set([...prod, ...dev])];

    // a dependency the lockfile resolves nowhere (an optional peer nobody installs) has no edge to check
    return names.flatMap((name) => {
      const to = target(resolve(key, name));

      return to === null ? [] : [{ name, key: to, optional: optional.has(name), dev: !prod.has(name) }];
    });
  };

  const edges = (key: string): string[] => {
    const e = packages[key];

    if (!e) return [];

    // a link's dependencies are its target's
    if (e.link === true) return e.resolved !== undefined && packages[e.resolved] ? [e.resolved] : [];

    return depsOf(key, { dev: false }).flatMap((d) => (d.key === null ? [] : [d.key]));
  };

  // the project's folders: the root and each folder of it the lockfile installs for (a workspace member)
  const importers: LockImporter[] = Object.keys(packages)
    .filter((k) => k === "" || (!isInstallPath(k) && folderOf(k) !== null))
    .map((dir) => ({ dir, deps: depsOf(dir, { dev: true }) }));

  const tops = (names: string[]): string[] => names.flatMap((r) => resolve(from, r) ?? []);
  const node = (key: string | null): LockNode[] => npmNode(packages, key, (k) => depsOf(k, { dev: false }));

  if (roots.kind === "top") return { nodes: roots.names.flatMap((n) => npmTop(packages, n, resolve(from, n), node)), importers };
  const keys = roots.kind === "all" ? Object.keys(packages).filter((k) => k !== "") : walk({ roots: tops(roots.names), edges });

  return { nodes: keys.flatMap((key) => node(key)), importers };
}

/** The node at `key` of a package-lock.json. A link whose target the lockfile holds is that target's node, so none here. */
function npmNode(packages: NpmPackages, key: string | null, depsOf: (key: string) => LockDep[]): LockNode[] {
  if (key === null) return [];
  const e = packages[key];

  if (!e) return [];
  const name = e.name ?? key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
  const optional = e.optional === true || e.devOptional === true;

  if (e.link === true) {
    if (e.resolved !== undefined && packages[e.resolved]) return [];

    return [{ key, name, version: `link:${e.resolved ?? ""}`, installedVersion: null, integrity: null, resolved: e.resolved ?? null, hasInstallScript: false, platform: false, supports: null, origin: npmOrigin(key, e), bundled: false, optional, deps: [] }];
  }

  // a workspace folder or a link's target: named by its own package.json
  const folderName = isInstallPath(key) ? name : (e.name ?? key.split("/").at(-1) ?? key);

  return [{ key, name: folderName, version: e.version ?? "0.0.0", installedVersion: e.version ?? null, integrity: e.integrity ?? null, resolved: e.resolved ?? null, hasInstallScript: e.hasInstallScript === true, platform: hasPlatform(e), supports: supportsOf(e), origin: npmOrigin(key, e), bundled: e.inBundle === true, optional, deps: depsOf(key) }];
}

/** A top-level entry of a package-lock.json asked for as `name`: a link (a workspace package) is a node too, never a registry version. */
function npmTop(packages: NpmPackages, name: string, key: string | null, node: (key: string | null) => LockNode[]): LockNode[] {
  const e = key === null ? undefined : packages[key];

  if (e?.link === true) return [{ key: name, name, version: `link:${e.resolved ?? ""}`, installedVersion: null, integrity: null, resolved: null, hasInstallScript: false, platform: false, supports: null, origin: originOf(`link:${e.resolved ?? ""}`), bundled: false, optional: false, deps: [] }];

  return node(key).map((n) => ({ ...n, key: name }));
}

// ---------- bun: bun.lock ----------
// "key": ["name@version", "registry tarball or empty", { dependencies, hasInstallScript, ... }, "sha512-..."]
const BunWorkspace = z
  .object({ name: z.string().optional(), version: z.string().optional(), dependencies: DepMap.optional(), devDependencies: DepMap.optional(), optionalDependencies: DepMap.optional(), peerDependencies: DepMap.optional() })
  .loose();

const BunLock = z.object({ packages: z.record(z.string(), z.array(z.unknown())), workspaces: z.record(z.string(), BunWorkspace).optional() }).loose();

const BunMeta = z
  .object({
    dependencies: DepMap.optional(),
    optionalDependencies: DepMap.optional(),
    peerDependencies: DepMap.optional(),
    optionalPeers: z.array(z.string()).optional().catch(undefined),
    hasInstallScript: z.boolean().optional(),
    os: Platforms,
    cpu: Platforms,
  })
  .loose();

/** "a/@s/b/c" -> ["a", "@s/b", "c"]: a bun.lock key is the install path's package names. */
export function bunKeyNames(key: string): string[] {
  const out: string[] = [];
  const parts = key.split("/");

  for (let i = 0; i < parts.length; i++) {
    const p = parts[i] ?? "";

    if (p.startsWith("@") && i + 1 < parts.length) {
      out.push(`${p}/${parts[i + 1] ?? ""}`);
      i++;
    } else out.push(p);
  }

  return out;
}

type BunEntry = { id: { name: string; spec: string }; resolved: string | null; meta: z.infer<typeof BunMeta>; integrity: string | null };

const Str = z.string();
const NonEmpty = z.string().min(1);

function bunEntry(raw: unknown[]): BunEntry | null {
  const first = Str.safeParse(raw[0]);
  const id = first.success ? splitId(first.data) : null;

  if (!id) return null;

  // registry packages carry [id, tarball, meta, integrity]; git, file and workspace entries are shorter
  if (isRegistryVersion(id.spec)) {
    const meta = BunMeta.safeParse(raw[2] ?? {});
    const resolved = NonEmpty.safeParse(raw[1]);
    const integrity = Str.safeParse(raw[3]);

    return { id, resolved: resolved.success ? resolved.data : null, meta: meta.success ? meta.data : {}, integrity: integrity.success ? integrity.data : null };
  }

  // the metadata object sits at a different index for each kind of non-registry entry
  const meta = raw.map((x) => BunMeta.safeParse(x)).find((m) => m.success);

  return { id, resolved: null, meta: meta?.success ? meta.data : {}, integrity: null };
}

/**
 * Where a bun.lock entry's bytes come from: a registry version from a registry tarball URL (or bun's default, which it
 * leaves empty), else the resolved location or spec. A version cannot prove an origin: a semver entry whose tarball is
 * somewhere else is that tarball (review of 2a098b1, finding 14).
 */
function bunOrigin(e: BunEntry): Origin {
  if (!isRegistryVersion(e.id.spec)) return originOf(e.id.spec);

  if (e.resolved !== null && !REGISTRY_TARBALL.test(e.resolved)) return originOf(e.resolved);

  return { kind: "registry" };
}

function bunGraph(text: string, roots: Roots): Parsed {
  const lock = BunLock.parse(Bun.JSONC.parse(text));
  const entries = new Map<string, BunEntry>();

  for (const [key, raw] of Object.entries(lock.packages)) {
    const e = bunEntry(raw);

    if (e) entries.set(key, e);
  }

  // a dependency of "a/b" is "a/b/<dep>" if bun nested it there, else "a/<dep>", else "<dep>"
  const resolve = (names: string[], dep: string): string | null => {
    for (let i = names.length; i >= 0; i--) {
      const candidate = [...names.slice(0, i), dep].join("/");

      if (entries.has(candidate)) return candidate;
    }

    return null;
  };

  const depsFrom = (input: { names: string[]; required: Record<string, string>; optional: readonly string[]; dev?: Record<string, string> }): LockDep[] => {
    const optional = new Set(input.optional);
    const dev = Object.keys(input.dev ?? {}).filter((name) => !(name in input.required));

    return [...Object.keys(input.required).map((name) => ({ name, dev: false })), ...dev.map((name) => ({ name, dev: true }))].flatMap(({ name, dev: isDev }) => {
      const key = resolve(input.names, name);

      return key === null ? [] : [{ name, key, optional: optional.has(name), dev: isDev }];
    });
  };

  const depsOf = (key: string): LockDep[] => {
    const m = entries.get(key)?.meta;

    if (!m) return [];

    return depsFrom({ names: bunKeyNames(key), required: { ...m.dependencies, ...m.optionalDependencies, ...m.peerDependencies }, optional: [...Object.keys(m.optionalDependencies ?? {}), ...(m.optionalPeers ?? [])] });
  };

  const edges = (key: string): string[] => depsOf(key).flatMap((d) => (d.key === null ? [] : [d.key]));

  const tops = (names: string[]): string[] => names.flatMap((r) => resolve([], r) ?? []);

  // each workspace's version, by its folder, so a workspace node is bound to the member it names
  const versionOf = (dir: string | null): string | null => (dir === null ? null : (lock.workspaces?.[dir]?.version ?? null));

  const node = (key: string): LockNode[] => {
    const e = entries.get(key);

    if (!e) return [];
    const base = bunOrigin(e);
    const origin: Origin = base.kind === "workspace" ? { ...base, version: versionOf(base.dir) } : base;

    return [{ key, name: e.id.name, version: e.id.spec, installedVersion: isRegistryVersion(e.id.spec) ? e.id.spec : null, integrity: e.integrity, resolved: e.resolved, hasInstallScript: e.meta.hasInstallScript === true, platform: hasPlatform(e.meta), supports: supportsOf(e.meta), origin, bundled: false, optional: false, deps: depsOf(key) }];
  };

  // the root ("") and each member: a member's own versions are keyed under its name ("app/leaf")
  const importers: LockImporter[] = Object.entries(lock.workspaces ?? {}).map(([dir, w]) => ({
    dir,
    deps: depsFrom({ names: dir === "" || w.name === undefined ? [] : [w.name], required: { ...w.dependencies, ...w.optionalDependencies, ...w.peerDependencies }, optional: Object.keys(w.optionalDependencies ?? {}), dev: w.devDependencies }),
  }));

  if (roots.kind === "top") return { nodes: roots.names.flatMap((n) => node(resolve([], n) ?? "").map((x) => ({ ...x, key: n }))), importers };
  const keys = roots.kind === "all" ? [...entries.keys()] : walk({ roots: tops(roots.names), edges });

  return { nodes: keys.flatMap(node), importers };
}

// ---------- pnpm: pnpm-lock.yaml v9 (and v6, where snapshots live under packages) ----------
const PnpmDep = z.union([z.string(), z.object({ version: z.string() }).loose().transform((o) => o.version)]);

const PnpmImporter = z
  .object({ dependencies: z.record(z.string(), PnpmDep).optional(), devDependencies: z.record(z.string(), PnpmDep).optional(), optionalDependencies: z.record(z.string(), PnpmDep).optional() })
  .loose();

const PnpmSnapshot = z.object({ dependencies: DepMap.optional(), optionalDependencies: DepMap.optional(), optional: z.boolean().optional() }).loose();
const PnpmResolution = z.object({ integrity: z.string().optional(), tarball: z.string().optional(), type: z.string().optional(), repo: z.string().optional(), commit: z.string().optional(), directory: z.string().optional() }).loose();
const PnpmPackage = PnpmSnapshot.extend({ resolution: PnpmResolution.optional(), requiresBuild: z.boolean().optional(), version: z.string().optional().catch(undefined), os: Platforms, cpu: Platforms });

const PnpmLock = z
  .object({
    importers: z.record(z.string(), PnpmImporter).optional(),
    packages: z.record(z.string(), PnpmPackage).optional(),
    snapshots: z.record(z.string(), PnpmSnapshot).optional(),
  })
  .loose();

/**
 * The snapshot key a dependency points at: "name@1.0.0(peer@2.0.0)", or the alias target "real@1.0.0". A file:
 * dependency (a tarball or folder) is its own entry, "name@file:../x.tgz", when the lockfile holds one (review of
 * 2b7767f, finding 4); `has` says whether it does. Null for link: and workspace: dependencies, and a file: one with no
 * entry: those are folders of the project.
 */
function pnpmKey(input: { name: string; version: string; has: (key: string) => boolean }): string | null {
  const { name, version } = input;

  if (version.startsWith("file:")) return input.has(`${name}@${version}`) ? `${name}@${version}` : null;

  if (/^(?:link|workspace):/.test(version)) return null;

  return /^@?[^@(]+@/.test(version) && !/^\d/.test(version) ? version : `${name}@${version}`;
}

/** Where a pnpm package's bytes come from: its resolution. */
function pnpmOrigin(spec: string, resolution: z.infer<typeof PnpmResolution> | undefined): Origin {
  if (resolution?.type === "git") return { kind: "git", source: `${resolution.repo ?? ""}#${resolution.commit ?? ""}` };

  if (resolution?.type === "directory") return { kind: "link", source: resolution.directory ?? spec };
  const tarball = resolution?.tarball;

  if (tarball !== undefined && !REGISTRY_TARBALL.test(tarball)) return originOf(tarball);

  if (!isRegistryVersion(spec)) return originOf(spec);

  return { kind: "registry" };
}

function pnpmGraph(text: string, importer: string, roots: Roots): Parsed {
  const lock = PnpmLock.parse(Bun.YAML.parse(text));
  const packages = lock.packages ?? {};
  const snapshots = lock.snapshots;
  const pkgOf = (key: string): z.infer<typeof PnpmPackage> | undefined => packages[key.replace(/\(.*$/, "")] ?? packages[`/${key}`] ?? packages[`/${key.replace(/\(.*$/, "")}`];
  const snapOf = (key: string): z.infer<typeof PnpmSnapshot> | undefined => (snapshots ? snapshots[key] : packages[key] ?? packages[`/${key}`]);
  const has = (key: string): boolean => snapOf(key) !== undefined && pkgOf(key) !== undefined;
  const keyOf = (name: string, version: string): string | null => pnpmKey({ name, version, has });
  const importers = lock.importers ?? {};
  const top = importers[importer] ?? importers["."];
  const depsOfImporter = (imp: z.infer<typeof PnpmImporter> | undefined) => ({ ...imp?.dependencies, ...imp?.devDependencies, ...imp?.optionalDependencies });
  const topDeps = depsOfImporter(top);

  const topKey = (r: string): string | null => {
    const v = topDeps[r];

    return v === undefined ? null : keyOf(r, v);
  };

  /** The importer a `link:` dependency of the importer at `from` points at, when it is one of the lockfile's importers. */
  const linkedImporter = (from: string, spec: string): string | null => {
    if (!spec.startsWith("link:")) return null;
    const dir = folderOf(posix.join(from === "." ? "" : from, spec.slice("link:".length)));

    return dir !== null && importers[dir] !== undefined ? dir : null;
  };

  /** A link:, file: or workspace: dependency: no package entry, kept with its origin; a link to an importer is that workspace member. */
  const localKey = (from: string, name: string, spec: string): string => {
    const member = linkedImporter(from, spec);

    return member === null ? `${name}@${spec}` : `workspace:${member}`;
  };

  const rootKeys = roots.kind === "all" ? Object.keys(snapshots ?? packages).map((k) => k.replace(/^\//, "")) : roots.names.flatMap((r) => topKey(r) ?? []);

  const depsOf = (key: string): LockDep[] => {
    const s = snapOf(key);
    const optional = new Set(Object.keys(s?.optionalDependencies ?? {}));

    return Object.entries({ ...s?.dependencies, ...s?.optionalDependencies }).flatMap(([name, v]) => {
      const to = keyOf(name, v);

      return to === null ? [] : [{ name, key: to, optional: optional.has(name), dev: false }];
    });
  };

  const edges = (key: string): string[] => depsOf(key).flatMap((d) => (d.key === null ? [] : [d.key]));

  const node = (key: string): LockNode[] => {
    const id = splitId(key.replace(/\(.*$/, ""));
    const p = pkgOf(key);

    if (!id || !p) return [];

    return [{ key, name: id.name, version: id.spec, installedVersion: p.version ?? (isRegistryVersion(id.spec) ? id.spec : null), integrity: p.resolution?.integrity ?? null, resolved: p.resolution?.tarball ?? null, hasInstallScript: p.requiresBuild === true, platform: hasPlatform(p), supports: supportsOf(p), origin: pnpmOrigin(id.spec, p.resolution), bundled: false, optional: snapOf(key)?.optional === true, deps: depsOf(key) }];
  };

  const local = (name: string, spec: string): LockNode => ({ key: `${name}@${spec}`, name, version: spec, installedVersion: null, integrity: null, resolved: null, hasInstallScript: false, platform: false, supports: null, origin: originOf(spec), bundled: false, optional: false, deps: [] });

  // every importer: the root ("") and each workspace member, with each dependency's edge
  const lockImporters: LockImporter[] = Object.entries(importers).map(([dir, imp]) => {
    const optional = new Set(Object.keys(imp.optionalDependencies ?? {}));
    const prod = new Set([...Object.keys(imp.dependencies ?? {}), ...optional]);

    return {
      dir: dir === "." ? "" : dir,
      deps: Object.entries(depsOfImporter(imp)).map(([name, v]) => ({ name, key: keyOf(name, v) ?? localKey(dir, name, v), optional: optional.has(name), dev: !prod.has(name) })),
    };
  });

  if (roots.kind === "top") {
    // a link:, file: or workspace: entry has no node: it is not a registry version, which projectPins says
    const nodes = roots.names.flatMap((n): LockNode[] => {
      const v = topDeps[n];

      if (v === undefined) return [];
      const key = topKey(n);

      return key === null ? [{ ...local(n, v), key: n }] : node(key).map((x) => ({ ...x, key: n }));
    });

    return { nodes, importers: lockImporters };
  }

  const nodes = walk({ roots: rootKeys, edges }).flatMap(node);

  if (roots.kind !== "all") return { nodes, importers: lockImporters };
  // every importer's local dependencies (a workspace member, a link): each kept, with its origin (review of a2227d1,
  // finding 4), and never in place of a package entry of the same key (review of 2b7767f, finding 4)
  const real = new Set(nodes.map((n) => n.key));
  const locals = new Map<string, LockNode>();

  // the workspace's own packages: each importer but the root, named by its directory (projectLayout knows its name)
  for (const dir of Object.keys(importers)) {
    if (dir !== ".") locals.set(`workspace:${dir}`, { ...local(dir, `workspace:${dir}`), key: `workspace:${dir}` });
  }

  for (const [dir, imp] of Object.entries(importers)) {
    for (const [n, v] of Object.entries(depsOfImporter(imp))) {
      // a link to another importer is that member's node, kept once above
      if (keyOf(n, v) === null && linkedImporter(dir, v) === null && !real.has(`${n}@${v}`)) locals.set(`${n}@${v}`, local(n, v));
    }
  }

  return { nodes: [...nodes, ...[...locals.values()].filter((l) => !real.has(l.key))], importers: lockImporters };
}

// ---------- yarn berry: yarn.lock (YAML, version 4 and up) ----------
const YarnBerryEntry = z.object({ version: z.string(), resolution: z.string(), checksum: z.string().optional(), dependencies: DepMap.optional(), linkType: z.string().optional() }).loose();

/**
 * A yarn berry lockfile's packages. Its checksums hash yarn's own archives, not the registry tarball, so apm sends no
 * integrity for them. The project's own workspace root is not a package.
 */
export function yarnBerryNodes(text: string): LockNode[] {
  const doc = z.record(z.string(), z.unknown()).parse(Bun.YAML.parse(text));
  const out: LockNode[] = [];

  for (const [key, raw] of Object.entries(doc)) {
    if (key === "__metadata") continue;
    const e = YarnBerryEntry.safeParse(raw);

    if (!e.success) throw new Error(`yarn.lock entry ${key} has no version or resolution`);
    const id = splitId(e.data.resolution);

    if (id === null) throw new Error(`yarn.lock entry ${key} has a resolution apm cannot read (${e.data.resolution})`);

    if (id.spec === "workspace:.") continue;
    const npm = /^npm:(.+)$/.exec(id.spec)?.[1];
    const origin: Origin = npm !== undefined && isRegistryVersion(npm) ? { kind: "registry" } : originOf(id.spec.replace(/^patch:/, "file:patch:"));

    out.push({ key, name: id.name, version: npm ?? id.spec, installedVersion: npm ?? null, integrity: null, resolved: null, hasInstallScript: false, platform: false, supports: null, origin, bundled: false, optional: false, deps: [] });
  }

  return out;
}

/** Whether `text` is a yarn berry lockfile (classic yarn.lock has no __metadata). */
export function isYarnBerryLock(text: string): boolean {
  return /^__metadata:/m.test(text);
}

function graphOf(input: { pm: LockPm; path: string; lockDir: string; cwd: string; roots: Roots }): Parsed {
  const text = readFileSync(input.path, "utf8");
  // the project directory relative to the lockfile's (workspaces keep one lockfile at the top)
  const from = relative(input.lockDir, input.cwd).split("\\").join("/");

  switch (input.pm) {
    case "npm":
      return npmGraph(text, from, input.roots);
    case "bun":
      return bunGraph(text, input.roots);
    case "pnpm":
      return pnpmGraph(text, from === "" ? "." : from, input.roots);
    default: {
      const _exhaustive: never = input.pm;

      return _exhaustive;
    }
  }
}

/** Every node of the lockfile at `path` (the one apm had the package manager compute), or why it could not be read. */
export function readLock(input: { pm: LockPm; path: string; cwd: string }): LockRead {
  try {
    return { kind: "read", path: input.path, ...graphOf({ pm: input.pm, path: input.path, lockDir: dirname(input.path), cwd: input.cwd, roots: { kind: "all" } }) };
  } catch (e) {
    return { kind: "unreadable", path: input.path, reason: e instanceof Error ? e.message : String(e) };
  }
}

/** Every node the lockfile puts under the packages named in `roots`, the roots included (or every node). */
export function lockedTree(input: { cwd: string; pm: LockPm; roots: Roots }): LockRead {
  const found = findLockfile(input.cwd, input.pm);
  // with the project lockfile turned off, npm and pnpm still keep one inside node_modules
  const hidden = HIDDEN_LOCKFILES[input.pm].map((f) => join(input.cwd, f)).find((p) => existsSync(p));
  const at = found ? { path: found, lockDir: dirname(found) } : hidden ? { path: hidden, lockDir: input.cwd } : null;

  if (!at) return { kind: "missing" };

  try {
    return { kind: "read", path: at.path, ...graphOf({ pm: input.pm, ...at, cwd: input.cwd, roots: input.roots }) };
  } catch (e) {
    return { kind: "unreadable", path: at.path, reason: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * What the project already installs under a name its package.json lists, as its lockfile says: `pinned`, a registry
 * version; `unknown`, a lockfile apm cannot read (yarn's, or one it fails to parse) or an entry it cannot pin to a
 * registry version (an alias, a git, file or link entry). A name with no lockfile, or none for it, is not in the map:
 * the package manager installs the newest version in range.
 */
export type ProjectPin = { kind: "pinned"; version: string } | { kind: "unknown"; why: string };

/** The nearest yarn.lock from `cwd` upward, or null. */
function findYarnLock(cwd: string): string | null {
  let dir = cwd;

  for (let i = 0; i < 20; i++) {
    if (existsSync(join(dir, "yarn.lock"))) return join(dir, "yarn.lock");
    const parent = dirname(dir);

    if (parent === dir) return null;
    dir = parent;
  }

  return null;
}

/** The version the project's lockfile pins for each of `names` (its direct dependencies), as ProjectPin says. */
export function projectPins(input: { cwd: string; pm: Pm; names: readonly string[] }): Map<string, ProjectPin> {
  const out = new Map<string, ProjectPin>();
  const { pm, cwd, names } = input;

  if (!isLockPm(pm)) {
    const yarn = findYarnLock(cwd);

    if (yarn !== null) for (const n of names) out.set(n, { kind: "unknown", why: `apm cannot read ${yarn}` });

    return out;
  }

  const read = lockedTree({ cwd, pm, roots: { kind: "top", names: [...names] } });

  switch (read.kind) {
    case "missing":
      return out;
    case "unreadable":
      for (const n of names) out.set(n, { kind: "unknown", why: `apm could not read ${read.path}: ${read.reason}` });

      return out;
    case "read":
      break;
    default: {
      const _exhaustive: never = read;

      return _exhaustive;
    }
  }

  const byName = new Map(read.nodes.map((x) => [x.key, x]));

  for (const n of names) {
    const node = byName.get(n);

    if (node === undefined) continue;

    if (node.name !== n) out.set(n, { kind: "unknown", why: `${n} installs ${node.name}, an alias` });
    // a git, file or remote tarball entry carries the version its package.json says, not a registry's
    else if (node.origin.kind !== "registry" || (node.resolved !== null && !/^https?:\/\//.test(node.resolved))) out.set(n, { kind: "unknown", why: `${n} is not installed from a registry (${node.resolved ?? node.version})` });
    else out.set(n, { kind: "pinned", version: node.version });
  }

  return out;
}
