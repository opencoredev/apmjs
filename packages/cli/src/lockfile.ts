// What a package manager locked: every node of a lockfile, each with where it comes from (a registry, git, a file, a
// link or the project's own workspace). apm add and apm x check the lockfile the package manager computes, in a
// directory of its own, before anything is installed (see docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked").
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { z } from "zod";
import type { Pm } from "./pm.ts";

export type Locked = { integrity: string | null; resolved: string | null };

/**
 * Where a lockfile entry's bytes come from. `registry`: a registry tarball, which the scan checks by name, version and
 * integrity. The others keep what the lockfile says (`source`): no registry can check them, so they warn and strict
 * mode refuses them.
 */
export type Origin = { kind: "registry" } | { kind: "git" | "file" | "link" | "workspace" | "tarball"; source: string };

/**
 * One installed package as the lockfile records it. `key` is the lockfile's own id for it (npm and bun: its install
 * path). `platform`: the entry names the os or cpu it is built for. `bundled`: it ships inside its parent's tarball
 * (npm's inBundle), so the parent's score covers it and it has no artifact of its own.
 */
export type LockNode = { key: string; name: string; version: string; integrity: string | null; resolved: string | null; hasInstallScript: boolean; platform: boolean; origin: Origin; bundled: boolean };

/** An os or cpu field: a list, or (bun) one name. */
const Platforms = z.union([z.array(z.string()), z.string()]).optional().catch(undefined);

const hasPlatform = (e: { os?: string[] | string | undefined; cpu?: string[] | string | undefined }): boolean => e.os !== undefined || e.cpu !== undefined;

/** The nodes of a lockfile, or why apm could not read them. */
export type LockRead = { kind: "read"; path: string; nodes: LockNode[] } | { kind: "missing" } | { kind: "unreadable"; path: string; reason: string };

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

/** The origin of a spec or resolved location that is not a plain registry version. */
function originOf(source: string): Origin {
  if (GIT.test(source) || /^https?:\/\/codeload\.github\.com\//.test(source)) return { kind: "git", source };

  if (source.startsWith("workspace:")) return { kind: "workspace", source };

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
  if (!isInstallPath(key)) return { kind: "workspace", source: key };

  if (e.link === true) return originOf(`link:${e.resolved ?? ""}`);
  const resolved = e.resolved;

  if (resolved !== undefined && !REGISTRY_TARBALL.test(resolved)) return originOf(resolved);

  if (e.version === undefined || !isRegistryVersion(e.version)) return originOf(resolved ?? e.version ?? key);

  return { kind: "registry" };
}

function npmGraph(text: string, from: string, roots: Roots): LockNode[] {
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

  const edges = (key: string): string[] => {
    const e = packages[key];

    if (!e) return [];

    // a link's dependencies are its target's
    if (e.link === true) return e.resolved !== undefined && packages[e.resolved] ? [e.resolved] : [];

    return Object.keys({ ...e.dependencies, ...e.optionalDependencies, ...e.peerDependencies }).flatMap((d) => resolve(key, d) ?? []);
  };

  const tops = (names: string[]): string[] => names.flatMap((r) => resolve(from, r) ?? []);

  if (roots.kind === "top") return roots.names.flatMap((n) => npmTop(packages, n, resolve(from, n)));
  const keys = roots.kind === "all" ? Object.keys(packages).filter((k) => k !== "") : walk({ roots: tops(roots.names), edges });

  return keys.flatMap((key) => npmNode(packages, key));
}

/** The node at `key` of a package-lock.json. A link whose target the lockfile holds is that target's node, so none here. */
function npmNode(packages: NpmPackages, key: string | null): LockNode[] {
  if (key === null) return [];
  const e = packages[key];

  if (!e) return [];
  const name = e.name ?? key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);

  if (e.link === true) {
    if (e.resolved !== undefined && packages[e.resolved]) return [];

    return [{ key, name, version: `link:${e.resolved ?? ""}`, integrity: null, resolved: e.resolved ?? null, hasInstallScript: false, platform: false, origin: npmOrigin(key, e), bundled: false }];
  }

  // a workspace folder or a link's target: named by its own package.json
  const folderName = isInstallPath(key) ? name : (e.name ?? key.split("/").at(-1) ?? key);

  return [{ key, name: folderName, version: e.version ?? "0.0.0", integrity: e.integrity ?? null, resolved: e.resolved ?? null, hasInstallScript: e.hasInstallScript === true, platform: hasPlatform(e), origin: npmOrigin(key, e), bundled: e.inBundle === true }];
}

/** A top-level entry of a package-lock.json asked for as `name`: a link (a workspace package) is a node too, never a registry version. */
function npmTop(packages: NpmPackages, name: string, key: string | null): LockNode[] {
  const e = key === null ? undefined : packages[key];

  if (e?.link === true) return [{ key: name, name, version: `link:${e.resolved ?? ""}`, integrity: null, resolved: null, hasInstallScript: false, platform: false, origin: originOf(`link:${e.resolved ?? ""}`), bundled: false }];

  return npmNode(packages, key).map((node) => ({ ...node, key: name }));
}

// ---------- bun: bun.lock ----------
// "key": ["name@version", "registry tarball or empty", { dependencies, hasInstallScript, ... }, "sha512-..."]
const BunLock = z.object({ packages: z.record(z.string(), z.array(z.unknown())) }).loose();

const BunMeta = z
  .object({ dependencies: DepMap.optional(), optionalDependencies: DepMap.optional(), peerDependencies: DepMap.optional(), hasInstallScript: z.boolean().optional(), os: Platforms, cpu: Platforms })
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

function bunGraph(text: string, roots: Roots): LockNode[] {
  const { packages } = BunLock.parse(Bun.JSONC.parse(text));
  const entries = new Map<string, BunEntry>();

  for (const [key, raw] of Object.entries(packages)) {
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

  const edges = (key: string): string[] => {
    const m = entries.get(key)?.meta;

    return m ? Object.keys({ ...m.dependencies, ...m.optionalDependencies, ...m.peerDependencies }).flatMap((d) => resolve(bunKeyNames(key), d) ?? []) : [];
  };

  const tops = (names: string[]): string[] => names.flatMap((r) => resolve([], r) ?? []);

  const node = (key: string): LockNode[] => {
    const e = entries.get(key);

    if (!e) return [];
    const origin: Origin = isRegistryVersion(e.id.spec) ? { kind: "registry" } : originOf(e.id.spec);

    return [{ key, name: e.id.name, version: e.id.spec, integrity: e.integrity, resolved: e.resolved, hasInstallScript: e.meta.hasInstallScript === true, platform: hasPlatform(e.meta), origin, bundled: false }];
  };

  if (roots.kind === "top") return roots.names.flatMap((n) => node(resolve([], n) ?? "").map((x) => ({ ...x, key: n })));
  const keys = roots.kind === "all" ? [...entries.keys()] : walk({ roots: tops(roots.names), edges });

  return keys.flatMap(node);
}

// ---------- pnpm: pnpm-lock.yaml v9 (and v6, where snapshots live under packages) ----------
const PnpmDep = z.union([z.string(), z.object({ version: z.string() }).loose().transform((o) => o.version)]);

const PnpmImporter = z
  .object({ dependencies: z.record(z.string(), PnpmDep).optional(), devDependencies: z.record(z.string(), PnpmDep).optional(), optionalDependencies: z.record(z.string(), PnpmDep).optional() })
  .loose();

const PnpmSnapshot = z.object({ dependencies: DepMap.optional(), optionalDependencies: DepMap.optional() }).loose();
const PnpmResolution = z.object({ integrity: z.string().optional(), tarball: z.string().optional(), type: z.string().optional(), repo: z.string().optional(), commit: z.string().optional(), directory: z.string().optional() }).loose();
const PnpmPackage = PnpmSnapshot.extend({ resolution: PnpmResolution.optional(), requiresBuild: z.boolean().optional(), os: Platforms, cpu: Platforms });

const PnpmLock = z
  .object({
    importers: z.record(z.string(), PnpmImporter).optional(),
    packages: z.record(z.string(), PnpmPackage).optional(),
    snapshots: z.record(z.string(), PnpmSnapshot).optional(),
  })
  .loose();

/** The snapshot key a dependency points at: "name@1.0.0(peer@2.0.0)", or the alias target "real@1.0.0". Null for link: and file: deps. */
function pnpmKey(name: string, version: string): string | null {
  if (/^(?:link|file|workspace):/.test(version)) return null;

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

function pnpmGraph(text: string, importer: string, roots: Roots): LockNode[] {
  const lock = PnpmLock.parse(Bun.YAML.parse(text));
  const packages = lock.packages ?? {};
  const snapshots = lock.snapshots;
  const pkgOf = (key: string): z.infer<typeof PnpmPackage> | undefined => packages[key.replace(/\(.*$/, "")] ?? packages[`/${key}`] ?? packages[`/${key.replace(/\(.*$/, "")}`];
  const snapOf = (key: string): z.infer<typeof PnpmSnapshot> | undefined => (snapshots ? snapshots[key] : packages[key] ?? packages[`/${key}`]);
  const top = lock.importers?.[importer] ?? lock.importers?.["."];
  const depsOf = (imp: z.infer<typeof PnpmImporter> | undefined) => ({ ...imp?.dependencies, ...imp?.devDependencies, ...imp?.optionalDependencies });
  const topDeps = depsOf(top);

  const topKey = (r: string): string | null => {
    const v = topDeps[r];

    return v === undefined ? null : pnpmKey(r, v);
  };

  const rootKeys = roots.kind === "all" ? Object.keys(snapshots ?? packages).map((k) => k.replace(/^\//, "")) : roots.names.flatMap((r) => topKey(r) ?? []);

  const edges = (key: string): string[] => {
    const s = snapOf(key);

    return Object.entries({ ...s?.dependencies, ...s?.optionalDependencies }).flatMap(([n, v]) => pnpmKey(n, v) ?? []);
  };

  const node = (key: string): LockNode[] => {
    const id = splitId(key.replace(/\(.*$/, ""));
    const p = pkgOf(key);

    if (!id || !p) return [];

    return [{ key, name: id.name, version: id.spec, integrity: p.resolution?.integrity ?? null, resolved: p.resolution?.tarball ?? null, hasInstallScript: p.requiresBuild === true, platform: hasPlatform(p), origin: pnpmOrigin(id.spec, p.resolution), bundled: false }];
  };

  /** A link:, file: or workspace: dependency: no package entry, kept with its origin. */
  const local = (name: string, spec: string): LockNode => ({ key: `${name}@${spec}`, name, version: spec, integrity: null, resolved: null, hasInstallScript: false, platform: false, origin: originOf(spec), bundled: false });

  if (roots.kind === "top") {
    // a link:, file: or workspace: entry has no node: it is not a registry version, which projectPins says
    return roots.names.flatMap((n): LockNode[] => {
      const v = topDeps[n];

      if (v === undefined) return [];
      const key = topKey(n);

      return key === null ? [{ ...local(n, v), key: n }] : node(key).map((x) => ({ ...x, key: n }));
    });
  }

  const nodes = walk({ roots: rootKeys, edges }).flatMap(node);

  if (roots.kind !== "all") return nodes;
  // every importer's local dependencies (a workspace member, a link): each kept, with its origin (review of a2227d1, finding 4)
  const locals = new Map<string, LockNode>();

  // the workspace's own packages: each importer but the root, named by its directory (projectLayout knows its name)
  for (const dir of Object.keys(lock.importers ?? {})) if (dir !== ".") locals.set(`workspace:${dir}`, { ...local(dir, `workspace:${dir}`), key: `workspace:${dir}` });

  for (const imp of Object.values(lock.importers ?? {})) {
    for (const [n, v] of Object.entries(depsOf(imp))) if (pnpmKey(n, v) === null) locals.set(`${n}@${v}`, local(n, v));
  }

  return [...nodes, ...locals.values()];
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

    out.push({ key, name: id.name, version: npm ?? id.spec, integrity: null, resolved: null, hasInstallScript: false, platform: false, origin, bundled: false });
  }

  return out;
}

/** Whether `text` is a yarn berry lockfile (classic yarn.lock has no __metadata). */
export function isYarnBerryLock(text: string): boolean {
  return /^__metadata:/m.test(text);
}

function graphOf(input: { pm: LockPm; path: string; lockDir: string; cwd: string; roots: Roots }): LockNode[] {
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
    return { kind: "read", path: input.path, nodes: graphOf({ pm: input.pm, path: input.path, lockDir: dirname(input.path), cwd: input.cwd, roots: { kind: "all" } }) };
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
    return { kind: "read", path: at.path, nodes: graphOf({ pm: input.pm, ...at, cwd: input.cwd, roots: input.roots }) };
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
