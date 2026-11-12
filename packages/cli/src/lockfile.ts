// What the package manager locked: the entry for one name@version (checked before an install), and every
// node an install put under the packages apm added (checked after it, before any install script runs).
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { z } from "zod";
import type { Pm } from "./pm.ts";

export type Locked = { integrity: string | null; resolved: string | null };

/** One installed package as the lockfile records it. `key` is the lockfile's own id for it. */
export type LockNode = { key: string; name: string; version: string; integrity: string | null; resolved: string | null; hasInstallScript: boolean };

/** The nodes under the added packages, or why apm could not read them. */
export type LockRead = { kind: "read"; path: string; nodes: LockNode[] } | { kind: "missing" } | { kind: "unreadable"; path: string; reason: string };

export type LockPm = Exclude<Pm, "yarn">;

export const LOCKFILES: Record<LockPm, string[]> = {
  bun: ["bun.lock"],
  npm: ["package-lock.json", "npm-shrinkwrap.json"],
  pnpm: ["pnpm-lock.yaml"],
};

// What each package manager keeps in node_modules when the project lockfile is turned off.
const HIDDEN_LOCKFILES: Record<LockPm, string[]> = {
  bun: [],
  npm: [join("node_modules", ".package-lock.json")],
  pnpm: [join("node_modules", ".pnpm", "lock.yaml")],
};

export function isLockPm(pm: Pm): pm is LockPm {
  return pm !== "yarn";
}

/** The nearest lockfile for `pm` from `cwd` upward, or null. */
export function findLockfile(cwd: string, pm: LockPm): string | null {
  let dir = cwd;

  for (let i = 0; i < 20; i++) {
    for (const f of LOCKFILES[pm]) if (existsSync(join(dir, f))) return join(dir, f);

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

const DepMap = z.record(z.string(), z.string());

/** Which nodes to read: those under the named top-level packages, or every node in the lockfile. */
export type Roots = { kind: "under"; names: string[] } | { kind: "all" };

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

// ---------- npm: package-lock.json v2/v3 ----------
const NpmEntry = z
  .object({
    name: z.string().optional(),
    version: z.string().optional(),
    resolved: z.string().optional(),
    integrity: z.string().optional(),
    link: z.boolean().optional(),
    hasInstallScript: z.boolean().optional(),
    dependencies: DepMap.optional(),
    optionalDependencies: DepMap.optional(),
    peerDependencies: DepMap.optional(),
  })
  .loose();
const NpmLock = z.object({ packages: z.record(z.string(), NpmEntry) }).loose();

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

    if (!e || e.link) return [];

    return Object.keys({ ...e.dependencies, ...e.optionalDependencies, ...e.peerDependencies }).flatMap((d) => resolve(key, d) ?? []);
  };
  const keys = roots.kind === "all" ? Object.keys(packages).filter((k) => k !== "") : walk({ roots: roots.names.flatMap((r) => resolve(from, r) ?? []), edges });

  return keys.flatMap((key): LockNode[] => {
    const e = packages[key];

    if (!e || e.link || e.version === undefined) return [];

    return [{ key, name: e.name ?? key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length), version: e.version, integrity: e.integrity ?? null, resolved: e.resolved ?? null, hasInstallScript: e.hasInstallScript === true }];
  });
}

// ---------- bun: bun.lock ----------
// "key": ["name@version", "registry tarball or empty", { dependencies, hasInstallScript, ... }, "sha512-..."]
const BunLock = z.object({ packages: z.record(z.string(), z.array(z.unknown())) }).loose();
const BunMeta = z
  .object({ dependencies: DepMap.optional(), optionalDependencies: DepMap.optional(), peerDependencies: DepMap.optional(), hasInstallScript: z.boolean().optional() })
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

function bunEntry(raw: unknown[]): BunEntry | null {
  const id = typeof raw[0] === "string" ? splitId(raw[0]) : null;

  if (!id) return null;

  // registry packages carry [id, tarball, meta, integrity]; git, file and workspace entries are shorter
  if (isRegistryVersion(id.spec)) {
    const meta = BunMeta.safeParse(raw[2] ?? {});

    return { id, resolved: typeof raw[1] === "string" && raw[1] !== "" ? raw[1] : null, meta: meta.success ? meta.data : {}, integrity: typeof raw[3] === "string" ? raw[3] : null };
  }

  const meta = BunMeta.safeParse(raw.find((x) => typeof x === "object" && x !== null && !Array.isArray(x)) ?? {});

  return { id, resolved: null, meta: meta.success ? meta.data : {}, integrity: null };
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
  const keys = roots.kind === "all" ? [...entries.keys()] : walk({ roots: roots.names.flatMap((r) => resolve([], r) ?? []), edges });

  return keys.flatMap((key): LockNode[] => {
    const e = entries.get(key);

    if (!e) return [];

    return [{ key, name: e.id.name, version: e.id.spec, integrity: e.integrity, resolved: e.resolved, hasInstallScript: e.meta.hasInstallScript === true }];
  });
}

// ---------- pnpm: pnpm-lock.yaml v9 (and v6, where snapshots live under packages) ----------
const PnpmDep = z.union([z.string(), z.object({ version: z.string() }).loose().transform((o) => o.version)]);
const PnpmImporter = z
  .object({ dependencies: z.record(z.string(), PnpmDep).optional(), devDependencies: z.record(z.string(), PnpmDep).optional(), optionalDependencies: z.record(z.string(), PnpmDep).optional() })
  .loose();
const PnpmSnapshot = z.object({ dependencies: DepMap.optional(), optionalDependencies: DepMap.optional() }).loose();
const PnpmPackage = PnpmSnapshot.extend({ resolution: z.object({ integrity: z.string().optional(), tarball: z.string().optional() }).loose().optional(), requiresBuild: z.boolean().optional() });
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

function pnpmGraph(text: string, importer: string, roots: Roots): LockNode[] {
  const lock = PnpmLock.parse(Bun.YAML.parse(text));
  const packages = lock.packages ?? {};
  const snapshots = lock.snapshots;
  const pkgOf = (key: string): z.infer<typeof PnpmPackage> | undefined => packages[key.replace(/\(.*$/, "")] ?? packages[`/${key}`] ?? packages[`/${key.replace(/\(.*$/, "")}`];
  const snapOf = (key: string): z.infer<typeof PnpmSnapshot> | undefined => (snapshots ? snapshots[key] : packages[key] ?? packages[`/${key}`]);
  const top = lock.importers?.[importer] ?? lock.importers?.["."];
  const topDeps = { ...top?.dependencies, ...top?.devDependencies, ...top?.optionalDependencies };
  const rootKeys =
    roots.kind === "all"
      ? Object.keys(snapshots ?? packages).map((k) => k.replace(/^\//, ""))
      : roots.names.flatMap((r) => {
          const v = topDeps[r];

          return v === undefined ? [] : (pnpmKey(r, v) ?? []);
        });

  const edges = (key: string): string[] => {
    const s = snapOf(key);

    return Object.entries({ ...s?.dependencies, ...s?.optionalDependencies }).flatMap(([n, v]) => pnpmKey(n, v) ?? []);
  };

  return walk({ roots: rootKeys, edges }).flatMap((key): LockNode[] => {
    const id = splitId(key.replace(/\(.*$/, ""));
    const p = pkgOf(key);

    if (!id || !p) return [];

    return [{ key, name: id.name, version: id.spec, integrity: p.resolution?.integrity ?? null, resolved: p.resolution?.tarball ?? null, hasInstallScript: p.requiresBuild === true }];
  });
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

/** The lockfile entry for name@version, or null when there is no lockfile or no entry apm can read (yarn's included). */
export function lockedEntry(input: { cwd: string; pm: Pm; name: string; version: string }): Locked | null {
  if (!isLockPm(input.pm)) return null;

  const read = lockedTree({ cwd: input.cwd, pm: input.pm, roots: { kind: "all" } });

  if (read.kind !== "read") return null;
  const hit = read.nodes.find((n) => n.name === input.name && n.version === input.version);

  return hit ? { integrity: hit.integrity, resolved: hit.resolved } : null;
}
