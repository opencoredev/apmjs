// After `apm add` installs with install scripts held back: is every package under the ones apm added the
// artifact the checked registry serves? Only then do the held-back scripts run. See docs/ARCHITECTURE.md.
import { existsSync, lstatSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import { encodeName, type Api } from "./api.ts";
import { installedPackages } from "./audit.ts";
import { findLockfile, isRegistryVersion, LOCKFILES, type LockNode } from "./lockfile.ts";
import type { Pm } from "./pm.ts";

/**
 * A node whose bytes are not what the checked registry serves, and why. `served`: the registry lists that version, with
 * other bytes; false when it does not list it at all (gone from it, or revoked or yanked there).
 */
export type Mismatch = { node: LockNode; why: string; served: boolean };

export type TreeCheck = { kind: "verified"; nodes: LockNode[]; notFromRegistry: LockNode[] } | { kind: "mismatch"; nodes: LockNode[]; bad: Mismatch[] };

const Dists = z.object({ versions: z.record(z.string(), z.object({ dist: z.object({ integrity: z.string().optional() }).loose() }).loose()) }).loose();

/** Runs `fn` over `items`, at most `limit` at a time. */
async function pool<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  let next = 0;

  const worker = async (): Promise<void> => {
    for (let i = next++; i < items.length; i = next++) {
      const item = items[i];

      if (item !== undefined) out[i] = await fn(item);
    }
  };

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));

  return out;
}

/**
 * Compares each lockfile node with the integrity `api`'s registry serves for that name@version. Git, file and link
 * nodes are not on a registry: they come back in `notFromRegistry` (the post-install check warns about each).
 */
export async function verifyNodes(input: { api: Api; nodes: readonly LockNode[] }): Promise<TreeCheck> {
  const read = { nodes: [...input.nodes] };
  const fromRegistry = read.nodes.filter((n) => isRegistryVersion(n.version));
  const names = [...new Set(fromRegistry.map((n) => n.name))];
  const served = new Map<string, Map<string, string>>();

  await pool(names, 8, async (name) => {
    const byVersion = new Map<string, string>();

    try {
      const doc = await input.api.get(encodeName(name), Dists);

      for (const [v, d] of Object.entries(doc.versions)) if (d.dist.integrity) byVersion.set(v, d.dist.integrity);
    } catch {
      // not on the checked registry: every version of it is a mismatch below
    }

    served.set(name, byVersion);
  });

  const registry = input.api.cfg.registry;

  const bad: Mismatch[] = fromRegistry.flatMap((node): Mismatch[] => {
    const expected = served.get(node.name)?.get(node.version);

    if (expected === undefined) return [{ node, why: `${registry} does not serve ${node.name}@${node.version}`, served: false }];

    if (node.integrity !== expected) return [{ node, why: `the lockfile has ${node.integrity ?? "no integrity"}${node.resolved ? ` from ${node.resolved}` : ""}, but ${registry} serves ${expected}`, served: true }];

    return [];
  });

  if (bad.length > 0) return { kind: "mismatch", nodes: read.nodes, bad };

  return { kind: "verified", nodes: read.nodes, notFromRegistry: read.nodes.filter((n) => !isRegistryVersion(n.version)) };
}

// ---------- undoing a refused install ----------
/**
 * The bytes of package.json and the lockfile before an install, so a refused one can be put back, and whether the
 * project had a node_modules then.
 */
export type Snapshot = { files: { path: string; bytes: Uint8Array | null }[]; hadNodeModules: boolean };

/** The nearest yarn.lock from `cwd` upward, else where yarn would write one. */
function yarnLock(cwd: string): string {
  let dir = cwd;

  for (let i = 0; i < 20; i++) {
    if (existsSync(join(dir, "yarn.lock"))) return join(dir, "yarn.lock");
    const parent = dirname(dir);

    if (parent === dir) break;
    dir = parent;
  }

  return join(cwd, "yarn.lock");
}

/** The lockfile `pm` reads and writes for `cwd`: the nearest one, else where it would write one. */
export function lockfileOf(input: { cwd: string; pm: Pm }): string {
  if (input.pm === "yarn") return yarnLock(input.cwd);

  return findLockfile(input.cwd, input.pm) ?? join(input.cwd, LOCKFILES[input.pm][0] ?? "");
}

export function snapshot(input: { cwd: string; pm: Pm }): Snapshot {
  const files = [join(input.cwd, "package.json"), lockfileOf(input)].map((path) => ({ path, bytes: existsSync(path) ? new Uint8Array(readFileSync(path)) : null }));

  return { files, hadNodeModules: existsSync(join(input.cwd, "node_modules")) };
}

/** Whether the snapshot held a lockfile (its second file). */
export function hadLockfile(s: Snapshot): boolean {
  return (s.files[1]?.bytes ?? null) !== null;
}

export function restore(s: Snapshot): void {
  for (const f of s.files) {
    if (f.bytes === null) rmSync(f.path, { force: true });
    else writeFileSync(f.path, f.bytes);
  }
}

const Manifest = z.object({ name: z.string(), version: z.string() }).loose();

/**
 * Removes every installed copy of the given name@versions under `cwd`'s node_modules, whatever layout the
 * package manager used (nested, hoisted, or pnpm's .pnpm store). Symlinks are not followed. Bounded.
 */
export function removeInstalled(input: { cwd: string; nodes: readonly { name: string; version: string }[] }): string[] {
  const wanted = new Set(input.nodes.map((n) => `${n.name}@${n.version}`));
  const removed: string[] = [];
  let budget = 50_000;

  const isDir = (p: string): boolean => {
    try {
      return lstatSync(p).isDirectory();
    } catch {
      return false;
    }
  };

  const list = (dir: string): string[] => {
    try {
      return readdirSync(dir);
    } catch {
      return [];
    }
  };

  const visitPackage = (dir: string): void => {
    if (--budget < 0 || !isDir(dir)) return;

    try {
      const m = Manifest.safeParse(JSON.parse(readFileSync(join(dir, "package.json"), "utf8")));

      if (m.success && wanted.has(`${m.data.name}@${m.data.version}`)) {
        rmSync(dir, { recursive: true, force: true });
        removed.push(dir);

        return;
      }
    } catch {
      // no readable package.json: look inside anyway
    }

    visitModules(join(dir, "node_modules"));
  };

  function visitModules(dir: string): void {
    for (const entry of list(dir)) {
      if (budget < 0) return;
      const p = join(dir, entry);

      if (entry === ".pnpm") for (const stored of list(p)) visitModules(join(p, stored, "node_modules"));
      else if (entry.startsWith("@")) for (const scoped of list(p)) visitPackage(join(p, scoped));
      else if (!entry.startsWith(".")) visitPackage(p);
    }
  }

  visitModules(join(input.cwd, "node_modules"));

  return removed;
}

/** Where bun installed a bun.lock key: "a/@s/b" is node_modules/a/node_modules/@s/b. */
export function bunInstallDir(cwd: string, names: string[]): string {
  return join(cwd, ...names.flatMap((n) => ["node_modules", ...n.split("/")]));
}

/** Whether each of `ids` (name@version) is still somewhere in `cwd`'s node_modules. */
export function stillInstalled(input: { cwd: string; ids: readonly string[] }): string[] {
  const disk = installedPackages(input.cwd);

  return input.ids.filter((id) => {
    const at = id.lastIndexOf("@");

    return at > 0 && disk.packages.get(id.slice(0, at))?.has(id.slice(at + 1)) === true;
  });
}

/**
 * Undoes a refused add: package.json and the lockfile go back to their bytes from before it, `reinstall` (the package
 * manager's own frozen install or remove, with scripts off) puts node_modules back in step, then the bytes are put back
 * again (a remove writes both), and every directory of a name@version the add brought in (`added`, never one installed
 * before) that is still there is removed. Returns which of `watch` are still on disk, and the command's exit code.
 */
export async function undoAdd(input: { cwd: string; before: Snapshot; reinstall: string[] | null; run: (cmd: string[]) => Promise<number>; added: readonly { name: string; version: string }[]; watch: readonly string[] }): Promise<{ code: number | null; left: string[] }> {
  restore(input.before);
  const modules = join(input.cwd, "node_modules");

  // the add made node_modules: removing it is the whole undo, and nothing is installed again
  if (!input.before.hadNodeModules) {
    rmSync(modules, { recursive: true, force: true });

    return { code: null, left: stillInstalled({ cwd: input.cwd, ids: input.watch }) };
  }

  const code = input.reinstall === null ? null : await input.run(input.reinstall);

  restore(input.before);
  removeInstalled({ cwd: input.cwd, nodes: input.added });

  return { code, left: stillInstalled({ cwd: input.cwd, ids: input.watch }) };
}
