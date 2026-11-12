// After `apm add` installs with install scripts held back: is every package under the ones apm added the
// artifact the checked registry serves? Only then do the held-back scripts run. See docs/ARCHITECTURE.md.
import { existsSync, lstatSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { encodeName, type Api } from "./api.ts";
import { findLockfile, isRegistryVersion, LOCKFILES, lockedTree, type LockNode, type LockPm } from "./lockfile.ts";

/** A node whose bytes are not what the checked registry serves, and why. */
export type Mismatch = { node: LockNode; why: string };

export type TreeCheck =
  | { kind: "verified"; nodes: LockNode[]; notFromRegistry: LockNode[] }
  | { kind: "mismatch"; nodes: LockNode[]; bad: Mismatch[] }
  | { kind: "unreadable"; reason: string };

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
 * Reads the lockfile the install just wrote and compares each node under `roots` with the integrity
 * `api`'s registry serves for that name@version. Git, file and link nodes are not on a registry: they
 * come back in `notFromRegistry` (the resolve tree already listed them as not checked).
 */
export async function verifyTree(input: { api: Api; cwd: string; pm: LockPm; roots: string[] }): Promise<TreeCheck> {
  const read = lockedTree({ cwd: input.cwd, pm: input.pm, roots: { kind: "under", names: input.roots } });

  switch (read.kind) {
    case "missing":
      return { kind: "unreadable", reason: `there is no ${LOCKFILES[input.pm].join(" or ")} to read` };
    case "unreadable":
      return { kind: "unreadable", reason: `${read.path} could not be read (${read.reason})` };
    case "read":
      break;
    default: {
      const _exhaustive: never = read;

      return _exhaustive;
    }
  }

  const missingRoots = input.roots.filter((r) => !read.nodes.some((n) => n.name === r));

  if (missingRoots.length > 0) return { kind: "unreadable", reason: `${read.path} has no entry for ${missingRoots.join(", ")}` };
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

    if (expected === undefined) return [{ node, why: `${registry} does not serve ${node.name}@${node.version}` }];

    if (node.integrity !== expected) return [{ node, why: `the lockfile has ${node.integrity ?? "no integrity"}${node.resolved ? ` from ${node.resolved}` : ""}, but ${registry} serves ${expected}` }];

    return [];
  });

  if (bad.length > 0) return { kind: "mismatch", nodes: read.nodes, bad };

  return { kind: "verified", nodes: read.nodes, notFromRegistry: read.nodes.filter((n) => !isRegistryVersion(n.version)) };
}

// ---------- undoing a refused install ----------
/** The bytes of package.json and the lockfile before an install, so a refused one can be put back. */
export type Snapshot = { files: { path: string; bytes: Uint8Array | null }[] };

export function snapshot(input: { cwd: string; pm: LockPm }): Snapshot {
  const lock = findLockfile(input.cwd, input.pm) ?? join(input.cwd, LOCKFILES[input.pm][0] ?? "");
  const files = [join(input.cwd, "package.json"), lock].map((path) => ({ path, bytes: existsSync(path) ? new Uint8Array(readFileSync(path)) : null }));

  return { files };
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
