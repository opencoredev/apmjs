// After apm add installs the lockfile it checked, with every install script off: did the package manager install
// exactly that? Only then do install scripts run. apm never undoes an install: when the answer is no, it says what
// differs and how to put the project back (see docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked").
//
// What was installed is checked the way Node will load it (review of 2a098b1, findings 3, 4 and 8): from each folder the
// lockfile installs for, every dependency edge it locks is looked up as Node looks it up, and must reach a package of
// the locked name and version (a workspace member: the member's own folder); from there, each of that package's own
// edges, and so on. npm's lockfile keys are install paths, so each one must also hold its locked version, with the
// integrity npm recorded for it. Every other package found in node_modules is accounted for: inside the tarball of a
// package that bundles it, there before the install (reported; strict refuses it), or else not the checked lockfile.
import { existsSync, lstatSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { z } from "zod";
import { integritiesConflict } from "@apm/core";
import { installedPackages, relPath, type Found } from "./audit.ts";
import { idOf, type Member } from "./installed.ts";
import { bunKeyNames, type LockDep, type LockImporter, type LockNode, type LockPm } from "./lockfile.ts";

const Manifest = z
  .object({
    name: z.string(),
    version: z.string(),
    // the lifecycle scripts a package manager runs while it installs a package
    scripts: z.object({ preinstall: z.string().optional().catch(undefined), install: z.string().optional().catch(undefined), postinstall: z.string().optional().catch(undefined) }).loose().optional().catch(undefined),
    bundleDependencies: z.union([z.boolean(), z.array(z.string())]).optional().catch(undefined),
    bundledDependencies: z.union([z.boolean(), z.array(z.string())]).optional().catch(undefined),
  })
  .loose();

type ManifestRead = { kind: "ok"; manifest: z.infer<typeof Manifest> } | { kind: "missing" } | { kind: "unreadable"; reason: string };

/** A package directory's package.json, or why there is none apm can read. */
function manifestAt(dir: string): ManifestRead {
  const path = join(dir, "package.json");

  if (!existsSync(path)) return { kind: "missing" };

  try {
    const m = Manifest.safeParse(JSON.parse(readFileSync(path, "utf8")));

    return m.success ? { kind: "ok", manifest: m.data } : { kind: "unreadable", reason: "package.json has no name or version" };
  } catch {
    return { kind: "unreadable", reason: "unreadable package.json" };
  }
}

/** Where bun installed a bun.lock key in its hoisted layout: "a/@s/b" is node_modules/a/node_modules/@s/b. */
export function bunInstallDir(root: string, names: string[]): string {
  return join(root, ...names.flatMap((n) => ["node_modules", ...n.split("/")]));
}

/** An npm lockfile key that is an install path (a package under node_modules), not a folder of the project. */
const isInstallPath = (key: string): boolean => key.startsWith("node_modules/") || key.includes("/node_modules/");

/** The real path of `p`, or null when nothing is there (a dangling link included). */
function realOrNull(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

const isInside = (p: string, root: string): boolean => p === root || p.startsWith(`${root}${sep}`);

/**
 * The directory Node loads `name` from when a module in `from` (a real path inside `root`) requires it: from's own
 * node_modules, then each parent's (never a node_modules/node_modules), stopping at `root`. Its real path, or null.
 */
export function resolveFrom(input: { root: string; from: string; name: string }): string | null {
  let dir = input.from;

  for (;;) {
    if (!dir.endsWith(`${sep}node_modules`)) {
      const hit = realOrNull(join(dir, "node_modules", ...input.name.split("/")));

      if (hit !== null) return hit;
    }

    if (dir === input.root) return null;
    const parent = dirname(dir);

    if (parent === dir || !isInside(parent, input.root)) return null;
    dir = parent;
  }
}

/** A package installed at a place the lockfile puts it: the node, its real path from the root's, and its package.json identity. */
export type Placed = { key: string; path: string; name: string; version: string; scripts: boolean };

/** A package found inside another's own node_modules, which ships it in its tarball (bundleDependencies). */
export type Embedded = { name: string; version: string; path: string; under: string };

/**
 * What the check after the install found. `unreadable`: package directories apm could not read (strict refuses them).
 * `extraneous`: packages outside the checked lockfile that were in node_modules before this install (strict refuses
 * them: install scripts could load them). `embedded`: packages inside a bundling package's tarball, whose state the
 * caller still asks about. `placed`: every package where the lockfile put it. `mismatch`: what is not the checked lockfile.
 */
export type Verified = { kind: "verified" | "mismatch"; problems: string[]; unreadable: { id: string; reason: string }[]; extraneous: Found[]; embedded: Embedded[]; placed: Placed[] };

/** Whether a package directory runs an install script: a lifecycle script, or a binding.gyp node-gyp builds. */
function runsInstallScript(dir: string, m: z.infer<typeof Manifest>): boolean {
  const s = m.scripts;

  return s?.preinstall !== undefined || s?.install !== undefined || s?.postinstall !== undefined || existsSync(join(dir, "binding.gyp"));
}

/** The names a package's tarball bundles, or "all" (bundleDependencies: true). */
function bundles(m: z.infer<typeof Manifest>): "all" | ReadonlySet<string> {
  const b = m.bundleDependencies ?? m.bundledDependencies;

  return b === true ? "all" : new Set(Array.isArray(b) ? b : []);
}

/** npm's record of what it installed where: node_modules/.package-lock.json. */
const HiddenLock = z.object({ packages: z.record(z.string(), z.object({ integrity: z.string().optional() }).loose()) }).loose();

function hiddenIntegrities(root: string): Map<string, string> {
  try {
    const h = HiddenLock.parse(JSON.parse(readFileSync(join(root, "node_modules", ".package-lock.json"), "utf8")));

    return new Map(Object.entries(h.packages).flatMap(([k, e]) => (e.integrity === undefined ? [] : [[k, e.integrity] as const])));
  } catch {
    return new Map();
  }
}

/**
 * Whether what the package manager installed at `root` is the lockfile apm checked: the lockfile is still the checked
 * bytes (the install was frozen), every dependency edge resolves as the lockfile locks it, every required package is
 * there, and nothing else is in node_modules but what was there before or ships inside a bundling package. `before`:
 * the packages node_modules held before the install (installedPackages(...).found).
 */
export function verifyInstall(input: { pm: LockPm; root: string; lockfile: string; checked: Uint8Array; nodes: readonly LockNode[]; importers: readonly LockImporter[]; members: readonly Member[]; before: readonly Found[] }): Verified {
  const problems: string[] = [];
  const now = existsSync(join(input.root, input.lockfile)) ? new Uint8Array(readFileSync(join(input.root, input.lockfile))) : null;

  if (now === null) problems.push(`${input.lockfile} is gone: the install removed it`);
  else if (!Buffer.from(now).equals(Buffer.from(input.checked))) problems.push(`${input.lockfile} is not the lockfile apm checked: ${input.pm} changed it while it installed`);

  const root = realOrNull(input.root) ?? input.root;
  const byKey = new Map(input.nodes.map((n) => [n.key, n]));
  const memberDirs = input.members.map((m) => m.dir);
  const disk = installedPackages(root, memberDirs);
  const unreadable = new Map(disk.unchecked.map((u) => [u.id, u.reason]));
  const placed = new Map<string, Placed>();
  const visited = new Set<string>();
  const queue: { key: string; dir: string }[] = [];
  const rel = (p: string): string => relPath(root, p) || ".";

  /** The folder a bound workspace member must resolve to, or null when the node is no bound member. */
  const memberFolder = (n: LockNode): { dir: string; name: string; version: string | null } | null => {
    if (n.origin.kind !== "workspace" || n.origin.dir === null) return null;
    const d = n.origin.dir;
    const m = input.members.find((x) => x.dir === d);

    return m === undefined || m.name === null ? null : { dir: join(root, d), name: m.name, version: m.version };
  };

  const place = (n: LockNode, at: string, m: z.infer<typeof Manifest>): void => {
    const key = `${n.key}\0${at}`;

    if (!placed.has(key)) placed.set(key, { key: n.key, path: rel(at), name: m.name, version: m.version, scripts: n.hasInstallScript || runsInstallScript(at, m) });
  };

  const follow = (from: { label: string; dir: string }, dep: LockDep): void => {
    const target = dep.key === null ? undefined : byKey.get(dep.key);

    if (target === undefined) return;
    const at = resolveFrom({ root, from: from.dir, name: dep.name });

    if (at === null) {
      if (!dep.optional && !target.optional) problems.push(`${dep.name} (${idOf(target)}), which ${from.label} needs, is not installed`);

      return;
    }

    const read = manifestAt(at);

    if (read.kind !== "ok") {
      unreadable.set(rel(at), read.kind === "missing" ? "no package.json" : read.reason);

      return;
    }

    const m = read.manifest;
    const member = memberFolder(target);

    const wrong =
      member !== null
        ? at !== (realOrNull(member.dir) ?? member.dir) || m.name !== member.name || (member.version !== null && m.version !== member.version)
        : m.name !== target.name || (target.origin.kind === "registry" && m.version !== target.version);

    if (wrong) {
      problems.push(`${from.label} resolves ${dep.name} to ${m.name}@${m.version} (${rel(at)}), but the checked lockfile locks ${member === null ? idOf(target) : `the workspace member ${member.name} in ${rel(member.dir)}`} there`);

      return;
    }

    place(target, at, m);

    // a member is a folder the lockfile installs for: its edges are its importer's; nothing outside the project is walked
    if (member !== null || !isInside(at, root) || visited.has(`${target.key}\0${at}`)) return;
    visited.add(`${target.key}\0${at}`);
    queue.push({ key: target.key, dir: at });
  };

  for (const imp of input.importers) {
    const dir = realOrNull(join(root, imp.dir));

    if (dir === null || !isInside(dir, root)) continue;

    for (const dep of imp.deps) follow({ label: imp.dir === "" ? "your project" : imp.dir, dir }, dep);
  }

  for (let i = 0; i < queue.length; i++) {
    const item = queue[i];
    const n = item === undefined ? undefined : byKey.get(item.key);

    if (item === undefined || n === undefined) continue;

    for (const dep of n.deps) follow({ label: `${idOf(n)} (${rel(item.dir)})`, dir: item.dir }, dep);
  }

  // npm's lockfile keys are install paths: each must hold its locked version, with the integrity npm recorded installing
  const hoisted = input.pm === "npm" || (input.pm === "bun" && !existsSync(join(root, "node_modules", ".bun")));
  const recorded = input.pm === "npm" ? hiddenIntegrities(root) : new Map<string, string>();

  for (const n of hoisted ? input.nodes : []) {
    if (n.origin.kind === "workspace" || n.version.startsWith("link:")) continue;
    const logical = input.pm === "npm" ? (isInstallPath(n.key) ? join(root, ...n.key.split("/")) : null) : bunInstallDir(root, bunKeyNames(n.key));

    if (logical === null) continue;
    const at = realOrNull(logical);

    if (at === null) {
      if (!n.optional) problems.push(`${n.key} is not installed, but the checked lockfile puts ${idOf(n)} there`);
      continue;
    }

    const read = manifestAt(at);

    if (read.kind !== "ok") {
      unreadable.set(rel(at), read.kind === "missing" ? "no package.json" : read.reason);
      continue;
    }

    const m = read.manifest;

    if (m.name !== n.name || (n.origin.kind === "registry" && m.version !== n.version)) {
      problems.push(`${n.key} holds ${m.name}@${m.version}, but the checked lockfile puts ${idOf(n)} there`);
      continue;
    }

    const npmRecorded = recorded.get(n.key);

    if (n.integrity !== null && npmRecorded !== undefined && integritiesConflict(n.integrity, npmRecorded)) {
      problems.push(`${n.key}: npm recorded installing ${npmRecorded} there, not the checked ${n.integrity}`);
      continue;
    }

    place(n, at, m);
  }

  // everything else node_modules holds
  const expected = new Set([...[...placed.values()].map((p) => p.path), ...memberDirs]);
  const before = new Set(input.before.map((f) => `${f.path} ${idOf(f)}`));
  const extraneous: Found[] = [];
  const embedded: Embedded[] = [];
  const extra: string[] = [];

  for (const f of disk.found) {
    if (f.path.startsWith("../") || f.path === ".." || expected.has(f.path)) continue;
    const parent = bundlerOf({ root, path: f.path, expected });

    if (parent !== null) embedded.push({ name: f.name, version: f.version, path: f.path, under: parent });
    else if (before.has(`${f.path} ${idOf(f)}`)) extraneous.push(f);
    else extra.push(idOf(f));
  }

  if (extra.length > 0) problems.push(`node_modules holds ${extra.length === 1 ? "a package" : `${extra.length} packages`} the checked lockfile does not: ${extra.slice(0, 10).join(", ")}${extra.length > 10 ? ", …" : ""}`);

  const verdict = { problems, unreadable: [...unreadable].map(([id, reason]) => ({ id, reason })), extraneous, embedded, placed: [...placed.values()] };

  return problems.length > 0 ? { kind: "mismatch", ...verdict } : { kind: "verified", ...verdict };
}

/**
 * The checked package whose tarball ships the package at `path`: the nearest package the lockfile placed whose own
 * node_modules holds it, when that package's bundleDependencies name the first package under it. Null otherwise.
 */
function bundlerOf(input: { root: string; path: string; expected: ReadonlySet<string> }): string | null {
  const marker = "/node_modules/";
  let at = input.path.lastIndexOf(marker);

  while (at > 0) {
    const owner = input.path.slice(0, at);

    if (input.expected.has(owner)) {
      const first = input.path.slice(at + marker.length).split("/");
      const name = first[0]?.startsWith("@") ? `${first[0]}/${first[1] ?? ""}` : (first[0] ?? "");
      const read = manifestAt(join(input.root, owner));

      if (read.kind !== "ok") return null;
      const b = bundles(read.manifest);

      return b === "all" || b.has(name) ? `${read.manifest.name}@${read.manifest.version}` : null;
    }

    at = input.path.lastIndexOf(marker, at - 1);
  }

  return null;
}

/** Why apm will not remove a directory, or that it removed it. */
export type Removal = { kind: "removed" } | { kind: "refused"; reason: string };

/**
 * Removes the package directory at `path` (relative to `root`'s real path) so bun installs it again, running its
 * scripts. Never through a symlink and never outside the project (review of 2a098b1, finding 5): the directory must be
 * a real directory whose real path is its path, inside the node_modules of the root or of a workspace member, and that
 * node_modules must itself be a real directory of the project, not a link to somewhere else. rm never follows a link
 * inside what it removes.
 */
export function removeInstalled(input: { root: string; members: readonly string[]; path: string }): Removal {
  const root = realOrNull(input.root);

  if (root === null) return { kind: "refused", reason: `${input.root} does not exist` };
  const target = join(root, ...input.path.split("/"));

  const boundaries = ["", ...input.members].flatMap((m) => {
    const nm = join(root, m, "node_modules");

    try {
      const st = lstatSync(nm);

      // a node_modules that is a link (to a shared or external store) is no boundary apm removes inside
      return st.isDirectory() && !st.isSymbolicLink() && realpathSync(nm) === nm ? [nm] : [];
    } catch {
      return [];
    }
  });

  try {
    const st = lstatSync(target);

    if (!st.isDirectory() || st.isSymbolicLink()) return { kind: "refused", reason: `${input.path} is not a directory of its own` };

    if (realpathSync(target) !== target) return { kind: "refused", reason: `${input.path} is reached through a symlink` };
  } catch {
    return { kind: "refused", reason: `${input.path} is not there` };
  }

  if (!boundaries.some((b) => target.startsWith(`${b}${sep}`))) return { kind: "refused", reason: `${input.path} is not inside the project's own node_modules` };
  rmSync(target, { recursive: true, force: true });

  return { kind: "removed" };
}
