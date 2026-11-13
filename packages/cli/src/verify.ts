// After apm add installs the lockfile it checked, with every install script off: did the package manager install
// exactly that? Only then do install scripts run. apm never undoes an install: when the answer is no, it says what
// differs and how to put the project back (see docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked").
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { join, sep } from "node:path";
import { z } from "zod";
import { isValidPackageName } from "@apm/core";
import { installedPackages } from "./audit.ts";
import { bunKeyNames, type LockNode, type LockPm } from "./lockfile.ts";

const Manifest = z.object({ name: z.string(), version: z.string() }).loose();

/** The name@version a package directory's package.json holds, or null when it has none apm can read. */
function manifestAt(dir: string): { name: string; version: string } | null {
  try {
    const m = Manifest.safeParse(JSON.parse(readFileSync(join(dir, "package.json"), "utf8")));

    return m.success ? { name: m.data.name, version: m.data.version } : null;
  } catch {
    return null;
  }
}

/** Where bun installed a bun.lock key: "a/@s/b" is node_modules/a/node_modules/@s/b. */
export function bunInstallDir(root: string, names: string[]): string {
  return join(root, ...names.flatMap((n) => ["node_modules", ...n.split("/")]));
}

/**
 * The directory a lockfile node is installed at, for the package managers whose lockfile keys are install paths (npm
 * and bun), relative to the install root; null for pnpm (its store layout is its own) and for a node that is not
 * installed under node_modules (a workspace folder).
 */
export function installPathOf(pm: LockPm, root: string, node: LockNode): string | null {
  switch (pm) {
    case "npm":
      return node.key.startsWith("node_modules/") ? join(root, ...node.key.split("/")) : null;
    case "bun":
      return node.origin.kind === "workspace" ? null : bunInstallDir(root, bunKeyNames(node.key));
    case "pnpm":
      return null;
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/**
 * Every directory a lockfile node is installed in that apm can find: npm's and bun's install path (bun's hoisted
 * layout), and bun's isolated store (node_modules/.bun/<name>@<version>…/node_modules/<name>, where a workspace's
 * node_modules hold only symlinks). Only directories holding that name@version.
 */
export function installedDirs(pm: LockPm, root: string, node: LockNode): string[] {
  const at = installPathOf(pm, root, node);
  const store = join(root, "node_modules", ".bun");
  const prefix = `${node.name.replace("/", "+")}@${node.version}`;

  const stored =
    pm === "bun" && existsSync(store)
      ? readdirSync(store)
          .filter((e) => e === prefix || e.startsWith(`${prefix}+`) || e.startsWith(`${prefix}_`))
          .map((e) => join(store, e, "node_modules", ...node.name.split("/")))
      : [];

  return [...(at === null ? [] : [at]), ...stored].filter((d) => {
    const m = manifestAt(d);

    return m !== null && m.name === node.name && m.version === node.version;
  });
}

/**
 * The nodes the install will put in place: those no directory holds at that same name@version now (a version that
 * moved, as when a new version takes over the hoisted place, is put in place again too). Read before the install, so
 * install scripts run for what it installed, not again for what was already there.
 */
export function freshNodes(input: { pm: LockPm; root: string; nodes: readonly LockNode[] }): LockNode[] {
  return input.nodes.filter((n) => installedDirs(input.pm, input.root, n).length === 0);
}

/** What the check after the install found: the install is the checked lockfile, or how it is not. */
export type Verified = { kind: "verified"; unreadable: { id: string; reason: string }[] } | { kind: "mismatch"; problems: string[]; unreadable: { id: string; reason: string }[] };

/**
 * Whether what the package manager installed at `root` is the lockfile apm checked: the lockfile is still the checked
 * bytes (the install was frozen), every package in node_modules is a name@version of the checked lockfile (or of the
 * project's own workspace), and every npm or bun install path holds the version the lockfile puts there. A package
 * directory apm cannot read is returned apart: the caller warns about it, and strict mode refuses it.
 */
export function verifyInstall(input: { pm: LockPm; root: string; lockfile: string; checked: Uint8Array; nodes: readonly LockNode[]; members: readonly { name: string | null; version: string | null }[] }): Verified {
  const problems: string[] = [];
  const now = existsSync(join(input.root, input.lockfile)) ? new Uint8Array(readFileSync(join(input.root, input.lockfile))) : null;

  if (now === null) problems.push(`${input.lockfile} is gone: the install removed it`);
  else if (!Buffer.from(now).equals(Buffer.from(input.checked))) problems.push(`${input.lockfile} is not the lockfile apm checked: ${input.pm} changed it while it installed`);

  const allowed = new Set([...input.nodes.map((n) => `${n.name}@${n.version}`), ...input.members.flatMap((m) => (m.name !== null && m.version !== null ? [`${m.name}@${m.version}`] : []))]);
  // a git, file or link package's version is its own package.json's, not the lockfile's spec: its name is enough
  const localNames = new Set(input.nodes.filter((n) => n.origin.kind !== "registry").map((n) => n.name));
  const disk = installedPackages(input.root);
  const extra: string[] = [];

  for (const [name, versions] of disk.packages) {
    for (const v of versions) if (!allowed.has(`${name}@${v}`) && !localNames.has(name)) extra.push(`${name}@${v}`);
  }

  if (extra.length > 0) problems.push(`node_modules holds ${extra.length === 1 ? "a package" : `${extra.length} packages`} the checked lockfile does not: ${extra.slice(0, 10).join(", ")}${extra.length > 10 ? ", …" : ""}`);

  for (const n of input.nodes) {
    const at = installPathOf(input.pm, input.root, n);

    if (at === null || n.origin.kind !== "registry" || !existsSync(at)) continue;
    const m = manifestAt(at);

    if (m !== null && (m.name !== n.name || m.version !== n.version)) problems.push(`${n.key} holds ${m.name}@${m.version}, but the checked lockfile puts ${n.name}@${n.version} there`);
  }

  return problems.length > 0 ? { kind: "mismatch", problems, unreadable: disk.unchecked } : { kind: "verified", unreadable: disk.unchecked };
}

/**
 * Removes the directories bun installed a node in, so bun installs it again (and runs its scripts). Only real
 * directories inside `root`'s node_modules: a symlink is resolved and the directory it names must be in there too, so
 * nothing outside the project is touched (review of a2227d1, finding 12). Returns whether one was removed.
 */
export function removeBunInstall(input: { root: string; node: LockNode }): boolean {
  if (!isValidPackageName(input.node.name)) return false;
  let modules: string;

  try {
    modules = `${realpathSync(join(input.root, "node_modules"))}${sep}`;
  } catch {
    return false;
  }

  let removed = false;

  for (const dir of installedDirs("bun", input.root, input.node)) {
    try {
      const real = realpathSync(dir);
      const st = lstatSync(real);

      if (!real.startsWith(modules) || !st.isDirectory() || st.isSymbolicLink()) continue;
      rmSync(real, { recursive: true, force: true });
      removed = true;
    } catch {
      // gone already
    }
  }

  return removed;
}
