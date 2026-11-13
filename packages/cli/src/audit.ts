// What `apm audit` and the check after an install read from disk: every installed package in node_modules, in npm's
// nested layout, pnpm's .pnpm store and bun's .bun store, where it is, and what could not be read. A directory that
// cannot be listed, or a package directory with no package.json, is never an empty one (review of 2a098b1, finding 4).
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { z } from "zod";

/** A package directory in node_modules: its real path from the root's real path ("/"-separated), and its package.json's name and version. */
export type Found = { path: string; name: string; version: string };

/**
 * `packages`: every name with the versions installed. `found`: each package directory once, by real path. `unchecked`:
 * what is in node_modules but could not be read (a package.json that is missing or not JSON, a directory that could
 * not be listed), by path.
 */
export type Installed = { packages: Map<string, Set<string>>; found: Found[]; unchecked: { id: string; reason: string }[] };

const MAX_DEPTH = 8;

// Metadata files and folders the package managers keep in node_modules; none of them hold packages.
const METADATA = new Set([".bin", ".cache", ".package-lock.json", ".modules.yaml", ".yarn-state.yml", ".yarn-integrity", ".vite", ".tmp", ".staging", ".ignored", ".pnpm-workspace-state.json", ".pnpm-workspace-state-v1.json"]);

// Files a package store (.pnpm, .bun) keeps beside its package directories: pnpm's copy of the lockfile it installed.
const STORE_METADATA = new Set(["lock.yaml"]);
const PackageJson = z.object({ name: z.string(), version: z.string() });

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** A directory's entries, or why they could not be read. */
function listDir(p: string): { kind: "listed"; entries: string[] } | { kind: "failed"; reason: string } {
  try {
    return { kind: "listed", entries: readdirSync(p) };
  } catch (e) {
    return { kind: "failed", reason: e instanceof Error && "code" in e ? `could not be listed (${String(e.code)})` : "could not be listed" };
  }
}

/** A path's real path, or itself when it has none (a dangling link). */
function realOf(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

/** Posix path of `p` from `base` ("" for base itself). */
export function relPath(base: string, p: string): string {
  return relative(base, p).split(sep).join("/");
}

/** Everything installed under `root`'s node_modules, and under each of `members` (workspace folders, relative to root). */
export function installedPackages(root: string, members: readonly string[] = []): Installed {
  const packages = new Map<string, Set<string>>();
  const found: Found[] = [];
  const unchecked: Installed["unchecked"] = [];
  const seen = new Set<string>();
  const realRoot = realOf(root);
  const rel = (p: string): string => relative(root, p) || ".";

  const once = (p: string): boolean => {
    const real = realOf(p);

    if (seen.has(real)) return false;
    seen.add(real);

    return true;
  };

  const list = (p: string): string[] => {
    const l = listDir(p);

    if (l.kind === "listed") return l.entries;
    unchecked.push({ id: rel(p), reason: l.reason });

    return [];
  };

  const visitPackage = (dir: string, depth: number): void => {
    if (!once(dir)) return;

    const pj = join(dir, "package.json");

    if (!existsSync(pj)) {
      // a dangling link, or a directory with no package.json: something is there that apm cannot name
      unchecked.push({ id: rel(dir), reason: isDir(dir) ? "no package.json" : "a link to nothing" });
    } else {
      try {
        const parsed = PackageJson.safeParse(JSON.parse(readFileSync(pj, "utf8")));

        if (parsed.success) {
          const set = packages.get(parsed.data.name) ?? new Set<string>();

          set.add(parsed.data.version);
          packages.set(parsed.data.name, set);
          found.push({ path: relPath(realRoot, realOf(dir)), name: parsed.data.name, version: parsed.data.version });
        } else {
          unchecked.push({ id: rel(dir), reason: "package.json has no name or version" });
        }
      } catch {
        unchecked.push({ id: rel(dir), reason: "unreadable package.json" });
      }
    }

    if (isDir(dir)) visitModules(join(dir, "node_modules"), depth + 1);
  };

  // pnpm: node_modules/.pnpm/<id>/node_modules/<name>; bun's isolated linker: node_modules/.bun/<id>/node_modules/<name>.
  // pnpm keeps a .pnpm with only its lock.yaml when the packages live elsewhere (node-linker=hoisted, or a virtual store
  // outside the project): that is metadata, not an unread store (review of efef668, finding 5). Anything else in a store
  // that is no package directory is reported, as is a store that cannot be listed.
  const visitStore = (store: string, depth: number): void => {
    for (const id of list(store)) {
      const p = join(store, id);

      if (id === "node_modules") {
        visitModules(p, depth + 1);
        continue;
      }

      const nm = join(p, "node_modules");

      if (isDir(nm)) visitModules(nm, depth + 1);
      else if (!(STORE_METADATA.has(id) && isFile(p))) unchecked.push({ id: rel(p), reason: "not a package directory of the package store" });
    }
  };

  const visitModules = (nm: string, depth: number): void => {
    if (!isDir(nm) || !once(nm)) return;

    if (depth > MAX_DEPTH) {
      unchecked.push({ id: rel(nm), reason: `nested more than ${MAX_DEPTH} levels deep` });

      return;
    }

    for (const entry of list(nm)) {
      const p = join(nm, entry);

      if (entry.startsWith(".")) {
        if (!METADATA.has(entry) && isDir(p)) visitStore(p, depth);
        continue;
      }

      if (entry.startsWith("@")) {
        for (const child of list(p)) visitPackage(join(p, child), depth);
        continue;
      }

      // a file directly in node_modules is no package; a link or a directory is one
      if (isDir(p) || isLink(p)) visitPackage(p, depth);
    }
  };

  visitModules(join(root, "node_modules"), 0);

  for (const m of members) visitModules(join(root, m, "node_modules"), 0);
  // pnpm's virtual store outside the project (virtual-store-dir): its packages are installed too, at paths from "../"
  const external = externalStore(root);

  switch (external.kind) {
    case "none":
      break;
    case "store":
      if (once(external.path)) visitStore(external.path, 0);
      break;
    case "unreadable":
      unchecked.push({ id: rel(external.path), reason: external.reason });
      break;
    default: {
      const _exhaustive: never = external;

      return _exhaustive;
    }
  }

  return { packages, found, unchecked };
}

const ModulesYaml = z.object({ virtualStoreDir: z.string() }).loose();

/**
 * pnpm's virtual store outside the project, as node_modules/.modules.yaml names it (virtual-store-dir). `none`: no
 * such file, the usual store inside node_modules, or a store that is not there. `unreadable`: the file or the store
 * could not be inspected (review of a24c6aa, finding 5): a parent directory that denies search hid the store, and the
 * strict check went on as if there were none. It is reported at the path apm tried.
 */
type ExternalStore = { kind: "none" } | { kind: "store"; path: string } | { kind: "unreadable"; path: string; reason: string };

/** A failed file system call's error code, as node gives it. */
const Errno = z.object({ code: z.string() });

function externalStore(root: string): ExternalStore {
  const nm = join(root, "node_modules");
  const file = join(nm, ".modules.yaml");
  let text: string;

  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    const code = Errno.safeParse(e).data?.code ?? "unknown error";

    return code === "ENOENT" || code === "ENOTDIR" ? { kind: "none" } : { kind: "unreadable", path: file, reason: `pnpm's metadata could not be read (${code})` };
  }

  let parsed: unknown;

  try {
    parsed = Bun.YAML.parse(text);
  } catch {
    return { kind: "unreadable", path: file, reason: "pnpm's metadata is not YAML" };
  }

  const m = ModulesYaml.safeParse(parsed);

  // a .modules.yaml that names no virtual store is not one apm can follow; the store, if any, is node_modules/.pnpm
  if (!m.success) return { kind: "none" };
  const store = resolve(nm, m.data.virtualStoreDir);
  const [real, inside] = [realOf(store), realOf(nm)];

  // the usual node_modules/.pnpm: the walk of node_modules reads it, and reports what it cannot
  if (real === inside || real.startsWith(`${inside}${sep}`)) return { kind: "none" };
  let isDirectory: boolean;

  try {
    isDirectory = statSync(store).isDirectory();
  } catch (e) {
    const code = Errno.safeParse(e).data?.code ?? "unknown error";

    return code === "ENOENT" || code === "ENOTDIR" ? { kind: "none" } : { kind: "unreadable", path: store, reason: `pnpm's virtual store could not be inspected (${code})` };
  }

  return isDirectory ? { kind: "store", path: real } : { kind: "unreadable", path: store, reason: "pnpm's virtual store is not a directory" };
}

function isLink(p: string): boolean {
  try {
    return lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
}

// npm's range grammar (node-semver): `||`-separated sets of comparators or one hyphen range.
const PART = "(?:0|[1-9]\\d*|[xX*])";
const IDENT = "[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*";
const PARTIAL = `v?${PART}(?:\\.${PART}(?:\\.${PART}(?:-${IDENT})?(?:\\+${IDENT})?)?)?`;
const COMPARATOR = new RegExp(`^(?:<=|>=|<|>|=|~>?|\\^)?${PARTIAL}$`);
const HYPHEN = new RegExp(`^${PARTIAL}\\s+-\\s+${PARTIAL}$`);

/**
 * Whether `range` is a range npm would parse. Bun.semver.satisfies answers true for garbage such as
 * ">>>" or "", which would flag every installed version, so audit checks the range first.
 */
export function isValidRange(range: string): boolean {
  const sets = range.split("||").map((s) => s.trim());

  return sets.every((set) => {
    if (set === "") return false;

    if (HYPHEN.test(set)) return true;

    return set
      .replace(/(<=|>=|<|>|=|~>?|\^)\s+/g, "$1")
      .split(/\s+/)
      .every((c) => COMPARATOR.test(c));
  });
}
