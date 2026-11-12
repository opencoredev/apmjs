// What `apm audit` reads from disk: every installed name@version in node_modules, in npm's nested
// layout, pnpm's .pnpm store and bun's .bun store, plus what it could not read.
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { z } from "zod";

/** `unchecked`: what is in node_modules but could not be read, by path. */
export type Installed = { packages: Map<string, Set<string>>; unchecked: { id: string; reason: string }[] };

const MAX_DEPTH = 8;

// Metadata files and folders the package managers keep in node_modules; none of them hold packages.
const METADATA = new Set([".bin", ".cache", ".package-lock.json", ".modules.yaml", ".yarn-state.yml", ".yarn-integrity", ".vite", ".tmp", ".staging", ".ignored", ".pnpm-workspace-state.json", ".pnpm-workspace-state-v1.json"]);
const PackageJson = z.object({ name: z.string(), version: z.string() });

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function listDir(p: string): string[] {
  try {
    return readdirSync(p);
  } catch {
    return [];
  }
}

export function installedPackages(root: string): Installed {
  const packages = new Map<string, Set<string>>();
  const unchecked: Installed["unchecked"] = [];
  const seen = new Set<string>();
  const rel = (p: string): string => relative(root, p) || ".";

  const once = (p: string): boolean => {
    let real = p;

    try {
      real = realpathSync(p);
    } catch {
      // keep the path as given
    }

    if (seen.has(real)) return false;
    seen.add(real);

    return true;
  };

  const visitPackage = (dir: string, depth: number): void => {
    if (!once(dir)) return;

    const pj = join(dir, "package.json");

    if (existsSync(pj)) {
      try {
        const parsed = PackageJson.safeParse(JSON.parse(readFileSync(pj, "utf8")));

        if (parsed.success) {
          const set = packages.get(parsed.data.name) ?? new Set<string>();

          set.add(parsed.data.version);
          packages.set(parsed.data.name, set);
        } else {
          unchecked.push({ id: rel(dir), reason: "package.json has no name or version" });
        }
      } catch {
        unchecked.push({ id: rel(dir), reason: "unreadable package.json" });
      }
    }

    visitModules(join(dir, "node_modules"), depth + 1);
  };

  // pnpm: node_modules/.pnpm/<id>/node_modules/<name>; bun's isolated linker: node_modules/.bun/<id>/node_modules/<name>
  const visitStore = (store: string, depth: number): void => {
    let found = false;

    for (const id of listDir(store)) {
      const p = join(store, id);

      if (id === "node_modules") {
        found = true;
        visitModules(p, depth + 1);
        continue;
      }

      const nm = join(p, "node_modules");

      if (isDir(nm)) {
        found = true;
        visitModules(nm, depth + 1);
      }
    }

    if (!found) unchecked.push({ id: rel(store), reason: "unknown package store layout" });
  };

  const visitModules = (nm: string, depth: number): void => {
    if (!isDir(nm) || !once(nm)) return;

    if (depth > MAX_DEPTH) {
      unchecked.push({ id: rel(nm), reason: `nested more than ${MAX_DEPTH} levels deep` });

      return;
    }

    for (const entry of listDir(nm)) {
      const p = join(nm, entry);

      if (entry.startsWith(".")) {
        if (!METADATA.has(entry) && isDir(p)) visitStore(p, depth);
        continue;
      }

      if (entry.startsWith("@")) {
        for (const child of listDir(p)) visitPackage(join(p, child), depth);
        continue;
      }

      if (isDir(p)) visitPackage(p, depth);
    }
  };

  visitModules(join(root, "node_modules"), 0);

  return { packages, unchecked };
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
