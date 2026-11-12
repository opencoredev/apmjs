// Loads a package version from disk as bytes, for `review-files`: a .tgz, or an already extracted
// directory (the eval's sample cache holds some versions that npm removed only in that form).
// Nothing here runs package code: files are read with lstat, and symlinks are skipped.
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { readTarball, type TarEntry } from "@apm/core";
import { packageFilesOf, type PackageFiles } from "@apm/ai-review";

const MAX_FILES = 5000;
const MAX_FILE_BYTES = 20_000_000;

/** The shallowest directory below `dir` holding a package.json (or `dir` itself). */
function packageRoot(dir: string, depth = 0): string | null {
  let entries: string[];

  try {
    entries = readdirSync(dir);
  } catch {
    return null;
  }

  if (entries.includes("package.json")) return dir;

  for (const e of entries.sort((a, b) => (a === "package" ? -1 : b === "package" ? 1 : 0))) {
    const p = join(dir, e);

    if (depth > 6 || !lstatSync(p).isDirectory()) continue;
    const found = packageRoot(p, depth + 1);

    if (found) return found;
  }

  return null;
}

function walk(root: string, dir: string, out: TarEntry[]): void {
  for (const e of readdirSync(dir)) {
    if (out.length >= MAX_FILES) return;
    const p = join(dir, e);
    const st = lstatSync(p);

    if (st.isSymbolicLink()) continue;

    if (st.isDirectory()) walk(root, p, out);
    else if (st.isFile()) {
      const data = st.size <= MAX_FILE_BYTES ? new Uint8Array(readFileSync(p)) : new Uint8Array(0);

      out.push({ path: relative(root, p), size: st.size, mode: st.mode & 0o777, data });
    }
  }
}

export function loadPackage(path: string): PackageFiles {
  if (path.endsWith(".tgz") || path.endsWith(".tar.gz")) return packageFilesOf(readTarball(new Uint8Array(readFileSync(path))));
  const root = packageRoot(path);

  if (!root) throw new Error(`no package.json under ${path}`);
  const files: TarEntry[] = [];

  walk(root, root, files);

  return packageFilesOf(files);
}
