// Loads a package version as bytes: from an unzipped dataset sample or from an npm tarball.
// Nothing here executes package code; files are read with lstat and symlinks are skipped.
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { readTarball, type TarEntry } from "../../packages/core/src/tarball.ts";

export type SampleFiles = { manifest: Record<string, unknown>; files: TarEntry[] };

const MAX_FILES = 5000;
const MAX_FILE_BYTES = 20_000_000;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function parseManifest(files: readonly TarEntry[]): Record<string, unknown> {
  const pj = files.find((f) => f.path === "package.json");
  if (!pj) return {};
  try {
    const v: unknown = JSON.parse(new TextDecoder().decode(pj.data));
    return isRecord(v) ? v : {};
  } catch {
    return {};
  }
}

/** Finds the shallowest directory holding a package.json (the dataset nests it under tmp/<x>/<name>/package/). */
function packageRoot(dir: string, depth = 0): string | null {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return null;
  }
  if (entries.includes("package.json") && depth > 0) return dir;
  for (const e of entries.sort((a, b) => (a === "package" ? -1 : b === "package" ? 1 : 0))) {
    const p = join(dir, e);
    if (!lstatSync(p).isDirectory()) continue;
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

export function loadDir(extracted: string): SampleFiles | null {
  const root = packageRoot(extracted);
  if (!root) return null;
  const files: TarEntry[] = [];
  walk(root, root, files);
  files.sort((a, b) => (a.path < b.path ? -1 : 1));
  return { manifest: parseManifest(files), files };
}

export function loadTgz(path: string): SampleFiles {
  const files = readTarball(new Uint8Array(readFileSync(path))).sort((a, b) => (a.path < b.path ? -1 : 1));
  return { manifest: parseManifest(files), files };
}
