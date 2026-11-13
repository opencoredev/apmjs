// The directories apm add and apm x compute and check in, and the only writes apm makes to a project: two files,
// each replaced whole. A temporary directory is made fresh under TMPDIR and removed without following a symlink out of
// it (review of a2227d1, finding 12). See docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked".
import { closeSync, fchmodSync, lstatSync, mkdtempSync, openSync, realpathSync, renameSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

/** A directory apm made under TMPDIR, by mkdtemp: nothing else is ever handed to removeTemp. */
export type TempDir = string & { readonly __brand: "TempDir" };

/** The prefix of every temporary directory apm makes. */
const PREFIX = "apm-";

/** TMPDIR with its symlinks resolved, so a temporary directory's real path can be compared with it. */
function tmpRoot(): string {
  return realpathSync(tmpdir());
}

/** A new, empty, private (0700) directory under TMPDIR, named `apm-<what>-XXXXXX`. */
export function makeTemp(what: string): TempDir {
  const dir = mkdtempSync(join(tmpRoot(), `${PREFIX}${what}-`));

  return isOwnTemp(dir) ? dir : refuse(dir);
}

function refuse(dir: string): never {
  throw new Error(`apm made ${dir}, which is not a directory of its own under TMPDIR`);
}

/**
 * Whether `dir` is one of apm's temporary directories: a real directory (not a symlink), directly inside TMPDIR's real
 * path, with apm's prefix.
 */
export function isOwnTemp(dir: string): dir is TempDir {
  try {
    const st = lstatSync(dir);

    return st.isDirectory() && !st.isSymbolicLink() && dirname(dir) === tmpRoot() && basename(dir).startsWith(PREFIX) && realpathSync(dir) === dir;
  } catch {
    return false;
  }
}

/**
 * Removes one of apm's temporary directories and everything in it. A symlink inside it is removed as a link: rm never
 * follows one, so nothing outside the directory is touched. Anything that is not apm's own temporary directory is left.
 */
export function removeTemp(dir: TempDir): void {
  if (!isOwnTemp(dir)) return;
  rmSync(dir, { recursive: true, force: true });
}

/** Whether `path` is a symlink (a missing path is not). */
export function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Replaces `path` with `bytes` in one step: written beside it under a fresh name, then renamed over it, so a reader
 * sees the old file or the new one, never half of either. `mode` is kept from the file it replaces: the new file is
 * made private, then given exactly that mode with fchmod, which the umask does not touch (review of 2a098b1, finding
 * 15). A failure leaves no temporary file behind.
 */
export function writeAtomic(path: string, bytes: Uint8Array): void {
  let mode = 0o644;

  try {
    mode = lstatSync(path).mode & 0o7777;
  } catch {
    // a new file
  }

  const tmp = join(dirname(path), `.${basename(path)}.apm-${process.pid}-${Date.now().toString(36)}`);
  const fd = openSync(tmp, "wx", 0o600);

  try {
    try {
      for (let at = 0; at < bytes.length; ) at += writeSync(fd, bytes, at, bytes.length - at);
      fchmodSync(fd, mode);
    } finally {
      closeSync(fd);
    }

    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}
