// Lockfile first: apm add has the package manager compute the lockfile of the add in a directory of its own, from a
// copy of the project's manifests, lockfile and configuration, and installs nothing there. apm checks that lockfile,
// and only then copies it and package.json back over the project's: those two files, nothing else. The project is
// never touched before the check passes, so a refusal has nothing to undo (review of a2227d1, findings 8 to 10).
// See docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked".
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Layout } from "./project.ts";
import { staysInside } from "./project.ts";
import { isSymlink, makeTemp, writeAtomic, type TempDir } from "./sandbox.ts";

/** The bytes of a file, or null when there is none. */
export type Bytes = Uint8Array | null;

function bytesOf(path: string): Bytes {
  return existsSync(path) ? new Uint8Array(readFileSync(path)) : null;
}

const same = (a: Bytes, b: Bytes): boolean => (a === null || b === null ? a === b : Buffer.from(a).equals(Buffer.from(b)));

/** The two files apm writes to a project: its package.json (the member's, in a workspace) and lockfile, relative to the install root. */
export type Targets = { manifest: string; lockfile: string };

export function targets(layout: Layout): Targets {
  return { manifest: layout.member === "" ? "package.json" : `${layout.member}/package.json`, lockfile: layout.lockfile };
}

/**
 * A copy of the project in a temporary directory: `dir` holds the layout's files at the same relative paths. `copied`:
 * each file's bytes as copied, so apm can tell what the package manager changed in the copy and whether the project's
 * own package.json or lockfile changed while it checked.
 */
export type Copy = { dir: TempDir; copied: Map<string, Uint8Array>; original: { manifest: Bytes; lockfile: Bytes } };

/** Copies the layout's files (and only those) into a new temporary directory. Reads through no file it writes. */
export function copyProject(layout: Layout): Copy {
  const dir = makeTemp("add");
  const copied = new Map<string, Uint8Array>();

  for (const rel of layout.copy) {
    if (!staysInside(rel)) continue;
    const bytes = bytesOf(join(layout.root, rel));

    if (bytes === null) continue;
    const to = join(dir, rel);

    mkdirSync(dirname(to), { recursive: true, mode: 0o700 });
    // wx: never through something already there; 0600: an .npmrc may hold a token
    writeFileSync(to, bytes, { flag: "wx", mode: 0o600 });
    copied.set(rel, bytes);
  }

  const t = targets(layout);

  return { dir, copied, original: { manifest: copied.get(t.manifest) ?? null, lockfile: copied.get(t.lockfile) ?? null } };
}

/**
 * What the package manager wrote in the copy: the package.json and lockfile to apply, or why apm will not apply them.
 * `others`: copied files the package manager changed besides those two, which apm never copies back, so it refuses.
 */
export type Computed = { kind: "computed"; manifest: Uint8Array; lockfile: Uint8Array } | { kind: "refused"; reason: string };

export function computedFiles(input: { layout: Layout; copy: Copy }): Computed {
  const t = targets(input.layout);
  const manifest = bytesOf(join(input.copy.dir, t.manifest));
  const lockfile = bytesOf(join(input.copy.dir, t.lockfile));

  if (manifest === null) return { kind: "refused", reason: `the package manager left no ${t.manifest}` };

  if (lockfile === null) return { kind: "refused", reason: `the package manager wrote no ${t.lockfile}` };
  const others = [...input.copy.copied].flatMap(([rel, bytes]) => (rel !== t.manifest && rel !== t.lockfile && !same(bytesOf(join(input.copy.dir, rel)), bytes) ? [rel] : []));

  if (others.length > 0) return { kind: "refused", reason: `the package manager also changed ${others.join(", ")}, which apm does not copy into your project` };

  return { kind: "computed", manifest, lockfile };
}

/** Where apm keeps the project's package.json and lockfile from before an apply, until the install's scripts have run. */
export type Backup = { dir: TempDir; files: { rel: string; saved: string | null }[] };

/**
 * What applying the checked files did: both written, nothing written (`refused`), or a write that failed part way
 * (`failed`, with the backup the project can be put back from).
 */
export type Applied = { kind: "applied"; backup: Backup } | { kind: "refused"; reason: string } | { kind: "failed"; reason: string; backup: Backup };

/**
 * Writes the checked package.json and lockfile over the project's, each in one rename. Refuses, writing nothing, when
 * either changed since apm copied it (someone else edited the project while apm checked) or is a symlink (a rename
 * would replace the link, not the file it points at). The files from before go into a backup first.
 */
export function applyChecked(input: { layout: Layout; copy: Copy; computed: Extract<Computed, { kind: "computed" }> }): Applied {
  const { layout, copy, computed } = input;
  const t = targets(layout);
  const now = { manifest: bytesOf(join(layout.root, t.manifest)), lockfile: bytesOf(join(layout.root, t.lockfile)) };
  const changed = [...(same(now.manifest, copy.original.manifest) ? [] : [t.manifest]), ...(same(now.lockfile, copy.original.lockfile) ? [] : [t.lockfile])];

  if (changed.length > 0) return { kind: "refused", reason: `${changed.join(" and ")} changed while apm checked the add, so apm wrote nothing. Run apm add again` };
  const linked = [t.manifest, t.lockfile].filter((rel) => isSymlink(join(layout.root, rel)));

  if (linked.length > 0) return { kind: "refused", reason: `${linked.join(" and ")} ${linked.length === 1 ? "is a symlink" : "are symlinks"}, which apm will not replace` };

  const dir = makeTemp("backup");

  const files = [
    { rel: t.manifest, bytes: copy.original.manifest },
    { rel: t.lockfile, bytes: copy.original.lockfile },
  ].map((f) => {
    if (f.bytes === null) return { rel: f.rel, saved: null };
    const saved = join(dir, f.rel.split("/").join("__"));

    writeFileSync(saved, f.bytes, { flag: "wx", mode: 0o600 });

    return { rel: f.rel, saved };
  });

  try {
    writeAtomic(join(layout.root, t.lockfile), computed.lockfile);
    writeAtomic(join(layout.root, t.manifest), computed.manifest);
  } catch (e) {
    return { kind: "failed", reason: e instanceof Error ? e.message : String(e), backup: { dir, files } };
  }

  return { kind: "applied", backup: { dir, files } };
}

/** The commands that put the project's package.json and lockfile back as they were before apm add, from the backup. */
export function restoreCommands(input: { layout: Layout; backup: Backup }): string[] {
  const q = (s: string): string => `'${s.replaceAll("'", "'\\''")}'`;

  return input.backup.files.map((f) => (f.saved === null ? `rm ${q(join(input.layout.root, f.rel))}` : `cp ${q(f.saved)} ${q(join(input.layout.root, f.rel))}`));
}
