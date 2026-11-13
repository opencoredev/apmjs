// A fingerprint of a project for "byte-identical" checks: every path under it with its type, mode and bytes (a
// symlink by its target, never followed). Two fingerprints are equal only when nothing under the project changed.
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { join } from "node:path";

/** `path type mode sha256` per entry under `dir`, sorted; `skip` names top-level entries to leave out (a test's own files). */
export function treeLines(dir: string, skip: readonly string[] = []): string[] {
  const out: string[] = [];

  const visit = (rel: string): void => {
    const abs = join(dir, rel);
    const st = lstatSync(abs);
    const mode = (st.mode & 0o777).toString(8);

    if (st.isSymbolicLink()) out.push(`${rel} link ${readlinkSync(abs)}`);
    else if (st.isDirectory()) {
      out.push(`${rel}/ dir ${mode}`);

      for (const e of readdirSync(abs).sort()) visit(rel === "" ? e : `${rel}/${e}`);
    } else out.push(`${rel} file ${mode} ${createHash("sha256").update(readFileSync(abs)).digest("hex")}`);
  };

  for (const e of readdirSync(dir).sort()) if (!skip.includes(e)) visit(e);

  return out;
}

/** One hash of treeLines, plus the lines themselves for a readable diff when a test fails. */
export type TreeHash = { hash: string; lines: string[] };

export function treeHash(dir: string, skip: readonly string[] = []): TreeHash {
  const lines = existsSync(dir) ? treeLines(dir, skip) : [];

  return { hash: createHash("sha256").update(lines.join("\n")).digest("hex"), lines };
}
