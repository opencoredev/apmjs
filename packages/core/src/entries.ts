// Entry points declared in package.json that must exist in the tarball.
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function stripDot(p: string): string {
  return p.replace(/^\.\//, "").replace(/^\//, "");
}

export function entryPaths(manifest: Record<string, unknown>): { field: string; path: string }[] {
  const out: { field: string; path: string }[] = [];
  if (typeof manifest.main === "string") out.push({ field: "main", path: manifest.main });
  if (typeof manifest.types === "string") out.push({ field: "types", path: manifest.types });
  if (typeof manifest.typings === "string") out.push({ field: "typings", path: manifest.typings });
  if (typeof manifest.bin === "string") out.push({ field: "bin", path: manifest.bin });
  if (isRecord(manifest.bin)) for (const [k, v] of Object.entries(manifest.bin)) if (typeof v === "string") out.push({ field: `bin.${k}`, path: v });
  return out;
}

/** Entries whose target is not among `files` (node's extension and index lookup applied). */
export function missingEntries(manifest: Record<string, unknown>, files: readonly { path: string }[]): { field: string; path: string }[] {
  const have = new Set(files.map((f) => f.path));
  return entryPaths(manifest).filter(({ path }) => {
    const p = stripDot(path);
    if (have.has(p)) return false;
    return ![".js", ".json", ".node", "/index.js", "/index.json"].some((ext) => have.has(p + ext));
  });
}
