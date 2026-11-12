// The /package/... URLs: a package page, or one file of one version. Pure, so proxy.ts, the page and the
// unit tests share it.
//
//   /package/zod                                  the package
//   /package/@scope/name                          a scoped package
//   /package/zod/v/4.1.0/file/lib/index.js#L12    one file of one version, opened at a line

export type PackageRoute = { kind: "package"; name: string } | { kind: "file"; name: string; version: string; path: string };

/** Reads the path segments after /package/ (still percent-encoded, as Next.js hands them over). Null for anything else. */
export function parsePackageRoute(encoded: readonly string[]): PackageRoute | null {
  let segs: string[];

  try {
    segs = encoded.map(decodeURIComponent);
  } catch {
    return null;
  }

  if (segs.length === 0 || segs.some((s) => s === "")) return null;
  const take = segs[0]?.startsWith("@") && segs.length > 1 ? 2 : 1;
  const name = segs.slice(0, take).join("/");
  const rest = segs.slice(take);

  if (rest.length === 0) return { kind: "package", name };
  const [v, version, file, ...path] = rest;

  if (v !== "v" || version === undefined || file !== "file" || path.length === 0) return null;

  return { kind: "file", name, version, path: path.join("/") };
}

/** The /package/... path for a name, one encoded segment per name part. */
export function packagePath(name: string): string {
  return `/package/${name.split("/").map(encodeURIComponent).join("/")}`;
}

/** The package page for one version, scrolled to its score. */
export function scoreHref(name: string, version: string): string {
  return `${packagePath(name)}?v=${encodeURIComponent(version)}#score`;
}

/**
 * Where a file of a version opens: at a line (`#L12`), at a package.json script (`#scripts.postinstall`), or at
 * the top. Null when the path can't survive a URL: browsers resolve `.` and `..` segments (even encoded) before
 * the request is sent, so such a path would open a different file.
 */
export function fileHref(input: { name: string; version: string; path: string; line?: number | null; anchor?: string | null }): string | null {
  const parts = input.path.split("/");

  if (parts.some((p) => p === "" || p === "." || p === "..")) return null;
  const at = input.line != null && input.line > 0 ? `#L${input.line}` : input.anchor ? `#${encodeURIComponent(input.anchor)}` : "";

  return `${packagePath(input.name)}/v/${encodeURIComponent(input.version)}/file/${parts.map(encodeURIComponent).join("/")}${at}`;
}
