// Entry points package.json declares. One collector for both users: the publish check (each must exist in
// the tarball) and the scorer (what runs is read first), so the two lists cannot drift apart.
import { z } from "zod";
import { sameSubstitution } from "./glob.ts";
import { ManifestTooLargeError, measureManifest } from "./manifest.ts";
import { charge } from "./meter.ts";

function stripDot(p: string): string {
  return p.replace(/^\.\//, "").replace(/^\//, "");
}

/** A path package.json names, and the field it came from (`exports["."].import`, `bin.cli`). */
export type EntryPoint = { field: string; path: string };

/** An `exports` value read into what matters here: a path, fallbacks, or subpaths and conditions. */
type ExportsTree = { kind: "path"; path: string } | { kind: "list"; items: ExportsTree[] } | { kind: "map"; entries: [string, ExportsTree][] } | { kind: "none" };

const ExportsTree: z.ZodType<ExportsTree> = z.lazy(() =>
  z.union([
    z.string().transform((path): ExportsTree => ({ kind: "path", path })),
    z.array(ExportsTree).transform((items): ExportsTree => ({ kind: "list", items })),
    z.record(z.string(), ExportsTree).transform((o): ExportsTree => ({ kind: "map", entries: Object.entries(o) })),
    // null blocks a subpath; anything else is not a target
    z.unknown().transform((): ExportsTree => ({ kind: "none" })),
  ]),
);

/** A field that is a path, or a map of names to paths (bin, browser). Values that are not paths are dropped. */
const PathOrMap = z
  .union([z.string().transform((path) => ({ kind: "path" as const, path })), z.record(z.string(), z.unknown()).transform((o) => ({ kind: "map" as const, o }))])
  .optional()
  .catch(undefined);

const OptionalPath = z.string().optional().catch(undefined);

const Fields = z.object({
  bin: PathOrMap,
  main: OptionalPath,
  module: OptionalPath,
  browser: PathOrMap,
  exports: ExportsTree.optional(),
  imports: ExportsTree.optional(),
  types: OptionalPath,
  typings: OptionalPath,
});

function exportTargets(tree: ExportsTree, field: string, out: EntryPoint[]): void {
  switch (tree.kind) {
    case "path":
      out.push({ field, path: tree.path });

      return;
    case "list":
      tree.items.forEach((x, i) => exportTargets(x, `${field}[${i}]`, out));

      return;
    case "map":
      for (const [k, x] of tree.entries) exportTargets(x, `${field}[${JSON.stringify(k)}]`, out);

      return;
    case "none":
      return;
    default: {
      const _exhaustive: never = tree;

      return _exhaustive;
    }
  }
}

function pathsIn(field: string, v: z.infer<typeof PathOrMap>, keyed: (k: string) => string): EntryPoint[] {
  if (v === undefined) return [];

  if (v.kind === "path") return [{ field, path: v.path }];

  return Object.entries(v.o).flatMap(([k, x]) => {
    const p = z.string().safeParse(x);

    return p.success ? [{ field: keyed(k), path: p.data }] : [];
  });
}

/**
 * Every entry point, most direct first: bin, main, module, browser, exports and imports (every subpath and
 * condition), then types and typings. `browser` may map paths to other paths or to false; its string values are
 * listed. A subpath pattern (`./docs/*.txt`) or folder mapping (`./lib/`) is listed as written; `targetFiles` says
 * which files it names. Throws ManifestTooLargeError for a manifest past MANIFEST_LIMITS (manifest.ts).
 */
export function entryPoints(manifest: Record<string, unknown>): EntryPoint[] {
  // the schema below recurses into `exports`: a manifest past the limits is refused before it can overflow the stack
  const reading = measureManifest(manifest);

  if (reading.kind === "over") throw new ManifestTooLargeError(reading.limit);
  const m = Fields.parse(manifest);
  const out: EntryPoint[] = [...pathsIn("bin", m.bin, (k) => `bin.${k}`)];

  for (const [field, path] of [["main", m.main], ["module", m.module]] as const) if (path !== undefined) out.push({ field, path });

  out.push(...pathsIn("browser", m.browser, (k) => `browser[${JSON.stringify(k)}]`));

  if (m.exports) exportTargets(m.exports, "exports", out);

  if (m.imports) exportTargets(m.imports, "imports", out);

  for (const [field, path] of [["types", m.types], ["typings", m.typings]] as const) if (path !== undefined) out.push({ field, path });

  return out;
}

/**
 * Entries that must name a file in the tarball. Not checked: `browser` (a bundler's remapping, which may
 * name other packages), `imports` (private aliases, which may name packages too), subpath patterns with `*`,
 * folder mappings ending in "/", and exports targets that do not start with "./" (node rejects those itself).
 */
function mustExist(e: EntryPoint): boolean {
  if (e.field.startsWith("browser") || e.field.startsWith("imports") || e.path.includes("*") || e.path.endsWith("/")) return false;

  return !e.field.startsWith("exports") || e.path.startsWith("./");
}

/** Entries whose target is not among `files` (node's extension and index lookup applied). */
export function missingEntries(manifest: Record<string, unknown>, files: readonly { path: string }[]): EntryPoint[] {
  const have = new Set(files.map((f) => f.path));

  return entryPoints(manifest)
    .filter(mustExist)
    .filter(({ path }) => {
      const p = stripDot(path);

      if (have.has(p)) return false;

      return ![".js", ".json", ".node", "/index.js", "/index.json"].some((ext) => have.has(p + ext));
    });
}

/** What an entry's target names: one path, or every file of `paths` a pattern or folder mapping matches. */
export type Target = { kind: "path"; path: string } | { kind: "files"; files: string[] };

/**
 * The files a target names. A pattern (`./docs/*.txt`) names every file it matches, with each `*` standing for the
 * same text, as node substitutes it; a folder mapping (`./lib/`) names every file under the folder. Anything else is
 * one path.
 */
export function targetFiles(target: string, paths: readonly string[]): Target {
  const t = stripDot(target);

  if (target.includes("*")) {
    // every `*` stands for the same non-empty text, as node substitutes it
    const parts = t.split("*");

    return { kind: "files", files: paths.filter((p) => sameSubstitution(p, parts)) };
  }

  // each comparison is charged, as sameSubstitution charges its own
  if (target.endsWith("/") && target.startsWith("./")) {
    return {
      kind: "files",
      files: paths.filter((p) => {
        charge("score", Math.ceil(Math.min(p.length, t.length) / 32) + 1);

        return p.startsWith(t);
      }),
    };
  }

  return { kind: "path", path: target };
}
