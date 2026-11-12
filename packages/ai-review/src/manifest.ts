// The parts of package.json the review reads, parsed once from the tarball's own package.json.
import { z } from "zod";
import type { TarEntry } from "@apm/core";

/** Every string leaf of an entry field (`main`, `bin`, `exports`, `browser`), whatever its nesting. */
const Paths: z.ZodType<string[]> = z.lazy(() =>
  z.union([
    z.string().transform((s) => [s]),
    z.array(Paths).transform((a) => a.flat()),
    z.record(z.string(), Paths).transform((r) => Object.values(r).flat()),
    z.unknown().transform((): string[] => []),
  ]),
);

/** A string-valued map where entries of any other type are dropped instead of failing the whole map. */
const StringMap = z
  .record(z.string(), z.string().optional().catch(undefined))
  .catch({})
  .transform((r) => {
    const out = new Map<string, string>();

    for (const [k, v] of Object.entries(r)) if (v !== undefined) out.set(k, v);

    return out;
  });

const ManifestSchema = z.object({
  name: z.string().catch(""),
  version: z.string().catch(""),
  scripts: StringMap.default(new Map()),
  main: Paths.default([]),
  module: Paths.default([]),
  bin: Paths.default([]),
  exports: Paths.default([]),
  browser: Paths.default([]),
  dependencies: StringMap.default(new Map()),
  optionalDependencies: StringMap.default(new Map()),
});

export type Manifest = z.infer<typeof ManifestSchema>;

export type PackageFiles = { manifest: Manifest; files: readonly TarEntry[] };

/** Lifecycle scripts npm, pnpm and bun run on install from a registry. `prepare` does not run there. */
export const INSTALL_SCRIPT_KEYS = ["preinstall", "install", "postinstall"] as const;

const EMPTY: Manifest = ManifestSchema.parse({});

export function parseManifest(text: string): Manifest {
  try {
    const parsed = ManifestSchema.safeParse(JSON.parse(text));

    return parsed.success ? parsed.data : EMPTY;
  } catch {
    return EMPTY;
  }
}

function byPath(a: TarEntry, b: TarEntry): number {
  if (a.path < b.path) return -1;

  return a.path > b.path ? 1 : 0;
}

/** Files sorted by path, with the manifest from their package.json (an empty one when it is missing or broken). */
export function packageFilesOf(entries: readonly TarEntry[]): PackageFiles {
  const files = [...entries].sort(byPath);
  const pj = files.find((f) => f.path === "package.json");

  return { manifest: parseManifest(pj ? new TextDecoder().decode(pj.data) : "{}"), files };
}

export type InstallScript = { key: (typeof INSTALL_SCRIPT_KEYS)[number]; command: string };

export function installScripts(m: Manifest): InstallScript[] {
  const out: InstallScript[] = [];

  for (const key of INSTALL_SCRIPT_KEYS) {
    const command = m.scripts.get(key);

    if (command !== undefined && command.trim() !== "") out.push({ key, command });
  }

  return out;
}

export function dependencyNamesOf(m: Manifest): string[] {
  return [...new Set([...m.dependencies.keys(), ...m.optionalDependencies.keys()])].sort();
}
