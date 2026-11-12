// After an install: did the package manager lock the artifact apm checked? It compares the integrity
// the lockfile records for each added name@version with the one the checked registry serves.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import type { Pm } from "./pm.ts";

export type Locked = { integrity: string | null; resolved: string | null };

const LOCKFILES: Record<Exclude<Pm, "yarn">, string[]> = {
  bun: ["bun.lock"],
  npm: ["package-lock.json", "npm-shrinkwrap.json"],
  pnpm: ["pnpm-lock.yaml"],
};

function findUp(cwd: string, files: string[]): string | null {
  let dir = cwd;

  for (let i = 0; i < 20; i++) {
    for (const f of files) if (existsSync(join(dir, f))) return join(dir, f);

    const parent = dirname(dir);

    if (parent === dir) return null;
    dir = parent;
  }

  return null;
}

const NpmLock = z.object({ packages: z.record(z.string(), z.object({ version: z.string().optional(), resolved: z.string().optional(), integrity: z.string().optional() }).loose()) }).loose();

// bun.lock: "name": ["name@version", "registry or empty", { deps }, "sha512-..."]
const BunLock = z.object({ packages: z.record(z.string(), z.array(z.unknown())) }).loose();
const PnpmLock = z.object({ packages: z.record(z.string(), z.object({ resolution: z.object({ integrity: z.string().optional(), tarball: z.string().optional() }).loose().optional() }).loose()).optional() }).loose();

function fromNpm(text: string, name: string, version: string): Locked | null {
  const lock = NpmLock.safeParse(JSON.parse(text));

  if (!lock.success) return null;

  const hit = Object.entries(lock.data.packages).find(([path, e]) => (path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`)) && e.version === version);

  return hit ? { integrity: hit[1].integrity ?? null, resolved: hit[1].resolved ?? null } : null;
}

function fromBun(text: string, name: string, version: string): Locked | null {
  const lock = BunLock.safeParse(Bun.JSONC.parse(text));

  if (!lock.success) return null;

  for (const entry of Object.values(lock.data.packages)) {
    const id = z.string().safeParse(entry[0]);

    if (!id.success || id.data !== `${name}@${version}`) continue;

    const resolved = z.string().safeParse(entry[1]);
    const integrity = z.string().safeParse(entry[3]);

    return { integrity: integrity.success ? integrity.data : null, resolved: resolved.success && resolved.data !== "" ? resolved.data : null };
  }

  return null;
}

function fromPnpm(text: string, name: string, version: string): Locked | null {
  const lock = PnpmLock.safeParse(Bun.YAML.parse(text));

  if (!lock.success) return null;

  const e = lock.data.packages?.[`${name}@${version}`] ?? lock.data.packages?.[`/${name}@${version}`];

  if (!e) return null;

  return { integrity: e.resolution?.integrity ?? null, resolved: e.resolution?.tarball ?? null };
}

/** The lockfile entry for name@version, or null when there is no lockfile or no entry apm can read (yarn's included). */
export function lockedEntry(input: { cwd: string; pm: Pm; name: string; version: string }): Locked | null {
  if (input.pm === "yarn") return null;

  const path = findUp(input.cwd, LOCKFILES[input.pm]);

  if (!path) return null;

  try {
    const text = readFileSync(path, "utf8");

    switch (input.pm) {
      case "npm":
        return fromNpm(text, input.name, input.version);
      case "bun":
        return fromBun(text, input.name, input.version);
      case "pnpm":
        return fromPnpm(text, input.name, input.version);
      default: {
        const _exhaustive: never = input.pm;

        return _exhaustive;
      }
    }
  } catch {
    return null;
  }
}
