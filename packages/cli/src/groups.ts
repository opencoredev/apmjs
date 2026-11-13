// Which dependency groups the package manager installs (review of 2b7767f, finding 3). A production install (npm's
// --omit=dev, npm_config_omit=dev, NODE_ENV=production; pnpm's --prod or production=true; bun's --production) leaves
// the folders' devDependencies out. apm reads that once, from the same places the package manager does, and the same
// answer drives all three steps: the lockfile is still computed and checked whole (every locked package is scanned),
// the frozen install is told it explicitly, and the check of what was installed lets those devDependencies be missing.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { userconfigPath } from "./config.ts";
import type { LockPm } from "./lockfile.ts";

type Env = Record<string, string | undefined>;

/** Whether the install leaves devDependencies out, and what said so. */
export type DevGroup = { kind: "include" } | { kind: "omit"; why: string };

/** One configuration value as npm reads it: the env variable first (npm_config_<key>, any case), then each .npmrc. */
type Layer = { source: string; values: (key: string) => string[] | null };

function envLayer(env: Env): Layer {
  return {
    source: "the environment",
    values: (key) => {
      const hit = Object.entries(env).find(([k, v]) => k.toLowerCase() === `npm_config_${key}` && v !== undefined);

      return hit?.[1] === undefined ? null : hit[1].split(/[\s,]+/).filter((x) => x !== "");
    },
  };
}

/** An .npmrc's values for a key: `key=a`, or each `key[]=a` line, as npm reads arrays. */
function npmrcLayer(path: string): Layer {
  let text = "";

  try {
    text = existsSync(path) ? readFileSync(path, "utf8") : "";
  } catch {
    text = "";
  }

  const lines = text.split(/\r?\n/).flatMap((raw) => {
    const line = raw.trim();
    const i = line.indexOf("=");

    return line === "" || line.startsWith("#") || line.startsWith(";") || i < 0 ? [] : [{ key: line.slice(0, i).trim(), value: line.slice(i + 1).trim() }];
  });

  return {
    source: path,
    values: (key) => {
      const hits = lines.filter((l) => l.key === key || l.key === `${key}[]`).flatMap((l) => l.value.split(/[\s,]+/).filter((x) => x !== ""));

      return hits.length === 0 ? null : hits;
    },
  };
}

/** The first layer that sets `key`: its values and where they came from. */
function first(layers: readonly Layer[], key: string): { values: string[]; source: string } | null {
  for (const l of layers) {
    const v = l.values(key);

    if (v !== null) return { values: v, source: l.source };
  }

  return null;
}

const isTrue = (v: { values: string[] } | null): boolean => v !== null && v.values[0] === "true";

/**
 * Whether the package manager at `root` leaves devDependencies out. `production`: apm add was given --omit=dev,
 * --prod or --production. npm: npm_config_include/omit/production in the environment, then the project's and the
 * user's .npmrc, then NODE_ENV=production (npm's default for omit). An include of dev beats an omit, as in npm. pnpm:
 * production=true in the environment or an .npmrc (pnpm 10 reads neither omit nor NODE_ENV for this). bun: only its
 * --production flag (bun reads none of these; bunfig's production = true also freezes the lockfile, so bun refuses the
 * add itself).
 */
export function devGroup(input: { pm: LockPm; root: string; env: Env; production: boolean }): DevGroup {
  if (input.production) return { kind: "omit", why: "apm add was asked for a production install" };

  const layers = [envLayer(input.env), npmrcLayer(join(input.root, ".npmrc")), npmrcLayer(userconfigPath(input.env))];

  switch (input.pm) {
    case "npm": {
      const include = first(layers, "include");
      const omit = first(layers, "omit");
      const production = first(layers, "production");

      if (include?.values.includes("dev") === true) return { kind: "include" };

      if (omit?.values.includes("dev") === true) return { kind: "omit", why: `omit=dev in ${omit.source}` };

      if (isTrue(production)) return { kind: "omit", why: `production=true in ${production?.source ?? "the environment"}` };

      if (omit === null && input.env.NODE_ENV === "production") return { kind: "omit", why: "NODE_ENV=production" };

      return { kind: "include" };
    }

    case "pnpm": {
      const production = first(layers, "production");

      return isTrue(production) ? { kind: "omit", why: `production=true in ${production?.source ?? "the environment"}` } : { kind: "include" };
    }

    case "bun":
      return { kind: "include" };
    default: {
      const _exhaustive: never = input.pm;

      return _exhaustive;
    }
  }
}

/** The flag that tells the frozen install to leave devDependencies out, so it does what apm verifies. */
export function omitArgs(pm: LockPm, group: DevGroup): string[] {
  if (group.kind === "include") return [];

  switch (pm) {
    case "npm":
      return ["--omit=dev"];
    case "pnpm":
      return ["--prod"];
    case "bun":
      return ["--production"];
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}
