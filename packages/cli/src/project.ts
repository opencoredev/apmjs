// Where an add happens: the project's package.json, the root the package manager installs at (a workspace's root, or
// the project itself), the lockfile it reads there, and the few files apm copies to compute that lockfile somewhere
// else. Nothing here writes. See docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked".
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, sep } from "node:path";
import { z } from "zod";
import { LOCKFILES, lockfileIn } from "./lockfile.ts";
import type { Pm } from "./pm.ts";

/**
 * A project as the package manager sees it. `root`: where it installs and keeps the lockfile. `member`: the project's
 * directory relative to `root` ("" when they are the same). `lockfile`: the lockfile's path relative to `root`, which
 * may not exist yet. `copy`: every file, relative to `root`, apm copies to compute the lockfile: the manifests, the
 * lockfile and the configuration that changes what the package manager resolves. `members`: the workspace's packages.
 */
export type Layout = { root: string; member: string; lockfile: string; copy: string[]; members: { dir: string; name: string | null; version: string | null }[] };

export type LayoutResult = { kind: "ok"; layout: Layout } | { kind: "refused"; reason: string };

/** Configuration files at the root that change what the package manager resolves, as apm copies them. */
const ROOT_CONFIG = [".npmrc", "pnpm-workspace.yaml", ".pnpmfile.cjs", "bunfig.toml", ".yarnrc.yml"];

/** Configuration a workspace member may keep beside its own package.json. */
const MEMBER_CONFIG = [".npmrc", "bunfig.toml"];

const Manifest = z
  .object({
    name: z.string().optional().catch(undefined),
    version: z.string().optional().catch(undefined),
    workspaces: z.union([z.array(z.string()), z.object({ packages: z.array(z.string()).optional() }).loose().transform((w) => w.packages ?? [])]).optional().catch(undefined),
    patchedDependencies: z.record(z.string(), z.string()).optional().catch(undefined),
    pnpm: z.object({ patchedDependencies: z.record(z.string(), z.string()).optional().catch(undefined) }).loose().optional().catch(undefined),
  })
  .loose();

const PnpmWorkspace = z.object({ packages: z.array(z.string()).optional().catch(undefined), patchedDependencies: z.record(z.string(), z.string()).optional().catch(undefined) }).loose();

const YarnRc = z.object({ yarnPath: z.string().optional().catch(undefined) }).loose();

function readJson(path: string): z.infer<typeof Manifest> | null {
  try {
    const m = Manifest.safeParse(JSON.parse(readFileSync(path, "utf8")));

    return m.success ? m.data : null;
  } catch {
    return null;
  }
}

function readYaml<T extends z.ZodType>(path: string, schema: T): z.infer<T> | null {
  try {
    const m = schema.safeParse(Bun.YAML.parse(readFileSync(path, "utf8")));

    return m.success ? m.data : null;
  } catch {
    return null;
  }
}

/** A relative path that stays inside its base: not absolute, no `..` out of it. */
export function staysInside(rel: string): boolean {
  const n = normalize(rel);

  return rel !== "" && !isAbsolute(rel) && n !== ".." && !n.startsWith(`..${sep}`);
}

/** A regular file or a symlink to one (read, never written through). */
function isFile(path: string): boolean {
  try {
    return lstatSync(path).isFile() || (lstatSync(path).isSymbolicLink() && existsSync(path));
  } catch {
    return false;
  }
}

/** The workspace patterns a directory declares for `pm`: pnpm-workspace.yaml for pnpm, package.json's workspaces otherwise. */
function workspacePatterns(dir: string, pm: Pm): string[] | null {
  if (pm === "pnpm") {
    const p = join(dir, "pnpm-workspace.yaml");

    return existsSync(p) ? (readYaml(p, PnpmWorkspace)?.packages ?? []) : null;
  }

  const m = existsSync(join(dir, "package.json")) ? readJson(join(dir, "package.json")) : null;

  return m?.workspaces ?? null;
}

/** Whether `rel` (a member's directory relative to the root) is one of `patterns`, as the package managers match them. */
function matches(rel: string, patterns: readonly string[]): boolean {
  const include = patterns.filter((p) => !p.startsWith("!"));
  const exclude = patterns.flatMap((p) => (p.startsWith("!") ? [p.slice(1)] : []));
  const clean = (p: string): string => p.replace(/^\.\//, "").replace(/\/+$/, "");

  return include.some((p) => new Bun.Glob(clean(p)).match(rel)) && !exclude.some((p) => new Bun.Glob(clean(p)).match(rel));
}

/** Every member directory (relative to `root`) the workspace patterns name: those holding a package.json, never inside node_modules. */
function membersOf(root: string, patterns: readonly string[]): string[] {
  const found = new Set<string>();

  for (const p of patterns.filter((x) => !x.startsWith("!"))) {
    const glob = new Bun.Glob(`${p.replace(/^\.\//, "").replace(/\/+$/, "")}/package.json`);

    for (const hit of glob.scanSync({ cwd: root, onlyFiles: true, followSymlinks: false, dot: false })) {
      const dir = dirname(hit).split(sep).join("/");

      if (dir.split("/").includes("node_modules") || !staysInside(dir)) continue;

      if (matches(dir, patterns)) found.add(dir);
    }
  }

  return [...found].sort();
}

/** The nearest directory from `cwd` upward that holds a package.json. */
function projectDir(cwd: string): string | null {
  let dir = cwd;

  for (let i = 0; i < 40; i++) {
    if (existsSync(join(dir, "package.json"))) return dir;
    const parent = dirname(dir);

    if (parent === dir) return null;
    dir = parent;
  }

  return null;
}

/** The patch files a project's package.json or pnpm-workspace.yaml names (pnpm and bun read them to compute the lockfile). */
function patchFiles(root: string): string[] {
  const m = readJson(join(root, "package.json"));
  const ws = existsSync(join(root, "pnpm-workspace.yaml")) ? readYaml(join(root, "pnpm-workspace.yaml"), PnpmWorkspace) : null;

  return [...Object.values(m?.patchedDependencies ?? {}), ...Object.values(m?.pnpm?.patchedDependencies ?? {}), ...Object.values(ws?.patchedDependencies ?? {})].filter((p) => staysInside(p) && isFile(join(root, p)));
}

/** yarn berry's own release, when .yarnrc.yml points at one inside the project: yarn cannot run without it. */
function yarnRelease(root: string): string[] {
  const rc = existsSync(join(root, ".yarnrc.yml")) ? readYaml(join(root, ".yarnrc.yml"), YarnRc) : null;
  const path = rc?.yarnPath;

  return path !== undefined && staysInside(path) && isFile(join(root, path)) ? [path] : [];
}

/** The lockfile `pm` reads at `root`, relative to it: npm-shrinkwrap.json before package-lock.json; the default name when there is none yet. */
function lockfileAt(root: string, pm: Pm): { kind: "ok"; file: string } | { kind: "refused"; reason: string } {
  if (pm === "yarn") return { kind: "ok", file: "yarn.lock" };

  if (pm === "bun" && !existsSync(join(root, "bun.lock")) && existsSync(join(root, "bun.lockb"))) {
    return { kind: "refused", reason: `${join(root, "bun.lockb")} is bun's binary lockfile, which apm cannot read. Run bun install --save-text-lockfile once (bun 1.2 or later) to write bun.lock, then apm add again` };
  }

  const found = lockfileIn(root, pm);

  return { kind: "ok", file: found === null ? LOCKFILES[pm][LOCKFILES[pm].length - 1] ?? "package-lock.json" : relative(root, found) };
}

/** The project the package manager would install for at `cwd`, and what apm copies to compute its lockfile. */
export function projectLayout(input: { cwd: string; pm: Pm }): LayoutResult {
  const project = projectDir(input.cwd);

  if (project === null) return { kind: "refused", reason: `there is no package.json in ${input.cwd} or above it` };
  let root = project;
  let patterns: string[] = [];

  // the workspace whose patterns take the project in, from the project upward
  for (let dir = project, i = 0; i < 40; i++) {
    const declared = workspacePatterns(dir, input.pm);
    const rel = relative(dir, project).split(sep).join("/");

    if (declared !== null && (rel === "" || matches(rel, declared))) {
      root = dir;
      patterns = declared;
      break;
    }

    const parent = dirname(dir);

    if (parent === dir || existsSync(join(dir, ".git"))) break;
    dir = parent;
  }

  const lock = lockfileAt(root, input.pm);

  if (lock.kind === "refused") return lock;

  const member = relative(root, project).split(sep).join("/");
  const memberDirs = [...new Set([...membersOf(root, patterns), ...(member === "" ? [] : [member])])];

  const members = memberDirs.map((dir) => {
    const m = readJson(join(root, dir, "package.json"));

    return { dir, name: m?.name ?? null, version: m?.version ?? null };
  });

  const wanted = [
    "package.json",
    lock.file,
    ...ROOT_CONFIG,
    ...memberDirs.flatMap((d) => [`${d}/package.json`, ...MEMBER_CONFIG.map((f) => `${d}/${f}`)]),
    ...patchFiles(root),
    ...yarnRelease(root),
  ];

  const copy = [...new Set(wanted)].filter((f) => isFile(join(root, f)));

  return { kind: "ok", layout: { root, member, lockfile: lock.file, copy, members } };
}

/**
 * A lockfile's workspace nodes named by the member's package.json where the lockfile names them by directory (pnpm's
 * importers), so a warning says which of the project's own packages it means.
 */
export function withMemberNames<N extends { name: string; origin: { kind: string } }>(nodes: readonly N[], members: Layout["members"]): N[] {
  const byDir = new Map(members.flatMap((m) => (m.name === null ? [] : [[m.dir, m.name] as const])));

  return nodes.map((n) => (n.origin.kind === "workspace" && byDir.has(n.name) ? { ...n, name: byDir.get(n.name) ?? n.name } : n));
}
