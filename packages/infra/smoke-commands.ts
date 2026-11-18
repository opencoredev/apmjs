// The installs the smoke check (smoke.ts) runs against a deployed stage. A registry answer must never decide what runs
// here, so none of them runs an install script, and none of the raw npm or bun installs resolves anything: each
// installs a committed lockfile (smoke-fixtures/<probe>/), exact versions with an integrity for every entry, and the
// package manager checks every tarball against it. --ignore-scripts alone is not enough: npm still runs a git
// dependency's `prepare` (review of 4a9c8fb, finding 1), and a registry that answers with a git dependency could add one.
// With a frozen lockfile the registry can only serve the locked bytes or fail the install. apm add goes through the
// apm CLI, which refuses any dependency that is not a registry version when scripts are ignored.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

/** The flag npm, pnpm, bun and the apm CLI (apm add, apm x) all take to run no install script. */
export const NO_SCRIPTS = "--ignore-scripts";

/**
 * Set on every command smoke runs, beside each command's own flag: npm reads npm_config_ignore_scripts (also for
 * `npm publish`'s own scripts) and the apm CLI reads APM_IGNORE_SCRIPTS.
 */
export const NO_SCRIPTS_ENV = { npm_config_ignore_scripts: "true", APM_IGNORE_SCRIPTS: "1" } as const;

/** Where the probes' committed package.json and lockfile live. */
export const FIXTURES = join(import.meta.dirname, "smoke-fixtures");

/** The host npm's committed lockfiles name; npm swaps it for --registry (replace-registry-host=npmjs). */
export const NPM_HOST = "https://registry.npmjs.org/";

/** The probes, each a committed project smoke installs. */
export const PROBE_NAMES = ["npm-app", "bun-app", "audit-app"] as const;

export type Probe = (typeof PROBE_NAMES)[number];

/** A probe's package manager and lockfile. */
export type ProbeKind = { pm: "npm" | "bun"; lockfile: "package-lock.json" | "bun.lock" };

/** Each probe: which package manager installs it, and its lockfile. */
export const PROBES = {
  "npm-app": { pm: "npm", lockfile: "package-lock.json" },
  "bun-app": { pm: "bun", lockfile: "bun.lock" },
  "audit-app": { pm: "bun", lockfile: "bun.lock" },
} as const satisfies Record<Probe, ProbeKind>;

/**
 * `npm ci` of a committed package-lock.json through `registry`, scripts off: npm installs exactly the lockfile (it
 * fails if package.json does not match it), fetches each tarball from `registry` in place of registry.npmjs.org, and
 * refuses one whose bytes do not match the lockfile's integrity. (The registry may answer a tarball with a redirect to
 * npm's own CDN: the bytes are checked all the same.)
 */
export function npmCi(registry: string): string[] {
  return ["npm", "ci", NO_SCRIPTS, "--no-audit", "--no-fund", `--registry=${registry}`, "--replace-registry-host=npmjs"];
}

/** `bun install` of a committed bun.lock through `registry`, scripts off: frozen (nothing resolved), every tarball checked against the lockfile's integrity. */
export function bunInstallLocked(registry: string): string[] {
  return ["bun", "install", "--frozen-lockfile", NO_SCRIPTS, `--registry=${registry}`];
}

/** `apm add` of one spec through the repo's own CLI entry (`cli`, run with bun), scripts off, then `extra` flags. */
export function apmAdd(cli: string, spec: string, extra: readonly string[] = []): string[] {
  return ["bun", cli, "add", spec, NO_SCRIPTS, ...extra];
}

/** A registry tarball's path under the registry's URL: `name/-/base-version.tgz` (base: the name without its scope). */
export function tarballPath(name: string, version: string): string {
  return `${name}/-/${name.slice(name.lastIndexOf("/") + 1)}-${version}.tgz`;
}

/** The dependency fields of a manifest, a lockfile entry or a version in install metadata. */
const EdgeFields = z.object({
  dependencies: z.record(z.string(), z.string()).optional(),
  optionalDependencies: z.record(z.string(), z.string()).optional(),
  peerDependencies: z.record(z.string(), z.string()).optional(),
  peerDependenciesMeta: z.record(z.string(), z.object({ optional: z.boolean().optional() }).loose()).optional(),
});

/** What a package manager does with an edge it cannot satisfy: a required edge fails the install, an optional one is skipped. */
export type EdgeKind = "required" | "optional";

/** One dependency edge: the range it asks for and its kind. */
export type Edge = { range: string; kind: EdgeKind };

/**
 * A version's dependency edges by name: `installs` holds dependencies and optionalDependencies (npm lists an optional
 * dependency in both; it is one optional edge, with the optionalDependencies range, as in npm), `peers` its
 * peerDependencies, optional when peerDependenciesMeta marks them so (review of ae21a19, finding 3: the kind is
 * compared as well as the range, so a required edge turned optional at the same range is a different version).
 */
export type Edges = { installs: Record<string, Edge>; peers: Record<string, Edge> };

/** The edges a manifest, lockfile entry or metadata version declares. */
export function edgesOf(fields: z.infer<typeof EdgeFields>): Edges {
  const installs = new Map<string, Edge>();

  for (const [name, range] of Object.entries(fields.dependencies ?? {})) installs.set(name, { range, kind: "required" });

  for (const [name, range] of Object.entries(fields.optionalDependencies ?? {})) installs.set(name, { range, kind: "optional" });

  const meta = fields.peerDependenciesMeta ?? {};

  const peers = Object.entries(fields.peerDependencies ?? {}).map(([name, range]): [string, Edge] => [
    name,
    { range, kind: Object.hasOwn(meta, name) && meta[name]?.optional === true ? "optional" : "required" },
  ]);

  // Object.fromEntries defines own data properties, so a name like __proto__ stays an ordinary key
  return { installs: Object.fromEntries(installs), peers: Object.fromEntries(peers) };
}

/** A locked registry version: what the lockfile pins, the integrity its tarball must have and its dependency edges. */
export type Locked = { name: string; version: string; integrity: string; edges: Edges };

/** A package's install metadata (application/vnd.npm.install-v1+json): what npm and bun resolve from. */
export const InstallMetadata = z.object({
  "dist-tags": z.record(z.string(), z.string()),
  versions: z.record(z.string(), EdgeFields.extend({ dist: z.object({ tarball: z.string(), integrity: z.string().optional() }) })),
});

/** One edge map in a fixed order, name to [range, kind], for comparing and printing. */
function edgeText(edges: Record<string, Edge>): string {
  const sorted = Object.entries(edges).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  return JSON.stringify(Object.fromEntries(sorted.map(([name, e]) => [name, [e.range, e.kind]])));
}

/**
 * Why a registry's install metadata for a locked version would not install as the lockfile does, or null when it
 * would (review of 96f0ba7, finding 4). The version must be listed with exactly the lockfile's integrity, and its
 * tarball advertised at exactly the URL a locked install fetches, `registry` + tarballPath (npm ci swaps the
 * lockfile's host for the registry; bun builds the same path), not just any URL on the registry. It must also declare
 * exactly the lockfile's dependency edges, each with its range and kind (review of e83dc4b, finding 4; review of
 * ae21a19, finding 3): a frozen install never reads them, so metadata that dropped, changed or reclassified one would
 * still pass it while every unlocked install resolves something else.
 * `latest`: "listed" when the latest dist-tag must name a version the metadata lists, "this" when it must name this
 * one (a version just published).
 */
export function metadataProblem(input: { registry: string; status: number; body: unknown; locked: Locked; latest: "listed" | "this" }): string | null {
  const { name, version, integrity } = input.locked;

  if (input.status !== 200) return `${name}: HTTP ${input.status}`;
  const doc = InstallMetadata.safeParse(input.body);

  if (!doc.success) return `${name}: unreadable metadata`;
  const latest = doc.data["dist-tags"].latest;

  if (latest === undefined) return `${name}: no latest dist-tag`;

  if (input.latest === "this" && latest !== version) return `${name}: latest is ${latest}, not ${version}`;

  if (!Object.hasOwn(doc.data.versions, latest)) return `${name}: latest names ${latest}, which the metadata does not list`;
  const listed = Object.hasOwn(doc.data.versions, version) ? doc.data.versions[version] : undefined;

  if (listed === undefined) return `${name}@${version}: missing`;
  const dist = listed.dist;

  if (dist.integrity !== integrity) return `${name}@${version}: integrity ${dist.integrity ?? "missing"}, not the lockfile's`;
  const expected = `${input.registry}${tarballPath(name, version)}`;

  if (dist.tarball !== expected) return `${name}@${version}: tarball ${dist.tarball}, not ${expected}`;
  const edges = edgesOf(listed);

  for (const kind of ["installs", "peers"] as const) {
    const got = edgeText(edges[kind]);
    const want = edgeText(input.locked.edges[kind]);

    if (got !== want) return `${name}@${version}: ${kind === "installs" ? "dependencies" : "peerDependencies"} ${got}, not the lockfile's ${want}`;
  }

  return null;
}

const EXACT = /^\d+\.\d+\.\d+$/;
const SHA512 = /^sha512-[A-Za-z0-9+/]{86}==$/;

const Manifest = z.object({ name: z.string(), version: z.string(), private: z.literal(true), dependencies: z.record(z.string(), z.string().regex(EXACT)) });

const NpmLock = z.object({
  lockfileVersion: z.literal(3),
  packages: z.record(z.string(), EdgeFields.extend({ version: z.string().regex(EXACT).optional(), resolved: z.string().optional(), integrity: z.string().optional(), link: z.boolean().optional() }).loose()),
});

/** A bun.lock package entry's metadata: the edge fields, with optional peers as a list of names. */
const BunMeta = EdgeFields.omit({ peerDependenciesMeta: true }).extend({ optionalPeers: z.array(z.string()).optional() });

const BunLock = z.object({
  workspaces: z.object({ "": z.object({ dependencies: z.record(z.string(), z.string()) }).loose() }).loose(),
  packages: z.record(z.string(), z.tuple([z.string(), z.literal(""), BunMeta.loose(), z.string().regex(SHA512)])),
});

/** bun.lock's metadata as the edge fields npm and the install metadata use (optionalPeers becomes peerDependenciesMeta). */
function bunEdges(meta: z.infer<typeof BunMeta>): Edges {
  const { optionalPeers, ...fields } = meta;

  return edgesOf({ ...fields, peerDependenciesMeta: Object.fromEntries((optionalPeers ?? []).map((name) => [name, { optional: true }])) });
}

/** bun.lock, which is JSON with trailing commas. */
function parseBunLock(text: string): z.infer<typeof BunLock> {
  return BunLock.parse(JSON.parse(text.replace(/,(\s*[}\]])/g, "$1")));
}

function npmEntries(text: string, deps: Record<string, string>): Locked[] {
  const lock = NpmLock.parse(JSON.parse(text));
  const root = lock.packages[""];

  if (JSON.stringify(root?.dependencies ?? {}) !== JSON.stringify(deps)) throw new Error("package-lock.json's root dependencies are not package.json's");

  return Object.entries(lock.packages).flatMap(([key, e]): Locked[] => {
    if (key === "") return [];
    const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);

    if (e.link === true || e.version === undefined || e.integrity === undefined || !SHA512.test(e.integrity)) throw new Error(`${key} is not a registry version with a sha512 integrity`);

    if (e.resolved !== `${NPM_HOST}${tarballPath(name, e.version)}`) throw new Error(`${key} resolves to ${e.resolved ?? "nothing"}, not its registry tarball`);

    return [{ name, version: e.version, integrity: e.integrity, edges: edgesOf(e) }];
  });
}

function bunEntries(text: string, deps: Record<string, string>): Locked[] {
  const lock = parseBunLock(text);

  if (JSON.stringify(lock.workspaces[""].dependencies) !== JSON.stringify(deps)) throw new Error("bun.lock's workspace dependencies are not package.json's");

  return Object.values(lock.packages).map(([id, , meta, integrity]) => {
    const at = id.lastIndexOf("@");
    const version = id.slice(at + 1);

    if (at <= 0 || !EXACT.test(version)) throw new Error(`bun.lock entry ${id} is not an exact registry version`);

    return { name: id.slice(0, at), version, integrity, edges: bunEdges(meta) };
  });
}

/**
 * Every version a probe's lockfile pins, with the dependency edges the lockfile records for it. Throws unless
 * package.json pins exact versions, the lockfile's root asks for exactly those, and every entry is an exact registry
 * version with a sha512 integrity (npm: resolved to its registry.npmjs.org tarball; bun: the default registry), so the
 * install can resolve nothing.
 */
export function lockedEntries(pm: "npm" | "bun", manifest: string, lock: string): Locked[] {
  const deps = Manifest.parse(JSON.parse(manifest)).dependencies;

  return pm === "npm" ? npmEntries(lock, deps) : bunEntries(lock, deps);
}

/** A probe's committed files, by name, and every version its lockfile pins. */
export type ProbeFixture = { files: Record<string, string>; locked: Locked[] };

/** The probe's committed files and every version its lockfile pins (lockedEntries). */
export function probeFixture(probe: Probe): ProbeFixture {
  const { pm, lockfile } = PROBES[probe];
  const manifest = readFileSync(join(FIXTURES, probe, "package.json"), "utf8");
  const lock = readFileSync(join(FIXTURES, probe, lockfile), "utf8");

  return { files: { "package.json": manifest, [lockfile]: lock }, locked: lockedEntries(pm, manifest, lock) };
}

/**
 * A package-lock.json for a project `name` that depends on exactly one registry version with no dependencies of its
 * own, at `resolved` with `integrity` (the staging check's own package, whose integrity smoke computed from the
 * tarball it packed itself before publishing it).
 */
export function singleLockfile(name: string, dep: Omit<Locked, "edges"> & { resolved: string }): string {
  return JSON.stringify(
    {
      name,
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: { "": { name, version: "1.0.0", dependencies: { [dep.name]: dep.version } }, [`node_modules/${dep.name}`]: { version: dep.version, resolved: dep.resolved, integrity: dep.integrity } },
    },
    null,
    2,
  );
}
