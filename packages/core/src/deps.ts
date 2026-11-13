// Versions, ranges and dependency specs, parsed the way npm reads package.json. Pure.
import { z } from "zod";
import { isValidPackageName } from "./names.ts";

const NUM = "(?:0|[1-9]\\d*)";
const PRE_ID = "(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)";
const BUILD_ID = "[0-9a-zA-Z-]+";
const SEMVER_RE = new RegExp(`^${NUM}\\.${NUM}\\.${NUM}(?:-${PRE_ID}(?:\\.${PRE_ID})*)?(?:\\+${BUILD_ID}(?:\\.${BUILD_ID})*)?$`);

/** Strict SemVer 2.0: "1.2.3", "1.2.3-beta.1", "1.2.3+build.5". Nothing else is a version on apm. */
export function isValidVersion(v: string): boolean {
  return v.length > 0 && v.length <= 256 && SEMVER_RE.test(v);
}

const XR = "(?:[xX*]|\\d+)";
const PARTIAL = `v?${XR}(?:\\.${XR}(?:\\.${XR}(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?)?)?`;
const COMPARATOR_RE = new RegExp(`^(?:<=|>=|<|>|=|~>|~|\\^)?${PARTIAL}$`);
const PARTIAL_RE = new RegExp(`^${PARTIAL}$`);

/** A node-semver range: "^1.2.0", ">=1 <2", "1.x || 2.0.0 - 2.4.0", "" and "*". */
export function isValidRange(r: string): boolean {
  if (r.length > 1024) return false;

  for (const part of r.split("||")) {
    const range = part.trim();

    if (range === "") continue;
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(range);

    if (hyphen) {
      if (!PARTIAL_RE.test(hyphen[1] ?? "") || !PARTIAL_RE.test(hyphen[2] ?? "")) return false;
      continue;
    }

    const comparators = range.replace(/(<=|>=|<|>|=|~>|~|\^)\s+/g, "$1").split(/\s+/);

    if (!comparators.every((c) => COMPARATOR_RE.test(c))) return false;
  }

  return true;
}

const TAG_RE = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;

/** A dist-tag name: a letter, then letters, digits, dot, dash or underscore, and never something npm would read as a version or range (`v1`, `x`). */
export function isValidTagName(tag: string): boolean {
  return TAG_RE.test(tag) && !isValidRange(tag);
}

/** What one dependency entry asks the package manager to install. `key` is the folder name in node_modules. */
export type DependencySpec =
  | { kind: "registry"; key: string; name: string; range: string; aliased: boolean }
  | { kind: "tag"; key: string; name: string; tag: string; aliased: boolean }
  | { kind: "git"; key: string; spec: string }
  | { kind: "url"; key: string; spec: string }
  | { kind: "file"; key: string; spec: string }
  | { kind: "workspace"; key: string; spec: string }
  | { kind: "invalid"; key: string; spec: string; reason: string };

/** A registry package apm can look up and score: plain names and npm: aliases. */
export type RegistryDependency = Extract<DependencySpec, { kind: "registry" | "tag" }>;

export function isRegistryDependency(d: DependencySpec): d is RegistryDependency {
  return d.kind === "registry" || d.kind === "tag";
}

/** "range or tag" for a registry name; invalid when it is neither. */
function registryTarget(key: string, name: string, spec: string, aliased: boolean): DependencySpec {
  if (isValidRange(spec)) return { kind: "registry", key, name, range: spec.trim() === "" ? "*" : spec.trim(), aliased };

  if (TAG_RE.test(spec)) return { kind: "tag", key, name, tag: spec, aliased };

  return { kind: "invalid", key, spec, reason: `"${spec}" is neither a version range nor a dist-tag` };
}

/** Reads `"key": value` from dependencies or optionalDependencies the way npm does. */
export function parseDependencySpec(key: string, value: unknown): DependencySpec {
  if (typeof value !== "string") return { kind: "invalid", key, spec: String(value), reason: "the spec is not a string" };
  const spec = value.trim();

  if (spec.startsWith("npm:")) {
    const rest = spec.slice(4);
    const at = rest.startsWith("@") ? rest.indexOf("@", 1) : rest.indexOf("@");
    const name = at > 0 ? rest.slice(0, at) : rest;
    const target = at > 0 ? rest.slice(at + 1) : "";

    if (!isValidPackageName(name)) return { kind: "invalid", key, spec, reason: `npm: alias to an invalid name "${name}"` };

    return registryTarget(key, name, target, true);
  }

  if (spec.startsWith("workspace:")) return { kind: "workspace", key, spec };

  if (/^(?:file|link|portal|patch):/.test(spec) || /^(?:\.{1,2}\/|\/|~\/)/.test(spec)) return { kind: "file", key, spec };

  if (/^(?:git\+|git:|ssh:|github:|gitlab:|bitbucket:|gist:)/.test(spec) || spec.startsWith('git@')) return { kind: "git", key, spec };

  if (/^https?:\/\//.test(spec)) return /\.git(?:#.*)?$/.test(spec) ? { kind: "git", key, spec } : { kind: "url", key, spec };

  if (!isValidPackageName(key)) return { kind: "invalid", key, spec, reason: `"${key}" is not a valid package name` };

  if (isValidRange(spec)) return registryTarget(key, key, spec, false);

  if (/^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec)) return { kind: "git", key, spec };

  return registryTarget(key, key, spec, false);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Every entry of dependencies and optionalDependencies (optional wins for a key in both, as in npm). */
export function dependencySpecs(manifest: Record<string, unknown>): DependencySpec[] {
  const merged = new Map<string, unknown>();

  for (const field of ["dependencies", "optionalDependencies"] as const) {
    const d = manifest[field];

    if (isRecord(d)) for (const [k, v] of Object.entries(d)) merged.set(k, v);
  }

  return [...merged].map(([k, v]) => parseDependencySpec(k, v));
}

/** What a spec installs, for people: "danger-leaf@1.0.0 (as aliased-dep)" or "gitdep (github:evil/repo)". */
export function describeDependency(d: DependencySpec): string {
  switch (d.kind) {
    case "registry":
      return `${d.name}@${d.range}${d.aliased ? ` (as ${d.key})` : ""}`;
    case "tag":
      return `${d.name}@${d.tag}${d.aliased ? ` (as ${d.key})` : ""}`;
    case "git":
    case "url":
    case "file":
    case "workspace":
    case "invalid":
      return `${d.key} (${d.spec})`;
    default: {
      const _exhaustive: never = d;

      return _exhaustive;
    }
  }
}

/** Why apm cannot score what a non-registry spec installs. */
export function uncheckableReason(d: Exclude<DependencySpec, RegistryDependency>): string {
  switch (d.kind) {
    case "git":
      return "git dependency: installs code from a repository, outside any registry";
    case "url":
      return "tarball URL: installs code from outside any registry";
    case "file":
      return "local path: not on a registry";
    case "workspace":
      return "workspace package: not on a registry";
    case "invalid":
      return d.reason;
    default: {
      const _exhaustive: never = d;

      return _exhaustive;
    }
  }
}

/**
 * How a package manager brings a dependency in: `required` (dependencies), `optional` (optionalDependencies: skipped
 * where it does not install, its os or cpu not the target's) or `peer` (a peerDependency it adds beside the package
 * when nothing in the tree already has one that fits).
 */
export type DependencyEdge = "required" | "optional" | "peer";

export type Dependency = { spec: DependencySpec; edge: DependencyEdge };

/** A dependency field as npm reads it: an object of specs, or nothing when it is anything else. */
const SpecField = z.record(z.string(), z.unknown()).optional().catch(undefined);

/** An os or cpu field: a name or a list of them, as npm reads it; anything else lists nothing. */
const PlatformField = z
  .union([z.string().transform((s) => [s]), z.array(z.unknown()).transform((xs) => xs.flatMap((x) => z.string().safeParse(x).data ?? []))])
  .optional()
  .catch(undefined)
  .transform((xs) => xs ?? []);

/** The fields of a manifest that decide what installs with it, and where. */
const InstallFields = z.object({
  dependencies: SpecField,
  optionalDependencies: SpecField,
  peerDependencies: SpecField,
  peerDependenciesMeta: z.record(z.string(), z.object({ optional: z.boolean().optional().catch(undefined) }).catch({})).optional().catch(undefined),
  os: PlatformField,
  cpu: PlatformField,
});

/** A manifest as read for its install fields: any object, each field it does not hold in npm's shape read as absent. */
export type InstallManifest = z.input<typeof InstallFields>;

/**
 * Every dependency a package manager installs for `manifest`: dependencies and optionalDependencies (optional wins
 * for a key in both, as in npm), then each peerDependency neither of those lists, unless peerDependenciesMeta marks it
 * optional: npm 7 and later, pnpm and bun add a required peer the tree does not already have, and leave optional
 * peers to the project.
 */
export function installEdges(manifest: InstallManifest): Dependency[] {
  const m = InstallFields.parse(manifest);
  const merged = new Map<string, { value: unknown; edge: DependencyEdge }>();

  for (const [k, v] of Object.entries(m.dependencies ?? {})) merged.set(k, { value: v, edge: "required" });

  for (const [k, v] of Object.entries(m.optionalDependencies ?? {})) merged.set(k, { value: v, edge: "optional" });

  for (const [k, v] of Object.entries(m.peerDependencies ?? {})) {
    if (merged.has(k) || m.peerDependenciesMeta?.[k]?.optional === true) continue;
    merged.set(k, { value: v, edge: "peer" });
  }

  return [...merged].map(([k, { value, edge }]) => ({ spec: parseDependencySpec(k, value), edge }));
}

/** What an install is for: node's `process.platform` and `process.arch`, or "any" for no platform in particular. */
export type InstallTarget = { os: string; cpu: string };

export const ANY_TARGET: InstallTarget = { os: "any", cpu: "any" };

const TARGET_RE = /^[a-z0-9_]{1,32}$/;

/** A target os or cpu as a query or a request body gives it: "any", or a lowercase platform or architecture name. */
export function isTargetValue(s: string): boolean {
  return s === "any" || TARGET_RE.test(s);
}

/** Whether `value` is allowed by a field's values: a `!name` forbids it, and when any plain name is listed it must be one. */
function allows(values: readonly string[], value: string): boolean {
  if (values.includes(`!${value}`)) return false;
  const listed = values.filter((x) => !x.startsWith("!"));

  return listed.length === 0 || listed.includes(value) || listed.includes("any");
}

/**
 * The platforms `manifest` is built for, as its os and cpu fields list them (npm's shape), or null when it lists none:
 * a platform binary, such as @next/swc-linux-x64-gnu, which installs only where they allow.
 */
export function platformOf(manifest: InstallManifest): { os: string[]; cpu: string[] } | null {
  const { os, cpu } = InstallFields.parse(manifest);

  return os.length === 0 && cpu.length === 0 ? null : { os, cpu };
}

/**
 * Why `manifest`'s os or cpu field rules `target` out, or null when it installs there (npm's rule: a listed value
 * allows, a `!`-prefixed one forbids). A target of "any" is ruled out by nothing.
 */
export function platformMismatch(manifest: InstallManifest, target: InstallTarget): string | null {
  const { os, cpu } = InstallFields.parse(manifest);

  if (target.os !== "any" && !allows(os, target.os)) return `built for os ${os.join(", ")}, not ${target.os}`;

  if (target.cpu !== "any" && !allows(cpu, target.cpu)) return `built for cpu ${cpu.join(", ")}, not ${target.cpu}`;

  return null;
}
