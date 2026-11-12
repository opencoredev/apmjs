// Versions, ranges and dependency specs, parsed the way npm reads package.json. Pure.
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
