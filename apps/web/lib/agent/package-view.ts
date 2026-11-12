// Loads what the package's Markdown view shows: the package, the state, facts and score of the version asked for,
// and its AI review. Shared by GET /package/<name>.md and the check_package MCP tool.
//
// The package answer lists only the newest 200 versions and carries latest's facts, so the shown version (latest
// included) is read from the registry's versions route, which knows every version. Nothing here is cached.
import { withholdSource, type PackageView } from "./package-md";
import type { AgentSource } from "./source";

export type LoadedView = { kind: "ok"; view: PackageView } | { kind: "missing"; reason: string } | { kind: "unavailable" };

export async function loadPackageView(input: { name: string; version: string | null; registry: string; source: AgentSource }): Promise<LoadedView> {
  const { name, source } = input;
  const found = await source.package(name);

  if (found.kind === "missing") return { kind: "missing", reason: `No package named ${name} on apm or npm.` };

  if (found.kind === "unavailable") return { kind: "unavailable" };
  const pkg = found.value;
  const version = input.version ?? pkg.latest;

  if (version === null) return { kind: "ok", view: { pkg, version: null, status: null, facts: null, score: null, review: { kind: "missing" }, registry: input.registry } };

  const [info, review] = await Promise.all([source.version({ name, version }), source.review({ name, version })]);

  if (info.kind === "missing") return { kind: "missing", reason: `${name} has no version ${version}. Latest is ${pkg.latest ?? "unknown"}.` };

  // without the version's own answer the view would show another version's facts or a stale status: say so instead
  if (info.kind === "unavailable") return { kind: "unavailable" };
  const v = info.value;

  // a revoked version's source stays out of every answer built from this view, the MCP tool's structured one included
  return {
    kind: "ok",
    view: withholdSource({ pkg, version: v.version, status: { status: v.status, statusReason: v.statusReason, deprecated: v.deprecated }, facts: v.facts, score: v.score, review, registry: input.registry }),
  };
}
