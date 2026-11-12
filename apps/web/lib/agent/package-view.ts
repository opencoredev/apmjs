// Loads what the package's Markdown view shows: the package, the score of the version asked for, and its AI
// review. Shared by GET /package/<name>.md and the check_package MCP tool.
import type { PackageView } from "./package-md";
import type { AgentSource } from "./source";

export type LoadedView = { kind: "ok"; view: PackageView } | { kind: "missing"; reason: string } | { kind: "unavailable" };

export async function loadPackageView(input: { name: string; version: string | null; registry: string; source: AgentSource }): Promise<LoadedView> {
  const { name, source } = input;
  const found = await source.package(name);

  if (found.kind === "missing") return { kind: "missing", reason: `No package named ${name} on apm or npm.` };

  if (found.kind === "unavailable") return { kind: "unavailable" };
  const pkg = found.value;

  if (input.version !== null && !pkg.versions.some((v) => v.version === input.version)) return { kind: "missing", reason: `${name} has no version ${input.version}. Latest is ${pkg.latest ?? "unknown"}.` };
  const version = input.version ?? pkg.latest;
  const older = version !== null && version !== pkg.latest;

  const [score, review] = await Promise.all([
    older ? source.versionScore({ name, version }) : Promise.resolve(null),
    version !== null ? source.review({ name, version }) : Promise.resolve({ kind: "missing" } as const),
  ]);

  return { kind: "ok", view: { pkg, version, score: older ? (score?.kind === "ok" ? score.value : null) : pkg.score, review, registry: input.registry } };
}
