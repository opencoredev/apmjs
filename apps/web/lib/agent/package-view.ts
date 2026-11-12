// Loads what the package's Markdown view shows: the package, the state, facts and score of the version asked for,
// and its AI review. Shared by GET /package/<name>.md and the check_package MCP tool.
//
// The package answer lists only the newest 200 versions and carries latest's facts, so the shown version (latest
// included) is read from the registry's versions route, which knows every version. Nothing here is cached.
//
// A withheld version's AI review is what the registry sends for it (each finding's sentence replaced, each file by
// reference), never an earlier answer: the version and its review are two reads, and a revoke between them leaves one
// withheld and the other not. Both are then read again; if they still disagree, the view is not built at all.
import type { Fetched } from "../registry";
import type { ReviewAnswer } from "../review-schema";
import { isWithheld, withholdSource, type PackageView } from "./package-md";
import type { AgentSource, VersionInfo } from "./source";

export type LoadedView = { kind: "ok"; view: PackageView } | { kind: "missing"; reason: string } | { kind: "unavailable" };

export async function loadPackageView(input: { name: string; version: string | null; registry: string; source: AgentSource }): Promise<LoadedView> {
  const { name, source } = input;
  const found = await source.package(name);

  if (found.kind === "missing") return { kind: "missing", reason: `No package named ${name} on apm or npm.` };

  if (found.kind === "unavailable") return { kind: "unavailable" };
  const pkg = found.value;
  const version = input.version ?? pkg.latest;

  if (version === null) return { kind: "ok", view: { pkg, version: null, status: null, facts: null, score: null, review: { kind: "missing" }, registry: input.registry } };

  const read = () => Promise.all([source.version({ name, version }), source.review({ name, version })]);
  const first = await read();
  const [info, review] = agree(...first) ? first : await read();

  if (!agree(info, review)) return { kind: "unavailable" };

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

/**
 * Whether the version answer and the review answer saw the version in the same state: both withheld or neither. A
 * review the registry did not send (missing, unreadable) has nothing of the version's to disagree with.
 */
function agree(info: Fetched<VersionInfo>, review: Fetched<ReviewAnswer>): boolean {
  if (info.kind !== "ok" || review.kind !== "ok") return true;

  return isWithheld(info.value.status) === review.value.redacted;
}
