// Loads what the package's Markdown view shows: the package, the state, facts and score of the version asked for,
// and its AI review. Shared by GET /package/<name>.md and the check_package MCP tool.
//
// The package answer lists only the newest 200 versions and carries latest's facts, so the shown version (latest
// included) is read from the registry's versions route, which knows every version. Nothing here is cached. Which
// version that is, and how its install commands name it, is the page's own selection (shown-version.ts).
//
// A withheld version's AI review is what the registry sends for it (each finding's sentence replaced, each file by
// reference), never an earlier answer: the version and its review are two reads, and a revoke between them leaves one
// withheld and the other not. Both are then read again; if they still disagree, the view is not built at all.
//
// Whether apm installs the shown version is the same read /api/explain makes: resolve, for exactly that version
// (lib/refusal.ts readPolicy), started alongside the version and review reads.
import { inCooldown } from "../install-note";
import { readPolicy } from "../refusal";
import type { Fetched } from "../registry";
import type { ReviewAnswer } from "../review-schema";
import { selectVersion } from "../shown-version";
import { isWithheld, withholdSource, type PackageView } from "./package-md";
import type { AgentSource, VersionInfo } from "./source";

export type LoadedView = { kind: "ok"; view: PackageView } | { kind: "missing"; reason: string } | { kind: "unavailable" };

/** `version` is what ?v= says: a version number, a dist-tag, or null for the version installs get by name. */
export async function loadPackageView(input: { name: string; version: string | null; registry: string; source: AgentSource }): Promise<LoadedView> {
  const { name, source } = input;
  const found = await source.package(name);

  if (found.kind === "missing") return { kind: "missing", reason: `No package named ${name} on apm or npm.` };

  if (found.kind === "unavailable") return { kind: "unavailable" };
  const pkg = found.value;
  const selected = await selectVersion({ pkg, asked: input.version ?? undefined, read: (version) => source.version({ name, version }) });

  switch (selected.kind) {
    case "none":
      return { kind: "ok", view: { pkg, version: null, status: null, policy: { kind: "unknown" }, facts: null, score: null, unscorable: null, review: { kind: "missing" }, install: { kind: "none", why: selected.why }, registry: input.registry } };
    case "no-such-version":
      return { kind: "missing", reason: `${name} has no version ${selected.asked}. Latest is ${pkg.latest ?? "unknown"}.` };
    case "unavailable":
      return { kind: "unavailable" };
    case "shown":
      break;
    default: {
      const _exhaustive: never = selected;

      return _exhaustive;
    }
  }

  const { version, install } = selected;
  const isLatest = version === pkg.latest;
  const status = selected.read?.status ?? pkg.versions.find((r) => r.version === version)?.status ?? "active";
  // the page's score for a version other than latest comes from the score route, with its capabilities: so does this one
  const routeScore = isLatest ? null : source.score({ name, version });
  // as on the page: resolve is asked only when the version's score marks it risky (lib/refusal.ts looksRisky)
  const risk = routeScore === null ? Promise.resolve({ score: pkg.score, installScripts: pkg.facts?.installScripts ?? null }) : routeScore.then((s) => ({ score: s.kind === "ok" ? s.value : null, installScripts: null }));
  const policy = readPolicy({ name, version, status, risk, resolve: source.resolve });
  const read = () => Promise.all([source.version({ name, version }), source.review({ name, version })]);
  // a version the package answer does not list was just read to find it: only its review is new
  const first: Awaited<ReturnType<typeof read>> = selected.read ? [{ kind: "ok", value: selected.read }, await source.review({ name, version })] : await read();
  const [info, review] = agree(...first) ? first : await read();

  if (!agree(info, review)) return { kind: "unavailable" };

  if (info.kind === "missing") return { kind: "missing", reason: `${name} has no version ${version}. Latest is ${pkg.latest ?? "unknown"}.` };

  // without the version's own answer the view would show another version's facts or a stale status: say so instead
  if (info.kind === "unavailable") return { kind: "unavailable" };
  const v = info.value;
  const routed = routeScore === null ? null : await routeScore;

  // a revoked version's source stays out of every answer built from this view, the MCP tool's structured one included
  return {
    kind: "ok",
    view: withholdSource({
      pkg,
      version: v.version,
      status: { status: v.status, statusReason: v.statusReason, deprecated: v.deprecated },
      policy: await policy,
      facts: v.facts,
      score: withCapabilities({ score: v.score, from: isLatest ? pkg.score : routed?.kind === "ok" ? routed.value : null }),
      unscorable: v.unscorable,
      review,
      install,
      inCooldown: inCooldown({ publishedAt: v.publishedAt ?? pkg.versions.find((r) => r.version === v.version)?.publishedAt, now: Date.now() }),
      registry: input.registry,
    }),
  };
}

/**
 * The version's score with the capabilities the page shows, when the version answer sent none (the registry leaves
 * them out of it): latest's from the package answer, any other version's from the score route. A version answer that
 * sent a list, even an empty one, is that version's own.
 */
function withCapabilities(input: { score: VersionInfo["score"]; from: VersionInfo["score"] }): VersionInfo["score"] {
  const { score, from } = input;

  if (score === null || from === null || score.capabilities !== undefined) return score;

  return { ...score, capabilities: from.capabilities, declaration: from.declaration };
}

/**
 * Whether the version answer and the review answer saw the version in the same state: both withheld or neither. A
 * review the registry did not send (missing, unreadable) has nothing of the version's to disagree with.
 */
function agree(info: Fetched<VersionInfo>, review: Fetched<ReviewAnswer>): boolean {
  if (info.kind !== "ok" || review.kind !== "ok") return true;

  return isWithheld(info.value.status) === review.value.redacted;
}
