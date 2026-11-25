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
import { isVersionNumber, selectVersion } from "../shown-version";
import { isWithheld, withholdSource, type PackageView } from "./package-md";
import { inlineCode } from "./text";
import type { AgentSource, ScoreReport, VersionInfo } from "./source";

export type LoadedView = { kind: "ok"; view: PackageView } | { kind: "missing"; reason: string } | { kind: "unavailable" };

/** `version` is what ?v= says: a version number, a dist-tag, or null for the version installs get by name. */
export async function loadPackageView(input: { name: string; version: string | null; registry: string; source: AgentSource }): Promise<LoadedView> {
  const { name, source } = input;
  const found = await source.package(name);

  // the name and version come from the URL or the tool call, not from apm: quoted as data, like publisher text
  if (found.kind === "missing") return { kind: "missing", reason: `No package named ${inlineCode(name)} on apm or npm.` };

  if (found.kind === "unavailable") return { kind: "unavailable" };
  const pkg = found.value;
  const selected = await selectVersion({ pkg, asked: input.version ?? undefined, read: (version) => source.version({ name, version }) });

  switch (selected.kind) {
    case "none":
      return { kind: "ok", view: { pkg, version: null, status: null, policy: { kind: "unknown" }, facts: null, score: null, unscorable: null, review: { kind: "missing" }, install: { kind: "none", why: selected.why }, registry: input.registry } };
    case "no-such-version":
      // the selector is the request's text: quoted unless it is a plain version number
      return { kind: "missing", reason: `${name} has no version ${isVersionNumber(selected.asked) ? selected.asked : inlineCode(selected.asked)}. Latest is ${pkg.latest ?? "unknown"}.` };
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
  // the page's score for a version other than latest comes from the score route, with its capabilities: so does this one
  const scoreRead = (): Promise<Fetched<ScoreReport> | null> => (isLatest ? Promise.resolve(null) : source.score({ name, version }));
  const read = () => Promise.all([source.version({ name, version }), source.review({ name, version }), scoreRead()]);
  // a version the package answer does not list was just read to find it: only its review and score are new
  const first: Awaited<ReturnType<typeof read>> = selected.read ? await Promise.all([{ kind: "ok", value: selected.read } as const, source.review({ name, version }), scoreRead()]) : await read();
  const last = agree(...first) ? first : await read();
  const [info, review, routed] = last;
  // a withdrawal any read of this request has seen stays seen: a retry's missing or unavailable answers never undo it
  const withheld = saysWithheld(first) || saysWithheld(last);

  // the reads still disagree about a revoke, or one saw it and the version answer does not say it: build no view at
  // all, rather than one mixing answers from both sides of it
  if (!agree(info, review, routed) || (withheld && versionSays(info) !== true)) return { kind: "unavailable" };

  if (info.kind === "missing") return { kind: "missing", reason: `${inlineCode(name)} has no version ${inlineCode(version)}. Latest is ${pkg.latest === null ? "unknown" : inlineCode(pkg.latest)}.` };

  // without the version's own answer the view would show another version's facts or a stale status: say so instead
  if (info.kind === "unavailable") return { kind: "unavailable" };
  const v = info.value;
  const routedScore = routed?.kind === "ok" ? routed.value : null;

  // as on the page: a withdrawal or a review apm reviewers confirmed refuses it, and resolve is asked only when the
  // version's score or review marks it risky (lib/refusal.ts readPolicy)
  const policy = readPolicy({
    name,
    version,
    status: v.status,
    risk: Promise.resolve({ score: isLatest ? pkg.score : routedScore, installScripts: isLatest ? (pkg.facts?.installScripts ?? null) : null, review: review.kind === "ok" ? (review.value.review?.state ?? null) : null, withheld }),
    resolve: source.resolve,
  });

  // a revoked version's source stays out of every answer built from this view, the MCP tool's structured one included
  return {
    kind: "ok",
    view: withholdSource({
      pkg,
      version: v.version,
      status: { status: v.status, statusReason: v.statusReason, deprecated: v.deprecated },
      policy: await policy,
      facts: v.facts,
      // capabilities come from another read only when no read says withheld
      score: withheld ? v.score : withCapabilities({ score: v.score, from: isLatest ? pkg.score : routedScore }),
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

/** What the version answer says about a revoke: withheld (its status or its score's redaction), not, or nothing. */
const versionSays = (read: Fetched<VersionInfo>): boolean | null => (read.kind === "ok" ? isWithheld(read.value.status) || read.value.score?.redacted === true : null);

/** What a review or score-route answer says about a revoke: redacted, not, or nothing when there is no answer. */
const redactedSays = (read: Fetched<{ redacted: boolean }> | null): boolean | null => (read?.kind === "ok" ? read.value.redacted : null);

/** Whether any read of a batch says withheld. */
const saysWithheld = ([info, review, routed]: [Fetched<VersionInfo>, Fetched<ReviewAnswer>, Fetched<ScoreReport> | null]): boolean =>
  versionSays(info) === true || redactedSays(review) === true || redactedSays(routed) === true;

/**
 * Whether the version, review and score-route answers saw the version in the same state: all withheld or none. A read
 * the registry did not answer (missing, unreadable, not made) has nothing of the version's to disagree with.
 */
function agree(info: Fetched<VersionInfo>, review: Fetched<ReviewAnswer>, routed: Fetched<ScoreReport> | null): boolean {
  const said = [versionSays(info), redactedSays(review), redactedSays(routed)].filter((s) => s !== null);

  return said.every((s) => s === said[0]);
}
