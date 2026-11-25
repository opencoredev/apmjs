// What the agent views (the package text view, the MCP tools, the explain endpoint) read from the registry,
// as one port. lib/agent/registry-source.ts reads the real registry; the unit tests pass a stand-in.
import { z } from "zod";
import type { ExcerptAnswer } from "../file-excerpt";
import type { Json } from "./json";
import type { Facts, Fetched, PackageInfo, Refused, Signal } from "../registry";
import type { ReviewAnswer } from "../review-schema";
import type { AlternativesPart, ExactPart, LookalikePart, SearchAnswer } from "../search-schema";

/** One version's score as the package answer and the score route both carry it. */
export type ScoreReport = NonNullable<PackageInfo["score"]>;

/**
 * One version as GET /-/apm/v1/packages/:name/versions/:version answers it: its state, its facts and its score. The
 * package answer lists only the newest 200 versions and carries latest's facts, so a view of any version reads this.
 */
export type VersionInfo = {
  version: string;
  status: string;
  statusReason: string | null;
  deprecated: string | null;
  facts: Facts | null;
  score: ScoreReport | null;
  /** Why apm can never score this version (the registry's reason and sentence); null when it has a score or may get one. */
  unscorable: { reason: string; text: string } | null;
  /** Why the registry does not serve this version (confirmed or known malicious); absent from an older registry. */
  refused?: Refused | null;
  /** When it was published; absent from an older registry. */
  publishedAt?: string | null;
};

/** The whole name check (GET /-/apm/v1/names without `part`): the three parts in one answer. */
export type NameReport = ExactPart & Omit<LookalikePart, "query" | "valid"> & Omit<AlternativesPart, "query" | "valid">;

const SignalWire = z.object({ id: z.string(), label: z.string(), points: z.number(), evidence: z.array(z.string()), confidence: z.enum(["confirmed", "possible"]).default("confirmed") });
const Skipped = z.array(z.object({ version: z.string(), reason: z.string() }));
/** How much apm read (apm-score-v11; earlier registries send none): a partial reading can score well and still is not a pass. */

const CoverageWire = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("complete") }),
  z.object({ kind: z.literal("partial"), omittedFiles: z.number(), omittedBytes: z.number(), reasons: z.array(z.string()), notes: z.array(z.string()).default([]) }),
]);

/**
 * A report's or a warning's coverage as the verdict reads it: null when none was sent (an earlier scorer or registry),
 * `unreadable` when what was sent does not parse. The verdict lets a partial reading install only on a coverage it
 * read (verdict.ts readingOf), so an unreadable one holds like any other gap and never fails the whole answer.
 */
export type ReportCoverage = z.infer<typeof CoverageWire> | { kind: "unreadable" };

export const CoverageField = z.union([CoverageWire, z.object({ kind: z.literal("unreadable") })]).nullable().catch({ kind: "unreadable" });

const ReportWire = z.object({ score: z.number(), grade: z.string(), signals: z.array(SignalWire), notChecked: z.array(z.string()).optional(), coverage: CoverageField.optional(), scorer: z.string().optional() }).loose();

const LostSignalWire = z.object({ id: z.string(), points: z.number() });

/**
 * A dependency the walk scored whose score carries a risk signal, whatever the score (the registry lists it even with
 * no warning); a registry before the agent-native verdict sends none.
 */
const RiskyDepWire = z.object({ name: z.string(), version: z.string(), via: z.array(z.string()), scorer: z.string().nullish(), score: z.number(), signals: z.array(LostSignalWire) });

const DepRefWire = z.object({ name: z.string(), version: z.string() });

/** The AI review standing of every dependency the walk checked; a registry from before it sends none. */
const TreeReviewsWire = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("off") }),
  // flagged: open AI flags while apm does not hold installs on them (a note); a registry from before it sends none
  z.object({ kind: z.literal("on"), confirmed: z.array(DepRefWire), underReview: z.array(DepRefWire), flagged: z.array(DepRefWire).optional(), pending: z.array(DepRefWire), noAnswer: z.array(DepRefWire) }),
]);

/**
 * One of resolve's warnings on an install that goes ahead: a low or incomplete score, no score, a dependency the
 * registry could not look up, a walk cut short. `via` is empty for the version itself. Older registries send none.
 */
const WarningWire = z
  .object({
    name: z.string(),
    version: z.string(),
    kind: z.enum(["low-score", "incomplete", "unscorable", "pending", "unavailable", "unchecked", "cooldown"]),
    text: z.string(),
    // at most three, each a signal's label and the file and line its evidence cites; older registries send none
    reasons: z.array(z.string()).optional(),
    // the package's or the version's page on the website
    url: z.string().optional(),
    via: z.array(z.string()),
    // a scored version's score, and every signal that cost it points (id and points); the verdict reads them for a risk
    // signal. Absent when the version has no score, and from registries before the agent-native verdict
    score: z.number().nullish(),
    signals: z.array(LostSignalWire).optional(),
    // the scorer whose ids `signals` are
    scorer: z.string().nullish(),
    // how much that score's analysis read, as stored; a partial reading of a dependency installs only on this record
    coverage: CoverageField.optional(),
    // for unscorable: why the registry decided the version will never be scored (too-large, analysis-limit, ...)
    unscorable: z.string().optional(),
  })
  .loose();

export type WarningInput = Pick<z.infer<typeof WarningWire>, "name" | "version" | "kind" | "text" | "reasons" | "url" | "via" | "score" | "signals" | "scorer" | "unscorable"> & { coverage?: ReportCoverage | null };

/** A dependency with a risk signal, as the verdict reads it: `scorer` null when the registry did not say. */
export type RiskyDep = { name: string; version: string; via: string[]; scorer: string | null; score: number; signals: { id: string; points: number }[] };

/** GET /-/apm/v1/resolve with a 200: the newest version in range that passes the policy, and its dependency walk. */
export const ResolveOkWire = z.object({
  name: z.string(),
  version: z.string(),
  source: z.string().optional(),
  report: ReportWire.nullable(),
  skipped: Skipped,
  tree: z
    .object({
      // the total; uncheckedDeps lists at most 50 of them
      unchecked: z.number().int().min(0).optional(),
      uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })).default([]),
      reviews: TreeReviewsWire.optional(),
      risks: z.array(RiskyDepWire).default([]),
    })
    .loose()
    .optional(),
  warnings: z.array(WarningWire).default([]),
});

export type DepRef = z.infer<typeof DepRefWire>;

/** How the AI reviews of the dependencies stand; "unknown" when the registry did not say. */
export type DepReviews = z.infer<typeof TreeReviewsWire> | { kind: "unknown" };

/**
 * The dependency walk as the verdict reads it: what apm could not score (the total and up to 50 named), the AI
 * reviews, and the registry's warnings on the install.
 */
export type DepCheck = { unchecked: number; uncheckedDeps: { dependency: string; reason: string }[]; reviews: DepReviews; warnings: WarningInput[]; risks: RiskyDep[] };

/**
 * GET /-/apm/v1/resolve with a 422: nothing in range passes (revoked, yanked, confirmed malicious), or the newest that
 * does pulls in a version an apm reviewer confirmed malicious (`confirmed`). A version inside its cooldown is a warning
 * on a 200 (review of 2fbf383, finding 1).
 */
export const ResolveRefusedWire = z.object({
  error: z.string(),
  skipped: Skipped,
  newest: z.object({ version: z.string() }).loose().nullish(),
  confirmed: z.array(DepRefWire).default([]),
  knownMalicious: z.array(z.object({ name: z.string(), version: z.string(), ids: z.array(z.string()) })).default([]),
});

/**
 * What the registry's install policy (revokes, confirmed malice, the dependency walk, and the 24-hour cooldown and the
 * score floor of 40 as warnings) says about a range.
 */
export type ResolveOutcome =
  | { kind: "ok"; version: string; source: string; report: { score: number; grade: string; signals: Signal[]; notChecked: string[]; coverage?: ReportCoverage | null; scorer: string | null } | null; skipped: { version: string; reason: string }[]; deps: DepCheck }
  | { kind: "refused"; reason: string; newest: string | null; skipped: { version: string; reason: string }[]; confirmed: DepRef[]; knownMalicious?: { name: string; version: string; ids: string[] }[] }
  | { kind: "missing"; reason: string }
  | { kind: "unavailable" };

/** Reads a /resolve answer by its status. Anything but 200, 404 and a well-formed 422 means the registry could not say. */
export function parseResolve(status: number, body: Json | null): ResolveOutcome {
  if (status === 200) {
    const ok = ResolveOkWire.safeParse(body);

    if (!ok.success) return { kind: "unavailable" };
    const r = ok.data.report;
    const tree = ok.data.tree;
    const uncheckedDeps = tree?.uncheckedDeps ?? [];

    return {
      kind: "ok",
      version: ok.data.version,
      source: ok.data.source ?? "local",
      report: r ? { score: r.score, grade: r.grade, signals: r.signals, notChecked: r.notChecked ?? [], coverage: r.coverage ?? null, scorer: r.scorer ?? null } : null,
      skipped: ok.data.skipped,
      deps: {
        unchecked: Math.max(tree?.unchecked ?? 0, uncheckedDeps.length),
        uncheckedDeps,
        reviews: tree?.reviews ?? { kind: "unknown" },
        warnings: ok.data.warnings,
        risks: (tree?.risks ?? []).map((d) => ({ ...d, scorer: d.scorer ?? null })),
      },
    };
  }

  if (status === 422) {
    const refused = ResolveRefusedWire.safeParse(body);

    if (!refused.success) return { kind: "unavailable" };

    const out: Extract<ResolveOutcome, { kind: "refused" }> = { kind: "refused", reason: refused.data.error, newest: refused.data.newest?.version ?? null, skipped: refused.data.skipped, confirmed: refused.data.confirmed };

    if (refused.data.knownMalicious.length > 0) out.knownMalicious = refused.data.knownMalicious;

    return out;
  }

  if (status === 404) {
    const msg = z.object({ error: z.string() }).safeParse(body);

    return { kind: "missing", reason: msg.success ? msg.data.error : "No such package." };
  }

  return { kind: "unavailable" };
}

/**
 * Everything the agent views read. Each call says "missing" or "unavailable" instead of throwing. Version state, the
 * AI review and file excerpts are read without a cache: a verdict or a view must never repeat a status that has since
 * changed, and only the registry, asked on every read, decides whether a version's source may be shown.
 */
export type AgentSource = {
  package: (name: string) => Promise<Fetched<PackageInfo>>;
  /** One version's state, facts and score, whatever its age; "missing" when the package has no such version. */
  version: (input: { name: string; version: string }) => Promise<Fetched<VersionInfo>>;
  review: (input: { name: string; version: string }) => Promise<Fetched<ReviewAnswer>>;
  resolve: (input: { name: string; range: string }) => Promise<ResolveOutcome>;
  search: (input: { query: string }) => Promise<SearchAnswer | null>;
  /** The name check; `scope` is the npm scope (without @) the alternatives are checked under. */
  names: (input: { name: string; scope: string | null }) => Promise<NameReport | null>;
  /** Lines of a file; a revoked version's answer is unavailable with status 410, a line past the end 416. */
  excerpt: (input: { name: string; version: string; path: string; line: number; context: number }) => Promise<Fetched<ExcerptAnswer>>;
};
