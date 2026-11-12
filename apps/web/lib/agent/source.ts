// What the agent views (the package text view, the MCP tools, the explain endpoint) read from the registry,
// as one port. lib/agent/registry-source.ts reads the real registry; the unit tests pass a stand-in.
import { z } from "zod";
import type { ExcerptAnswer } from "../file-excerpt";
import type { Json } from "./json";
import type { Facts, Fetched, PackageInfo, Signal } from "../registry";
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
};

/** The whole name check (GET /-/apm/v1/names without `part`): the three parts in one answer. */
export type NameReport = ExactPart & Omit<LookalikePart, "query" | "valid"> & Omit<AlternativesPart, "query" | "valid">;

const SignalWire = z.object({ id: z.string(), label: z.string(), points: z.number(), evidence: z.array(z.string()), confidence: z.enum(["confirmed", "possible"]).default("confirmed") });
const Skipped = z.array(z.object({ version: z.string(), reason: z.string() }));
const ReportWire = z.object({ score: z.number(), grade: z.string(), signals: z.array(SignalWire), notChecked: z.array(z.string()).optional() }).loose();

const DepRefWire = z.object({ name: z.string(), version: z.string() });

/** The AI review standing of every dependency the walk checked; a registry from before it sends none. */
const TreeReviewsWire = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("off") }),
  z.object({ kind: z.literal("on"), confirmed: z.array(DepRefWire), underReview: z.array(DepRefWire), pending: z.array(DepRefWire), noAnswer: z.array(DepRefWire) }),
]);

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
    })
    .loose()
    .optional(),
});

export type DepRef = z.infer<typeof DepRefWire>;

/** How the AI reviews of the dependencies stand; "unknown" when the registry did not say. */
export type DepReviews = z.infer<typeof TreeReviewsWire> | { kind: "unknown" };

/** The dependency walk as the verdict reads it: what apm could not score (the total and up to 50 named) and the AI reviews. */
export type DepCheck = { unchecked: number; uncheckedDeps: { dependency: string; reason: string }[]; reviews: DepReviews };

/** GET /-/apm/v1/resolve with a 422: nothing in range passes, or the newest that does pulls in a dangerous dependency. */
export const ResolveRefusedWire = z.object({
  error: z.string(),
  skipped: Skipped,
  newest: z.object({ version: z.string() }).loose().nullish(),
});

/** What the registry's install policy (24-hour cooldown, score floor 40, revokes, the dependency walk) says about a range. */
export type ResolveOutcome =
  | { kind: "ok"; version: string; source: string; report: { score: number; grade: string; signals: Signal[]; notChecked: string[] } | null; skipped: { version: string; reason: string }[]; deps: DepCheck }
  | { kind: "refused"; reason: string; newest: string | null; skipped: { version: string; reason: string }[] }
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
      report: r ? { score: r.score, grade: r.grade, signals: r.signals, notChecked: r.notChecked ?? [] } : null,
      skipped: ok.data.skipped,
      deps: { unchecked: Math.max(tree?.unchecked ?? 0, uncheckedDeps.length), uncheckedDeps, reviews: tree?.reviews ?? { kind: "unknown" } },
    };
  }

  if (status === 422) {
    const refused = ResolveRefusedWire.safeParse(body);

    return refused.success ? { kind: "refused", reason: refused.data.error, newest: refused.data.newest?.version ?? null, skipped: refused.data.skipped } : { kind: "unavailable" };
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
