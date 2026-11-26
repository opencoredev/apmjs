// The install verdict: the registry's policy answer and the AI reviews in, one word and its reasons out. The cases in
// tests/fixtures/explain-verdicts.json run here and in packages/cli/test/explain.test.ts, so both copies agree.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import cases from "../../../../tests/fixtures/explain-verdicts.json";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { newestFirst, satisfies } from "../../../../packages/registry/src/semver";
import { belowFreshRun, COOLDOWN_MS, explainFor, MAX_OLDER_LOOKUPS, olderRange, parsePackageSpec } from "./explain";
import { CoverageField, parseResolve, type ResolveOutcome } from "./source";
import { fakeSource, NETWORK, pkg, REVIEW_CLEAN, signal } from "./testing";
import { KNOWN_VULNERABILITIES } from "../limitations";
import { ReviewAnswer } from "../review-schema";
import { AI_REVIEW_COVERAGE, AS_VERSION, DEPENDENCY_COVERAGE, ESTABLISHED_DEPENDENCY_NAMES, explainInstall, GAP_SIGNALS, isRisky, LEGACY_RISK_SIGNALS, NOTE_KINDS, reviewInput, readingOf, RISK_SIGNALS, riskSignalsOf, VERDICTS, verdictText, type OlderSearch, type ReviewInput } from "./verdict";

/** A coverage as the registry sends it, read through this copy's own parser: null when none was sent. */
const readCoverage = CoverageField.optional().transform((c) => c ?? null);

// ---------- the shared cases ----------

const DepRef = z.object({ name: z.string(), version: z.string() });

const Case = z.object({
  name: z.string(),
  resolve: z.discriminatedUnion("kind", [
    z.object({
      kind: z.literal("ok"),
      version: z.string(),
      score: z.number().nullable(),
      // a partial reading (apm-score-v11): how much the registry's score did not read
      partial: z.object({ omittedFiles: z.number(), omittedBytes: z.number() }).optional(),
      // the report's coverage exactly as the registry sends it, read through this copy's own parser (CoverageField);
      // absent, it is built from `partial` (reasons over-budget) or is complete
      coverage: z.unknown().optional(),
      // `id` and `evidence` for a signal the verdict reads by id (incomplete); the rest are s0, s1, …
      lost: z.array(z.object({ label: z.string(), points: z.number(), id: z.string().optional(), evidence: z.array(z.string()).default([]) })),
      skipped: z.array(z.object({ version: z.string(), reason: z.string() })),
      unchecked: z.number(),
      uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })),
      // the registry's warnings on the install (resolve's `warnings`): via empty for the version itself
      warnings: z.array(z.object({ name: z.string(), version: z.string(), kind: z.enum(["low-score", "incomplete", "unscorable", "pending", "unavailable", "unchecked", "cooldown"]), text: z.string(), reasons: z.array(z.string()).optional(), url: z.string().optional(), via: z.array(z.string()), score: z.number().nullish(), signals: z.array(z.object({ id: z.string(), points: z.number() })).optional(), scorer: z.string().nullish(), coverage: z.unknown().optional(), unscorable: z.string().optional() })).default([]),
      // the registry's tree.risks: dependencies it scored with a risk signal, whatever the score
      risks: z.array(z.object({ name: z.string(), version: z.string(), via: z.array(z.string()), scorer: z.string().nullable(), score: z.number(), signals: z.array(z.object({ id: z.string(), points: z.number() })) })).default([]),
      // the scorer that wrote the version's analysis; absent, the current one
      scorer: z.string().nullable().default("apm-score-v11"),
      // what the explain step did about a picked version inside the cooldown (passed in as `older`); absent, nothing
      older: z.discriminatedUnion("kind", [z.object({ kind: z.literal("picked"), passedOver: z.array(z.object({ version: z.string(), text: z.string() })) }), z.object({ kind: z.literal("none") }), z.object({ kind: z.literal("gave-up"), looked: z.number() })]).optional(),
      depReviews: z.discriminatedUnion("kind", [
        z.object({ kind: z.literal("off") }),
        z.object({ kind: z.literal("unknown") }),
        z.object({ kind: z.literal("on"), confirmed: z.array(DepRef), underReview: z.array(DepRef), pending: z.array(DepRef), noAnswer: z.array(DepRef) }),
      ]),
    }),
    z.object({ kind: z.literal("refused"), reason: z.string(), newest: z.string().nullable(), skipped: z.array(z.object({ version: z.string(), reason: z.string() })), confirmed: z.array(DepRef).default([]) }),
    z.object({ kind: z.literal("missing"), reason: z.string() }),
    z.object({ kind: z.literal("unavailable") }),
  ]),
  review: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("reviewed"), state: z.enum(["found-nothing", "under-review", "no-answer", "confirmed", "cleared"]), findings: z.number() }),
    z.object({ kind: z.enum(["queued", "leased", "failed", "not-reviewed", "off", "unreadable"]) }),
    // the registry's raw GET /-/apm/v1/review answer, read through this copy's own parser
    z.object({ kind: z.literal("answer"), status: z.number(), body: z.unknown() }),
  ]),
  expect: z.object({
    verdict: z.enum(VERDICTS),
    commands: z.boolean(),
    summary: z.string(),
    reasons: z.array(z.string()).optional(),
    coverage: z.object({ aiReview: z.enum(AI_REVIEW_COVERAGE), dependencies: z.enum(DEPENDENCY_COVERAGE) }),
    // the verdict's evidence lines and page link, exactly; a case that leaves them out does not check them
    evidence: z.array(z.string()).optional(),
    url: z.string().nullable().optional(),
    // the verdict's notes, exactly; a case that leaves them out does not check them
    notes: z.array(z.object({ kind: z.enum(NOTE_KINDS), text: z.string() })).optional(),
  }),
});

export const CASES = z.object({ cases: z.array(Case).min(20) }).parse(cases).cases;

/**
 * A case's review: given as the verdict's input, or as the registry's raw answer, read the way lib/registry.ts reads
 * it (the ReviewAnswer schema; a 404 is missing, anything unparsable unavailable) and then through reviewInput.
 */
function reviewOf(r: z.infer<typeof Case>["review"]): ReviewInput {
  if (r.kind !== "answer") return r;

  if (r.status === 404) return reviewInput({ kind: "missing" });
  const parsed = r.status === 200 ? ReviewAnswer.safeParse(r.body) : null;

  return reviewInput(parsed?.success ? { kind: "ok", value: parsed.data } : { kind: "unavailable", reason: { kind: "invalid", message: "not a review answer" } });
}

const grade = (score: number): string => (score >= 90 ? "A" : score >= 75 ? "B" : "C");

function resolveOf(c: z.infer<typeof Case>["resolve"]): ResolveOutcome {
  switch (c.kind) {
    case "ok":
      return {
        kind: "ok",
        version: c.version,
        source: "upstream",
        report: c.score === null ? null : { score: c.score, grade: c.partial ? "P" : grade(c.score), signals: c.lost.map((l, i) => signal({ id: l.id ?? `s${i}`, label: l.label, points: l.points, evidence: l.evidence })), notChecked: [], coverage: c.coverage !== undefined ? readCoverage.parse(c.coverage) : c.partial ? { kind: "partial", omittedFiles: c.partial.omittedFiles, omittedBytes: c.partial.omittedBytes, reasons: ["over-budget"], notes: [] } : { kind: "complete" }, scorer: c.scorer },
        skipped: c.skipped,
        deps: { unchecked: c.unchecked, uncheckedDeps: c.uncheckedDeps, reviews: c.depReviews, warnings: c.warnings.map((w) => ({ ...w, coverage: readCoverage.parse(w.coverage) })), risks: c.risks },
      };
    case "refused":
    case "missing":
    case "unavailable":
      return c;
    default: {
      const _exhaustive: never = c;

      return _exhaustive;
    }
  }
}

/** A case's `older`, as the explain step would pass it. */
function olderOf(c: z.infer<typeof Case>["resolve"]): OlderSearch {
  return c.kind === "ok" && c.older !== undefined ? c.older : { kind: "not-needed" };
}

describe("the shared verdict cases (tests/fixtures/explain-verdicts.json)", () => {
  for (const c of CASES) {
    test(c.name, () => {
      const review = reviewOf(c.review);
      const v = explainInstall({ name: "x", range: null, resolve: resolveOf(c.resolve), review, older: olderOf(c.resolve) });

      expect(v.verdict).toBe(c.expect.verdict);
      expect(v.summary).toBe(c.expect.summary);
      expect(v.commands !== null).toBe(c.expect.commands);

      expect(v.coverage).toEqual(c.expect.coverage);

      for (const r of c.expect.reasons ?? []) expect(v.reasons).toContain(r);

      if (c.expect.evidence !== undefined) expect(v.evidence).toEqual(c.expect.evidence);

      if (c.expect.url !== undefined) expect(v.url).toBe(c.expect.url);

      if (c.expect.notes !== undefined) expect(v.notes).toEqual(c.expect.notes);
      expect(v.summary).not.toMatch(/\bsafe\b/);
    });
  }

  // the agent-native policy: review-first means a person should look, so an install never carries a real risk, and
  // a real risk is never an install
  test("no install carries a risk signal, an open AI flag, a risky dependency or a fresh version apm cannot clear", () => {
    for (const c of CASES.filter((x) => x.expect.verdict === "install")) {
      expect(c.resolve.kind).toBe("ok");

      if (c.resolve.kind !== "ok") continue;
      const signals = c.resolve.lost.map((l, i) => ({ id: l.id ?? `s${i}`, points: l.points }));

      expect(riskSignalsOf(signals, c.resolve.scorer, AS_VERSION)).toEqual([]);
      expect(c.resolve.score === null || !isRisky({ score: c.resolve.score, signals, scorer: c.resolve.scorer }, AS_VERSION)).toBe(true);
      expect(c.resolve.risks.filter((r) => isRisky(r, { kind: "dependency", name: r.name }))).toEqual([]);
      expect(c.resolve.depReviews.kind === "off" || (c.resolve.depReviews.kind === "on" && c.resolve.depReviews.underReview.length + c.resolve.depReviews.confirmed.length === 0)).toBe(true);
      expect(c.resolve.warnings.some((w) => w.via.length === 0 && w.kind === "cooldown")).toBe(false);
      // a version with no score installs only when the registry recorded it too large to score: a queued one is pending, never clean
      expect(c.resolve.score !== null || c.resolve.warnings.some((w) => w.via.length === 0 && w.kind === "unscorable" && w.unscorable === "too-large")).toBe(true);
      expect(c.resolve.warnings.some((w) => w.via.length > 0 && w.kind === "cooldown" && w.signals === undefined)).toBe(false);

      const review = reviewOf(c.review);

      expect(["unreadable", "pulled"]).not.toContain(review.kind);
      expect(review.kind === "reviewed" && (review.state === "under-review" || review.state === "confirmed")).toBe(false);
    }
  });

  test("every case with a risk signal in the version is review-first or worse, never install", () => {
    const risky = CASES.filter((c) => c.resolve.kind === "ok" && riskSignalsOf(c.resolve.lost.map((l, i) => ({ id: l.id ?? `s${i}`, points: l.points })), c.resolve.scorer, AS_VERSION).length > 0);

    expect(risky.length).toBeGreaterThan(2);

    for (const c of risky) expect(c.expect.verdict).not.toBe("install");
  });

  test("an install with something apm did not finish says so in its notes", () => {
    for (const c of CASES.filter((x) => x.expect.verdict === "install" && x.expect.summary.startsWith("Install "))) expect(c.expect.notes?.length ?? 0).toBeGreaterThan(0);
  });

  test("the established-name exception is the same list in both copies", () => {
    const cli = readFileSync(join(import.meta.dir, "../../../../packages/cli/src/explain.ts"), "utf8");

    expect(cli).toContain(`export const ESTABLISHED_DEPENDENCY_NAMES = ${JSON.stringify(ESTABLISHED_DEPENDENCY_NAMES)} as const;`);
  });

  test("both copies read the same risk signals and gaps (packages/cli/src/explain.ts)", () => {
    const cli = readFileSync(join(import.meta.dir, "../../../../packages/cli/src/explain.ts"), "utf8");

    expect(cli).toContain(`export const RISK_SIGNALS = ${JSON.stringify(RISK_SIGNALS).replaceAll(",", ", ")} as const;`);
    expect(cli).toContain(`export const GAP_SIGNALS = ${JSON.stringify(GAP_SIGNALS).replaceAll(",", ", ")} as const;`);
  });
});

// ---------- the web copy's own surface ----------

const ok = (score: number, over: Partial<Extract<ResolveOutcome, { kind: "ok" }>> = {}): ResolveOutcome => ({
  kind: "ok",
  version: "1.3.0",
  source: "upstream",
  report: { score, grade: grade(score), signals: score < 100 ? [NETWORK] : [], notChecked: [], scorer: "apm-score-v10" },
  skipped: [],
  deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] }, warnings: [], risks: [] },
  ...over,
});

describe("explainInstall", () => {
  test("install gives the exact commands for every client", () => {
    const v = explainInstall({ name: "zod", range: null, resolve: ok(92), review: { kind: "reviewed", state: "found-nothing", findings: 0 } });

    expect(v.commands).toEqual({ apm: "apm add zod@1.3.0", bun: "bun add zod@1.3.0", npm: "npm install zod@1.3.0", pnpm: "pnpm add zod@1.3.0" });
  });

  test("verdictText is the summary, reasons and the command", () => {
    const text = verdictText(explainInstall({ name: "zod", range: null, resolve: ok(92), review: { kind: "reviewed", state: "found-nothing", findings: 0 } }));

    expect(text.split("\n")[0]).toBe("Verdict: install");
    expect(text).toContain("Run: apm add zod@1.3.0");
  });
});

// 2026-11-25: ticket-symbol-stream-native@1.0.0 is in the OSSF malicious-packages feed (MAL-2026-20520) and was
// answered "install" at 100/A. The registry now refuses a listed version, or one that installs a listed version.
describe("the OSSF malicious-packages feed", () => {
  const NONE: ReviewInput = { kind: "reviewed", state: "found-nothing", findings: 0 };

  test("a refusal citing a listed root is do-not-install, with the advisory", () => {
    const body = {
      error: "No version of ticket-symbol-stream-native matching latest passes the policy.",
      skipped: [{ version: "1.0.0", reason: "known malicious: the OSSF malicious-packages feed lists ticket-symbol-stream-native@1.0.0 (MAL-2026-20520)", revokeReason: null }],
      newest: { version: "1.0.0" },
      knownMalicious: [{ name: "ticket-symbol-stream-native", version: "1.0.0", ids: ["MAL-2026-20520"] }],
    };

    const v = explainInstall({ name: "ticket-symbol-stream-native", range: null, resolve: parseResolve(422, body), review: NONE });

    expect(v.verdict).toBe("do-not-install");
    expect(v.commands).toBeNull();
    expect(v.summary).toContain("MAL-2026-20520");
    expect(v.reasons).toContain("Advisory: https://osv.dev/vulnerability/MAL-2026-20520");
  });

  test("a refusal for a listed dependency is do-not-install too", () => {
    const body = { error: "x@1.0.0 would install evil@2.0.0 (MAL-2026-1), which the OSSF malicious-packages feed lists as malicious.", skipped: [], newest: { version: "1.0.0" }, knownMalicious: [{ name: "evil", version: "2.0.0", ids: ["MAL-2026-1"] }] };
    const v = explainInstall({ name: "x", range: null, resolve: parseResolve(422, body), review: NONE });

    expect(v.verdict).toBe("do-not-install");
    expect(v.summary).toContain("evil@2.0.0 (MAL-2026-1)");
  });

  test("a skip for a listed version alone reads as pulled, for a registry answer without the list", () => {
    const v = explainInstall({ name: "x", range: null, resolve: { kind: "refused", reason: "none", newest: "1.0.0", skipped: [{ version: "1.0.0", reason: "known malicious: the OSSF malicious-packages feed lists x@1.0.0 (MAL-2026-2)" }], confirmed: [] }, review: NONE });

    expect(v.verdict).toBe("do-not-install");
  });
});

describe("parseResolve", () => {
  test("reads 200, 422 and 404 answers; anything else is unavailable", () => {
    expect(parseResolve(200, { name: "zod", version: "4.1.0", report: null, skipped: [], tree: { unchecked: 7, uncheckedDeps: [{ dependency: "a@1", reason: "r", via: [] }], reviews: { kind: "off" } } })).toMatchObject({
      kind: "ok",
      version: "4.1.0",
      deps: { unchecked: 7, uncheckedDeps: [{ dependency: "a@1" }], reviews: { kind: "off" } },
    });
    expect(parseResolve(422, { error: "too new", name: "zod", version: null, skipped: [], newest: { version: "5.0.0", report: {} } })).toEqual({ kind: "refused", reason: "too new", newest: "5.0.0", skipped: [], confirmed: [] });
    expect(parseResolve(404, { error: "No package named q." })).toEqual({ kind: "missing", reason: "No package named q." });
    expect(parseResolve(500, {})).toEqual({ kind: "unavailable" });
    expect(parseResolve(200, { nope: true })).toEqual({ kind: "unavailable" });
  });

  // review finding 4 and 5: the registry's dependency review standings and its total of unchecked dependencies
  test("keeps the registry's total of unchecked dependencies, and a missing review summary is unknown, not clean", () => {
    const listed = Array.from({ length: 50 }, (_, i) => ({ dependency: `d${i}@1`, reason: "r", via: [] }));
    const r = parseResolve(200, { name: "zod", version: "4.1.0", report: null, skipped: [], tree: { unchecked: 312, uncheckedDeps: listed } });

    expect(r.kind === "ok" && r.deps.unchecked).toBe(312);
    expect(r.kind === "ok" && r.deps.reviews).toEqual({ kind: "unknown" });

    const confirmed = parseResolve(200, {
      name: "zod",
      version: "4.1.0",
      report: null,
      skipped: [],
      tree: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [{ name: "evil", version: "1.0.0" }], underReview: [], pending: [], noAnswer: [] } },
    });

    expect(confirmed.kind === "ok" && confirmed.deps.reviews).toEqual({ kind: "on", confirmed: [{ name: "evil", version: "1.0.0" }], underReview: [], pending: [], noAnswer: [] });
  });
});

describe("reviewInput", () => {
  // review finding 3: a failed read, a queued job, a leased job, a failed job and no answer each stay distinct
  test("keeps every state of the AI review distinct", () => {
    const answer = (over: Partial<typeof REVIEW_CLEAN>) => ({ kind: "ok", value: { ...REVIEW_CLEAN, review: null, ...over } }) as const;

    expect(reviewInput({ kind: "unavailable", reason: { kind: "timeout" } })).toEqual({ kind: "unreadable" });
    expect(reviewInput({ kind: "missing" })).toEqual({ kind: "off" });
    expect(reviewInput(answer({ status: "queued", job: "queued" }))).toEqual({ kind: "queued" });
    expect(reviewInput(answer({ status: "queued", job: "leased" }))).toEqual({ kind: "leased" });
    // an older registry sends no job: queued is all it can say
    expect(reviewInput(answer({ status: "queued" }))).toEqual({ kind: "queued" });
    expect(reviewInput(answer({ status: "failed", job: "failed" }))).toEqual({ kind: "failed" });
    expect(reviewInput(answer({ status: "not-reviewed", job: null }))).toEqual({ kind: "not-reviewed" });
    expect(reviewInput({ kind: "ok", value: REVIEW_CLEAN })).toEqual({ kind: "reviewed", state: "found-nothing", findings: 0 });
  });

  // review finding P1: the answer's redacted flag and version state were dropped, so its clean review read as install
  test("an answer that says the version is withheld, revoked, being revoked or yanked is pulled, before its review", () => {
    const answer = (over: Partial<typeof REVIEW_CLEAN>) => ({ kind: "ok", value: { ...REVIEW_CLEAN, ...over } }) as const;

    expect(reviewInput(answer({ versionStatus: "revoke-pending", redacted: true }))).toEqual({ kind: "pulled", status: "revoke-pending" });
    expect(reviewInput(answer({ versionStatus: "revoked", redacted: true }))).toEqual({ kind: "pulled", status: "revoked" });
    expect(reviewInput(answer({ versionStatus: "yanked", redacted: false }))).toEqual({ kind: "pulled", status: "yanked" });
    expect(reviewInput(answer({ redacted: true }))).toEqual({ kind: "pulled", status: "withheld" });
    // contradictory: an active state with a redacted answer is still withheld
    expect(reviewInput(answer({ versionStatus: "active", redacted: true }))).toEqual({ kind: "pulled", status: "withheld" });
    expect(reviewInput(answer({ versionStatus: "active", redacted: false }))).toEqual({ kind: "reviewed", state: "found-nothing", findings: 0 });
  });
});

describe("explainFor reads the registry", () => {
  const clean = ok(92);

  // review finding 3: a review that could not be fetched used to read as "no review", and install
  test("a review read that fails is unknown, never install", async () => {
    const source = fakeSource({ resolve: () => clean, down: false });
    source.review = async () => ({ kind: "unavailable", reason: { kind: "timeout" } });
    const v = await explainFor({ name: "zod", range: null, source });

    expect(v.verdict).toBe("unknown");
    expect(v.commands).toBeNull();
  });

  // the agent-native policy: apm's own unfinished review never interrupts anyone
  test("a queued review installs, with a note", async () => {
    const source = fakeSource({ resolve: () => clean, reviews: { "zod@1.3.0": { ...REVIEW_CLEAN, status: "queued", job: "queued", review: null } } });
    const v = await explainFor({ name: "zod", range: null, source });

    expect(v.verdict).toBe("install");
    expect(v.notes.map((n) => n.kind)).toEqual(["ai-review-pending"]);
  });
});

describe("the risk rules", () => {
  test("readingOf: a partial reading installs only on the current scorer's record that its one gap is size or budget", () => {
    const partial = (reasons: readonly string[] | string) => readCoverage.parse({ kind: "partial", omittedFiles: 2, omittedBytes: 9, reasons, notes: [] });

    expect(readingOf({ scorer: "apm-score-v11", signals: [], coverage: partial(["too-large", "over-budget"]) })).toEqual({ kind: "partial", omittedFiles: 2, omittedBytes: 9 });
    expect(readingOf({ scorer: "apm-score-v11", signals: [], coverage: { kind: "complete" } }).kind).toBe("complete");
    // an earlier scorer stored no coverage, and counted every file it left unread as a gap signal
    expect(readingOf({ scorer: "apm-score-v10", signals: [], coverage: null }).kind).toBe("complete");
    // the rest hold: a gap signal, a stop, an empty, unknown or malformed list, no record from the current scorer, an
    // earlier scorer's partial reading
    expect(readingOf({ scorer: "apm-score-v11", signals: [{ id: "incomplete" }], coverage: partial(["over-budget"]) }).kind).toBe("incomplete");
    expect(readingOf({ scorer: "apm-score-v11", signals: [{ id: "unanalyzed-files" }], coverage: { kind: "complete" } }).kind).toBe("incomplete");
    expect(readingOf({ scorer: "apm-score-v11", signals: [], coverage: partial(["stopped"]) }).kind).toBe("incomplete");
    expect(readingOf({ scorer: "apm-score-v11", signals: [], coverage: partial([]) }).kind).toBe("incomplete");
    expect(readingOf({ scorer: "apm-score-v11", signals: [], coverage: partial(["too-large", "new-reason"]) }).kind).toBe("incomplete");
    expect(readingOf({ scorer: "apm-score-v11", signals: [], coverage: partial("over-budget") }).kind).toBe("incomplete");
    expect(readingOf({ scorer: "apm-score-v11", signals: [], coverage: null }).kind).toBe("incomplete");
    expect(readingOf({ scorer: "apm-score-v10", signals: [], coverage: partial(["over-budget"]) }).kind).toBe("incomplete");
    expect(readingOf({ scorer: null, signals: [], coverage: partial(["over-budget"]) }).kind).toBe("incomplete");
    // apm-score-v12 states coverage as v11 does: this build reads it before any registry writes it
    expect(readingOf({ scorer: "apm-score-v12", signals: [], coverage: partial(["over-budget"]) })).toEqual({ kind: "partial", omittedFiles: 2, omittedBytes: 9 });
    expect(readingOf({ scorer: "apm-score-v12", signals: [], coverage: null }).kind).toBe("incomplete");
  });

  test("isRisky: any risk signal that cost points, or a score under the floor", () => {
    for (const id of RISK_SIGNALS) expect(isRisky({ score: 95, signals: [{ id, points: -5 }], scorer: "apm-score-v10" }, AS_VERSION)).toBe(true);
    // shown but not scored, or a capability: not a risk
    expect(isRisky({ score: 100, signals: [{ id: "obfuscated", points: 0 }], scorer: "apm-score-v10" }, AS_VERSION)).toBe(false);

    for (const id of ["install-script", "install-shell", "install-eval", "new-publisher", "new-dependency", "credential-mention", "encoded-data", "undeclared-capability", "deprecated"]) expect(isRisky({ score: 80, signals: [{ id, points: -15 }], scorer: "apm-score-v10" }, AS_VERSION)).toBe(false);
    // no add-back for what apm could not read: an incomplete analysis holds on its own (readingOf), and its score counts
    expect(isRisky({ score: 39, signals: [{ id: "incomplete", points: -61 }], scorer: "apm-score-v10" }, AS_VERSION)).toBe(true);
    expect(isRisky({ score: 35, signals: [{ id: "risky-dependency", points: -30 }, { id: "new-publisher", points: -10 }, { id: "deprecated", points: -5 }, { id: "credential-mention", points: -10 }, { id: "new-dependency", points: -5 }, { id: "undeclared-capability", points: -5 }], scorer: "apm-score-v10" }, AS_VERSION)).toBe(true);
  });

  // review of 307521b, P2: the blanket dependency exemption let any look-alike dependency through; only an audited name
  test("a look-alike name counts in a dependency too, except an established one (safer-buffer)", () => {
    const signals = [{ id: "typosquat", points: -20 }];
    const scored = { score: 80, signals, scorer: "apm-score-v10" };

    expect(isRisky(scored, AS_VERSION)).toBe(true);
    expect(isRisky(scored, { kind: "dependency", name: "safer-buffer" })).toBe(false);
    expect(isRisky(scored, { kind: "dependency", name: "lodahs" })).toBe(true);
    // asked for by name, safer-buffer's look-alike signal counts: the agent picked it
    expect(isRisky({ ...scored, signals }, AS_VERSION)).toBe(true);
    expect(isRisky({ score: 60, signals: [...signals, { id: "remote-shell", points: -50 }], scorer: "apm-score-v10" }, { kind: "dependency", name: "safer-buffer" })).toBe(true);
  });

  test("GAP_SIGNALS are apm's own gaps, never a risk signal", () => {
    const risks: readonly string[] = [...RISK_SIGNALS, ...LEGACY_RISK_SIGNALS];

    for (const id of GAP_SIGNALS) expect(risks.includes(id)).toBe(false);
  });
});

describe("an older version past the cooldown", () => {
  test("olderRange keeps a tag's channel and adds the bound to every alternative of a range", () => {
    expect(olderRange("latest", "4.13.19")).toBe("<4.13.19");
    expect(olderRange("next", "2.0.0-beta.3")).toBe("<2.0.0-beta.3");
    expect(olderRange("^4", "4.2.0")).toBe("^4 <4.2.0");
    expect(olderRange("^3 || ^4.1", "4.2.0")).toBe("^3 <4.2.0 || ^4.1 <4.2.0");
    expect(olderRange("1.2.3", "1.2.3")).toBe("1.2.3 <1.2.3");
    expect(olderRange("x", "1.0.0")).toBe("x <1.0.0");
    expect(olderRange("v1", "1.4.0")).toBe("v1 <1.4.0");
    expect(olderRange("*", "1.0.0")).toBe("* <1.0.0");
  });

  const fresh = (version: string): ResolveOutcome => ok(100, { version, deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] }, warnings: [{ name: "hono", version, kind: "cooldown", text: "published 2 hours ago, inside apm's 24-hour cooldown", via: [] }], risks: [] } });

  // review of abcbb18, P2: "1.0.0 - 2.0.0 <2.0.0" is no range node-semver reads, so an older 1.9.0 was never found
  test("a hyphen range becomes a comparator set before the bound is added, and the registry's semver reads it", () => {
    expect(olderRange("1.0.0 - 2.0.0", "2.0.0")).toBe(">=1.0.0 <=2.0.0 <2.0.0");
    expect(satisfies("1.9.0", olderRange("1.0.0 - 2.0.0", "2.0.0"))).toBe(true);
    expect(satisfies("2.0.0", olderRange("1.0.0 - 2.0.0", "2.0.0"))).toBe(false);
    expect(olderRange("^1 || 2.0.0 - 2.5.0", "2.5.0")).toBe("^1 <2.5.0 || >=2.0.0 <=2.5.0 <2.5.0");
    expect(satisfies("2.4.0", olderRange("^1 || 2.0.0 - 2.5.0", "2.5.0"))).toBe(true);
  });

  test("a fresh pick in a hyphen range falls back to the older version the registry finds", async () => {
    const versions = ["1.9.0", "2.0.0"];

    const source = fakeSource({
      resolve: (_n, range) => {
        const v = versions.filter((x) => satisfies(x, range)).at(-1);

        return v === "2.0.0" ? fresh("2.0.0") : v === undefined ? { kind: "refused", reason: "none", newest: null, skipped: [], confirmed: [] } : ok(100, { version: v });
      },
      reviews: { "hono@1.9.0": REVIEW_CLEAN },
    });

    const v = await explainFor({ name: "hono", range: "1.0.0 - 2.0.0", source });

    expect(v.verdict).toBe("install");
    expect(v.version).toBe("1.9.0");
  });

  test("a picked version inside the cooldown is swapped for the newest older one past it, which installs, and the review read is the older one's", async () => {
    const source = fakeSource({ resolve: (_n, range) => (range === "latest" ? fresh("4.13.19") : range === "<4.13.19" ? ok(100, { version: "4.13.18" }) : { kind: "missing", reason: "no" }), reviews: { "hono@4.13.18": REVIEW_CLEAN } });
    const v = await explainFor({ name: "hono", range: null, source });

    expect(source.calls).toEqual(["resolve hono@latest", "package hono", "resolve hono@<4.13.19", "review hono@4.13.18"]);
    expect(v.verdict).toBe("install");
    expect(v.version).toBe("4.13.18");
    expect(v.commands?.npm).toBe("npm install hono@4.13.18");
    expect(v.notes[0]?.kind).toBe("older-version");
    expect(v.notes[0]?.text).toContain("`hono@4.13.19: published 2 hours ago, inside apm's 24-hour cooldown`");
    expect(v.summary).toContain("it is not the newest version: that one is inside apm's 24-hour cooldown");
  });

  test("a range is narrowed, never widened: ^4 asks for ^4 below the fresh version", async () => {
    const source = fakeSource({ resolve: (_n, range) => (range === "^4" ? fresh("4.2.0") : ok(100, { version: "4.1.9" })), reviews: { "hono@4.1.9": REVIEW_CLEAN } });
    const v = await explainFor({ name: "hono", range: "^4", source });

    expect(source.calls[2]).toBe("resolve hono@^4 <4.2.0");
    expect(v.version).toBe("4.1.9");
  });

  test("no older version in range keeps the fresh one, review-first: the cooldown is the defence against a fresh release", async () => {
    const source = fakeSource({ resolve: (_n, range) => (range === "latest" ? fresh("1.0.0") : { kind: "refused", reason: "No version of hono matching <1.0.0 passes the policy.", newest: null, skipped: [], confirmed: [] }), reviews: { "hono@1.0.0": REVIEW_CLEAN } });
    const v = await explainFor({ name: "hono", range: null, source });

    expect(v.verdict).toBe("review-first");
    expect(v.version).toBe("1.0.0");
    expect(v.summary).toContain("no older version in range is past it");
  });

  test("a burst of fresh releases: after MAX_OLDER_LOOKUPS more it gives up on the newest, review-first", async () => {
    let n = 9;
    const source = fakeSource({ resolve: () => fresh(`1.0.${n--}`), reviews: { "hono@1.0.9": REVIEW_CLEAN } });
    const v = await explainFor({ name: "hono", range: null, source });

    expect(source.calls.filter((c) => c.startsWith("resolve"))).toHaveLength(MAX_OLDER_LOOKUPS + 1);
    expect(v.verdict).toBe("review-first");
    expect(v.version).toBe("1.0.9");
    expect(v.summary).toContain(`it and the ${MAX_OLDER_LOOKUPS} versions before it in range were all published inside apm's 24-hour cooldown`);
  });

  // launch audit 2026-11-18: ai, openai and electron-to-chromium publish several versions a day, and stepping back one
  // version a lookup gave up after three with an older version past the cooldown in range
  const NOW = Date.UTC(2026, 10, 18, 17);
  const HOUR = 60 * 60 * 1000;
  const listed = (hoursAgo: Record<string, number>) => Object.entries(hoursAgo).map(([version, h]) => ({ version, publishedAt: new Date(NOW - h * HOUR).toISOString(), publishedBy: "a", status: "active", statusReason: null, deprecated: null, score: 100, grade: "A" }));

  test("a burst of releases inside the cooldown: one lookup below the whole run finds the version past it", async () => {
    // ai@7.0.176: 7.0.174 to 7.0.176 inside the cooldown, 7.0.173 115 hours old
    const versions = listed({ "7.0.176": 2, "7.0.175": 9, "7.0.174": 20, "7.0.173": 115, "7.0.172": 200 });
    const all = versions.map((v) => v.version);
    const ages = new Map(versions.map((v) => [v.version, Date.parse(v.publishedAt)]));

    const source = fakeSource({
      packages: { ai: pkg({ name: "ai", latest: "7.0.176", versions }) },
      resolve: (_n, range) => {
        const v = range === "latest" ? "7.0.176" : all.filter((x) => satisfies(x, range)).toSorted(newestFirst)[0];

        if (v === undefined) return { kind: "refused", reason: "none", newest: null, skipped: [], confirmed: [] };

        return NOW - (ages.get(v) ?? 0) < COOLDOWN_MS ? fresh(v) : ok(100, { version: v });
      },
      reviews: { "ai@7.0.173": REVIEW_CLEAN },
    });

    // the test's own clock: the ages above are relative to NOW, not to when the suite runs
    const v = await explainFor({ name: "ai", range: null, source, now: NOW });

    expect(source.calls).toEqual(["resolve ai@latest", "package ai", "resolve ai@<7.0.174", "review ai@7.0.173"]);
    expect(v.verdict).toBe("install");
    expect(v.version).toBe("7.0.173");
  });

  test("belowFreshRun: the lowest fresh version under the pick by number, stopping at the first one past the cooldown", () => {
    const versions = listed({ "2.0.0": 1, "2.0.0-rc.2": 3, "1.10.0": 5, "1.9.1": 6, "1.9.0": 30, "1.2.0": 2 });

    expect(belowFreshRun({ version: "2.0.0", listed: versions, now: NOW })).toBe("1.9.1");
    // a version the list does not have: ask below it, as before
    expect(belowFreshRun({ version: "3.0.0", listed: versions, now: NOW })).toBe("3.0.0");
    // a time the list does not give stops the run
    expect(belowFreshRun({ version: "2.0.0", listed: [...versions.filter((x) => x.version !== "1.10.0"), { ...versions[0], version: "1.10.0", publishedAt: "" }].map((x) => ({ version: x.version, publishedAt: x.publishedAt })), now: NOW })).toBe("2.0.0-rc.2");
    // its order is semver's, as the registry's
    const numbers = ["1.0.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "0.9.10", "0.10.0", "10.0.0"];
    const run = (top: string, old: string | null = null) => belowFreshRun({ version: top, listed: numbers.map((version) => ({ version, publishedAt: new Date(version === old ? NOW - 2 * COOLDOWN_MS : NOW).toISOString() })), now: NOW });

    expect([...numbers].toSorted(newestFirst).at(-1)).toBe("0.9.10");
    expect(run("10.0.0")).toBe("0.9.10");
    // 1.0.0 > rc.1 > beta.11 > beta.2 > alpha.beta: the run stops above the one past the cooldown
    expect(run("1.0.0", "1.0.0-alpha.beta")).toBe("1.0.0-beta.2");
    expect(run("1.0.0", "1.0.0-beta.2")).toBe("1.0.0-beta.11");
  });

  test("an older lookup the registry does not answer is unknown, never the fresh version as an install", async () => {
    const source = fakeSource({ resolve: (_n, range) => (range === "latest" ? fresh("1.0.0") : { kind: "unavailable" }) });
    const v = await explainFor({ name: "hono", range: null, source, now: NOW });

    expect(v.verdict).toBe("unknown");
    expect(v.commands).toBeNull();
  });

  test("a version past the cooldown is not looked at twice", async () => {
    const source = fakeSource({ resolve: () => ok(100), reviews: { "zod@1.3.0": REVIEW_CLEAN } });

    await explainFor({ name: "zod", range: null, source });
    expect(source.calls).toEqual(["resolve zod@latest", "review zod@1.3.0"]);
  });
});

test("the rendered verdict lists the notes and says the install goes ahead", () => {
  const text = verdictText(explainInstall({ name: "zod", range: null, resolve: ok(92), review: { kind: "queued" } }));

  expect(text).toContain("Verdict: install");
  expect(text).toContain("Notes (install anyway, then tell the person):\n- The AI review of this version is queued and has not started.");
  expect(text).toContain("Run: apm add zod@1.3.0");
});

// an install verdict for lodash@4.17.20 (known CVEs) said it passes apm's checks and listed nothing about CVEs
test("every verdict says known vulnerabilities are not checked, and where to find them", () => {
  const install = explainInstall({ name: "zod", range: null, resolve: ok(92), review: { kind: "queued" } });
  const missing = explainInstall({ name: "zod", range: null, resolve: { kind: "missing", reason: "no such package" }, review: { kind: "unreadable" } });

  expect(KNOWN_VULNERABILITIES).toMatch(/published security advisories/);
  expect(KNOWN_VULNERABILITIES).toMatch(/apm audit or npm audit lists the advisories for what is installed/);
  expect(install.notChecked).toEqual([KNOWN_VULNERABILITIES]);
  expect(missing.notChecked).toEqual([KNOWN_VULNERABILITIES]);
  expect(verdictText(install)).toContain(`Not checked:\n- ${KNOWN_VULNERABILITIES}`);
});

describe("parsePackageSpec", () => {
  test("splits name and range, scoped names included", () => {
    expect(parsePackageSpec("zod")).toEqual({ name: "zod", range: null });
    expect(parsePackageSpec("zod@^4")).toEqual({ name: "zod", range: "^4" });
    expect(parsePackageSpec("@scope/Name@1.2.3")).toEqual({ name: "@scope/Name", range: "1.2.3" });
    expect(parsePackageSpec("@scope/name")).toEqual({ name: "@scope/name", range: null });
    expect(parsePackageSpec("")).toBeNull();
    expect(parsePackageSpec("../etc")).toBeNull();
  });

  // npm names are case-sensitive: JSONStream (1.3.5) and jsonstream (1.0.3) are two packages
  test("keeps the name's case, so a legacy mixed-case name is the package asked for", () => {
    expect(parsePackageSpec("JSONStream")).toEqual({ name: "JSONStream", range: null });
    expect(parsePackageSpec("JSONStream@^1.3")).toEqual({ name: "JSONStream", range: "^1.3" });
    expect(parsePackageSpec("JSON Stream")).toBeNull();
  });

  // the Kelvin sign lowercases to an ASCII k: a name is checked as given, in ASCII, never in a folded form
  test("a non-ASCII character that lowercases to ASCII is not a name", () => {
    expect(parsePackageSpec("\u212Aelvin")).toBeNull();
    expect(parsePackageSpec("@\u212A/x")).toBeNull();
    expect(parsePackageSpec("@Scope/X@1.2.3")).toEqual({ name: "@Scope/X", range: "1.2.3" });
  });
});

// review of a76b9fc, finding 4: the rendered verdict (explain_install, /api/explain's text) names the evidence and the page
test("the rendered verdict lists the evidence, quoted, and the version's page", () => {
  const c = CASES.find((x) => x.name.startsWith("a score under the floor names its evidence"));

  if (!c) throw new Error("missing the finding-4 case");
  const text = verdictText(explainInstall({ name: "x", range: null, resolve: resolveOf(c.resolve), review: reviewOf(c.review) }));

  expect(text).toContain("Evidence:\n- `Runs code built at runtime: index.js:7: eval(body)`");
  expect(text).toContain("Details: https://apmjs.dev/package/x?v=1.0.0");
});
