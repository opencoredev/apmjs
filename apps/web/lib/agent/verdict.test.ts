// The install verdict: the registry's policy answer and the AI reviews in, one word and its reasons out. The cases in
// tests/fixtures/explain-verdicts.json run here and in packages/cli/test/explain.test.ts, so both copies agree.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import cases from "../../../../tests/fixtures/explain-verdicts.json";
import { explainFor, parsePackageSpec } from "./explain";
import { parseResolve, type ResolveOutcome } from "./source";
import { fakeSource, NETWORK, REVIEW_CLEAN, signal } from "./testing";
import { ReviewAnswer } from "../review-schema";
import { AI_REVIEW_COVERAGE, DEPENDENCY_COVERAGE, explainInstall, reviewInput, VERDICTS, verdictText, type ReviewInput } from "./verdict";

// ---------- the shared cases ----------

const DepRef = z.object({ name: z.string(), version: z.string() });

const Case = z.object({
  name: z.string(),
  resolve: z.discriminatedUnion("kind", [
    z.object({
      kind: z.literal("ok"),
      version: z.string(),
      score: z.number().nullable(),
      // `id` and `evidence` for a signal the verdict reads by id (incomplete); the rest are s0, s1, …
      lost: z.array(z.object({ label: z.string(), points: z.number(), id: z.string().optional(), evidence: z.array(z.string()).default([]) })),
      skipped: z.array(z.object({ version: z.string(), reason: z.string() })),
      unchecked: z.number(),
      uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })),
      // the registry's warnings on the install (resolve's `warnings`): via empty for the version itself
      warnings: z.array(z.object({ name: z.string(), version: z.string(), kind: z.enum(["low-score", "incomplete", "unscorable", "pending", "unavailable", "unchecked"]), text: z.string(), reasons: z.array(z.string()).optional(), url: z.string().optional(), via: z.array(z.string()) })).default([]),
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
        report: c.score === null ? null : { score: c.score, grade: grade(c.score), signals: c.lost.map((l, i) => signal({ id: l.id ?? `s${i}`, label: l.label, points: l.points, evidence: l.evidence })), notChecked: [] },
        skipped: c.skipped,
        deps: { unchecked: c.unchecked, uncheckedDeps: c.uncheckedDeps, reviews: c.depReviews, warnings: c.warnings },
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

describe("the shared verdict cases (tests/fixtures/explain-verdicts.json)", () => {
  for (const c of CASES) {
    test(c.name, () => {
      const review = reviewOf(c.review);
      const v = explainInstall({ name: "x", range: null, resolve: resolveOf(c.resolve), review });

      expect(v.verdict).toBe(c.expect.verdict);
      expect(v.summary).toBe(c.expect.summary);
      expect(v.commands !== null).toBe(c.expect.commands);

      expect(v.coverage).toEqual(c.expect.coverage);

      for (const r of c.expect.reasons ?? []) expect(v.reasons).toContain(r);

      if (c.expect.evidence !== undefined) expect(v.evidence).toEqual(c.expect.evidence);

      if (c.expect.url !== undefined) expect(v.url).toBe(c.expect.url);
      expect(v.summary).not.toMatch(/\bsafe\b/);
    });
  }

  test("only a version apm read in full, with nothing pending anywhere in its tree, gets install", () => {
    const installs = CASES.filter((c) => c.expect.verdict === "install");

    for (const c of installs) {
      expect(c.resolve.kind).toBe("ok");

      if (c.resolve.kind !== "ok") continue;
      expect(c.resolve.unchecked).toBe(0);
      expect(c.resolve.depReviews.kind === "unknown" || (c.resolve.depReviews.kind === "on" && c.resolve.depReviews.confirmed.length + c.resolve.depReviews.underReview.length + c.resolve.depReviews.pending.length + c.resolve.depReviews.noAnswer.length > 0)).toBe(false);
      expect(["queued", "leased", "failed", "unreadable", "pulled"]).not.toContain(reviewOf(c.review).kind);
    }
  });
});

// ---------- the web copy's own surface ----------

const ok = (score: number, over: Partial<Extract<ResolveOutcome, { kind: "ok" }>> = {}): ResolveOutcome => ({
  kind: "ok",
  version: "1.3.0",
  source: "upstream",
  report: { score, grade: grade(score), signals: score < 100 ? [NETWORK] : [], notChecked: [] },
  skipped: [],
  deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] }, warnings: [] },
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

  test("a queued review is review-first", async () => {
    const source = fakeSource({ resolve: () => clean, reviews: { "zod@1.3.0": { ...REVIEW_CLEAN, status: "queued", job: "queued", review: null } } });

    expect((await explainFor({ name: "zod", range: null, source })).verdict).toBe("review-first");
  });
});

describe("parsePackageSpec", () => {
  test("splits name and range, scoped names included", () => {
    expect(parsePackageSpec("zod")).toEqual({ name: "zod", range: null });
    expect(parsePackageSpec("zod@^4")).toEqual({ name: "zod", range: "^4" });
    expect(parsePackageSpec("@scope/Name@1.2.3")).toEqual({ name: "@scope/name", range: "1.2.3" });
    expect(parsePackageSpec("@scope/name")).toEqual({ name: "@scope/name", range: null });
    expect(parsePackageSpec("")).toBeNull();
    expect(parsePackageSpec("../etc")).toBeNull();
  });
});

// review of a76b9fc, finding 4: the rendered verdict (explain_install, /api/explain's text) names the evidence and the page
test("the rendered verdict lists the evidence, quoted, and the version's page", () => {
  const c = CASES.find((x) => x.name.startsWith("a score under the floor names its evidence"));

  if (!c) throw new Error("missing the finding-4 case");
  const text = verdictText(explainInstall({ name: "x", range: null, resolve: resolveOf(c.resolve), review: reviewOf(c.review) }));

  expect(text).toContain("Evidence:\n- `Runs code built at runtime: index.js:7: eval(body)`");
  expect(text).toContain("Details: https://apmjs.dev/package/x/v/1.0.0");
});
