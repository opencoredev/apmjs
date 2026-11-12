// The install verdict: the registry's policy answer and the AI reviews in, one word and its reasons out. The cases in
// tests/fixtures/explain-verdicts.json run here and in packages/cli/test/explain.test.ts, so both copies agree.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import cases from "../../../../tests/fixtures/explain-verdicts.json";
import { explainFor, parsePackageSpec } from "./explain";
import { parseResolve, type ResolveOutcome } from "./source";
import { fakeSource, NETWORK, REVIEW_CLEAN, signal } from "./testing";
import { explainInstall, reviewInput, VERDICTS, verdictText, type ReviewInput } from "./verdict";

// ---------- the shared cases ----------

const DepRef = z.object({ name: z.string(), version: z.string() });

const Case = z.object({
  name: z.string(),
  resolve: z.discriminatedUnion("kind", [
    z.object({
      kind: z.literal("ok"),
      version: z.string(),
      score: z.number().nullable(),
      lost: z.array(z.object({ label: z.string(), points: z.number() })),
      skipped: z.array(z.object({ version: z.string(), reason: z.string() })),
      unchecked: z.number(),
      uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })),
      depReviews: z.discriminatedUnion("kind", [
        z.object({ kind: z.literal("off") }),
        z.object({ kind: z.literal("unknown") }),
        z.object({ kind: z.literal("on"), confirmed: z.array(DepRef), underReview: z.array(DepRef), pending: z.array(DepRef), noAnswer: z.array(DepRef) }),
      ]),
    }),
    z.object({ kind: z.literal("refused"), reason: z.string(), newest: z.string().nullable(), skipped: z.array(z.object({ version: z.string(), reason: z.string() })) }),
    z.object({ kind: z.literal("missing"), reason: z.string() }),
    z.object({ kind: z.literal("unavailable") }),
  ]),
  review: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("reviewed"), state: z.enum(["found-nothing", "under-review", "no-answer", "confirmed", "cleared"]), findings: z.number() }),
    z.object({ kind: z.enum(["queued", "leased", "failed", "not-reviewed", "off", "unreadable"]) }),
  ]),
  expect: z.object({ verdict: z.enum(VERDICTS), commands: z.boolean(), summary: z.string(), reasons: z.array(z.string()).optional() }),
});

export const CASES = z.object({ cases: z.array(Case).min(20) }).parse(cases).cases;

const grade = (score: number): string => (score >= 90 ? "A" : score >= 75 ? "B" : "C");

function resolveOf(c: z.infer<typeof Case>["resolve"]): ResolveOutcome {
  switch (c.kind) {
    case "ok":
      return {
        kind: "ok",
        version: c.version,
        source: "upstream",
        report: c.score === null ? null : { score: c.score, grade: grade(c.score), signals: c.lost.map((l, i) => signal({ id: `s${i}`, label: l.label, points: l.points })), notChecked: [] },
        skipped: c.skipped,
        deps: { unchecked: c.unchecked, uncheckedDeps: c.uncheckedDeps, reviews: c.depReviews },
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
      const review: ReviewInput = c.review;
      const v = explainInstall({ name: "x", range: null, resolve: resolveOf(c.resolve), review });

      expect(v.verdict).toBe(c.expect.verdict);
      expect(v.summary).toBe(c.expect.summary);
      expect(v.commands !== null).toBe(c.expect.commands);

      for (const r of c.expect.reasons ?? []) expect(v.reasons).toContain(r);
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
      expect(["queued", "leased", "failed", "unreadable"]).not.toContain(c.review.kind);
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
  deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] } },
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
    expect(parseResolve(422, { error: "too new", name: "zod", version: null, skipped: [], newest: { version: "5.0.0", report: {} } })).toEqual({ kind: "refused", reason: "too new", newest: "5.0.0", skipped: [] });
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
