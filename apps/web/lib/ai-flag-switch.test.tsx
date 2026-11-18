// "AI flags hold installs" as the website's verdict reads it, the review queue's pure rules, and what reaches the HTML:
// a quoted key never does, on a package page or in a finding list, even from a registry that did not mask it.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { AiReviewSection } from "@/components/ai-review";
import { FindingList } from "@/components/finding-list";
import { explainInstall } from "./agent/verdict";
import type { ResolveOutcome } from "./agent/source";
import { moveFocus, Queue, verdictOf, windowLeft } from "./review-queue";
import { ReviewAnswer } from "./review-schema";

const ok = (reviews: Extract<ResolveOutcome, { kind: "ok" }>["deps"]["reviews"]): ResolveOutcome => ({
  kind: "ok",
  version: "4.18.1",
  source: "upstream",
  report: { score: 100, grade: "A", signals: [], notChecked: [], scorer: "apm-score-v10" },
  skipped: [],
  deps: { unchecked: 0, uncheckedDeps: [], reviews, warnings: [], risks: [] },
});

const NONE = { kind: "on" as const, confirmed: [], underReview: [], pending: [], noAnswer: [] };
const LODASH = [{ name: "lodash", version: "4.18.1" }];

describe("the off switch, as the verdict reads it", () => {
  test("an open flag holds while the switch is on (under-review) and is a note while it is off (flagged)", () => {
    const held = explainInstall({ name: "lodash", range: null, resolve: ok(NONE), review: { kind: "reviewed", state: "under-review", findings: 0 } });
    const off = explainInstall({ name: "lodash", range: null, resolve: ok(NONE), review: { kind: "reviewed", state: "flagged", findings: 0 } });

    expect(held.verdict).toBe("review-first");
    expect(off.verdict).toBe("install");
    expect(off.notes.map((n) => n.kind)).toContain("ai-review-flagged");
    expect(off.notes.find((n) => n.kind === "ai-review-flagged")?.text).toContain("a person at apm has not looked yet");
  });

  test("a dependency's open flag: a hold in underReview, a note in flagged", () => {
    const review = { kind: "reviewed" as const, state: "found-nothing" as const, findings: 0 };

    expect(explainInstall({ name: "sequelize", range: null, resolve: ok({ ...NONE, underReview: LODASH }), review }).verdict).toBe("review-first");
    const off = explainInstall({ name: "sequelize", range: null, resolve: ok({ ...NONE, flagged: LODASH }), review });

    expect(off.verdict).toBe("install");
    expect(off.notes.some((n) => n.kind === "dependency-ai-review" && n.text.includes("lodash@4.18.1"))).toBe(true);
  });

  test("confirmed malicious is refused whatever the switch says", () => {
    const self = explainInstall({ name: "evil", range: null, resolve: ok(NONE), review: { kind: "reviewed", state: "confirmed", findings: 1 } });
    const dep = explainInstall({ name: "app", range: null, resolve: ok({ ...NONE, confirmed: [{ name: "evil", version: "1.0.0" }], flagged: LODASH }), review: { kind: "reviewed", state: "found-nothing", findings: 0 } });

    expect(self.verdict).toBe("do-not-install");
    expect(dep.verdict).toBe("do-not-install");
  });
});

describe("the review queue's rules", () => {
  test("j/k and the arrows move one row, clamped; Home and End jump", () => {
    expect(moveFocus({ key: "j", at: -1, count: 3 })).toBe(0);
    expect(moveFocus({ key: "j", at: 2, count: 3 })).toBe(2);
    expect(moveFocus({ key: "ArrowUp", at: 1, count: 3 })).toBe(0);
    expect(moveFocus({ key: "k", at: 0, count: 3 })).toBe(0);
    expect(moveFocus({ key: "End", at: 0, count: 3 })).toBe(2);
    expect(moveFocus({ key: "x", at: 0, count: 3 })).toBeNull();
    expect(moveFocus({ key: "j", at: 0, count: 0 })).toBeNull();
  });

  test("the window shows minutes and seconds left, and nothing once it ended", () => {
    const now = Date.parse("2026-11-18T12:00:00Z");

    expect(windowLeft("2026-11-18T12:09:41Z", now)).toBe("9:41");
    expect(windowLeft("2026-11-18T12:00:00Z", now)).toBeNull();
    expect(windowLeft(null, now)).toBeNull();
  });

  test("an older registry's queue still parses, and the chip says what the model said", () => {
    const item = {
      name: "lodash",
      version: "4.18.1",
      digest: "sha512-x",
      reviewedAt: "2026-11-13T00:00:00Z",
      public: { state: "under-review", model: "m", reviewedAt: "2026-11-13T00:00:00Z", coverage: { mode: "diff", previousVersion: "4.18.0", filesInScope: 8, filesRead: 8 }, read: [], notRead: [], findings: [], decidedAt: null, note: null },
      private: { outcome: "flagged", verdict: "suspicious", reason: null, summary: "s", findings: [], humanState: "pending", attempts: [] },
      decidedBy: null,
    };

    const q = Queue.parse({ pending: [item], decided: [], secondStage: null });
    const [first] = q.pending;

    expect(q.flagsHold).toBeNull();
    expect(first?.weeklyDownloads).toBeNull();
    expect(first ? verdictOf(first) : null).toEqual({ label: "suspicious", tone: "warn" });
  });
});

// built at run time so no secret-shaped literal sits in the repository
const KEY = ["sk", "proj", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("-");
const PASSWORD = ["S3cret", "Passw0rd", "42"].join("");

describe("no quoted secret reaches the HTML", () => {
  const findings = [
    { file: "index.js", line: 3, excerpt: `const ai = new OpenAI({ apiKey: "${KEY}" });`, issue: `Ships a live OpenAI key ${KEY}.`, severity: "high" as const },
    { file: "index.js", line: 3, excerpt: `mongoose.connect("mongodb://shop:${PASSWORD}@db.example.invalid/shop")`, issue: "Connects with a password.", severity: "medium" as const },
  ];

  test("a finding list masks keys and passwords, and keeps two findings on one line apart", () => {
    const html = renderToStaticMarkup(<FindingList findings={findings} name="shop" version="1.0.0" />);

    expect(html).not.toContain(KEY);
    expect(html).not.toContain(PASSWORD);
    expect(html).toContain(`[redacted, ${KEY.length} chars]`);
    expect(html.match(/<li /g)?.length).toBe(2);
  });

  test("the package page's card shows a maintainer the findings, masked, and links everyone to /reviews", () => {
    const answer = ReviewAnswer.parse({
      name: "shop",
      version: "1.0.0",
      status: "reviewed",
      review: { state: "under-review", model: "m", reviewedAt: "2026-11-13T00:00:00Z", coverage: { mode: "files", previousVersion: null, filesInScope: 1, filesRead: 1 }, read: ["index.js"], notRead: [], findings: [], decidedAt: null, note: null },
      redacted: false,
      viewer: "maintainer",
      private: { outcome: "flagged", verdict: "malicious", reason: null, summary: `Hardcodes ${KEY}.`, findings, humanState: "pending" },
      canRequest: false,
    });

    const html = renderToStaticMarkup(<AiReviewSection initial={answer} signInHref="/signin" />);

    expect(html).toContain("Under review");
    expect(html).toContain('href="/reviews"');
    expect(html).not.toContain(KEY);
    expect(html).not.toContain(PASSWORD);
  });
});
