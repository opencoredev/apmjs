import { describe, expect, test } from "bun:test";
import { headerNotice, PUBLIC_STATES, type PublicReview, type PublicState } from "./review-schema";

function review(state: PublicState): PublicReview {
  return {
    state,
    model: "morph-dsv41flash-1017",
    reviewedAt: "2026-11-12T12:51:23.759Z",
    coverage: { mode: "diff", previousVersion: "4.18.0", filesInScope: 8, filesRead: 8 },
    read: ["package.json"],
    notRead: [],
    findings: [],
    decidedAt: null,
    note: null,
  };
}

describe("header notice for the AI review", () => {
  test("an open flag is shown before the install command, as a warning", () => {
    expect(headerNotice(review("under-review"))).toEqual({ tone: "warn", text: "AI review flagged this version, pending confirmation" });
  });

  test("a confirmed flag is shown as malicious", () => {
    expect(headerNotice(review("confirmed"))).toEqual({ tone: "bad", text: "Confirmed malicious by apm reviewers" });
  });

  test("clean, cleared and unanswered reviews add nothing to the header", () => {
    for (const state of ["found-nothing", "cleared", "no-answer"] as const) expect(headerNotice(review(state))).toBeNull();
  });

  test("every public state is handled", () => {
    for (const state of PUBLIC_STATES) expect(() => headerNotice(review(state))).not.toThrow();
  });
});

describe("headline for a partial AI review", () => {
  test("a review that read only some files says so", async () => {
    const { headline } = await import("./review-schema");
    const r: PublicReview = { state: "found-nothing", model: "m", reviewedAt: "2026-11-12T00:00:00Z", coverage: { mode: "diff", previousVersion: "8.3.7", filesInScope: 3, filesRead: 1 }, read: [], notRead: [], findings: [], decidedAt: null, note: null };

    expect(headline(r)).toBe("Partial AI review: no findings in the 1 of 3 files it read");
  });

  test("a full read keeps the plain headline", async () => {
    const { headline } = await import("./review-schema");
    const r: PublicReview = { state: "found-nothing", model: "m", reviewedAt: "2026-11-12T00:00:00Z", coverage: { mode: "diff", previousVersion: "4.6.6", filesInScope: 4, filesRead: 4 }, read: [], notRead: [], findings: [], decidedAt: null, note: null };

    expect(headline(r)).toBe("AI review found nothing in the change from 4.6.6");
  });
});
