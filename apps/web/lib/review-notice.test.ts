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
