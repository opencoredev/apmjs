import { describe, expect, test } from "bun:test";
import { offersRequest, POLL_EVERY_MS, POLL_FOR_MS, pollStep } from "./review-poll";
import type { ReviewAnswer } from "./review-schema";

const answer = (over: Partial<ReviewAnswer>): ReviewAnswer => ({ name: "x", version: "1.0.0", status: "not-reviewed", review: null, redacted: false, viewer: "public", private: null, canRequest: false, ...over });

describe("pollStep", () => {
  test("a queued review is asked again every 5 seconds", () => {
    expect(pollStep({ status: "queued", startedAt: 0, now: 1_000 })).toEqual({ kind: "wait", ms: POLL_EVERY_MS });
  });

  test("the last wait ends at 3 minutes, then the card gives up", () => {
    expect(pollStep({ status: "queued", startedAt: 0, now: POLL_FOR_MS - 2_000 })).toEqual({ kind: "wait", ms: 2_000 });
    expect(pollStep({ status: "queued", startedAt: 0, now: POLL_FOR_MS })).toEqual({ kind: "stop", reason: "gave-up" });
  });

  test("any other answer stops the polling", () => {
    for (const status of ["reviewed", "failed", "not-reviewed"] as const) expect(pollStep({ status, startedAt: 0, now: 1 })).toEqual({ kind: "stop", reason: "settled" });
  });
});

describe("offersRequest", () => {
  test("offered for a version the automatic review did not take, or that failed", () => {
    expect(offersRequest(answer({ status: "not-reviewed" }))).toBe(true);
    expect(offersRequest(answer({ status: "failed" }))).toBe(true);
  });

  test("not offered while queued or once reviewed with an answer", () => {
    expect(offersRequest(answer({ status: "queued" }))).toBe(false);
    const review = { state: "found-nothing", model: "m", reviewedAt: "2026-11-12T00:00:00Z", coverage: { mode: "files", previousVersion: null, filesInScope: 1, filesRead: 1 }, read: [], notRead: [], findings: [], decidedAt: null, note: null } as const;
    expect(offersRequest(answer({ status: "reviewed", review: { ...review, read: [], notRead: [], findings: [] } }))).toBe(false);
    expect(offersRequest(answer({ status: "reviewed", review: { ...review, state: "no-answer", read: [], notRead: [], findings: [] } }))).toBe(true);
  });
});
