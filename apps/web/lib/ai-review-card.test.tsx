// The AI review card while a requested retry is queued: the older result stays, the card says another review is on
// the way, and it keeps asking. Rendered to HTML with react-dom/server, no browser.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { AiReviewSection } from "@/components/ai-review";
import { FindingList } from "@/components/finding-list";
import { offersRequest, pollStep } from "./review-poll";
import { ReviewAnswer } from "./review-schema";

const noAnswer = ReviewAnswer.parse({
  name: "quiet-lib",
  version: "1.0.1",
  status: "queued",
  review: {
    state: "no-answer",
    model: "fake-flash",
    reviewedAt: "2026-11-12T00:00:00Z",
    coverage: { mode: "files", previousVersion: null, filesInScope: 1, filesRead: 1 },
    read: ["index.js"],
    notRead: [],
    findings: [],
    decidedAt: null,
    note: null,
  },
  redacted: false,
  viewer: "public",
  private: null,
  canRequest: false,
});

describe("a retry queued after a review with no answer", () => {
  test("the card shows the older result and that another review is queued", () => {
    const html = renderToStaticMarkup(<AiReviewSection initial={noAnswer} signInHref="/signin" />);

    expect(html).toContain("AI review gave no answer");
    expect(html).toContain("Queued for another AI review");
    expect(html).not.toContain("Request an AI review");
  });

  test("the card keeps asking while the retry is queued, and stops once it is reviewed", () => {
    expect(pollStep({ status: noAnswer.status, startedAt: 0, now: 1_000 }).kind).toBe("wait");
    expect(offersRequest(noAnswer)).toBe(false);
    expect(pollStep({ status: "reviewed", startedAt: 0, now: 1_000 }).kind).toBe("stop");
  });
});

describe("the findings of a revoked version", () => {
  test("a finding without its line shows the file, line and sentence, and no empty code block", () => {
    const finding = { file: "index.js", line: 2, issue: "Posts process.env to a remote host.", severity: "high" } as const;
    const revoked = renderToStaticMarkup(<FindingList findings={[{ ...finding, excerpt: "" }]} name="x" version="1.0.0" />);
    const shown = renderToStaticMarkup(<FindingList findings={[{ ...finding, excerpt: "https.request(x)" }]} name="x" version="1.0.0" />);

    expect(revoked).toContain("index.js:2");
    expect(revoked).toContain("Posts process.env to a remote host.");
    expect(revoked).not.toContain("<pre");
    expect(shown).toContain("<pre");
  });
});
