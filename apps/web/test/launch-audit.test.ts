// Launch-audit check (Web explain verdict behavior for nonexistent version ranges).
import { describe, expect, test } from "bun:test";
import { explainInstall } from "../lib/agent/verdict";

describe("launch audit: web explain verdict", () => {
  test("P1: nonexistent version range returns not-found (not review-first) on web /api/explain", () => {
    const v = explainInstall({
      name: "zod",
      range: "99.99.99",
      resolve: {
        kind: "refused",
        reason: "No version of zod matching 99.99.99 passes the policy.",
        skipped: [],
        newest: null,
        confirmed: [],
      },
      review: { kind: "not-reviewed" },
    });

    expect(v.verdict).toBe("not-found");
  });
});
