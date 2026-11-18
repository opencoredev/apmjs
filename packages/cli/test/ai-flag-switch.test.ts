// `apm explain` under apm's "AI flags hold installs" switch: an open flag is a hold while the registry says
// under-review, and a note once it says flagged (the switch is off). The website's verdict has the same test
// (apps/web/lib/ai-flag-switch.test.tsx).
import { describe, expect, test } from "bun:test";
import { parseReview } from "../src/agent.ts";
import { explain, type DepReviews, type ResolvedInput } from "../src/explain.ts";

const ok = (reviews: DepReviews): ResolvedInput => ({
  kind: "ok",
  version: "4.18.1",
  report: { score: 100, grade: "A", signals: [], capabilities: [], notChecked: [], scorer: "apm-score-v10" },
  skipped: [],
  deps: { unchecked: 0, uncheckedDeps: [], reviews, warnings: [], risks: [] },
});

const NONE: DepReviews = { kind: "on", confirmed: [], underReview: [], pending: [], noAnswer: [] };

const answer = (state: string) =>
  parseReview({ status: 200, body: { name: "lodash", version: "4.18.1", status: "reviewed", job: "done", versionStatus: "active", redacted: false, review: { state, findings: [] } } });

describe("apm explain and the switch", () => {
  test("the registry's under-review holds; its flagged is an install with a note", () => {
    expect(explain({ name: "lodash", range: null, resolved: ok(NONE), review: answer("under-review") }).verdict).toBe("review-first");
    const off = explain({ name: "lodash", range: null, resolved: ok(NONE), review: answer("flagged") });

    expect(off.verdict).toBe("install");
    expect(off.notes.map((n) => n.kind)).toContain("ai-review-flagged");
  });

  test("a dependency in flagged is a note; in underReview a hold; confirmed is refused either way", () => {
    const clean = answer("found-nothing");
    const lodash = [{ name: "lodash", version: "4.18.1" }];

    expect(explain({ name: "knex", range: null, resolved: ok({ kind: "on", confirmed: [], underReview: lodash, pending: [], noAnswer: [] }), review: clean }).verdict).toBe("review-first");
    expect(explain({ name: "knex", range: null, resolved: ok({ kind: "on", confirmed: [], underReview: [], flagged: lodash, pending: [], noAnswer: [] }), review: clean }).verdict).toBe("install");
    expect(explain({ name: "knex", range: null, resolved: ok({ kind: "on", confirmed: [{ name: "evil", version: "1.0.0" }], underReview: [], flagged: lodash, pending: [], noAnswer: [] }), review: clean }).verdict).toBe("do-not-install");
    expect(explain({ name: "evil", range: null, resolved: ok(NONE), review: answer("confirmed") }).verdict).toBe("do-not-install");
  });
});
