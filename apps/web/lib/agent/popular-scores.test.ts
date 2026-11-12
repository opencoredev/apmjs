// Review finding 11: each popular package's badge read its own score, so a cold isolate made twelve registry requests
// for the home page. Now one request answers every badge.
import { describe, expect, test } from "bun:test";
import { popularScores, type PopularScoresAnswer } from "./popular-scores";
import { POPULAR_PACKAGES } from "./site";

const answer: PopularScoresAnswer = {
  packages: POPULAR_PACKAGES.map((p, i) => (i === 0 ? { name: p.name, version: null, score: null, grade: null } : { name: p.name, version: "1.0.0", score: 80 + i, grade: "B" })),
};

describe("popularScores", () => {
  test("every badge on a cold isolate shares one registry request", async () => {
    let loads = 0;

    const popular = popularScores({
      load: async () => {
        loads++;
        await Bun.sleep(5);

        return { kind: "ok", value: answer };
      },
      ttlMs: 60_000,
      missTtlMs: 1_000,
    });

    const scores = await Promise.all(POPULAR_PACKAGES.map((p) => popular.score(p.name, 0)));

    expect(POPULAR_PACKAGES.length).toBeGreaterThanOrEqual(12);
    expect(loads).toBe(1);
    // a package apm has not scored yet has no badge; the rest have theirs
    expect(scores[0]).toBeNull();
    expect(scores[1]).toEqual({ version: "1.0.0", score: 81, grade: "B" });
    // fresh: no more requests
    await Promise.all(POPULAR_PACKAGES.map((p) => popular.score(p.name, 30_000)));
    expect(loads).toBe(1);
    // stale: one more
    await Promise.all(POPULAR_PACKAGES.map((p) => popular.score(p.name, 61_000)));
    expect(loads).toBe(2);
  });

  test("a failed read is remembered briefly, then tried again", async () => {
    let loads = 0;

    const popular = popularScores({
      load: async () => {
        loads++;

        return { kind: "unavailable", reason: { kind: "timeout" } };
      },
      ttlMs: 60_000,
      missTtlMs: 1_000,
    });

    expect(await popular.score("react", 0)).toBeNull();
    expect(await popular.score("next", 500)).toBeNull();
    expect(loads).toBe(1);
    await popular.score("react", 1_500);
    expect(loads).toBe(2);
  });
});
