// Review of cd74781, findings 3 and 4: an npm outage is not "no packages match", and screen readers hear loading,
// failures and partial answers, not only counts.
import { describe, expect, mock, test } from "bun:test";

// a module mock holds for every later test file in the process, so it carries every hook the app imports
// (search-fallback.test.tsx says why)
void mock.module("next/navigation", () => ({
  usePathname: () => "/package/next",
  useRouter: () => ({ push: () => undefined, replace: () => undefined, prefetch: () => undefined }),
  useParams: () => ({}),
  useSearchParams: () => new URLSearchParams(),
}));

const { announcement, noteText } = await import("@/components/search-bar");

const ok = (upstreamFailed: boolean) => ({ kind: "ok" as const, answer: { query: "lodash", hits: [], total: 0, upstreamFailed } });

describe("the dropdown's note", () => {
  test("an npm outage with no hits says npm didn't answer, not that nothing matches", () => {
    expect(noteText({ done: ok(true), q: "lodash", hasHits: false })).toBe("npm search didn't answer.");
  });

  test("an npm outage with apm's own hits says the list is apm's only", () => {
    expect(noteText({ done: ok(true), q: "lodash", hasHits: true })).toBe("npm search didn't answer; showing packages published on apm only.");
  });

  test("a real empty answer says nothing matches; a full answer with hits says nothing", () => {
    expect(noteText({ done: ok(false), q: "lodash", hasHits: false })).toBe("No packages match lodash.");
    expect(noteText({ done: ok(false), q: "lodash", hasHits: true })).toBeNull();
  });

  test("a failed request says so", () => {
    expect(noteText({ done: { kind: "error" }, q: "lodash", hasHits: false })).toBe("Search didn't answer.");
  });
});

describe("what screen readers hear", () => {
  test("loading, failure, an outage and a count", () => {
    expect(announcement({ done: null, pending: true, q: "lodash", count: 0 })).toBe("Searching");
    expect(announcement({ done: { kind: "error" }, pending: false, q: "lodash", count: 0 })).toBe("Search didn't answer. Try again.");
    expect(announcement({ done: ok(true), pending: false, q: "lodash", count: 0 })).toBe("npm search didn't answer. 0 packages for lodash published on apm.");
    expect(announcement({ done: ok(false), pending: false, q: "lodash", count: 1 })).toBe("1 package for lodash");
  });
});
