import { describe, expect, test } from "bun:test";
import { moveActive, normalizeQuery, packageHref, searchHref, submitHref, topHits, TYPEAHEAD_LIMIT } from "./typeahead";
import type { SearchHit } from "./search-schema";

function hit(name: string): SearchHit {
  return { name, version: "1.0.0", description: "", date: null, source: "npm", score: null, weeklyDownloads: null };
}

const names = (hits: readonly SearchHit[]) => hits.map((h) => h.name);

describe("topHits", () => {
  test("keeps npm's order and stops at the limit", () => {
    const hits = ["a", "b", "c", "d", "e", "f", "g", "h"].map(hit);
    expect(names(topHits({ hits, q: "zzz" }))).toEqual(["a", "b", "c", "d", "e", "f"]);
    expect(TYPEAHEAD_LIMIT).toBe(6);
  });

  test("an exact name match comes first, even from past the limit", () => {
    const hits = ["react-dom", "react-is", "preact", "react-router", "@types/react", "react-redux", "react-native", "react"].map(hit);
    expect(names(topHits({ hits, q: "react" }))).toEqual(["react", "react-dom", "react-is", "preact", "react-router", "@types/react"]);
  });

  test("no exact match leaves the order alone", () => {
    const hits = ["email-sdk-js", "email-sdk-core"].map(hit);
    expect(names(topHits({ hits, q: "email-sdk" }))).toEqual(["email-sdk-js", "email-sdk-core"]);
  });
});

describe("moveActive", () => {
  test("down walks the rows and returns to the input after the last", () => {
    expect(moveActive({ active: -1, count: 3, key: "ArrowDown" })).toBe(0);
    expect(moveActive({ active: 1, count: 3, key: "ArrowDown" })).toBe(2);
    expect(moveActive({ active: 2, count: 3, key: "ArrowDown" })).toBe(-1);
  });

  test("up from the input goes to the last row, up from the first goes to the input", () => {
    expect(moveActive({ active: -1, count: 3, key: "ArrowUp" })).toBe(2);
    expect(moveActive({ active: 0, count: 3, key: "ArrowUp" })).toBe(-1);
  });

  test("no rows, nothing to highlight", () => {
    expect(moveActive({ active: -1, count: 0, key: "ArrowDown" })).toBe(-1);
  });
});

describe("submitHref", () => {
  const hits = ["react", "react-dom", "@types/react"].map(hit);

  test("Enter on a highlighted row opens that package", () => {
    expect(submitHref({ q: "react", hits, active: 1 })).toBe("/package/react-dom");
    expect(submitHref({ q: "react", hits, active: 2 })).toBe("/package/@types/react");
  });

  test("Enter with nothing highlighted opens the home page's results for the query", () => {
    expect(submitHref({ q: "  Email-SDK ", hits, active: -1 })).toBe("/?q=email-sdk");
    expect(submitHref({ q: "@scope/pkg", hits: [], active: -1 })).toBe("/?q=%40scope%2Fpkg");
  });

  test("an empty box goes home", () => {
    expect(submitHref({ q: "   ", hits: [], active: -1 })).toBe("/");
  });

  test("a highlight past the list (the list shrank) searches instead", () => {
    expect(submitHref({ q: "react", hits, active: 5 })).toBe("/?q=react");
  });
});

test("hrefs", () => {
  expect(normalizeQuery("  ReAct ")).toBe("react");
  expect(packageHref("next")).toBe("/package/next");
  expect(searchHref("")).toBe("/");
});
