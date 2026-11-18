// Launch QA finding: react's package page said "200 total" for a package with over 3,000 versions, because the
// package answer lists only the newest 200. A full list now says "newest".
import { describe, expect, test } from "bun:test";
import { LISTED_VERSIONS, showAllLabel, versionCountLabel } from "./version-count";

describe("the version count on the package page", () => {
  test("a list shorter than the registry's limit is the whole history", () => {
    expect(versionCountLabel(117)).toBe("117 total");
    expect(showAllLabel(117)).toBe("Show all 117 versions");
  });

  test("a list at the limit says newest, since older versions may be left out", () => {
    expect(versionCountLabel(LISTED_VERSIONS)).toBe("newest 200");
    expect(showAllLabel(LISTED_VERSIONS)).toBe("Show the newest 200 versions");
  });
});
