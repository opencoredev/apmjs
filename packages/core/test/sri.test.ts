// Review of 2a098b1, findings 1 and 10: one SRI parse and comparison for the registry's scan and the CLI's lockfile
// check. An installer verifies with the strongest algorithm an SRI lists, so a match must cover that one.
import { describe, expect, test } from "bun:test";
import { compareIntegrity, formatSri, integritiesConflict, parseSri, strongestAlgorithm } from "../src/sri.ts";

describe("compareIntegrity", () => {
  test("matched: the installer's algorithm is shared and every shared digest is known", () => {
    expect(compareIntegrity({ sent: "sha512-A sha1-B", known: "sha1-B sha512-A" })).toEqual({ kind: "matched" });
    expect(compareIntegrity({ sent: "sha512-A", known: "sha512-A sha1-B" })).toEqual({ kind: "matched" });
  });

  test("mismatched: any shared algorithm with a digest the other does not list", () => {
    expect(compareIntegrity({ sent: "sha1-B sha512-Z", known: "sha1-B sha512-A" })).toEqual({ kind: "mismatched", algorithm: "sha512" });
    expect(compareIntegrity({ sent: "sha512-A sha512-Z", known: "sha512-A" })).toEqual({ kind: "mismatched", algorithm: "sha512" });
  });

  test("unverified: no algorithm in common, or the strongest sent is unknown to the other side", () => {
    expect(compareIntegrity({ sent: "sha256-C", known: "sha512-A" }).kind).toBe("unverified");
    expect(compareIntegrity({ sent: "sha1-B sha512-Z", known: "sha1-B" }).kind).toBe("unverified");
    expect(compareIntegrity({ sent: "md5-Q", known: "sha512-A" }).kind).toBe("unverified");
  });
});

describe("integritiesConflict", () => {
  test("the same digests in another order are not a conflict (review of 2a098b1, finding 10)", () => {
    expect(integritiesConflict("sha1-B sha512-A", "sha512-A sha1-B")).toBe(false);
  });

  test("an algorithm only one lists is not a conflict; different digests under a shared one are", () => {
    expect(integritiesConflict("sha512-A", "sha512-A sha1-B")).toBe(false);
    expect(integritiesConflict("sha512-A", "sha512-Z")).toBe(true);
  });
});

test("parseSri drops options and unknown algorithms; formatSri is canonical", () => {
  const sri = parseSri("sha1-B?opt sha512-A x-1 nodash");

  expect(strongestAlgorithm(sri)).toBe("sha512");
  expect(formatSri(sri)).toBe("sha512-A sha1-B");
  expect(formatSri(parseSri("sha1-B sha512-A"))).toBe(formatSri(parseSri("sha512-A   sha1-B")));
});
