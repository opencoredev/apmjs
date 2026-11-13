// Review of 2a098b1, finding 1: the scan's integrity check (scanIntegrity, on @apm/core's compareIntegrity) has three
// answers. Hashes listed in another order are the same bytes; other bytes under a shared algorithm are a mismatch,
// refused in every mode; a lockfile hash the registry cannot compare is unverified (a warning, strict refuses it),
// never clean. A lockfile entry with no integrity is not compared here: the CLI warns about it instead.
import { describe, expect, test } from "bun:test";
import { scanIntegrity } from "../src/apm.ts";

describe("scanIntegrity", () => {
  const stored = { integrity: "sha512-AAAA sha1-BBBB", shasum: "" };

  test("the same hashes in another order are the same bytes", () => {
    expect(scanIntegrity("sha1-BBBB sha512-AAAA", stored)?.kind).toBe("matched");
  });

  test("a hash of an algorithm the registry does not know is unverified, not matched (on 2a098b1: not a mismatch, so clean)", () => {
    expect(scanIntegrity("sha256-CCCC", stored)).toEqual({ kind: "unverified", reason: "it lists sha256 and the registry knows sha512, sha1, so the two cannot be compared" });
  });

  test("other bytes under a shared algorithm are a mismatch, even when a weaker shared hash matches (on 2a098b1: the matching sha1 was enough)", () => {
    expect(scanIntegrity("sha512-ZZZZ", stored)?.kind).toBe("mismatched");
    expect(scanIntegrity("sha1-BBBB sha512-ZZZZ", stored)?.kind).toBe("mismatched");
  });

  test("several digests of one algorithm: any one the registry does not serve is a mismatch", () => {
    expect(scanIntegrity("sha512-AAAA sha512-ZZZZ", stored)?.kind).toBe("mismatched");
  });

  test("the registry's shasum is a sha1 it knows", () => {
    const sha1 = `sha1-${Buffer.from("ab".repeat(20), "hex").toString("base64")}`;

    expect(scanIntegrity(sha1, { integrity: "sha512-AAAA", shasum: "ab".repeat(20) })?.kind).toBe("matched");
  });

  test("no integrity sent is not compared; none stored is unverified", () => {
    expect(scanIntegrity(undefined, stored)).toBeNull();
    expect(scanIntegrity("sha512-AAAA", { integrity: "", shasum: "" })?.kind).toBe("unverified");
  });
});
