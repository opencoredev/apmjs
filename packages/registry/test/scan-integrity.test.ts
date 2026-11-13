// Review of a2227d1, finding 13: the integrity check apm add relies on is the scan's (integrityDiffers). A hash list
// in another order, or a lockfile holding only another algorithm, is not a mismatch; other bytes under the same
// algorithm are. A lockfile entry with no integrity is never called a mismatch here: the CLI warns about it instead.
import { describe, expect, test } from "bun:test";
import { integrityDiffers } from "../src/apm.ts";

describe("integrityDiffers", () => {
  const stored = "sha512-AAAA sha1-BBBB";

  test("the same hashes in another order are the same bytes", () => {
    expect(integrityDiffers("sha1-BBBB sha512-AAAA", stored)).toBe(false);
  });

  test("a hash of another algorithm only cannot be compared, so it is not a mismatch", () => {
    expect(integrityDiffers("sha256-CCCC", stored)).toBe(false);
  });

  test("other bytes under a shared algorithm are a mismatch", () => {
    expect(integrityDiffers("sha512-ZZZZ", stored)).toBe(true);
  });

  test("no integrity sent, or none stored, is not a mismatch", () => {
    expect(integrityDiffers(undefined, stored)).toBe(false);
    expect(integrityDiffers("sha512-AAAA", "")).toBe(false);
  });
});
