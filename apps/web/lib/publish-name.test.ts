// The name check's answer for a free name, per visitor (HOME-564 item 6: the home page said "available" for a free name
// under someone else's scope, which only that scope's owner can publish).
import { describe, expect, test } from "bun:test";
import { ownerOnlySentence, publishability, publishabilityText } from "./publish-name";

describe("publishability", () => {
  test("a free name under the visitor's own scope is theirs to publish", () => {
    expect(publishability({ name: "@leo/lib", available: true, scope: "leo" })).toEqual({ kind: "yours", scope: "@leo" });
    expect(publishability({ name: "@leo/lib", available: true, scope: "Leo" })).toEqual({ kind: "yours", scope: "@leo" });
  });

  test("a free name under another scope is its owner's, never the visitor's", () => {
    const p = publishability({ name: "@sindresorhus/h564-probe", available: true, scope: "leo" });

    expect(p).toEqual({ kind: "not-yours", scope: "@sindresorhus", yours: "@leo" });
    expect(publishabilityText({ name: "@sindresorhus/h564-probe", publishable: p })).toBe("@sindresorhus/h564-probe is free, but only the owner of @sindresorhus can publish it. Yours is @leo.");
  });

  test("with no visitor known, a free scoped name is its scope owner's", () => {
    expect(publishability({ name: "@sindresorhus/h564-probe", available: true })).toEqual({ kind: "scoped", scope: "@sindresorhus" });
    expect(ownerOnlySentence("@sindresorhus", null)).toBe("Only the GitHub account sindresorhus can publish under @sindresorhus. Sign in with GitHub to see whether that is you.");
  });

  test("bare and taken names are unchanged", () => {
    expect(publishability({ name: "fresh-name", available: true })).toEqual({ kind: "needs-scope", suggestion: "@you/fresh-name" });
    expect(publishability({ name: "@leo/lib", available: false, scope: "leo" })).toEqual({ kind: "not-free" });
  });
});
