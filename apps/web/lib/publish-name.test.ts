// The name check's answer for a free name, per visitor (HOME-564 item 6: the home page said "available" for a free name
// under someone else's scope, which only that scope's owner can publish).
import { describe, expect, test } from "bun:test";
import { mayPublish, ownerOnlySentence, publishability, publishabilityText } from "./publish-name";

describe("publishability", () => {
  test("a free name under the visitor's own scope is theirs to publish", () => {
    expect(publishability({ name: "@leo/lib", available: true, scope: "leo", policy: "scoped" })).toEqual({ kind: "yours", scope: "@leo" });
    expect(publishability({ name: "@leo/lib", available: true, scope: "Leo", policy: "scoped" })).toEqual({ kind: "yours", scope: "@leo" });
  });

  test("a free name under another scope is its owner's, never the visitor's", () => {
    const p = publishability({ name: "@sindresorhus/h564-probe", available: true, scope: "leo", policy: "scoped" });

    expect(p).toEqual({ kind: "not-yours", scope: "@sindresorhus", yours: "@leo" });
    expect(publishabilityText({ name: "@sindresorhus/h564-probe", publishable: p })).toBe("@sindresorhus/h564-probe is free, but only the owner of @sindresorhus can publish it. Yours is @leo.");
  });

  test("with no visitor known, a free scoped name is its scope owner's", () => {
    expect(publishability({ name: "@sindresorhus/h564-probe", available: true, policy: "scoped" })).toEqual({ kind: "scoped", scope: "@sindresorhus" });
    expect(publishabilityText({ name: "@sindresorhus/h564-probe", publishable: { kind: "scoped", scope: "@sindresorhus" } })).toBe("@sindresorhus/h564-probe is free; only the owner of @sindresorhus (a GitHub login) can publish it.");
    expect(ownerOnlySentence("@sindresorhus", { kind: "signed-out" })).toBe("Only the GitHub account sindresorhus can publish under @sindresorhus. Sign in with GitHub to see whether that is you.");
    expect(ownerOnlySentence("@sindresorhus", { kind: "signed-in", scope: "@leo" })).toBe("Only the GitHub account sindresorhus can publish under @sindresorhus. Yours is @leo.");
  });

  // a failed lookup of who is asking is not a signed-out answer: it never tells a signed-in publisher to sign in
  test("when apm could not ask who the visitor is, the sentence says so instead of asking them to sign in", () => {
    expect(ownerOnlySentence("@sindresorhus", { kind: "unknown" })).toBe("Only the GitHub account sindresorhus can publish under @sindresorhus. apm could not check whether that is you.");
    expect(ownerOnlySentence("@sindresorhus", { kind: "checking" })).toBe("Only the GitHub account sindresorhus can publish under @sindresorhus.");
  });

  test("bare and taken names are unchanged", () => {
    expect(publishability({ name: "fresh-name", available: true, policy: "scoped" })).toEqual({ kind: "needs-scope", suggestion: "@you/fresh-name" });
    expect(publishability({ name: "@leo/lib", available: false, scope: "leo", policy: "scoped" })).toEqual({ kind: "not-free" });
  });

  test("a free bare name follows the registry's name policy", () => {
    const open = publishability({ name: "fresh-name", available: true, policy: "open" });
    const unread = publishability({ name: "fresh-name", available: true, policy: null });

    expect(open).toEqual({ kind: "open" });
    expect(mayPublish(open)).toBe(true);
    expect(publishabilityText({ name: "fresh-name", publishable: open })).toBe("fresh-name is available.");
    expect(unread).toEqual({ kind: "policy-unknown", suggestion: "@you/fresh-name" });
    expect(mayPublish(unread)).toBe(false);
    expect(mayPublish(publishability({ name: "fresh-name", available: true, policy: "scoped" }))).toBe(false);
    expect(publishability({ name: "@sindresorhus/x", available: true, policy: "open" })).toEqual({ kind: "scoped", scope: "@sindresorhus" });
  });
});
