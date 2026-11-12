// The "Free alternatives" slot suggests only names someone could publish: under the GitHub-scope policy,
// scoped names under the signed-in login, or @you/ placeholders for a visitor. Never bare names.
import { describe, expect, test } from "bun:test";
import { AlternativesPart, alternativesView } from "./search-schema";

describe("alternativesView", () => {
  test("a visitor gets @you/ placeholders to sign in for, not bare names", () => {
    const view = alternativesView(
      AlternativesPart.parse({
        query: "hono",
        valid: true,
        scope: null,
        suggestions: [
          { name: "@you/hono", available: false, taken: false, checked: false },
          { name: "@you/use-hono", available: false, taken: false, checked: false },
        ],
      }),
    );

    expect(view).toEqual({ kind: "sign-in", names: ["@you/hono", "@you/use-hono"] });
  });

  test("a signed-in user gets the free names under their own scope", () => {
    const view = alternativesView(
      AlternativesPart.parse({
        query: "hono",
        valid: true,
        scope: "octo",
        suggestions: [
          { name: "@octo/hono", available: false, taken: true },
          { name: "@octo/hono-js", available: true, taken: false },
          { name: "@octo/use-hono", available: true, taken: false },
        ],
      }),
    );

    expect(view).toEqual({ kind: "free", scope: "octo", names: ["@octo/hono-js", "@octo/use-hono"] });
  });

  test("nothing free and nothing to sign in for shows nothing", () => {
    expect(alternativesView(AlternativesPart.parse({ query: "hono", valid: true, scope: "octo", suggestions: [{ name: "@octo/hono", available: false, taken: true }] }))).toEqual({ kind: "none" });
  });

  test("an older registry answer without scope or checked still parses", () => {
    expect(alternativesView(AlternativesPart.parse({ query: "x", valid: true, suggestions: [{ name: "@octo/x-js", available: true, taken: false }] }))).toEqual({ kind: "free", scope: null, names: ["@octo/x-js"] });
  });
});
