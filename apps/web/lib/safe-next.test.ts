import { describe, expect, test } from "bun:test";
import { DEFAULT_NEXT, safeNext } from "./safe-next";

describe("safeNext", () => {
  test.each([
    ["/account", "/account"],
    ["/approve/abc_123", "/approve/abc_123"],
    ["/device?code=ABCD-1234", "/device?code=ABCD-1234"],
    ["/package/@scope/name#readme", "/package/@scope/name#readme"],
    ["/package/%40scope%2Fname", "/package/%40scope%2Fname"],
  ])("keeps the same-site path %s", (raw, expected) => {
    expect(safeNext(raw)).toBe(expected);
  });

  test.each([
    null,
    "",
    "account",
    "https://evil.example/",
    "//evil.example",
    "/\\evil.example",
    "/%5Cevil.example",
    "/%2F%2Fevil.example",
    "/%2f/evil.example",
    "%2F%2Fevil.example",
    "/%252F%252Fevil.example",
    "/%25252F%25252F%25252F%25252Fevil.example",
    "/\tevil.example",
    "/\t/evil.example",
    "/%09/evil.example",
    "/\n/evil.example",
    "/%",
    "/%E0%A4%A",
    "javascript:alert(1)",
  ])("rejects %p", (raw) => {
    expect(safeNext(raw)).toBe(DEFAULT_NEXT);
  });

  test("whatever it returns resolves to the site's own origin", () => {
    const tricky = ["/\\/evil.example", "/.//evil.example", "/..//evil.example", "/%2e%2e//evil.example", "/　/evil.example", "/@evil.example", "/javascript:alert(1)//"];

    for (const raw of tricky) expect(new URL(safeNext(raw), "https://apm.example").origin).toBe("https://apm.example");
  });
});
