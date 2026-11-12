// The name check's typo-risk line: the phone's collapsed summary shows it, so it must name the real package.
import { describe, expect, test } from "bun:test";
import { LookalikePart, typoRisk } from "./search-schema";

describe("typoRisk", () => {
  test("a look-alike gives the summary line and the real package's name", () => {
    const risk = typoRisk(LookalikePart.parse({ query: "reakt", valid: true, lookalikes: [{ name: "react", reason: 'one edit away from "react"' }], similar: [] }));

    expect(risk).toEqual({ name: "react", reason: 'one edit away from "react"', summary: "Typo risk: similar to react" });
  });

  test("a look-alike outranks a similar name", () => {
    const risk = typoRisk(
      LookalikePart.parse({ query: "expresss", valid: true, lookalikes: [{ name: "express", reason: "one edit away" }], similar: [{ name: "expressjs", reason: "shares a stem" }] }),
    );

    expect(risk?.name).toBe("express");
  });

  test("a similar name still counts when there is no look-alike", () => {
    expect(typoRisk(LookalikePart.parse({ query: "lodahs", valid: true, lookalikes: [], similar: [{ name: "lodash", reason: "letters swapped" }] }))?.summary).toBe("Typo risk: similar to lodash");
  });

  test("nothing close gives no line", () => {
    expect(typoRisk(LookalikePart.parse({ query: "zod", valid: true, lookalikes: [], similar: [] }))).toBeNull();
  });
});
