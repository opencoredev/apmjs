import { describe, expect, test } from "bun:test";
import { afterNavigation } from "./header-search";

describe("afterNavigation", () => {
  test("the reakt -> react -> puppeteer flow never leaves an old query in the field", () => {
    let s = { path: "/package/hono", value: "reakt" };
    // Enter goes home with ?q=reakt; the header field is hidden there
    s = afterNavigation(s, "/");
    expect(s.value).toBe("");
    s = afterNavigation({ ...s, value: "" }, "/package/react");
    expect(s).toEqual({ path: "/package/react", value: "" });
    s = afterNavigation({ ...s, value: "puppeteer" }, "/");
    s = afterNavigation(s, "/package/puppeteer");
    expect(s).toEqual({ path: "/package/puppeteer", value: "" });
  });

  test("typing on the same page keeps the text", () => {
    const s = { path: "/package/react", value: "pupp" };
    expect(afterNavigation(s, "/package/react")).toBe(s);
  });
});
