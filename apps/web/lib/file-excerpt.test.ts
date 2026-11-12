// The excerpt view of files over 1 MB: the links that open one, the registry requests behind "Show more", and
// what the view draws for a cut line or a hidden character.
import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ExcerptView } from "../components/file-excerpt";
import { citedLine, EXCERPT_CONTEXT, ExcerptAnswer, mergeLines, MORE_LINES, moreRequest, openingWindow, type Excerpt } from "./file-excerpt";
import { fileHref, parsePackageRoute } from "./package-route";
import { excerptApiPath, readmeApiPath } from "./registry-url";

describe("excerpt links", () => {
  test("a citation into vite's 1.3 MB chunk carries the line where the server can read it", () => {
    const href = fileHref({ name: "vite", version: "7.1.0", path: "dist/node/chunks/node.js", line: 25_134 });
    expect(href).toBe("/package/vite/v/7.1.0/file/dist/node/chunks/node.js?line=25134#L25134");
    const url = new URL(href ?? "", "https://apmjs.dev");
    expect(citedLine(url.searchParams.get("line") ?? undefined)).toBe(25_134);
    expect(parsePackageRoute(url.pathname.slice("/package/".length).split("/"))).toEqual({ kind: "file", name: "vite", version: "7.1.0", path: "dist/node/chunks/node.js" });
  });

  test("a whole-file citation and a package.json script carry no line", () => {
    expect(fileHref({ name: "x", version: "1.0.0", path: "binding.gyp" })).toBe("/package/x/v/1.0.0/file/binding.gyp");
    expect(fileHref({ name: "x", version: "1.0.0", path: "package.json", anchor: "scripts.install" })).toBe("/package/x/v/1.0.0/file/package.json#scripts.install");
    expect(fileHref({ name: "x", version: "1.0.0", path: "a.js", line: 0 })).toBe("/package/x/v/1.0.0/file/a.js");
  });

  test("reads ?line= strictly", () => {
    expect(citedLine("12")).toBe(12);
    expect(citedLine(["7", "9"])).toBe(7);

    for (const bad of [undefined, "", "0", "-1", "1.5", "1e3", "12abc", "9999999999"]) expect(citedLine(bad)).toBeNull();
  });

  test("the registry paths for an excerpt and a tarball readme", () => {
    expect(excerptApiPath({ name: "@acme/tool", version: "1.0.0", path: "dist/a b.js", line: 40, context: 20 })).toBe("-/apm/v1/file/@acme%2Ftool/1.0.0?path=dist%2Fa%20b.js&line=40&context=20");
    expect(readmeApiPath({ name: "@acme/tool", version: "1.0.0-rc.1" })).toBe("-/apm/v1/readme/@acme%2Ftool/1.0.0-rc.1");
  });
});

describe("excerpt windows", () => {
  test("opens about 40 lines around the cited line, or the top of the file", () => {
    expect(openingWindow(25_134)).toEqual({ line: 25_134, context: EXCERPT_CONTEXT });
    expect(openingWindow(null)).toEqual({ line: 1, context: 2 * EXCERPT_CONTEXT });
  });

  /** The lines the registry returns for a request: centre ± context, clamped to the file. */
  const served = (req: { line: number; context: number }, total: number): [number, number] => [Math.max(1, req.line - req.context), Math.min(total, req.line + req.context)];

  test("show more above and below adds up to 100 lines with no gap, and stops at the file's ends", () => {
    const total = 40_000;
    const above = moreRequest({ from: 25_114, to: 25_154, total, direction: "above" });
    const below = moreRequest({ from: 25_114, to: 25_154, total, direction: "below" });
    expect(above && served(above, total)).toEqual([25_114 - MORE_LINES, 25_114]);
    expect(below && served(below, total)).toEqual([25_154, 25_154 + MORE_LINES]);
    // near the ends it asks for what is left, still touching the shown lines
    const top = moreRequest({ from: 30, to: 70, total, direction: "above" });
    expect(top && served(top, total)).toEqual([1, 51]);
    const end = moreRequest({ from: 39_900, to: 39_990, total, direction: "below" });
    expect(end && served(end, total)).toEqual([39_950, 40_000]);
    expect(moreRequest({ from: 1, to: 41, total, direction: "above" })).toBeNull();
    expect(moreRequest({ from: 39_960, to: 40_000, total, direction: "below" })).toBeNull();
  });

  test("merges what a click loads with what is shown, in order, each line once", () => {
    const line = (n: number) => ({ n, text: `l${n}`, truncated: null });
    expect(mergeLines([line(5), line(6)], [line(1), line(2), line(3), line(4), line(5)]).map((l) => l.n)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  test("the answer schema refuses an excerpt with no lines or a line number below 1", () => {
    const head = { name: "x", version: "1.0.0", path: "a.js", size: 5, kind: "excerpt", line: 1, totalLines: 1, from: 1, to: 1 };
    expect(ExcerptAnswer.safeParse({ ...head, lines: [] }).success).toBe(false);
    expect(ExcerptAnswer.safeParse({ ...head, lines: [{ n: 0, text: "", truncated: null }] }).success).toBe(false);
    expect(ExcerptAnswer.safeParse({ ...head, lines: [{ n: 1, text: "", truncated: null }] }).success).toBe(true);
  });
});

describe("excerpt view", () => {
  const excerpt: Excerpt = {
    name: "vite",
    version: "7.1.0",
    path: "dist/node/chunks/node.js",
    size: 1_300_000,
    kind: "excerpt",
    line: 25_134,
    totalLines: 40_000,
    from: 25_133,
    to: 25_135,
    lines: [
      { n: 25_133, text: "const a = 1;\r", truncated: null },
      { n: 25_134, text: "readFileSync(home + '/.npmrc') // ‮evil", truncated: null },
      { n: 25_135, text: "x".repeat(4096), truncated: { bytes: 51_200 } },
    ],
  };

  const html = renderToStaticMarkup(createElement(ExcerptView, { excerpt, cited: 25_134 }));

  test("numbers the lines with their real numbers and says where they sit in the file", () => {
    expect(html).toContain("25133\n25134\n25135");
    expect(html).toContain("Lines 25,133–25,135 of 40,000");
  });

  test("offers more above and below, with how much is hidden", () => {
    expect(html).toContain("Show 100 more lines above");
    expect(html).toContain("25,132 not shown");
    expect(html).toContain("Show 100 more lines below");
    expect(html).toContain("14,865 not shown");
  });

  test("marks a cut line with its full size, and hidden characters as markers", () => {
    expect(html).toContain("line truncated, 50.0 kB in all");
    expect(html).toContain("⟨U+202E⟩evil");
    expect(html).not.toContain("‮");
    expect(html).not.toContain("\r");
  });

  test("has no show-more control at the file's ends", () => {
    const whole = renderToStaticMarkup(createElement(ExcerptView, { excerpt: { ...excerpt, from: 1, to: 1, totalLines: 1, lines: [{ n: 1, text: "only", truncated: null }] }, cited: 1 }));
    expect(whole).not.toContain("more lines");
  });
});
