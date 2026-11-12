// Re-review finding 4: the quoting helpers spread every backtick run into Math.max, so a large description with many
// runs overflowed the call stack (a RangeError under workerd), and a publisher field of any length went out whole.
import { describe, expect, test } from "bun:test";
import { capText, codeBlock, inlineCode, longestBacktickRun, MAX_BLOCK, MAX_INLINE } from "./text";

/** 300 KB of "`a": 150,000 separate backtick runs, the size that overflowed under workerd. */
const MANY_RUNS = "`a".repeat(150_000);

/** 2 MB, a million runs: enough to overflow Bun's JavaScriptCore too, so the old helper fails this test here. */
const MILLION_RUNS = "`a".repeat(1_000_000);

describe("quoting large publisher text", () => {
  test("a 300 KB field with 150,000 backtick runs is quoted without a stack overflow", () => {
    expect(MANY_RUNS.length).toBe(300_000);
    expect(() => inlineCode(MANY_RUNS)).not.toThrow();
    expect(() => codeBlock(MANY_RUNS)).not.toThrow();
    expect(() => inlineCode(MILLION_RUNS)).not.toThrow();
    expect(() => codeBlock(MILLION_RUNS)).not.toThrow();
  });

  test("a one-line field is cut to MAX_INLINE characters, and a note outside the span says how much was cut", () => {
    const out = inlineCode(MANY_RUNS);

    expect(out.length).toBeLessThan(MAX_INLINE + 100);
    expect(out).toEndWith(`(cut: ${300_000 - MAX_INLINE} more characters not shown)`);
    // the span still opens and closes with a fence longer than any run inside
    expect(out.startsWith("``")).toBe(true);
  });

  test("a block is cut to MAX_BLOCK characters, with the note after the closing fence", () => {
    const out = codeBlock(`${"line\n".repeat(10_000)}`);
    const fenceEnd = out.lastIndexOf("```");

    expect(out.length).toBeLessThan(MAX_BLOCK + 200);
    expect(out.slice(fenceEnd)).toContain(`(Cut: ${50_000 - MAX_BLOCK} more characters not shown.)`);
  });

  test("short fields are quoted whole, with no note", () => {
    expect(inlineCode("MIT")).toBe("`MIT`");
    expect(inlineCode("a `b` c")).toBe("``a `b` c``");
    expect(codeBlock("x")).toBe("```\nx\n```");
  });

  test("the longest run is counted in one pass", () => {
    expect(longestBacktickRun("")).toBe(0);
    expect(longestBacktickRun("a``b````c`")).toBe(4);
    expect(longestBacktickRun(MANY_RUNS)).toBe(1);
  });

  test("a cut never splits a surrogate pair", () => {
    const { text, cut } = capText("ab😀cd", 3);

    expect(text).toBe("ab");
    expect(cut).toBe(4);
  });
});
