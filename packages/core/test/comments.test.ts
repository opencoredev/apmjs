// Launch review blocker 6: a comment must not hide code from the rules. Payloads are inert stand-ins.
import { describe, expect, test } from "bun:test";
import { commentRanges, scanText } from "../src/source.ts";

function ids(text: string): string[] {
  return scanText(text).map((f) => f.id);
}

function commented(text: string): string[] {
  return commentRanges(text).map(([a, b]) => text.slice(a, b));
}

describe("commentRanges", () => {
  test("a block comment ends where it closes", () => {
    expect(commented("/* a */ code(); // b\n")).toEqual(["/* a */", "// b"]);
  });

  test("comment openers inside strings, templates and regexes are not comments", () => {
    expect(commented("const s = '/*'; x(); const t = '*/';\n")).toEqual([]);
    expect(commented("const u = `${'/*'}`; x(); // real\n")).toEqual(["// real"]);
    expect(commented("if (ok) /\\/*/.test(s); x(); // real\n")).toEqual(["// real"]);
    expect(commented("return /\\/\\/x/.test(s); // real\n")).toEqual(["// real"]);
  });

  test("an unclosed block comment is code", () => {
    expect(commented("x(); /* never closed\ny();\n")).toEqual([]);
  });
});

describe("docs-shaped patterns", () => {
  test("a closed comment at the start of a line does not hide the code after it", () => {
    expect(ids("/* ordinary comment */ const b = process.binding('spawn_sync');\n")).toContain("shell-exec");
    expect(ids("/* ordinary comment */ require('dns').lookup('example.invalid', () => {});\n")).toContain("network");
    expect(ids("/* ordinary comment */ const e = (0, eval)('1');\n")).toContain("eval");
  });

  test("any number of commented examples does not hide a later call", () => {
    const docs = Array.from({ length: 500 }, (_, i) => `// example ${i}: new EventSource(url)\n`).join("");

    expect(ids(`${docs}module.exports = new EventSource('https://example.invalid/stream');\n`)).toContain("network");
  });

  test("a code line that starts with * is code unless it is inside a comment", () => {
    expect(ids("const n = a\n* process.binding('spawn_sync');\n")).toContain("shell-exec");
  });

  test("examples in JSDoc and line comments are still passed over", () => {
    expect(ids("/**\n * Usage:\n *   const es = new EventSource(url);\n *   process.binding('fs');\n */\nmodule.exports = 1;\n")).toEqual([]);
    expect(ids("// e.g. require('dns').lookup(host, cb)\nmodule.exports = 1;\n")).toEqual([]);
  });
});
