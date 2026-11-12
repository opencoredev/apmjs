// Launch review blocker 6, and the v4 review's findings 1, 3 and 4: a comment must not hide code from the rules.
// Comments come from the parser, so they end where JavaScript ends them. Payloads are inert stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, POINTS, SCORE_FLOOR, type TarEntry } from "../src/index.ts";
import { commentRanges, scanText, type Lang } from "../src/source.ts";

function confirmed(text: string, lang: Lang = "js"): string[] {
  return scanText(text, lang)
    .filter((f) => f.confidence === "confirmed")
    .map((f) => f.id);
}

function commented(text: string): string[] {
  return commentRanges(text).map(([a, b]) => text.slice(a, b));
}

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreOf(file: string, text: string): number {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: file };
  const a = analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry(file, text)], publisher: "a", previousPublishers: [] });

  return finalize(a, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null }).score;
}

// four confirmed signals and one obfuscation: 100 - 15 - 10 - 25 - 10 - 10
const PAYLOAD = "require('chi'+'ld_process');fetch('https://example.invalid');process.env.NPM_TOKEN;eval('1');";

describe("commentRanges", () => {
  test("a block comment ends where it closes", () => {
    expect(commented("/* a */ code(); // b\n")).toEqual(["/* a */", "// b"]);
  });

  test("comment openers inside strings, templates and regexes are not comments", () => {
    expect(commented("const s = '/*'; x(); const t = '*/';\n")).toEqual([]);
    expect(commented("const u = `${'/*'}`; x(); // real\n")).toEqual(["// real"]);
    expect(commented("if (ok) /\\/*/.test(s); x(); // real\n")).toEqual(["// real"]);
    expect(commented("function f() { return /\\/\\/x/.test(s); } // real\n")).toEqual(["// real"]);
  });

  test("an unclosed block comment is a syntax error, so the file has no comments to trust", () => {
    expect(commented("x(); /* never closed\ny();\n")).toEqual([]);
  });

  test("a line comment ends at every ECMAScript line terminator, not only LF", () => {
    for (const end of ["\r", "\u2028", "\u2029", "\r\n"]) expect(commented(`// note${end}x();`)).toEqual(["// note"]);
  });

  test("a hashbang ends at a carriage return too", () => {
    expect(confirmed("#!/usr/bin/env node\rrequire('child_process');")).toEqual(["shell-exec"]);
  });

  test("HTML-like comments are comments in a script, and only to the end of their line", () => {
    expect(commented("<!-- /*\nx();\nconst end = '*/';\n")).toEqual(["<!-- /*"]);
    expect(commented("x();\n--> /*\ny();\n")).toEqual(["--> /*"]);
  });
});

describe("a comment cannot hide code (v4 review, findings 1, 3 and 4)", () => {
  for (const [label, prefix] of [
    ["a carriage return", "// note\r"],
    ["a line separator", "// note\u2028"],
    ["a paragraph separator", "// note\u2029"],
    ["a carriage-return hashbang", "#!/usr/bin/env node\r"],
    ["an HTML open comment holding /*", "<!-- /*\n"],
    ["an HTML close comment holding /*", "--> /*\n"],
  ] as const) {
    test(`${label} before the payload keeps it below the floor`, () => {
      const suffix = label.startsWith("an HTML") ? "\nconst end = '*/';" : "";
      const score = scoreOf("index.js", `${prefix}${PAYLOAD}${suffix}`);

      expect(score).toBe(30);
      expect(score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("a file node runs as a module reads `<!--` as code, so a script's HTML comment cannot hide the rest of the line", () => {
    // as a script `<!-- y` is a comment; as a module it is `x < !(--y)`, then the call
    expect(confirmed("let x = 1, y = 2; x <!-- y\nrequire('child_process');\n")).toEqual(["shell-exec"]);
    expect(confirmed("let x = 1, y = 2;\nx <!-- y; require('child_process');\n")).toEqual(["shell-exec"]);
  });

  for (const [file, text] of [
    ["index.jsx", "const a = <p>\n// {require('child_process')}\n</p>;"],
    ["index.tsx", "const a = <p>\n// {require('child_process')}\n</p>;"],
    ["index.jsx", "const a = <p>/*\n* {require('child_process')}\n*/</p>;"],
    ["index.js", "const a = <p>/*</p>; require('child_process'); const b = <p>*/</p>;"],
  ] as const) {
    test(`JSX child text that looks like a comment does not hide an expression (${file}: ${JSON.stringify(text.slice(10, 30))})`, () => {
      expect(scoreOf(file, text)).toBe(100 + POINTS["shell-exec"]);
    });
  }
});

describe("docs-shaped patterns", () => {
  test("a closed comment at the start of a line does not hide the code after it", () => {
    expect(confirmed("/* ordinary comment */ const b = process.binding('spawn_sync');\n")).toEqual(["shell-exec"]);
    expect(confirmed("/* ordinary comment */ require('dns').lookup('example.invalid', () => {});\n")).toEqual(["network"]);
    expect(confirmed("/* ordinary comment */ const e = (0, eval)('1');\n")).toEqual(["eval"]);
  });

  test("any number of commented examples does not hide a later call", () => {
    const docs = Array.from({ length: 500 }, (_, i) => `// example ${i}: new EventSource(url)\n`).join("");

    expect(confirmed(`${docs}module.exports = new EventSource('https://example.invalid/stream');\n`)).toEqual(["network"]);
  });

  test("a code line that starts with * is code unless it is inside a comment", () => {
    expect(confirmed("const n = a\n* process.binding('spawn_sync');\n")).toEqual(["shell-exec"]);
  });

  test("examples in JSDoc and line comments count, and say they sit in a comment (apm-score-v9)", () => {
    // `String(fn)` returns a function's comments, so code can run them or use them as data
    for (const text of ["/**\n * Usage:\n *   const es = new EventSource(url);\n *   process.binding('fs');\n */\nmodule.exports = 1;\n", "// e.g. require('dns').lookup(host, cb)\nmodule.exports = 1;\n"]) {
      const found = scanText(text, "js");

      expect(found.length).toBeGreaterThan(0);
      expect(found.every((f) => f.confidence === "confirmed" && f.hidden === "comment")).toBe(true);
    }
  });
});
