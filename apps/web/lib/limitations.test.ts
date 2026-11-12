import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { GENERAL_LIMITS, limitationCount, sortLimitations, splitPossible, splitTestFile, summarizeLimitations } from "./limitations";

/** NOT_CHECKED as packages/core/src/score.ts writes it, read from the source so the two lists cannot drift. */
function coreNotChecked(): string[] {
  const src = readFileSync(join(import.meta.dir, "../../../packages/core/src/score.ts"), "utf8");
  const block = /export const NOT_CHECKED: readonly string\[\] = \[([\s\S]*?)\];/.exec(src)?.[1] ?? "";

  return [...block.matchAll(/^\s*"((?:[^"\\]|\\.)*)",?$/gm)].map((m) => String(JSON.parse(`"${m[1] ?? ""}"`)));
}

// what apm-score-v9 stored with @opencoredev/email-sdk 3.0.1, the list the owner flagged
const STORED_V9 = [
  "runtime behavior: code that downloads, decrypts or builds a second stage while running",
  "code hidden by anything but base64, hex, \\x escapes, char codes or joined string literals (XOR, compression, a custom encoding)",
  "names built at runtime from values apm cannot work out in the file (array lookups, computed indexes, values read at runtime, values passed through a function's parameters)",
  "documentation, type, JSON, style and markup files that no code reaches by a path apm can read; a computed require is reported as dynamic-require",
  "native binaries and WebAssembly: listed, not read",
  "a popular name reused under another scope (@someone/react): scopes exist so names can be reused",
  "the code of dependencies beyond their own scores",
  "whether the publisher's machine or CI was compromised",
  "an expression that can be more than 6 values: the rest were read as unknown, and judged by the text rules alone (dist/smtp.cjs)",
];

describe("sortLimitations", () => {
  test("the general list is core's NOT_CHECKED, word for word, and short", () => {
    expect(coreNotChecked()).toEqual([...GENERAL_LIMITS]);
    expect(GENERAL_LIMITS.length).toBeGreaterThanOrEqual(4);
    expect(GENERAL_LIMITS.length).toBeLessThanOrEqual(6);
  });

  test("an older stored list shows as today's plain list plus one line for complex code", () => {
    const l = sortLimitations(STORED_V9);
    expect(l.general).toEqual(GENERAL_LIMITS);
    expect(l.complex).toEqual([{ limit: "an expression that can be more than 6 values", files: "dist/smtp.cjs" }]);
    expect(l.other).toEqual([]);
    expect(limitationCount(l)).toBe(GENERAL_LIMITS.length + 1);
  });

  test("today's notes, unread files and dependencies are sorted apart", () => {
    const l = sortLimitations([
      ...GENERAL_LIMITS,
      "an expression with more than 6 possible values (dist/a.js, dist/b.js)",
      "a function with more than 32 return statements (lib/x.js)",
      "3 file(s) not analyzed: the package is larger than the 200.0 MB one analysis reads",
      "dependency left-pad",
      "dependency git+https://x",
    ]);

    expect(l.complex).toEqual([
      { limit: "an expression with more than 6 possible values", files: "dist/a.js, dist/b.js" },
      { limit: "a function with more than 32 return statements", files: "lib/x.js" },
    ]);
    expect(l.unread).toHaveLength(1);
    expect(l.dependencies).toEqual(["left-pad", "git+https://x"]);
    expect(limitationCount(l)).toBe(GENERAL_LIMITS.length + 3);
  });

  test("an entry it does not recognize is kept as written", () => {
    expect(sortLimitations(["something new the scorer says"]).other).toEqual(["something new the scorer says"]);
  });
});

describe("summarizeLimitations", () => {
  test("names runtime behavior, dependencies and a compromised publisher, and counts what the list shows", () => {
    const s = summarizeLimitations(STORED_V9);
    expect(s.headline).toMatch(/runtime/);
    expect(s.headline).toMatch(/dependencies/);
    expect(s.headline).toMatch(/compromised publisher/);
    expect(s.extra).toBeNull();
    expect(s.total).toBe(GENERAL_LIMITS.length + 1);
  });

  test("adds what is specific to the version", () => {
    const s = summarizeLimitations([...GENERAL_LIMITS, "dependency left-pad", "dependency git+https://x", "3 file(s) not analyzed: the package is larger than the 200.0 MB one analysis reads"]);
    expect(s.extra).toBe("Also: 2 dependencies apm could not score, 3 files not analyzed.");
  });
});

describe("splitPossible", () => {
  test("possible evidence keeps its reason apart from the cited line", () => {
    expect(splitPossible('lib/a.js:3: ".npmrc", [possible: a string names a credential file]')).toEqual({ text: 'lib/a.js:3: ".npmrc",', why: "a string names a credential file" });
    expect(splitPossible("lib/a.js:3: fetch(u)")).toEqual({ text: "lib/a.js:3: fetch(u)", why: null });
  });
});

describe("splitTestFile", () => {
  test("a citation from a shipped test file is marked, the reason split off first", () => {
    const ev = "src/v4/classic/tests/error.test.ts:1027: const gc = vm.runInNewContext(\"gc\") (in a test file) [possible: x]";
    const { text } = splitPossible(ev);
    expect(splitTestFile(text)).toEqual({ text: 'src/v4/classic/tests/error.test.ts:1027: const gc = vm.runInNewContext("gc")', testFile: true });
    expect(splitTestFile("lib/a.js:3: fetch(u)")).toEqual({ text: "lib/a.js:3: fetch(u)", testFile: false });
  });
});
