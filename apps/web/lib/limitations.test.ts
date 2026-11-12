import { describe, expect, test } from "bun:test";
import { splitPossible, splitTestFile, summarizeLimitations } from "./limitations";

const BASE = [
  "runtime behavior: code that downloads, decrypts or builds a second stage while running",
  "the code of dependencies beyond their own scores",
  "whether the publisher's machine or CI was compromised",
];

describe("summarizeLimitations", () => {
  test("names runtime behavior, dependencies and a compromised publisher, and counts the full list", () => {
    const s = summarizeLimitations(BASE);
    expect(s.headline).toMatch(/runtime/);
    expect(s.headline).toMatch(/dependencies/);
    expect(s.headline).toMatch(/compromised publisher/);
    expect(s.extra).toBeNull();
    expect(s.total).toBe(3);
  });

  test("adds what is specific to the version", () => {
    const s = summarizeLimitations([...BASE, "dependency left-pad", "dependency git+https://x", "3 file(s) not analyzed: the package is larger than the 200.0 MB one analysis reads"]);
    expect(s.extra).toBe("Also: 2 dependencies apm could not score, 3 files not analyzed.");
    expect(s.total).toBe(6);
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
