import { describe, expect, test } from "bun:test";
import { splitLimitation, splitPossible, summarizeLimitations } from "./limitations";

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

describe("splitLimitation and splitPossible", () => {
  test("a topic before its first colon is set apart", () => {
    expect(splitLimitation(BASE[0] ?? "")).toEqual({ topic: "runtime behavior", detail: "code that downloads, decrypts or builds a second stage while running" });
    expect(splitLimitation(BASE[1] ?? "")).toEqual({ topic: BASE[1], detail: null });
  });

  test("possible evidence keeps its reason apart from the cited line", () => {
    expect(splitPossible('lib/a.js:3: ".npmrc", [possible: a string names a credential file]')).toEqual({ text: 'lib/a.js:3: ".npmrc",', why: "a string names a credential file" });
    expect(splitPossible("lib/a.js:3: fetch(u)")).toEqual({ text: "lib/a.js:3: fetch(u)", why: null });
  });
});
