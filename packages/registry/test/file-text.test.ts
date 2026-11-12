// The file routes' pure parts: which README npm would pick, and how an excerpt numbers and cuts lines.
import { describe, expect, test } from "bun:test";
import { countLines, pickReadme, sliceLines } from "../src/file-text.ts";

const bytes = (s: string) => new TextEncoder().encode(s);

describe("pickReadme", () => {
  test("a markdown README at the root wins, in path order, whatever its case", () => {
    expect(pickReadme(["index.js", "README", "README.md", "readme.md"])).toBe("README.md");
    expect(pickReadme(["readme.md", "README.txt"])).toBe("readme.md");
    expect(pickReadme(["README.markdown", "README"])).toBe("README.markdown");
    expect(pickReadme(["Readme.MD"])).toBe("Readme.MD");
  });

  test("else a file named exactly README", () => {
    expect(pickReadme(["README.txt", "README"])).toBe("README");
  });

  test("nothing for README.txt alone, nested readmes, or names that only start with readme", () => {
    expect(pickReadme(["README.txt"])).toBeNull();
    expect(pickReadme(["docs/README.md", "lib/readme.md"])).toBeNull();
    expect(pickReadme(["readme-notes.md", "READMEFIRST.md"])).toBeNull();
    expect(pickReadme([])).toBeNull();
  });
});

describe("excerpt lines", () => {
  test("counts lines the way the scorer splits them", () => {
    expect(countLines(bytes(""))).toBe(1);
    expect(countLines(bytes("a"))).toBe(1);
    expect(countLines(bytes("a\n"))).toBe(1);
    expect(countLines(bytes("a\nb"))).toBe(2);
    expect(countLines(bytes("a\n\n"))).toBe(2);
  });

  test("slices a range with real line numbers and cuts long lines on a character boundary", () => {
    const data = bytes("one\ntwo\n€€€€\nfour");
    expect(sliceLines({ data, from: 2, to: 4, maxLineBytes: 100 })).toEqual([
      { n: 2, text: "two", truncated: null },
      { n: 3, text: "€€€€", truncated: null },
      { n: 4, text: "four", truncated: null },
    ]);
    // "€" is three bytes, so a 7-byte cut keeps two of them
    expect(sliceLines({ data, from: 3, to: 3, maxLineBytes: 7 })).toEqual([{ n: 3, text: "€€", truncated: { bytes: 12 } }]);
  });

  test("keeps a byte order mark that is not at the start of the file", () => {
    expect(sliceLines({ data: bytes("﻿a\n﻿b"), from: 1, to: 2, maxLineBytes: 100 }).map((l) => l.text)).toEqual(["a", "﻿b"]);
  });
});
