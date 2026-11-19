// Static reading of one file's text. Every file is read with the text rules (rules.ts) over its whole text, after a
// pass that joins strings split to dodge them and decoders for the cheap encodings (base64, hex, \x escapes, char
// codes); JavaScript and TypeScript are also parsed (js.ts), which adds what the tree sees. Pure.
import { keepString, tempBytes } from "./kept.ts";
import { scanJs, type Command, type EnvRead, type ExecutedCode, type FlowFinding, type Imports, type Unread } from "./js.ts";
import type { Dialect, ParseOutcome, Range } from "./parse.ts";
import { MAX_PARSED_TOKENS, MAX_PARSED_TS_BYTES, parseEach } from "./parse.ts";
import { joinStrings, scanTextRules } from "./textrules.ts";
import { tokenText } from "./tokens.ts";
import { lineOf, type Hidden, type TextFinding } from "./rules.ts";
import type { Exports } from "./flow.ts";

export { decodedStrings, joinStrings, type Built, type Decoded, type Joined } from "./textrules.ts";

export { namedSignal, type CodeSignal, type Confidence, type Hidden, type TextFinding, type Where } from "./rules.ts";

import { chargeText } from "./meter.ts";

export type { Command, EnvRead, ExecutedCode, FlowFinding, Imports, Unread } from "./js.ts";

/**
 * How a file is read: `js`, `jsx`, `ts` and `tsx` are parsed, and read whole with the text rules too; everything else
 * is read whole with the text rules. `json` and `declaration` (a `.d.ts` file) load nothing, and their matches say
 * they sit in a JSON file or a type; `c`, `python` and `plain` are read as apm-score-v3 read them.
 */
export type Lang = Dialect | "c" | "python" | "json" | "declaration" | "plain";

/** The language a file is read as: by extension, then by a node/bun/deno shebang. */
export function langOf(path: string, text: string): Lang {
  chargeText("text", path.length, 9);

  if (/\.json$/i.test(path)) return "json";

  if (/\.d\.[cm]?ts$/i.test(path)) return "declaration";

  if (/\.[cm]?ts$/i.test(path)) return "ts";

  if (/\.tsx$/i.test(path)) return "tsx";

  if (/\.jsx$/i.test(path)) return "jsx";

  if (/\.[cm]?js$/i.test(path)) return "js";

  if (/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|cs|java|go|rs|swift|kt|m|mm)$/i.test(path)) return "c";

  if (/\.py$/i.test(path)) return "python";

  if (!/\.[^/]+$/.test(path) && text.startsWith("#!")) {
    // the shebang test reads the first line
    const eol = text.indexOf("\n");

    chargeText("text", eol === -1 ? text.length : eol, 4);

    if (/^#!.*\b(?:node|bun|deno)\b/.test(text)) return "js";
  }

  return "plain";
}

function isDialect(lang: Lang): lang is Dialect {
  return lang === "js" || lang === "jsx" || lang === "ts" || lang === "tsx";
}

/** The [start, end) offsets of every comment in JavaScript or TypeScript source, as the parser read them. */
export function commentRanges(text: string, dialect: Dialect = "js"): Range[] {
  let comments: Range[] | null = null;

  parseEach(text, dialect, (p) => {
    comments ??= p.comments;

    return false;
  });

  return comments ?? [];
}

/**
 * JavaScript with no tree: the text rules on the whole file as written, however large (everything apm-score-v3
 * caught), and on its tokens in plain form, which undo what only the tokenizer sees through: escaped names, escaped
 * strings and comments between joined pieces. The token pass only adds: it adds what the pass as written did not
 * confirm, so no confirmed citation moves. It reads in windows of about TOKEN_WINDOW characters that end where a
 * statement ends, or past a token in a file without one (tokens.ts); each window also reaches TOKEN_OVERLAP back.
 */
function scanUnparsed(text: string): FileScan {
  const raw = scanTextRules(text);
  // the copy of each window and the joining of its imports, on top of what the rules charge
  chargeText("text", text.length, 3);
  const rawImports = importsOf(joinStrings(text).text);
  const tokens = tokenText(text);

  if (tokens === null || tokens.text === text) return { findings: raw, imports: rawImports, read: "raw", rejected: false, notes: [] };
  const plain = tokens.text;
  const sure = new Set(raw.filter((f) => f.confidence === "confirmed").map((f) => f.id));
  const more: TextFinding[] = [];
  const paths = new Set(rawImports.paths);
  const loads = new Set(rawImports.loads);

  for (const w of tokenWindows(plain.length, tokens.cuts)) {
    const piece = plain.slice(w.from, w.end);

    for (const f of scanTextRules(piece, { shown: text, origin: (i) => tokens.origin(i + w.from) })) {
      if (sure.has(f.id)) continue;
      more.push(f);

      // a name only the tokenizer reads (escaped, or split by comments) was hidden from the text as written, as the
      // tree reports it: obfuscation (apm-score-v10 weighs a hidden dangerous name as obfuscated)
      if (f.id !== "obfuscated" && f.confidence === "confirmed" && !sure.has("obfuscated")) more.push({ ...f, id: "obfuscated", how: "after joining strings" });
    }

    const found = importsOf(joinStrings(piece).text);

    for (const p of found.paths) paths.add(p);

    for (const p of found.loads) loads.add(p);
  }

  const imports: Imports = { paths: [...paths], loads: [...loads], dynamic: rawImports.dynamic };

  return { findings: [...raw, ...more], imports, read: "raw", rejected: false, notes: [] };
}

/** How much of a file's tokens one pass of the text rules reads, and how far each window reaches back into the last. */
export const TOKEN_WINDOW = 4 * 1024 * 1024;
const TOKEN_OVERLAP = 64 * 1024;

/**
 * The windows the token pass reads, `[from, end)`: each ends at the first cut (`cuts`) past `window` characters from
 * where the last one ended, or at the end of the text, and starts `overlap` before that. Exported with its sizes as
 * parameters so tests can place a construct on a boundary without a 4 MB file.
 */
export function tokenWindows(length: number, cuts: readonly number[], window = TOKEN_WINDOW, overlap = TOKEN_OVERLAP): { from: number; end: number }[] {
  const out: { from: number; end: number }[] = [];
  let ci = 0;

  for (let start = 0; start < length; ) {
    const target = start + window;
    // the cuts are in order, so the search starts where the last one stopped

    while (ci < cuts.length && (cuts[ci] ?? length) < target) ci++;
    chargeText("text", 1);
    const end = target >= length ? length : (cuts[ci] ?? length);

    out.push({ from: Math.max(0, start - overlap), end });
    start = end;
  }

  return out;
}

// ---------- what a file loads ----------
const STATIC_IMPORT = /(?:\brequire(?:\.resolve)?\s*\(|\bimport\s*\(|\bfrom\s+|\bimport\s+)\s*['"\x60](\.{1,2}\/[^'"\x60\n]+)['"\x60]/g;
// `(?<![\w$])`, not `\b`: `\b` falls between every `a` and `$` of `a$a$…`, and each start there scanned to the end

const DIRNAME_JOIN = /(?<![\w$])[\w$]+\.(?:join|resolve)\s*\(\s*__dirname\s*((?:,\s*['"][^'"\n]+['"]\s*)+)\)/g;

/** One quoted argument of a `path.join(__dirname, ...)` call. */
const SEGMENT = /['"]([^'"\n]+)['"]/g;

const DIRNAME_PLUS = /\b__dirname\s*\+\s*['"](\/[^'"\n]+)['"]/g;

// the same patterns with where each group sits (importParts)
const STATIC_IMPORT_AT = /(?:\brequire(?:\.resolve)?\s*\(|\bimport\s*\(|\bfrom\s+|\bimport\s+)\s*['"\x60](\.{1,2}\/[^'"\x60\n]+)['"\x60]/dg;
const DIRNAME_JOIN_AT = /(?<![\w$])[\w$]+\.(?:join|resolve)\s*\(\s*__dirname\s*((?:,\s*['"][^'"\n]+['"]\s*)+)\)/dg;
const SEGMENT_AT = /['"]([^'"\n]+)['"]/dg;
const DIRNAME_PLUS_AT = /\b__dirname\s*\+\s*['"](\/[^'"\n]+)['"]/dg;
const CALL = /(?<![\w$.])(?:require|import)\s*\(/g;

/** A path importsOf read, as the text and spans of `text` it is made of, in the order importsOf lists its paths. */
export type ImportPart = { readonly kind: "text"; readonly text: string } | { readonly kind: "span"; readonly start: number; readonly end: number };

export type ImportParts = readonly ImportPart[];

/**
 * Where each path importsOf(text) lists sits in `text`, in its order: a static load is one span, a `path.join(__dirname,
 * ...)` its segments joined by "/", and `__dirname + '/x'` its literal. A binary's view holds one character for each of
 * production's, so a span of the view is where production's text held that path, and the bytes give its real characters
 * where the view holds a stand-in (binary-text.ts; round 15 review of c139b5b, P1: a stand-in matched a file production's
 * exact path did not, and changed how that file was read).
 */
export function importParts(text: string): ImportParts[] {
  const out: ImportParts[] = [];

  for (const m of text.matchAll(STATIC_IMPORT_AT)) {
    const at = m.indices?.[1];

    if (m[1] && at) out.push([{ kind: "span", start: at[0], end: at[1] }]);
  }

  for (const m of text.matchAll(DIRNAME_JOIN_AT)) {
    const at = m.indices?.[1];
    const args = m[1] ?? "";
    const parts: ImportPart[] = [{ kind: "text", text: "./" }];

    for (const s of args.matchAll(SEGMENT_AT)) {
      const seg = s.indices?.[1];

      if (!at || !seg) continue;

      if (parts.length > 1) parts.push({ kind: "text", text: "/" });
      parts.push({ kind: "span", start: at[0] + seg[0], end: at[0] + seg[1] });
    }

    out.push(parts);
  }

  for (const m of text.matchAll(DIRNAME_PLUS_AT)) {
    const at = m.indices?.[1];

    if (at) out.push([{ kind: "text", text: "." }, { kind: "span", start: at[0], end: at[1] }]);
  }

  return out;
}

/**
 * Relative paths a file no parser read loads (a literal require or import, require.resolve, path.join(__dirname,
 * ...) and __dirname + '/...'), and the calls whose argument is not a path apm can read.
 * Run it on joined text so `require('./lib/' + 'x')` is a literal.
 */
export function importsOf(text: string): Imports {
  // the four patterns' passes; each match's own work is charged as it is read
  chargeText("text", text.length, 4);
  const paths: string[] = [];

  // in a binary's reading, each path is charged as it is found, once as a path and once as a load; past what it may
  // keep, none is (kept.ts)
  for (const m of text.matchAll(STATIC_IMPORT)) if (m[1] && keepString(m[1]) && keepString(m[1])) paths.push(m[1]);

  // read raw, every literal require or import is taken for a load
  const loads = [...paths];

  // in a binary's reading, each segment is held to the temporary budget as it is read (kept.ts; round 11 review of ee69d23)
  const temp = tempBytes();

  for (const m of text.matchAll(DIRNAME_JOIN)) {
    chargeText("text", m[0].length, 3);
    const args = m[1] ?? "";
    let path: string | null = "./";
    let first = true;

    SEGMENT.lastIndex = 0;

    for (let s = SEGMENT.exec(args); s !== null && path !== null; s = SEGMENT.exec(args)) {
      const seg = s[1] ?? "";

      // past the budget the path is not known, and the reading is stopped
      if (!temp.fits(48 + 2 * seg.length)) path = null;
      else {
        path += first ? seg : `/${seg}`;
        first = false;
      }
    }

    if (path !== null && keepString(path)) paths.push(path);
  }

  for (const m of text.matchAll(DIRNAME_PLUS)) {
    const path = `.${m[1] ?? ""}`;

    if (keepString(path)) paths.push(path);
  }

  const dynamic: Imports["dynamic"] = [];

  for (const m of text.matchAll(CALL)) {
    // the 12 characters before the call and the 200 after it, read by up to seven patterns
    chargeText("text", 212, 8);
    const before = text.slice(Math.max(0, m.index - 12), m.index);

    if (/function\s*$/.test(before)) continue;
    const arg = text.slice(m.index + m[0].length, m.index + m[0].length + 200).trimStart();

    if (arg.startsWith(")")) continue;

    if (/^(['"])[^'"\n]*\1\s*[),]/.test(arg)) continue;

    if (/^\x60[^\x60$]*\x60\s*[),]/.test(arg)) continue;

    if (/^require\.resolve\s*\(\s*['"][^'"\n]*['"]\s*\)\s*\)/.test(arg) || /^[\w$]+\.(?:join|resolve)\s*\(\s*__dirname\s*(?:,\s*['"][^'"\n]+['"]\s*)+\)\s*\)/.test(arg)) continue;

    if (/^__dirname\s*\+\s*['"][^'"\n]+['"]\s*\)/.test(arg)) continue;

    if (dynamic.length < 5) dynamic.push(lineOf(text, m.index));
    else break;
  }

  // every path, however many: a file a cut list left out would be read as one nothing loads
  return { paths, loads, dynamic };
}

// ---------- one file ----------

/**
 * What one file's text shows: the rules it matches, and the files and modules it loads. `rejected` says no parser
 * accepted it as JavaScript or TypeScript (a syntax error, not a size limit), so node could not run it either.
 */
export type FileScan = {
  findings: TextFinding[];
  imports: Imports;
  read: "parsed" | "raw";
  rejected: boolean;
  /** Limits the tree's reading ran into; what was past them was judged by the text rules alone. */
  notes: string[];
  /** For a parsed file: the comment, regex body or type a position sits in, if any. */
  hidden?: (index: number) => Hidden | undefined;
  /** For a parsed file: the strings it passes to a process. */
  commands?: Command[];
  /** For a parsed file: values that reach a call that sends, runs or reads them (flow.ts). */
  flows?: FlowFinding[];
  /** For a parsed file: what its exports carry, for a file that loads it. */
  exports?: Exports;
  /** For a parsed file: code it holds as text, run, recovered from its own source or held in a string. */
  executed?: ExecutedCode[];
  /** For a parsed file: environment variables it reads, however it reaches the environment. */
  env?: EnvRead[];
  /** For a parsed file: code it runs that apm did not read, which makes the analysis incomplete. */
  unread?: Unread[];
  /** For a parsed file: whether its flow reading stopped before it finished (js.ts JsScan's flowStopped). */
  flowStopped?: boolean;
};

/** What left-out text every match in a file of this language sits in: all of a JSON file, all of a type declaration. */
const WHOLE_FILE_HIDDEN: Partial<Record<Lang, Hidden>> = { json: "json", declaration: "type" };

/** Why a file no tree was read for is unread, by the parser limit it hit (parse.ts). */
const PARSE_LIMIT_WHY: Record<Exclude<ParseOutcome, "parsed" | "syntax">, string> = {
  "too-large": `the file is too large for apm to read as a tree (more than ${MAX_PARSED_TOKENS} tokens, or ${MAX_PARSED_TS_BYTES / (1024 * 1024)} MB of TypeScript), so where its values go was not followed; its text rules still counted`,
  "too-deep": "the file nests too deeply for apm to read as a tree (the reading ran out of stack), so where its values go was not followed; its text rules still counted",
};

/**
 * Reads one file as `lang`. JavaScript and TypeScript go to the parser, and the text rules read the whole file (the
 * floor, js.ts). When no parser accepts the file it is read raw: every match counts, as in apm-score-v3, and its
 * tokens are read too, so escapes and comments cannot hide a name from the rules. A file a parser stopped on at one of
 * its limits (too large, too deep) is read raw the same way, and its raw findings all count, but they never stand in
 * for the tree's reading: the file is listed as unread, which makes the analysis incomplete.
 */
export function scanFile(text: string, lang: Lang): FileScan {
  if (isDialect(lang)) {
    const js = scanJs(text, lang);

    if (js.kind === "parsed") {
      return { findings: js.findings, imports: js.imports, read: "parsed", rejected: false, notes: js.notes, hidden: js.hidden, commands: js.commands, flows: js.flows, exports: js.exports, executed: js.executed, env: js.env, unread: js.unread, flowStopped: js.flowStopped };
    }

    if (js.reason === "syntax") return { ...scanUnparsed(text), rejected: true };

    return { ...scanUnparsed(text), rejected: false, unread: [{ ...lineOf(text, 0), why: PARSE_LIMIT_WHY[js.reason] }] };
  }

  const kind = WHOLE_FILE_HIDDEN[lang];
  // JSON and type declarations never run, so nothing in them is a load
  const imports = kind ? { paths: [], loads: [], dynamic: [] } : importsOf(joinStrings(text).text);

  return { findings: scanTextRules(text, kind ? { hidden: () => kind } : {}), imports, read: "raw", rejected: false, notes: [] };
}

/** The rule findings for one text read as `lang`. */
export function scanText(text: string, lang: Lang = "js"): TextFinding[] {
  return scanFile(text, lang).findings;
}
