// Static reading of one file's text. JavaScript and TypeScript are parsed (js.ts); a file no parser accepts, install
// commands, shell scripts and other languages are read with the text rules (rules.ts), after a pass that joins strings
// split to dodge them and decoders for the cheap encodings (base64, hex, \x escapes, char codes). Pure.
import { scanJs, type Imports } from "./js.ts";
import type { Dialect, Range } from "./parse.ts";
import { parseEach } from "./parse.ts";
import { joinStrings, scanTextRules } from "./textrules.ts";
import { tokenText } from "./tokens.ts";
import { lineOf, type TextFinding } from "./rules.ts";

export { decodedStrings, joinStrings, type Built, type Decoded, type Joined } from "./textrules.ts";

export { namedSignal, type CodeSignal, type Confidence, type TextFinding, type Where } from "./rules.ts";

export type { Imports } from "./js.ts";

/**
 * How a file is read: `js`, `jsx`, `ts` and `tsx` are parsed; `c` and `python` are lexed for comments and strings;
 * `data` is JSON and type declarations (node parses JSON and never runs it, and a `.d.ts` file only describes code);
 * anything else is `plain`, read raw with every match counted.
 */
export type Lang = Dialect | "c" | "python" | "data" | "plain";

/** The language a file is read as: by extension, then by a node/bun/deno shebang. */
export function langOf(path: string, text: string): Lang {
  if (/\.(?:json|d\.[cm]?ts)$/i.test(path)) return "data";

  if (/\.[cm]?ts$/i.test(path)) return "ts";

  if (/\.tsx$/i.test(path)) return "tsx";

  if (/\.jsx$/i.test(path)) return "jsx";

  if (/\.[cm]?js$/i.test(path)) return "js";

  if (/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|cs|java|go|rs|swift|kt|m|mm)$/i.test(path)) return "c";

  if (/\.py$/i.test(path)) return "python";

  if (!/\.[^/]+$/.test(path) && /^#!.*\b(?:node|bun|deno)\b/.test(text)) return "js";

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
 * JavaScript with no tree: the text rules on the file as written (everything apm-score-v3 caught), and on its tokens
 * in plain form, which undo what only the tokenizer sees through: escaped names, escaped strings and comments between
 * joined pieces. The token pass adds only what the pass as written did not confirm, so no confirmed citation moves.
 * It reads in windows of about TOKEN_WINDOW characters that end only where a statement ends (tokens.ts), so a call
 * is never split from its arguments, whatever lies between them; each window also reaches TOKEN_OVERLAP back.
 */
function scanUnparsed(text: string): FileScan {
  const raw = scanTextRules(text, "unparsed");
  const rawImports = importsOf(joinStrings(text).text);
  const tokens = tokenText(text);

  if (tokens === null || tokens.text === text) return { findings: raw, imports: rawImports, read: "raw", rejected: false, notes: [], sinkOnly: [], patches: null };
  const plain = tokens.text;
  const sure = new Set(raw.filter((f) => f.confidence === "confirmed").map((f) => f.id));
  const more: TextFinding[] = [];
  const paths = new Set(rawImports.paths);
  const loads = new Set(rawImports.loads);

  for (const w of tokenWindows(plain.length, tokens.cuts)) {
    const piece = plain.slice(w.from, w.end);

    for (const f of scanTextRules(piece, "unparsed", { shown: text, offset: w.from })) if (!sure.has(f.id)) more.push(f);
    const found = importsOf(joinStrings(piece).text);

    for (const p of found.paths) paths.add(p);

    for (const p of found.loads) loads.add(p);
  }

  const imports: Imports = { paths: [...paths].slice(0, 500), loads: [...loads].slice(0, 500), dynamic: rawImports.dynamic };

  return { findings: [...raw, ...more], imports, read: "raw", rejected: false, notes: [], sinkOnly: [], patches: null };
}

/** How much of a file's tokens one pass of the text rules reads, and how far each window reaches back into the last. */
export const TOKEN_WINDOW = 4 * 1024 * 1024;
const TOKEN_OVERLAP = 64 * 1024;

/**
 * The windows the token pass reads, `[from, end)`: each ends at the first statement end (`cuts`) past `window`
 * characters from where the last one ended, or at the end of the text, and starts `overlap` before that. Exported
 * with its sizes as parameters so tests can place a construct on a boundary without a 4 MB file.
 */
export function tokenWindows(length: number, cuts: readonly number[], window = TOKEN_WINDOW, overlap = TOKEN_OVERLAP): { from: number; end: number }[] {
  const out: { from: number; end: number }[] = [];

  for (let start = 0; start < length; ) {
    const target = start + window;
    const end = target >= length ? length : (cuts.find((c) => c >= target) ?? length);

    out.push({ from: Math.max(0, start - overlap), end });
    start = end;
  }

  return out;
}

// ---------- what a file loads ----------
const STATIC_IMPORT = /(?:\brequire(?:\.resolve)?\s*\(|\bimport\s*\(|\bfrom\s+|\bimport\s+)\s*['"\x60](\.{1,2}\/[^'"\x60\n]+)['"\x60]/g;
const DIRNAME_JOIN = /\b[\w$]+\.(?:join|resolve)\s*\(\s*__dirname\s*((?:,\s*['"][^'"\n]+['"]\s*)+)\)/g;
const DIRNAME_PLUS = /\b__dirname\s*\+\s*['"](\/[^'"\n]+)['"]/g;
const CALL = /(?<![\w$.])(?:require|import)\s*\(/g;

/**
 * Relative paths a file no parser read loads (a literal require or import, require.resolve, path.join(__dirname,
 * ...) and __dirname + '/...'), and the calls whose argument is not a path apm can read.
 * Run it on joined text so `require('./lib/' + 'x')` is a literal.
 */
export function importsOf(text: string): Imports {
  const paths: string[] = [];

  for (const m of text.matchAll(STATIC_IMPORT)) if (m[1]) paths.push(m[1]);
  // read raw, every literal require or import is taken for a load
  const loads = [...paths];

  for (const m of text.matchAll(DIRNAME_JOIN)) {
    const segs = [...(m[1] ?? "").matchAll(/['"]([^'"\n]+)['"]/g)].map((s) => s[1] ?? "");
    paths.push(`./${segs.join("/")}`);
  }

  for (const m of text.matchAll(DIRNAME_PLUS)) paths.push(`.${m[1] ?? ""}`);
  const dynamic: Imports["dynamic"] = [];

  for (const m of text.matchAll(CALL)) {
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

  return { paths: paths.slice(0, 500), loads: loads.slice(0, 500), dynamic };
}

// ---------- one file ----------

/**
 * What one file's text shows: the rules it matches, and the files and modules it loads. `rejected` says no parser
 * accepted it as JavaScript or TypeScript (a syntax error, not a size limit), so node could not run it either.
 */
export type FileScan = {
  findings: TextFinding[];
  imports: Imports;
  read: "parsed" | "raw" | "lexed";
  rejected: boolean;
  /** Limits the reading ran into; what was past them was judged by the text rules alone. */
  notes: string[];
  /**
   * What the text rules found that only a proof resting on a global or builtin module being what its name says
   * (fetch, path.join, an Error) removed. The package adds these back when any of its files could change one.
   */
  sinkOnly: TextFinding[];
  /** Where and why this file could change what a global or builtin module is (a write to one, or one handed to code apm cannot follow); null when it cannot. */
  patches: string | null;
};

/**
 * Reads one file as `lang`. JavaScript and TypeScript go to the parser; when no parser accepts the file, or it is
 * too large to hold as a tree, it is read raw (fail closed): every match counts, as in apm-score-v3, and its tokens
 * are read too, so escapes and comments cannot hide a name from the raw rules.
 */
export function scanFile(text: string, lang: Lang): FileScan {
  if (isDialect(lang)) {
    const js = scanJs(text, lang);

    if (js.kind === "parsed") return { findings: js.findings, imports: js.imports, read: "parsed", rejected: false, notes: js.notes, sinkOnly: js.sinkOnly, patches: js.patches };

    return { ...scanUnparsed(text), rejected: js.reason === "syntax" };
  }

  // JSON and type declarations never run, so nothing in them is a load
  const imports = lang === "data" ? { paths: [], loads: [], dynamic: [] } : importsOf(joinStrings(text).text);

  return { findings: scanTextRules(text, lang), imports, read: lang === "plain" ? "raw" : "lexed", rejected: false, notes: [], sinkOnly: [], patches: null };
}

/** The rule findings for one text read as `lang`. */
export function scanText(text: string, lang: Lang = "js"): TextFinding[] {
  return scanFile(text, lang).findings;
}
