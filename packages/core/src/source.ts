// Static reading of one file's text. JavaScript and TypeScript are parsed (js.ts); a file no parser accepts, install
// commands, shell scripts and other languages are read with the text rules (rules.ts), after a pass that joins strings
// split to dodge them and decoders for the cheap encodings (base64, hex, \x escapes, char codes). Pure.
import { scanJs, type Imports } from "./js.ts";
import { lex, type Lang as LexLang, type Lexed } from "./lexer.ts";
import type { Dialect, Range } from "./parse.ts";
import { parseEach } from "./parse.ts";
import {
  encodedLiterals,
  envExfil,
  hexIdentifierRun,
  IN_STRING,
  judged,
  lineOf,
  namedSignal,
  printable,
  RAW,
  ruleHits,
  type CodeSignal,
  type Confidence,
  type RegionOf,
  type TextFinding,
  type Where,
} from "./rules.ts";

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

// ---------- joining split strings ----------
const LIT = String.raw`(?:'[^'\\\n]*'|"[^"\\\n]*"|\x60[^\x60\\$\n]*\x60)`;
const CHAIN = new RegExp(`${LIT}(?:[ \\t]*\\+[ \\t\\n]*${LIT})+`, "g");
const ONE_LIT = new RegExp(LIT, "g");
const ESCAPED_LIT = /(['"])((?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|[\w./:@ -])*)\1/g;

function unescapeJs(s: string): string {
  return s.replace(/\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})/g, (_, x: string | undefined, u: string | undefined) => String.fromCharCode(Number.parseInt(x ?? u ?? "0", 16)));
}

function quote(s: string): string {
  return `'${s.replace(/['\\\n]/g, " ")}'`;
}

/** One replacement made while joining: `[start, end)` of the text before it, and the length that replaced it. */
type Edit = { start: number; end: number; length: number };

/**
 * Applies `re`'s replacements to `text` and records each one, so a position in the result can be traced back to
 * the text the replacement came from (provenance by position, never by searching for the value).
 */
type Tracked = { text: string; edits: Edit[] };

function replaceTracked(text: string, re: RegExp, fn: (m: string, groups: string[]) => string | null): Tracked {
  const edits: Edit[] = [];
  let out = "";
  let last = 0;

  for (const m of text.matchAll(re)) {
    const replacement = fn(m[0], m.slice(1).map((g) => g ?? ""));

    if (replacement === null) continue;
    out += text.slice(last, m.index) + replacement;
    edits.push({ start: m.index, end: m.index + m[0].length, length: replacement.length });
    last = m.index + m[0].length;
  }

  return { text: out + text.slice(last), edits };
}

/** Maps a position in the edited text back to the original: inside a replacement, the replacement's start. */
function traceBack(edits: readonly Edit[], index: number): number {
  let shift = 0;

  for (const e of edits) {
    const outStart = e.start + shift;

    if (index < outStart) break;

    if (index < outStart + e.length) return e.start;
    shift += e.length - (e.end - e.start);
  }

  return index - shift;
}

/** A string the joining pass had to build, and where in the original text it starts. */
export type Built = { value: string; index: number };

/**
 * Undoes the disguises that only move characters around: `'\x63hild'` becomes `'child'`, `'chi' + 'ld_'`
 * becomes `'child_'`, and `x['ex' + 'ec']` becomes `x.exec`. Nothing is run. Returns the new text, every string it
 * had to build (from escapes or from two or more pieces) with where it starts in `text`, and `origin`, which maps a
 * position in the new text back to `text`.
 */
export type Joined = { text: string; built: Built[]; origin: (index: number) => number };

export function joinStrings(text: string): Joined {
  const built: Built[] = [];
  const passes: Edit[][] = [];
  let out = text;

  // positions of each pass are traced back through the passes before it
  const toOriginal = (index: number, upTo: number): number => {
    let i = index;

    for (let p = upTo - 1; p >= 0; p--) i = traceBack(passes[p] ?? [], i);

    return i;
  };

  if (out.includes("\\x") || out.includes("\\u")) {
    const step = replaceTracked(out, ESCAPED_LIT, (_m, [, body = ""]) => {
      if (!/\\[xu]/.test(body)) return null;

      return quote(unescapeJs(body));
    });

    for (const e of step.edits) built.push({ value: unescapeJs(text.slice(e.start + 1, e.end - 1)), index: e.start });
    passes.push(step.edits);
    out = step.text;
  }

  if (out.includes("+")) {
    const before = out;
    const step = replaceTracked(out, CHAIN, (m) => quote([...m.matchAll(ONE_LIT)].map((p) => p[0].slice(1, -1)).join("")));

    for (const e of step.edits) {
      const value = [...before.slice(e.start, e.end).matchAll(ONE_LIT)].map((p) => p[0].slice(1, -1)).join("");
      built.push({ value, index: toOriginal(e.start, passes.length) });
    }

    passes.push(step.edits);
    out = step.text;
  }

  if (out.includes("[")) {
    const step = replaceTracked(out, /(?<=[\w$)\]])\s*\[\s*(['"])([A-Za-z_$][\w$]*)\1\s*\]/g, (_m, [, name = ""]) => `.${name}`);
    passes.push(step.edits);
    out = step.text;
  }

  const count = passes.length;

  return { text: out, built, origin: (index) => toOriginal(index, count) };
}

// ---------- decoding ----------
const MAX_DECODED_BYTES = 256 * 1024;

export type Decoded = { value: string; how: string; index: number };

/** Strings hidden by base64, hex or char codes, decoded when the result is readable text. Bounded per file. */
export function decodedStrings(text: string): Decoded[] {
  const out: Decoded[] = [];
  let budget = MAX_DECODED_BYTES;

  const push = (value: string, how: string, index: number): void => {
    if (budget <= 0 || !printable(value)) return;
    budget -= value.length;
    out.push({ value, how, index });
  };

  for (const m of text.matchAll(/(['"\x60])([A-Za-z0-9+/]{16,65536}={0,2})\1/g)) {
    const raw = m[2] ?? "";

    if (budget <= 0) break;

    // identifiers and alphabets are base64-shaped too; real payloads mix cases and digits
    if (raw.length % 4 === 1 || !/[0-9+/=]/.test(raw)) continue;
    push(Buffer.from(raw, "base64").toString("latin1"), "base64", m.index);
  }

  for (const m of text.matchAll(/(['"])((?:[0-9a-fA-F]{2}){4,32768})\1\s*,\s*['"]hex['"]/g)) push(Buffer.from(m[2] ?? "", "hex").toString("latin1"), "hex", m.index);

  if (text.includes("fromCharCode")) {
    for (const m of text.matchAll(/fromCharCode\s*\(\s*((?:\d{1,3}\s*,\s*){2,}\d{1,3})\s*\)|\[\s*((?:\d{2,3}\s*,\s*){3,}\d{2,3})\s*\]/g)) {
      const codes = (m[1] ?? m[2] ?? "").split(",").map((n) => Number(n.trim()));

      if (codes.every((c) => c >= 32 && c < 127)) push(String.fromCharCode(...codes), "char codes", m.index);
    }
  }

  return out;
}

// ---------- reading text without a parser ----------

function regionsOf(text: string, lang: LexLang): RegionOf {
  if (lang === "plain") return RAW;
  let lexed: Lexed | null = null;

  // lexed once, and only when something matched
  return (index) => (lexed ??= lex(text, lang)).region(index);
}

/**
 * The text rules on a file no parser reads: install commands and shell scripts (`plain`), C and Python (comments and
 * strings told apart), JSON and type declarations (`data`), and JavaScript that no parser accepted (read raw, as
 * apm-score-v3 read every file). The rules run on the text as written, then with split strings joined, then on
 * readable strings decoded from base64, hex and char codes; a dangerous name that had to be built or decoded also
 * counts as obfuscation. Every finding cites where it is in `text`, traced back through the joining.
 */
function scanTextRules(text: string, lang: LexLang): TextFinding[] {
  const region = regionsOf(text, lang);
  const out = ruleHits(text, "as written", new Set(), region);
  const confirmed = (): Set<CodeSignal> => new Set(out.filter((f) => f.confidence === "confirmed").map((f) => f.id));
  const hex = hexIdentifierRun(text);

  if (hex >= 0) out.push({ id: "obfuscated", ...lineOf(text, hex), how: "as written", confidence: "confirmed" });
  out.push(...encodedLiterals(text, region));
  const joined = joinStrings(text);
  const at = (index: number): Where => lineOf(text, joined.origin(index));
  const jregion: RegionOf = (index) => region(joined.origin(index));

  if (joined.text !== text) {
    const found = new Set(out.map((f) => f.id));

    // joining can confirm what the text as written only suggested, but a second "possible" adds nothing
    for (const f of ruleHits(joined.text, "after joining strings", confirmed(), jregion, at)) if (f.confidence === "confirmed" || !found.has(f.id)) out.push(f);
  }

  for (const b of joined.built) {
    const id = namedSignal(b.value);

    if (!id) continue;
    const r = region(b.index);

    if (r === "excluded") continue;
    const confidence: Confidence = r === "string" ? "possible" : "confirmed";
    const why = `builds "${b.value.slice(0, 40)}" from pieces, but apm did not see it loaded or called`;
    const where = lineOf(text, b.index);

    out.push(judged({ id, ...where, how: "after joining strings" }, confidence, why));
    out.push(judged({ id: "obfuscated", line: where.line, snippet: `builds "${b.value.slice(0, 40)}" from pieces: ${where.snippet}`, how: "after joining strings" }, confidence, why));
  }

  for (const d of decodedStrings(joined.text)) {
    const r = jregion(d.index);

    if (r === "excluded") continue;
    const outer: Confidence = r === "string" ? "possible" : "confirmed";
    const where = at(d.index);
    const named = namedSignal(d.value);
    const hits = ruleHits(d.value, "decoded", new Set(), RAW);

    if (named) hits.push({ id: named, line: where.line, snippet: d.value.slice(0, 80), how: "decoded", confidence: "confirmed" });

    if (hits.length === 0) continue;
    const hidden = `decoded from ${d.how} in an ordinary string that apm did not see code load or run`;

    for (const h of hits) {
      const confidence: Confidence = outer === "possible" || h.confidence === "possible" ? "possible" : "confirmed";
      const snippet = `${d.how} "${d.value.slice(0, 60)}" at ${where.snippet}`.slice(0, 120);

      out.push(judged({ id: h.id, line: where.line, snippet, how: "decoded" }, confidence, h.confidence === "possible" ? h.why : hidden));
    }

    out.push(judged({ id: "obfuscated", line: where.line, snippet: `hides code in ${d.how}: ${where.snippet}`, how: "decoded" }, outer, hidden));
  }

  if (!confirmed().has("credential-access") && out.some((f) => f.id === "network")) {
    const hit = envExfil(text, region);

    if (hit) out.push(judged({ id: "credential-access", ...lineOf(text, hit.index), how: "as written" }, hit.confidence, IN_STRING));
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

/** What one file's text shows: the rules it matches, and the files and modules it loads. */
export type FileScan = { findings: TextFinding[]; imports: Imports; read: "parsed" | "raw" | "lexed" };

/**
 * Reads one file as `lang`. JavaScript and TypeScript go to the parser; when no parser accepts the file, or it is
 * too large to hold as a tree, it is read raw (fail closed): every match counts, as in apm-score-v3.
 */
export function scanFile(text: string, lang: Lang): FileScan {
  if (isDialect(lang)) {
    const js = scanJs(text, lang);

    if (js.kind === "parsed") return { findings: js.findings, imports: js.imports, read: "parsed" };

    return { findings: scanTextRules(text, "plain"), imports: importsOf(joinStrings(text).text), read: "raw" };
  }

  // JSON and type declarations never run, so nothing in them is a load
  const imports = lang === "data" ? { paths: [], loads: [], dynamic: [] } : importsOf(joinStrings(text).text);

  return { findings: scanTextRules(text, lang), imports, read: lang === "plain" ? "raw" : "lexed" };
}

/** The rule findings for one text read as `lang`. */
export function scanText(text: string, lang: Lang = "js"): TextFinding[] {
  return scanFile(text, lang).findings;
}
