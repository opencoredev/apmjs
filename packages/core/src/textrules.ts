// The text rules read over a whole text, the way apm-score-v3 read every file: the rules as written, then with split
// strings joined (`'chi' + 'ld_process'`, `x['ex' + 'ec']`, `\x63hild`), then on strings decoded from base64, hex, char
// codes and URI escapes. A dangerous name that had to be built or decoded also counts as obfuscation. Who reads the
// text decides what each match means through `region`: install commands and shell scripts count every match, C and
// Python are lexed, JavaScript with no tree is read as v3 read it, and a parsed program passes its own judge, which
// keeps a match unless the tree proves it harmless (the floor, js.ts). Pure.
import { lex, type Lang as LexLang, type Lexed } from "./lexer.ts";
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
  UNPARSED,
  type Where,
} from "./rules.ts";

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

/** How a file read with the text rules is read: lexed (C, Python), raw, or JavaScript that has no tree. */
/** How a file read with the text rules is read: lexed (C, Python), raw, or JavaScript that has no tree. */
export type TextLang = LexLang | "unparsed";

function regionsOf(text: string, lang: TextLang): RegionOf {
  if (lang === "unparsed") return UNPARSED;

  if (lang === "plain") return RAW;
  let lexed: Lexed | null = null;

  // lexed once, and only when something matched. C and Python have no tree to prove a string harmless, so their
  // comments are left out, shell text counts only where the lexer says it is a string (`a || sh` in code is not a
  // pipe), and everything else is read as apm-score-v3 read it. JSON and type declarations never run, so what they
  // name stays possible at most
  return (index, _end, _id, kind) => {
    const r = (lexed ??= lex(text, lang)).region(index);

    if (lang === "data" || r === "excluded") return r;

    return r === "code" && kind === "text" ? "excluded" : "unparsed";
  };
}

/**
 * How one text is read. `shown` and `offset`: `text` is a window of `shown` (the file as written) that starts at
 * `offset`, with every offset kept, so findings cite `shown`. `region` overrides what `lang` says each match means
 * (a parsed program's judge). `encoded`: also look for long escape runs, long base64 and `_0x` identifier runs,
 * which are read on the file as written (by default, only when `text` is the file itself).
 */
export type TextRead = { shown?: string; offset?: number; region?: RegionOf; encoded?: boolean };

/**
 * The text rules on a whole text: install commands and shell scripts (`plain`), C and Python (comments and strings
 * told apart), JavaScript that no parser accepted (read raw, as apm-score-v3 read every file), and a parsed program's
 * floor (its own `region`). The rules run on the text as written, then with split strings joined, then on readable
 * strings decoded from base64, hex and char codes; a dangerous name that had to be built or decoded also counts as
 * obfuscation. Every finding cites where it is in the file as written, traced back through the joining. A region
 * is asked about each match with its span, signal and rule kind, so a judge can tell which token a match rests on.
 */
export function scanTextRules(text: string, lang: TextLang, read: TextRead = {}): TextFinding[] {
  const region = read.region ?? regionsOf(text, lang);
  const shown = read.shown;
  const offset = read.offset ?? 0;
  const place = (index: number): Where => (shown !== undefined ? lineOf(shown, index + offset) : lineOf(text, index));
  const out = ruleHits(text, "as written", new Set(), region, place);
  const confirmed = (): Set<CodeSignal> => new Set(out.filter((f) => f.confidence === "confirmed").map((f) => f.id));

  // escapes and identifier runs are read on the file as written; its tokens in plain form have them decoded
  if (read.encoded ?? shown === undefined) {
    const hex = hexIdentifierRun(text);

    if (hex >= 0) out.push({ id: "obfuscated", ...place(hex), how: "as written", confidence: "confirmed" });
    out.push(...encodedLiterals(text, region, place));
  }

  const joined = joinStrings(text);
  const at = (index: number): Where => place(joined.origin(index));
  const jregion: RegionOf = (index, end, id, kind) => region(joined.origin(index), end === undefined ? undefined : joined.origin(Math.max(index, end - 1)) + 1, id, kind);

  if (joined.text !== text) {
    const found = new Set(out.map((f) => f.id));

    // joining can confirm what the text as written only suggested, but a second "possible" adds nothing
    for (const f of ruleHits(joined.text, "after joining strings", confirmed(), jregion, at)) if (f.confidence === "confirmed" || !found.has(f.id)) out.push(f);
  }

  for (const b of joined.built) {
    const id = namedSignal(b.value);

    if (!id) continue;
    const where = place(b.index);
    const why = `builds "${b.value.slice(0, 40)}" from pieces, but apm did not see it loaded or called`;

    for (const signal of [id, "obfuscated"] as const) {
      const r = region(b.index, b.index + 1, signal, "name");

      if (r === "excluded") continue;
      const confidence: Confidence = r === "string" ? "possible" : "confirmed";
      const snippet = signal === "obfuscated" ? `builds "${b.value.slice(0, 40)}" from pieces: ${where.snippet}` : where.snippet;

      out.push(judged({ id: signal, line: where.line, snippet, how: "after joining strings" }, confidence, why));
    }
  }

  for (const d of decodedStrings(joined.text)) {
    const where = at(d.index);
    const named = namedSignal(d.value);
    const hits = ruleHits(d.value, "decoded", new Set(), RAW);

    if (named) hits.push({ id: named, line: where.line, snippet: d.value.slice(0, 80), how: "decoded", confidence: "confirmed" });

    if (hits.length === 0) continue;
    const hidden = `decoded from ${d.how} in an ordinary string that apm did not see code load or run`;
    let shownAny = false;

    for (const h of hits) {
      const r = jregion(d.index, d.index + 1, h.id, "decoded");

      if (r === "excluded") continue;
      const outer: Confidence = r === "string" ? "possible" : "confirmed";
      const confidence: Confidence = outer === "possible" || h.confidence === "possible" ? "possible" : "confirmed";
      const snippet = `${d.how} "${d.value.slice(0, 60)}" at ${where.snippet}`.slice(0, 120);

      out.push(judged({ id: h.id, line: where.line, snippet, how: "decoded" }, confidence, h.confidence === "possible" ? h.why : hidden));
      shownAny = true;
    }

    const r = jregion(d.index, d.index + 1, "obfuscated", "decoded");

    if (shownAny && r !== "excluded") out.push(judged({ id: "obfuscated", line: where.line, snippet: `hides code in ${d.how}: ${where.snippet}`, how: "decoded" }, r === "string" ? "possible" : "confirmed", hidden));
  }

  if (!confirmed().has("credential-access") && out.some((f) => f.id === "network")) {
    const hit = envExfil(text, region);

    if (hit) out.push(judged({ id: "credential-access", ...place(hit.index), how: "as written" }, hit.confidence, IN_STRING));
  }

  return out;
}
