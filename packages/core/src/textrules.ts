// The text rules read over a whole text, the way apm-score-v3 read every file: the rules as written, then with split
// strings joined (`'chi' + 'ld_process'`, `x['ex' + 'ec']`, `\x63hild`), then on strings decoded from base64, hex, char
// codes and URI escapes. A dangerous name that had to be built or decoded also counts as obfuscation. Every match is
// confirmed wherever it sits, comments, regex bodies, types and JSON included (apm-score-v9); a parsed program only
// says which of those a match sits in, so the evidence can name it. Pure.
import { encodedLiterals, envExfil, hexIdentifierRun, lineOf, namedSignal, printable, ruleHits, type Hidden, type TextFinding, v3Encoded, type Where } from "./rules.ts";
import { chargeText } from "./meter.ts";

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
  // the match pass, and the text copied into the result
  chargeText("text", text.length, 2);
  const edits: Edit[] = [];
  let out = "";
  let last = 0;

  for (const m of text.matchAll(re)) {
    const replacement = fn(m[0], m.slice(1).map((g) => g ?? ""));

    if (replacement === null) continue;
    chargeText("text", m[0].length + replacement.length, 2);
    out += text.slice(last, m.index) + replacement;
    edits.push({ start: m.index, end: m.index + m[0].length, length: replacement.length });
    last = m.index + m[0].length;
  }

  return { text: out + text.slice(last), edits };
}

/** Maps a position in the edited text back to the original: inside a replacement, the replacement's start. */
function traceBack(edits: readonly Edit[], index: number): number {
  chargeText("text", edits.length * 8);
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
  // the three `includes` tests
  chargeText("text", text.length, 3);
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

    for (const e of step.edits) {
      chargeText("text", e.end - e.start, 3);
      built.push({ value: unescapeJs(text.slice(e.start + 1, e.end - 1)), index: e.start });
    }

    passes.push(step.edits);
    out = step.text;
  }

  if (out.includes("+")) {
    const before = out;
    const step = replaceTracked(out, CHAIN, (m) => quote([...m.matchAll(ONE_LIT)].map((p) => p[0].slice(1, -1)).join("")));

    for (const e of step.edits) {
      chargeText("text", e.end - e.start, 3);
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
  // the three patterns' passes; what each match decodes is charged as it is decoded
  chargeText("text", text.length, 4);
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
    chargeText("text", raw.length, 3);
    push(Buffer.from(raw, "base64").toString("latin1"), "base64", m.index);
  }

  for (const m of text.matchAll(/(['"])((?:[0-9a-fA-F]{2}){4,32768})\1\s*,\s*['"]hex['"]/g)) {
    chargeText("text", m[0].length, 3);
    push(Buffer.from(m[2] ?? "", "hex").toString("latin1"), "hex", m.index);
  }

  if (text.includes("fromCharCode")) {
    for (const m of text.matchAll(/fromCharCode\s*\(\s*((?:\d{1,3}\s*,\s*){2,}\d{1,3})\s*\)|\[\s*((?:\d{2,3}\s*,\s*){3,}\d{2,3})\s*\]/g)) {
      chargeText("text", m[0].length, 4);
      const codes = (m[1] ?? m[2] ?? "").split(",").map((n) => Number(n.trim()));

      if (codes.every((c) => c >= 32 && c < 127)) push(String.fromCharCode(...codes), "char codes", m.index);
    }
  }

  return out;
}

// ---------- reading text ----------

/**
 * How one text is read. `shown` and `origin`: `text` is a window of `shown` (the file as written), and `origin` maps
 * a position in `text` to `shown`, so findings cite `shown`. `hidden` says what left-out text a position of `shown`
 * sits in (a comment, a regex body, a type), for the evidence line; it never changes what counts. `encoded`: also look
 * for long escape runs, long base64 and `_0x` identifier runs, which are read on the file as written (by default, only
 * when `text` is the file itself).
 */
export type TextRead = { shown?: string; origin?: (index: number) => number; hidden?: (index: number) => Hidden | undefined; encoded?: boolean };

/**
 * The text rules on a whole text, as apm-score-v3 read every file: install commands, shell scripts, C and Python,
 * JavaScript with or without a tree, JSON and type declarations. The rules run on the text as written, then with split
 * strings joined, then on readable strings decoded from base64, hex and char codes; a dangerous name that had to be
 * built or decoded also counts as obfuscation. Every match counts, confirmed. Every finding cites where it is in the
 * file as written, traced back through the joining. Each pass is at least what v3's `scanText` ran on the same text
 * (`test/v3/source.ts`): its patterns are in `RULES`, and its `obfuscated` rule runs on the joined text and on each
 * decoded string here too.
 */
export function scanTextRules(text: string, read: TextRead = {}): TextFinding[] {
  const shown = read.shown;
  const origin = read.origin ?? ((index: number) => index);
  const hidden = read.hidden;

  const place = (index: number): Where => {
    const at = origin(index);
    const where = lineOf(shown ?? text, at);
    const kind = hidden?.(at);

    return kind ? { ...where, hidden: kind } : where;
  };

  const out = ruleHits(text, "as written", new Set(), place);
  const have = (): Set<TextFinding["id"]> => new Set(out.map((f) => f.id));

  // escapes and identifier runs are read on the file as written; its tokens in plain form have them decoded
  if (read.encoded ?? shown === undefined) {
    const hex = hexIdentifierRun(text);

    if (hex >= 0) out.push({ id: "obfuscated", ...place(hex), how: "as written", confidence: "confirmed" });
    out.push(...encodedLiterals(text, place));
  }

  const joined = joinStrings(text);
  const at = (index: number): Where => place(joined.origin(index));

  if (joined.text !== text) {
    out.push(...ruleHits(joined.text, "after joining strings", have(), at));

    // v3's obfuscated rule also ran on the joined text: base64 split into pieces is one run once joined
    const encoded = have().has("obfuscated") ? -1 : v3Encoded(joined.text);

    if (encoded >= 0) out.push({ id: "obfuscated", ...at(encoded), how: "after joining strings", confidence: "confirmed" });
  }

  for (const b of joined.built) {
    const id = namedSignal(b.value);

    if (!id) continue;
    const where = place(b.index);

    out.push({ id, ...where, how: "after joining strings", confidence: "confirmed" });
    out.push({ id: "obfuscated", ...where, snippet: `builds "${b.value.slice(0, 40)}" from pieces: ${where.snippet}`, how: "after joining strings", confidence: "confirmed" });
  }

  for (const d of decodedStrings(joined.text)) {
    chargeText("text", d.value.length, 2);
    const where = at(d.index);
    const named = namedSignal(d.value);
    const hits = ruleHits(d.value, "decoded", new Set());

    if (named) hits.push({ id: named, line: 0, snippet: "", how: "decoded", confidence: "confirmed" });

    // v3's obfuscated rule also ran on each decoded string
    if (v3Encoded(d.value) >= 0) hits.push({ id: "obfuscated", line: 0, snippet: "", how: "decoded", confidence: "confirmed" });

    if (hits.length === 0) continue;
    const snippet = `${d.how} "${d.value.slice(0, 60)}" at ${where.snippet}`.slice(0, 120);

    for (const h of hits) out.push({ ...where, id: h.id, snippet, how: "decoded", confidence: "confirmed" });
    out.push({ ...where, id: "obfuscated", snippet: `hides code in ${d.how}: ${where.snippet}`, how: "decoded", confidence: "confirmed" });
  }

  if (!have().has("credential-access") && have().has("network")) {
    const dump = envExfil(text);

    if (dump >= 0) out.push({ id: "credential-access", ...place(dump), how: "as written", confidence: "confirmed" });
  }

  return out;
}
