// A file that runs but has no tree (too large to hold as one, or a syntax no parser here accepts) is still read token
// by token: acorn's tokenizer streams tokens without building a tree, so its memory stays flat whatever the size.
// Each token is written back in its plain form: an escaped name (`require`) as the name, a string with escapes
// (`'ch\u{69}ld'`) as its value. What sits between two tokens (blank space and comments) is written as blanks, and a
// gap longer than MAX_GAP as one character, so no comment, however long, keeps a name from its call. `origin` maps
// every position back to the file as written, so evidence cites the file. The text rules then read the result the
// way they read any raw text. Pure.
import { tokTypes as tt, tokenizer, type Token } from "acorn";
import { chargeText, MeterExhausted } from "./meter.ts";

/** How many times the tokenizer may skip a character it cannot read (a decorator's `@`, Flow syntax) and go on. */
const MAX_RESUMES = 64;

/** How far apart the places a window may end are offered: the first statement end past each step. */
const CUT_STEP = 256 * 1024;

/** A gap between two tokens longer than this is written as one character: a line break if it holds one, else a space. */
const MAX_GAP = 64;

/**
 * The file's tokens in plain form (`text`), `origin`, which maps a position in `text` to the file, and `cuts`:
 * positions in `text` where a window of the text rules may end, at most about every CUT_STEP characters. A cut is
 * always between two tokens, so no comment, string, template or escape is split. It is just past a `;` that ends a
 * statement (outside every `(`, `[` and `${`, so never inside a `for` header or a function passed as an argument)
 * when one comes within a step of the last cut; otherwise, in a file that has none, just past the first token after
 * a further step, so a window stays near its size. Since long gaps are written short, a call and its arguments are
 * always close together, and the overlap each window reads back covers one cut between them.
 */
export type TokenText = { text: string; cuts: number[]; origin: (index: number) => number };

/** A string literal as the text rules read one: single quotes, with nothing in it that would end it early. */
function quoted(value: string): string {
  return `'${value.replace(/['\\\n\r\u2028\u2029]/g, " ")}'`;
}

function blank(text: string): string {
  return text.replace(/[^\n]/g, " ");
}

function tokenValue(t: Token): string | null {
  return "value" in t && t.value !== null && t.value !== undefined ? String(t.value) : null;
}

/** A token's plain form, never longer than its source; null keeps the source as it is. */
function plainForm(t: Token, source: string): string | null {
  const value = tokenValue(t);

  if (value === null) return null;

  if (t.type === tt.name) return value;

  if (t.type === tt.string) return quoted(value);

  // template text: its cooked value, with nothing in it that would end the template or start a substitution
  if (t.type === tt.template) return value.replace(/[`$\\]/g, " ");

  return source.length === value.length ? value : null;
}

/** The brackets a token opens or closes; a `;` ends a statement only when none but `{` is open. */
function bracketOf(t: Token): "open" | "open-expression" | "close" | null {
  if (t.type === tt.braceL) return "open";

  if (t.type === tt.parenL || t.type === tt.bracketL || t.type === tt.dollarBraceL) return "open-expression";

  if (t.type === tt.braceR || t.type === tt.parenR || t.type === tt.bracketR) return "close";

  return null;
}

/** Positions in the written text where the file's offsets jump (a gap written short), with the file offset there. */
type Jumps = { at: number[]; to: number[] };

function originOf(jumps: Jumps): (index: number) => number {
  return (index) => {
    let lo = 0;
    let hi = jumps.at.length - 1;
    let found = -1;

    while (lo <= hi) {
      const mid = (lo + hi) >> 1;

      if ((jumps.at[mid] ?? Number.POSITIVE_INFINITY) <= index) {
        found = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }

    return found < 0 ? index : (jumps.to[found] ?? 0) + index - (jumps.at[found] ?? 0);
  };
}

/**
 * The file's tokens in their plain forms, or null when not even one token could be read. A character the tokenizer
 * cannot read is kept as it is and reading resumes after it. `cutStep` spaces the offered cuts (a parameter so tests
 * can make small windows).
 */
export function tokenText(text: string, cutStep = CUT_STEP): TokenText | null {
  const parts: string[] = [];
  let written = 0;
  let last = 0;
  let resumes = 0;
  let from = 0;
  let any = false;
  let done = false;
  const cuts: number[] = [];
  const jumps: Jumps = { at: [], to: [] };
  let nextCut = cutStep;
  // brackets open at this point: `true` for `(`, `[` and `${`, inside which a `;` does not end a statement
  const open: boolean[] = [];
  let inExpression = 0;

  const write = (s: string): void => {
    parts.push(s);
    written += s.length;
  };

  // what lies between two tokens: blanks of the same length, or one character for a long gap
  const gap = (start: number, end: number): void => {
    if (end - start <= MAX_GAP) {
      write(blank(text.slice(start, end)));

      return;
    }

    jumps.at.push(written);
    jumps.to.push(start);
    write(text.slice(start, end).includes("\n") ? "\n" : " ");
    jumps.at.push(written);
    jumps.to.push(end);
  };

  while (from < text.length) {
    // each start copies the rest of the text and reads it again from there
    chargeText("text", text.length - from, 2);

    try {
      const tokens = tokenizer(from === 0 ? text : text.slice(from), { ecmaVersion: "latest", sourceType: "module", allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true });

      for (let t = tokens.getToken(); t.type !== tt.eof; t = tokens.getToken()) {
        const start = from + t.start;
        const end = from + t.end;

        // a token: its slice, its plain form and its write, and the gap before it
        chargeText("text", (end - last) * 3 + 64);
        const source = text.slice(start, end);
        const form = plainForm(t, source);
        gap(last, start);
        write(form !== null && form.length <= source.length ? form + " ".repeat(source.length - form.length) : source);
        last = end;
        any = true;
        const bracket = bracketOf(t);

        if (bracket === "open" || bracket === "open-expression") {
          open.push(bracket === "open-expression");

          if (bracket === "open-expression") inExpression++;
        } else if (bracket === "close" && open.pop() === true) inExpression--;

        const statementEnd = t.type === tt.semi && inExpression === 0;

        if ((statementEnd && written >= nextCut) || written >= nextCut + cutStep) {
          cuts.push(written);
          nextCut = written + cutStep;
        }
      }

      done = true;
      break;
    } catch (e) {
      if (e instanceof MeterExhausted) throw e;
      // acorn's SyntaxError carries the offset it stopped at; the character there is kept and reading goes on after it
      const at = e instanceof SyntaxError && "pos" in e && Number.isInteger(e.pos) ? from + Number(e.pos) : -1;

      if (at < last || ++resumes > MAX_RESUMES) break;
      gap(last, at);
      write(text.slice(at, at + 1));
      last = at + 1;
      from = at + 1;
    }
  }

  if (!any) return null;

  // what follows the last token is blank space and comments once every token was read; otherwise it stays as it is
  if (done) gap(last, text.length);
  else write(text.slice(last));

  return { text: parts.join(""), cuts, origin: originOf(jumps) };
}
