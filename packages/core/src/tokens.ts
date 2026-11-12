// A file that runs but has no tree (too large to hold as one, or a syntax no parser here accepts) is still read token
// by token: acorn's tokenizer streams tokens without building a tree, so its memory stays flat whatever the size.
// Each token is written back in its plain form at the offset it had: an escaped name (`require`) as the name, a
// string with escapes (`'ch\u{69}ld'`) as its value, and comments as blanks. Nothing gets longer, so every offset in
// the result is the same offset in the file and evidence cites the file as written. The text rules then read the
// result the way they read any raw text. Pure.
import { tokTypes as tt, tokenizer, type Token } from "acorn";

/** How many times the tokenizer may skip a character it cannot read (a decorator's `@`, Flow syntax) and go on. */
const MAX_RESUMES = 64;

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

/**
 * The file's tokens in their plain forms, at their own offsets (same length as `text`), or null when not even one
 * token could be read. A character the tokenizer cannot read is kept as it is and reading resumes after it.
 */
export function tokenText(text: string): string | null {
  let out = "";
  let last = 0;
  let resumes = 0;
  let from = 0;
  let any = false;
  let done = false;

  while (from < text.length) {
    try {
      const tokens = tokenizer(from === 0 ? text : text.slice(from), { ecmaVersion: "latest", sourceType: "module", allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true });

      for (let t = tokens.getToken(); t.type !== tt.eof; t = tokens.getToken()) {
        const start = from + t.start;
        const end = from + t.end;
        const source = text.slice(start, end);
        const form = plainForm(t, source);
        out += blank(text.slice(last, start));
        out += form !== null && form.length <= source.length ? form + " ".repeat(source.length - form.length) : source;
        last = end;
        any = true;
      }

      done = true;
      break;
    } catch (e) {
      // acorn's SyntaxError carries the offset it stopped at; the character there is kept and reading goes on after it
      const at = e instanceof SyntaxError && "pos" in e && Number.isInteger(e.pos) ? from + Number(e.pos) : -1;

      if (at < last || ++resumes > MAX_RESUMES) break;
      out += blank(text.slice(last, at));
      out += text.slice(at, at + 1);
      last = at + 1;
      from = at + 1;
    }
  }

  if (!any) return null;

  // what follows the last token is blank space and comments once every token was read; otherwise it stays as it is
  return out + (done ? blank(text.slice(last)) : text.slice(last));
}
