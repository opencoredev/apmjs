// How the file view lays out a file's text. Package code is untrusted, so it is only ever text, and characters
// that would hide or reorder what is on screen are shown as visible markers instead.

/** Lines per rendered block. Every line is one 20px row, so a block of this many is exactly CHUNK_LINES * 20px tall. */
export const CHUNK_LINES = 200;

/** Bidirectional controls (Trojan Source), and characters a browser draws as a line break or not at all. */
// oxlint-disable-next-line eslint/no-control-regex -- matching control characters is the point: they are drawn as markers
const HIDDEN = /[\u0000\u000b\u000c\r\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** A visible stand-in for one hidden character: the control picture when there is one, else its code point. */
function visible(ch: string): string {
  switch (ch) {
    case "\0":
      return "␀";
    case "\v":
      return "␋";
    case "\f":
      return "␌";
    case "\r":
      return "␍";
    default:
      return `⟨U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}⟩`;
  }
}

/**
 * The file's lines, numbered the way the scorer numbers them (split on "\n"). A trailing newline does not make
 * an extra empty line, a "\r" before "\n" is dropped, and hidden characters become markers.
 */
export function displayLines(text: string): string[] {
  const lines = text.split("\n");

  if (lines.length > 1 && lines.at(-1) === "") lines.pop();

  return lines.map(displayLine);
}

/** One line as the file view draws it: a "\r" before its newline dropped, hidden characters as markers. */
export function displayLine(line: string): string {
  return (line.endsWith("\r") ? line.slice(0, -1) : line).replace(HIDDEN, visible);
}

export type Chunk = { start: number; text: string; numbers: string; count: number };

/**
 * Lines grouped into blocks of CHUNK_LINES, each with its text and its line numbers (1-based). Each block's text
 * ends with "\n": a browser draws no row for a final newline, so this keeps an empty last line as a row.
 */
export function chunkLines(lines: readonly string[]): Chunk[] {
  const out: Chunk[] = [];

  for (let i = 0; i < lines.length; i += CHUNK_LINES) {
    const part = lines.slice(i, i + CHUNK_LINES);

    out.push({ start: i + 1, text: `${part.join("\n")}\n`, numbers: part.map((_, j) => String(i + j + 1)).join("\n"), count: part.length });
  }

  return out;
}
