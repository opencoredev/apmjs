// How apm lays out its human output for a terminal: width-aware wrapping and truncation that keep ANSI colors intact.
// Only a terminal is wrapped: a pipe, a file or CI gets every line whole, so nothing that reads apm's output changes.

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const RESET = `${ESC}[0m`;

/** A CSI sequence (colors among them) or an OSC one (a link): built from ESC so no control sits in a regex literal. */
const ESCAPES = new RegExp(`(${ESC}\\[[0-9;?]*[ -/]*[@-~]|${ESC}\\][^${BEL}${ESC}]*(?:${BEL}|${ESC}\\\\))`);
const SGR = new RegExp(`^${ESC}\\[[0-9;]*m$`);
const graphemes = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/** Whether CI is set: a CI job gets plain whole lines even on a terminal. */
export function inCi(env: Record<string, string | undefined> = process.env): boolean {
  const ci = env.CI;

  return ci !== undefined && ci !== "" && ci !== "0" && ci !== "false";
}

/** The columns a stream shows, or null when it is not a terminal or this is CI (then nothing is wrapped or cut). */
export function columnsOf(stream: { isTTY?: boolean; columns?: number }, env: Record<string, string | undefined> = process.env): number | null {
  if (stream.isTTY !== true || inCi(env)) return null;

  return stream.columns !== undefined && stream.columns > 0 ? stream.columns : 80;
}

/** How many columns `text` takes on screen: escapes take none, wide characters two. */
export function widthOf(text: string): number {
  return Bun.stringWidth(text);
}

/** One piece of a line: an escape sequence (no width), or one grapheme with its width. */
type Piece = { kind: "escape"; text: string } | { kind: "grapheme"; text: string; width: number };

function piecesOf(text: string): Piece[] {
  return text.split(ESCAPES).flatMap((part, i): Piece[] => {
    if (part === "") return [];

    if (i % 2 === 1) return [{ kind: "escape", text: part }];

    return [...graphemes.segment(part)].map((g) => ({ kind: "grapheme", text: g.segment, width: Bun.stringWidth(g.segment) }));
  });
}

/** The color codes still open after `pieces`: every SGR code since the last reset. */
function openColors(pieces: readonly Piece[]): string[] {
  const open: string[] = [];

  for (const p of pieces) {
    if (p.kind !== "escape" || !SGR.test(p.text)) continue;

    if (p.text === RESET || p.text === `${ESC}[m`) open.length = 0;
    else open.push(p.text);
  }

  return open;
}

/** `text` cut to `width` columns with an ellipsis, cut between characters and closing only the colors it opened. */
export function truncate(text: string, width: number): string {
  if (widthOf(text) <= width) return text;
  const kept: Piece[] = [];
  let used = 0;

  // a link or other escape that is not a color is dropped: cut short, it could stay open past the line. Only the
  // part that can show is split into characters, however long the text
  for (const p of piecesOf(Bun.sliceAnsi(bounded(text), 0, width + 1))) {
    if (p.kind === "escape") {
      if (SGR.test(p.text)) kept.push(p);
    } else if (used + p.width <= width - 1) {
      kept.push(p);
      used += p.width;
    } else break;
  }

  return `${kept.map((p) => p.text).join("")}…${openColors(kept).length > 0 ? RESET : ""}`;
}

/**
 * Where a wrapped line's continuation starts: under the text after a label column (`advisory  MAL-…`, the first two or
 * more spaces, within 44 columns), else under the text after a leading mark (`✓ `, `! `, `- `), else at the line's own indent.
 */
function hangOf(plain: string): number {
  const indent = /^ */.exec(plain)?.[0].length ?? 0;
  const label = /^ *\S(?:.*?\S)? {2,}(?=\S)/.exec(plain);

  if (label !== null && label[0].length <= 44) return widthOf(label[0]);
  const mark = /^ *(?:[✓✗!·•→$+-]|\d+\.|-?\d+) (?=\S)/u.exec(plain);

  if (mark !== null && mark[0].length - indent <= 6) return widthOf(mark[0]);

  return indent;
}

/**
 * Text laid out by hand for a wide terminal, with each line that continues the one above (indented under its text) joined
 * back onto it, so it can be wrapped again at the terminal's width.
 */
export function reflow(text: string): string {
  const out: string[] = [];

  for (const line of text.split("\n")) {
    const prev = out.at(-1);
    const indent = /^ */.exec(line)?.[0].length ?? 0;

    if (prev === undefined || prev.trim() === "" || line.trim() === "") {
      out.push(line);
      continue;
    }

    const prevIndent = /^ */.exec(prev)?.[0].length ?? 0;
    const hang = hangOf(Bun.stripANSI(prev));
    // under a label column, or a paragraph's next line: same indent, no column of its own, not a new flag or item
    const continues = indent > prevIndent ? indent === hang : indent === prevIndent && hang === prevIndent && hangOf(Bun.stripANSI(line)) === indent && !/^ *-/.test(line);

    if (continues) out[out.length - 1] = `${prev} ${line.trimStart()}`;
    else out.push(line);
  }

  return out.join("\n");
}

/** The most code units of one line apm lays out for a terminal, escapes and invisible characters included. */
const MAX_LAID_OUT = 8000;

/** The most color codes a wrapped line carries open across a break: older ones are let go first. */
const MAX_OPEN = 16;

/**
 * `text` cut to MAX_LAID_OUT code units with an ellipsis when longer, keeping only its colors: registry text can be
 * megabytes (a yank reason), and a link or other escape cut short could stay open past the line.
 */
function bounded(text: string): string {
  if (text.length <= MAX_LAID_OUT) return text;

  const kept = piecesOf(text.slice(0, MAX_LAID_OUT)).filter((p) =>
    p.kind === "escape" ? SGR.test(p.text) : !p.text.includes(ESC),
  );

  return `${kept.map((p) => p.text).join("")}…${RESET}`;
}

/** The fewest columns a wrapped line keeps for its text: a deeper indent is given up first. */
const MIN_TEXT = 16;

/**
 * `line` wrapped to `width` columns: at spaces where it can, between characters where a word is longer than a line.
 * Each continuation is indented under the text it continues, and the colors open at a break are closed and reopened.
 */
export function wrap(full: string, width: number): string {
  const line = bounded(full);

  if (widthOf(line) <= width) return line;
  const plain = Bun.stripANSI(line);
  const room = Math.max(0, width - MIN_TEXT);
  const indent = Math.min(/^ */.exec(plain)?.[0].length ?? 0, room);
  const hang = Math.min(hangOf(plain), room);
  const all = piecesOf(line);
  // the line's own leading spaces become the first line's indent
  const lead = all.findIndex((p) => p.kind === "grapheme" && p.text !== " ");
  const pieces = all.filter((p, i) => !(i < lead && p.kind === "grapheme"));
  const lines: Piece[][] = [[]];
  let used = 0;
  let avail = width - indent;

  // the colors open so far, kept as pieces are placed so each break costs only its own line
  let open: string[] = [];

  const current = (): Piece[] => lines[lines.length - 1] ?? [];

  const place = (p: Piece): void => {
    current().push(p);

    if (p.kind !== "escape" || !SGR.test(p.text)) return;

    if (p.text === RESET || p.text === `${ESC}[m`) open = [];
    else open = [...open, p.text].slice(-MAX_OPEN);
  };

  const breakLine = (): void => {
    const line = current();

    // the spaces a line ends in are dropped, wherever its colors close
    for (let i = line.length - 1; i >= 0; i--) {
      const p = line[i];

      if (p?.kind === "grapheme" && p.text !== " ") break;

      if (p?.kind === "grapheme") line.splice(i, 1);
    }

    if (open.length > 0) current().push({ kind: "escape", text: RESET });
    lines.push(open.map((text): Piece => ({ kind: "escape", text })));
    used = 0;
    avail = Math.max(1, width - hang);
  };

  // words and the runs of spaces between them, each kept whole where it fits
  const runs: { pieces: Piece[]; width: number; space: boolean }[] = [];

  for (const p of pieces) {
    const space = p.kind === "grapheme" && p.text === " ";
    const last = runs.at(-1);

    if (last !== undefined && (p.kind === "escape" || last.space === space)) {
      last.pieces.push(p);
      last.width += p.kind === "grapheme" ? p.width : 0;
    } else runs.push({ pieces: [p], width: p.kind === "grapheme" ? p.width : 0, space });
  }

  for (const run of runs) {
    if (run.space) {
      // spaces at a break are dropped; their colors are kept
      if (used + run.width >= avail) {
        breakLine();

        for (const p of run.pieces) if (p.kind === "escape") place(p);
      } else {
        for (const p of run.pieces) place(p);
        used += run.width;
      }

      continue;
    }

    // a word longer than a whole line starts where it is and is cut between characters
    if (used > 0 && used + run.width > avail && run.width <= width - hang) breakLine();

    for (const p of run.pieces) {
      if (p.kind === "grapheme" && used + p.width > avail && used > 0) breakLine();
      place(p);
      used += p.kind === "grapheme" ? p.width : 0;
    }
  }

  return lines.map((l, i) => `${" ".repeat(i === 0 ? indent : hang)}${l.map((p) => p.text).join("").trimEnd()}`).join("\n");
}

/** The words of a shell command: split at spaces outside quotes, a backslash keeping the next character in its word. */
function shellWords(command: string): string[] {
  const words: string[] = [];
  let word = "";
  let quote: "'" | '"' | null = null;

  for (let i = 0; i < command.length; i++) {
    const c = command[i] ?? "";

    if (quote === null && c === " ") {
      if (word !== "") words.push(word);
      word = "";
      continue;
    }

    word += c;

    if (quote === null && c === "\\") word += command[++i] ?? "";
    else if (quote === null && (c === "'" || c === '"')) quote = c;
    else if (quote === '"' && c === "\\") word += command[++i] ?? "";
    else if (c === quote) quote = null;
  }

  return word === "" ? words : [...words, word];
}

/**
 * A shell command laid out to `width` for someone to read or paste: broken only between its words, each line but the last
 * ending in " \", so it stays one command with every argument whole. A word longer than a line is left whole.
 */
export function wrapCommand(input: { command: string; first: string; rest: string; width: number }): string[] {
  if (widthOf(input.first + input.command) <= input.width) return [input.first + input.command];
  const lines: string[] = [];
  let line = input.first;
  let empty = true;

  for (const word of shellWords(input.command)) {
    if (!empty && widthOf(`${line} ${word} \\`) > input.width) {
      lines.push(`${line} \\`);
      line = input.rest + word;
    } else line = empty ? line + word : `${line} ${word}`;

    empty = false;
  }

  return [...lines, line];
}
