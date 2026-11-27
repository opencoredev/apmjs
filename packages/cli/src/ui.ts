// How apm lays out its human output for a terminal: width-aware wrapping and truncation that keep ANSI colors intact.
// Only a terminal is wrapped: a pipe, a file or CI gets every line whole, so nothing that reads apm's output changes.

/** The columns a stream shows, or null when it is not a terminal (then nothing is wrapped or cut). */
export function columnsOf(stream: { isTTY?: boolean; columns?: number }): number | null {
  if (stream.isTTY !== true) return null;

  return Math.max(MIN_COLUMNS, stream.columns !== undefined && stream.columns > 0 ? stream.columns : 80);
}

/** An ANSI color code (SGR), the only escape apm's own lines carry; built from ESC so no control sits in a regex literal. */
const SGR = `${String.fromCharCode(27)}\\[[0-9;]*m`;
const SGR_ALL = new RegExp(SGR, "g");
const SGR_AT_START = new RegExp(`^${SGR}`);
const LEADING_SPACE = new RegExp(`^((?:${SGR})*) +`);

/** Below this a terminal is taken as this wide: a wrap at a handful of columns helps nobody. */
const MIN_COLUMNS = 40;

/** How many columns `text` takes on screen: ANSI escapes take none, wide characters two. */
export function widthOf(text: string): number {
  return Bun.stringWidth(text);
}

/** `text` cut to `width` columns with an ellipsis, colors kept and closed. */
export function truncate(text: string, width: number): string {
  if (widthOf(text) <= width) return text;

  return `${Bun.sliceAnsi(text, 0, Math.max(1, width - 1))}\x1b[0m…`;
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

/** `line` wrapped to `width` columns: each continuation is indented under the text it continues, colors carried over. */
export function wrap(line: string, width: number): string {
  if (widthOf(line) <= width) return line;
  const plain = Bun.stripANSI(line);
  const hang = Math.min(hangOf(plain), Math.floor(width / 2));
  const indent = /^ */.exec(plain)?.[0].length ?? 0;
  // the line's own indent is kept by hand: wrapAnsi trims each line's leading space
  const body = line.replace(LEADING_SPACE, "$1");
  const first = Bun.wrapAnsi(body, width - indent, { hard: true }).split("\n")[0] ?? "";
  const end = sliceEnd(body, first);
  const rest = `${openCodes(body.slice(0, end))}${body.slice(end)}`;
  const lines = [`${" ".repeat(indent)}${first}`];

  if (rest.trim() !== "") for (const l of Bun.wrapAnsi(rest.replace(/^ +/, ""), width - hang, { hard: true }).split("\n")) lines.push(`${" ".repeat(hang)}${l}`);

  return lines.join("\n");
}

/** The color codes still open at the end of `head`, to reopen them where the next line starts. */
function openCodes(head: string): string {
  const codes = head.match(SGR_ALL) ?? [];
  const reset = codes.findLastIndex((c) => c === "\x1b[0m" || c === "\x1b[m");

  return codes.slice(reset + 1).join("");
}

/** Where in `body` the visible text of `first` ends, so the rest of the line can be wrapped at its own width. */
function sliceEnd(body: string, first: string): number {
  const want = Bun.stripANSI(first).trimEnd().length;
  let seen = 0;
  let i = 0;

  while (i < body.length && seen < want) {
    const esc = SGR_AT_START.exec(body.slice(i));

    if (esc !== null) {
      i += esc[0].length;
      continue;
    }

    seen += 1;
    i += 1;
  }

  return i;
}
