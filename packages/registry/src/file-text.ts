// The file routes' pure parts, kept apart from the Worker bindings so unit tests can import them: how an excerpt
// numbers and cuts lines, and which README npm would pick from a tarball.
import { z } from "zod";

/** One line of an excerpt; `truncated` holds the line's full length in bytes when it was cut. */
export const ExcerptLine = z.object({ n: z.number(), text: z.string(), truncated: z.object({ bytes: z.number() }).nullable() });

export type ExcerptLine = z.infer<typeof ExcerptLine>;

const NEWLINE = 0x0a;

/** Whether the bytes are valid UTF-8, checked a megabyte at a time so a large file is never decoded whole. */
export function isUtf8(data: Uint8Array): boolean {
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  const step = 1024 * 1024;

  try {
    for (let i = 0; i < data.length; i += step) decoder.decode(data.subarray(i, i + step), { stream: true });
    decoder.decode();

    return true;
  } catch {
    return false;
  }
}

/** Lines the way the scorer counts them: "a\nb" and "a\nb\n" both have two; an empty file has one. */
export function countLines(data: Uint8Array): number {
  let breaks = 0;

  for (const b of data) if (b === NEWLINE) breaks += 1;

  return data.length > 0 && data[data.length - 1] === NEWLINE ? breaks : breaks + 1;
}

/** Where a cut at `at` bytes lands on a character boundary (never inside a UTF-8 sequence). */
function charBoundary(data: Uint8Array, at: number): number {
  let cut = at;

  while (cut > 0 && ((data[cut] ?? 0) & 0xc0) === 0x80) cut -= 1;

  return cut;
}

/** Lines `from` to `to` (1-based, inclusive, within the file) of valid UTF-8 bytes, each cut to the line cap. */
export function sliceLines(input: { data: Uint8Array; from: number; to: number; maxLineBytes: number }): ExcerptLine[] {
  const { data, from, to, maxLineBytes } = input;
  const out: ExcerptLine[] = [];
  let line = 1;
  let start = 0;

  while (line < from) {
    const nl = data.indexOf(NEWLINE, start);

    if (nl === -1) return out;
    start = nl + 1;
    line += 1;
  }

  for (; line <= to; line += 1) {
    const nl = data.indexOf(NEWLINE, start);
    const end = nl === -1 ? data.length : nl;
    const full = end - start;
    const cut = full > maxLineBytes ? charBoundary(data, start + maxLineBytes) : end;
    // only the file's first bytes can be a byte order mark (the whole-file view drops it the same way)
    const text = new TextDecoder("utf-8", { fatal: false, ignoreBOM: start !== 0 }).decode(data.subarray(start, cut));

    out.push({ n: line, text, truncated: full > maxLineBytes ? { bytes: full } : null });

    if (nl === -1) break;
    start = nl + 1;
  }

  return out;
}

/** npm's test for a markdown-like extension: ".md", ".markdown", ".mdown" and the other runs of those letters. */
const MARKDOWN_EXT = /\.m?a?r?k?d?o?w?n?$/i;

/** The README npm would pick from a tarball's paths, or null when it has none. */
export function pickReadme(paths: readonly string[]): string | null {
  const candidates = [...new Set(paths)].filter((p) => !p.includes("/") && /^readme(\..*)?$/i.test(p)).sort();
  let plain: string | null = null;

  for (const p of candidates) {
    if (MARKDOWN_EXT.test(p)) return p;

    if (p.endsWith("README")) plain = p;
  }

  return plain;
}
