// The excerpt view of a file too large to show whole: which lines open first, which a "Show more" click asks
// for, and the registry's answer. Pure, so the server page, the client view and the unit tests share it.
import { z } from "zod";

/** Lines each side of the cited one when an excerpt opens (about 40 lines in all). */
export const EXCERPT_CONTEXT = 20;

/** Lines each side of the centre a "Show more" request asks for. */
export const MORE_CONTEXT = 50;

/** One line of an excerpt; `truncated` holds the line's full length in bytes when the registry cut it. */
export const ExcerptLine = z.object({ n: z.number().int().positive(), text: z.string(), truncated: z.object({ bytes: z.number() }).nullable() });

export type ExcerptLine = z.infer<typeof ExcerptLine>;

const Head = { name: z.string(), version: z.string(), path: z.string(), size: z.number() };

export const ExcerptAnswer = z.discriminatedUnion("kind", [
  z.object({ ...Head, kind: z.literal("excerpt"), line: z.number(), totalLines: z.number().int().positive(), from: z.number(), to: z.number(), lines: z.array(ExcerptLine).min(1) }),
  z.object({ ...Head, kind: z.literal("binary") }),
]);

export type ExcerptAnswer = z.infer<typeof ExcerptAnswer>;

export type Excerpt = Extract<ExcerptAnswer, { kind: "excerpt" }>;

/** The cited line a `?line=` parameter names, or null when it names none. */
export function citedLine(raw: string | string[] | undefined): number | null {
  const v = Array.isArray(raw) ? raw[0] : raw;

  if (v === undefined || !/^\d{1,9}$/.test(v)) return null;
  const n = Number(v);

  return n >= 1 ? n : null;
}

/** What an excerpt opens with: the cited line and EXCERPT_CONTEXT each side, or the top of the file. */
export function openingWindow(cited: number | null): { line: number; context: number } {
  return cited === null ? { line: 1, context: 2 * EXCERPT_CONTEXT } : { line: cited, context: EXCERPT_CONTEXT };
}

/** New lines one "Show more" click adds, at most. */
export const MORE_LINES = 2 * MORE_CONTEXT;

/**
 * The request that loads the lines just above or below what is shown. The registry answers centre ± context,
 * clamped to the file, so a centre MORE_CONTEXT past the edge returns the edge line again (no gap) and up to
 * MORE_LINES new ones. Null when that side already reaches the end of the file.
 */
export function moreRequest(input: { from: number; to: number; total: number; direction: "above" | "below" }): { line: number; context: number } | null {
  const { from, to, total } = input;

  if (input.direction === "above") return from <= 1 ? null : { line: Math.max(1, from - MORE_CONTEXT), context: MORE_CONTEXT };

  return to >= total ? null : { line: Math.min(total, to + MORE_CONTEXT), context: MORE_CONTEXT };
}

/** Two runs of lines as one, in order, each line number once. */
export function mergeLines(a: readonly ExcerptLine[], b: readonly ExcerptLine[]): ExcerptLine[] {
  const byLine = new Map<number, ExcerptLine>();

  for (const l of [...a, ...b]) byLine.set(l.n, l);

  return [...byLine.values()].sort((x, y) => x.n - y.n);
}
