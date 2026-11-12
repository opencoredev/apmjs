// The citation check: a finding survives only when its file exists in the version, its line is in
// range, and its quote is on that line. The eval kept 270 of 275 findings this way; the ones it drops
// are the model misremembering, and a flag with no surviving citation is not treated as a flag.
import type { TarEntry } from "@apm/core";
import { linesOf, textOf } from "./files.ts";
import type { RawFinding, Severity } from "./reply.ts";

export type Finding = {
  file: string;
  line: number;
  /** The model's quote, checked against the line. */
  quote: string;
  /** The cited line from the package, cut around the quote when it is long. */
  excerpt: string;
  /** One sentence on what the line does. */
  issue: string;
  severity: Severity;
};

export type DropReason = "no-such-file" | "no-such-line" | "quote-not-on-line";

export type DroppedFinding = { file: string; line: number; why: DropReason };

/** Findings kept per review. The prompt asks for at most six. */
export const MAX_FINDINGS = 6;
const MAX_QUOTE = 160;
const EXCERPT_CHARS = 240;

const norm = (s: string): string => s.replace(/\s+/g, " ").trim();

function quoteCore(quote: string): string {
  const first = quote.split("\n").map((s) => s.trim()).find((s) => s !== "") ?? "";

  return norm(first.replace(/^(?:\.\.\.|…)+|(?:\.\.\.|…)+$/g, "")).slice(0, MAX_QUOTE);
}

/** True when the quote (its first line, ellipses trimmed) appears on the line, whitespace-insensitive. */
export function quoteMatches(line: string, quote: string): boolean {
  const q = quoteCore(quote);

  if (q.length < 3) return false;
  const l = norm(line);

  return l.includes(q) || (q.length > 40 && l.includes(q.slice(0, 40)));
}

/** The line, or a window of it around the quote when the line is long (minified code). */
export function excerptOf(line: string, quote: string): string {
  const l = norm(line);

  if (l.length <= EXCERPT_CHARS) return l;
  const q = quoteCore(quote);
  const at = Math.max(0, l.indexOf(q.length > 40 ? q.slice(0, 40) : q));
  const start = Math.max(0, Math.min(at - 40, l.length - EXCERPT_CHARS));

  return `${start > 0 ? "…" : ""}${l.slice(start, start + EXCERPT_CHARS)}${start + EXCERPT_CHARS < l.length ? "…" : ""}`;
}

/** The first sentence, at most 300 characters. */
export function oneSentence(text: string): string {
  const t = norm(text);
  const m = /^(.+?[.!?])(?:\s|$)/.exec(t);
  const s = m?.[1] ?? t;

  return s.length > 300 ? `${s.slice(0, 297)}…` : s;
}

function normalizePath(raw: string, paths: ReadonlySet<string>): string {
  const p = raw.trim().replace(/^\.\//, "").replace(/^package\//, "");

  if (paths.has(p)) return p;
  // models sometimes write "path:line" into the file field
  const m = /^(.*):(\d+)$/.exec(p);

  return m?.[1] && paths.has(m[1]) ? m[1] : p;
}

export type Verified = { kept: Finding[]; dropped: DroppedFinding[] };

export function verifyCitations(findings: readonly RawFinding[], files: readonly TarEntry[]): Verified {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const paths = new Set(byPath.keys());
  const lineCache = new Map<string, string[]>();
  const kept: Finding[] = [];
  const dropped: DroppedFinding[] = [];

  for (const raw of findings) {
    const file = normalizePath(raw.file, paths);
    const entry = byPath.get(file);

    if (!entry) {
      dropped.push({ file, line: raw.line, why: "no-such-file" });
      continue;
    }

    let lines = lineCache.get(file);

    if (!lines) {
      lines = linesOf(textOf(entry));
      lineCache.set(file, lines);
    }

    const line = raw.line >= 1 ? lines[raw.line - 1] : undefined;

    if (line === undefined) {
      dropped.push({ file, line: raw.line, why: "no-such-line" });
      continue;
    }

    if (!quoteMatches(line, raw.quote)) {
      dropped.push({ file, line: raw.line, why: "quote-not-on-line" });
      continue;
    }

    if (kept.some((k) => k.file === file && k.line === raw.line)) continue;
    kept.push({ file, line: raw.line, quote: quoteCore(raw.quote), excerpt: excerptOf(line, raw.quote), issue: oneSentence(raw.issue), severity: raw.severity });
  }

  return { kept: kept.slice(0, MAX_FINDINGS), dropped };
}
