// The citation check: a finding survives only when its file exists in the version, its line is in
// range, and its quote is on that line. The eval kept 270 of 275 findings this way; the ones it drops
// are the model misremembering, and a flag with no surviving citation is not treated as a flag.
import type { TarEntry } from "@apm/core";
import { cutPath, linesOf, listedPath, shownPath, singleLine, textOf } from "./files.ts";
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

/** The files a cited path can name, and the path to report when it names none. */
type Candidates = { files: readonly string[]; file: string };

function candidatesOf(raw: string, named: ReadonlyMap<string, readonly string[]>): Candidates {
  // the path exactly as named or as the prompt showed it, before any loosening: `package/x.js` and `x.js` can both be in
  // a tarball, and a citation of one must not land on the other
  for (const p of [raw, raw.trim()]) {
    const files = named.get(p);

    if (files) return { files, file: p };
  }

  const p = raw.trim().replace(/^\.\//, "").replace(/^package\//, "");
  // models sometimes write "path:line" into the file field
  const m = /^(.*):(\d+)$/.exec(p);

  for (const q of m?.[1] ? [p, m[1]] : [p]) {
    const files = named.get(q);

    if (files) return { files, file: q };
  }

  return { files: [], file: p };
}

export type Verified = { kept: Finding[]; dropped: DroppedFinding[] };

/**
 * Every name the prompt showed a file under (its path, escaped onto one line, cut to a citation's length, or cut
 * shorter in a list of paths) and the
 * files shown under it. A publisher can make two files share a shown name (`a\nb.js` and a file literally named
 * `a\\nb.js`, or two paths cut to the same length), so a citation of a shared name is checked against each of them.
 */
function shownNames(files: readonly TarEntry[]): Map<string, string[]> {
  const out = new Map<string, Set<string>>();

  for (const f of files) {
    for (const s of [f.path, singleLine(f.path), shownPath(f.path), listedPath(f.path)]) {
      const named = out.get(s);

      if (named) named.add(f.path);
      else out.set(s, new Set([f.path]));
    }
  }

  return new Map([...out].map(([s, named]) => [s, [...named]]));
}

export function verifyCitations(findings: readonly RawFinding[], files: readonly TarEntry[]): Verified {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const named = shownNames(files);
  const lineCache = new Map<string, string[]>();
  const kept: Finding[] = [];
  const dropped: DroppedFinding[] = [];

  const linesAt = (file: string, entry: TarEntry): string[] => {
    let lines = lineCache.get(file);

    if (!lines) {
      lines = linesOf(textOf(entry));
      lineCache.set(file, lines);
    }

    return lines;
  };

  for (const raw of findings) {
    const candidates = candidatesOf(raw.file, named);

    if (candidates.files.length === 0) {
      dropped.push({ file: candidates.file, line: raw.line, why: "no-such-file" });
      continue;
    }

    let found: { file: string; line: string } | null = null;
    let why: DropReason = "no-such-line";

    for (const file of candidates.files) {
      const entry = byPath.get(file);
      const line = entry && raw.line >= 1 ? linesAt(file, entry)[raw.line - 1] : undefined;

      if (line === undefined) continue;

      if (quoteMatches(line, raw.quote)) {
        found = { file, line };
        break;
      }

      why = "quote-not-on-line";
    }

    if (found === null) {
      dropped.push({ file: candidates.files[0] ?? candidates.file, line: raw.line, why });
      continue;
    }

    const { file, line } = found;
    // recorded as the wire holds it (wire.ts WireFinding): a path past its limit is cut there, as the prompt showed it,
    // and an empty one (a `package/` entry) is named so the wire, which refuses empty strings, keeps the result
    const recorded = file === "" ? '""' : cutPath(file, file);

    if (kept.some((k) => k.file === recorded && k.line === raw.line)) continue;
    kept.push({ file: recorded, line: raw.line, quote: quoteCore(raw.quote), excerpt: excerptOf(line, raw.quote), issue: oneSentence(raw.issue), severity: raw.severity });
  }

  return { kept: kept.slice(0, MAX_FINDINGS), dropped };
}
