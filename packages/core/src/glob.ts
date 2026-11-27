// Wildcard matching for patterns a package writes (capability declarations, npm-run-all script patterns, `exports`
// subpath patterns). Each was a regex built from the pattern (`*` as `.*`, or `(.+)` and `\1`), and a pattern with
// many stars made the engine try every way to split the text between them: exponential in the stars. These match in
// one pass with no search. Pure.
import { charge } from "./meter.ts";

/**
 * Whether `text` matches `pattern`, each `*` standing for any run of characters (empty too). The classic greedy match:
 * on a mismatch it moves only the last star's start, so it takes at most `text.length × pattern.length` steps, which
 * are charged before it runs.
 */
export function wildcardMatch(text: string, pattern: string): boolean {
  charge("score", Math.ceil(((text.length + 1) * (pattern.length + 1)) / 32));
  let t = 0;
  let p = 0;
  let star = -1;
  let mark = 0;

  while (t < text.length) {
    const c = pattern[p];

    if (c !== undefined && c !== "*" && c === text[t]) {
      t++;
      p++;
    } else if (c === "*") {
      star = p++;
      mark = t;
    } else if (star >= 0) {
      p = star + 1;
      t = ++mark;
    } else return false;
  }

  while (pattern[p] === "*") p++;

  return p === pattern.length;
}

/**
 * Whether `text` is `parts` joined with one same non-empty substitution between each (node's `exports` subpath
 * patterns: every `*` stands for the same text). The substitution's length is fixed by the lengths, so this is a
 * single comparison pass. `parts` has at least two entries: the text before the first `*` and after the last.
 */
export function sameSubstitution(text: string, parts: readonly string[]): boolean {
  charge("score", Math.ceil(text.length / 32) + 1);
  const stars = parts.length - 1;

  if (stars < 1) return text === parts[0];
  const fixed = parts.reduce((n, s) => n + s.length, 0);
  const each = (text.length - fixed) / stars;

  if (!Number.isInteger(each) || each < 1) return false;
  let at = 0;
  let sub: string | null = null;

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] ?? "";

    if (!text.startsWith(part, at)) return false;
    at += part.length;

    if (i === parts.length - 1) break;
    const piece = text.slice(at, at + each);

    if (sub === null) sub = piece;
    else if (piece !== sub) return false;
    at += each;
  }

  return at === text.length;
}

/** One character of a shell glob: a literal, `?`, `*`, or a bracket class (`[a-z]`, `[!x]`). */
type GlobToken = { kind: "literal"; c: string } | { kind: "any" } | { kind: "star" } | { kind: "class"; negated: boolean; ranges: [string, string][] };

/**
 * The tokens of one path segment of a shell glob, in one pass: a `[` with no `]` after it is a literal, as the shell
 * reads it, which the last `]`'s position tells without a search from each one.
 */
function globTokens(segment: string): GlobToken[] {
  const out: GlobToken[] = [];
  const lastClose = segment.lastIndexOf("]");

  for (let i = 0; i < segment.length; i++) {
    const c = segment[i] ?? "";

    if (c === "*") out.push({ kind: "star" });
    else if (c === "?") out.push({ kind: "any" });
    else if (c === "[" && lastClose > i + 1) {
      let j = i + 1;
      const negated = segment[j] === "!" || segment[j] === "^";

      if (negated) j++;
      const from = j;

      // a `]` first in the class is one of its characters
      if (segment[j] === "]") j++;

      while (j < lastClose && segment[j] !== "]") j++;

      if (segment[j] !== "]" || j <= from) {
        out.push({ kind: "literal", c });
        continue;
      }
      const ranges: [string, string][] = [];

      for (let k = from; k < j; k++) {
        const lo = segment[k] ?? "";

        if (segment[k + 1] === "-" && k + 2 < j) {
          ranges.push([lo, segment[k + 2] ?? ""]);
          k += 2;
        } else ranges.push([lo, lo]);
      }

      out.push({ kind: "class", negated, ranges });
      i = j;
    } else out.push({ kind: "literal", c });
  }

  return out;
}

function tokenMatches(t: GlobToken, c: string): boolean {
  if (t.kind === "literal") return t.c === c;

  if (t.kind === "class") return t.ranges.some(([lo, hi]) => lo <= c && c <= hi) !== t.negated;

  return true;
}

/**
 * Whether `path` matches the shell glob `pattern` segment by segment, as sh expands it: `*`, `?` and bracket classes
 * match within one segment, never a `/`, and never a segment's leading `.`, which only a literal `.` matches. Each
 * segment is the greedy match wildcardMatch uses, so it takes at most `path.length × pattern.length` steps, which are
 * charged before anything is read.
 */
export function shellGlobMatch(path: string, pattern: string): boolean {
  charge("score", Math.ceil(((path.length + 1) * (pattern.length + 1)) / 32));
  const texts = path.split("/");
  const patterns = pattern.split("/");

  if (texts.length !== patterns.length) return false;

  return patterns.every((p, i) => {
    const text = texts[i] ?? "";
    const tokens = globTokens(p);

    if (text.startsWith(".") && !(tokens[0]?.kind === "literal" && tokens[0].c === ".")) return false;
    let t = 0;
    let k = 0;
    let star = -1;
    let mark = 0;

    while (t < text.length) {
      const tok = tokens[k];

      if (tok !== undefined && tok.kind !== "star" && tokenMatches(tok, text[t] ?? "")) {
        t++;
        k++;
      } else if (tok?.kind === "star") {
        star = k++;
        mark = t;
      } else if (star >= 0) {
        k = star + 1;
        t = ++mark;
      } else return false;
    }

    while (tokens[k]?.kind === "star") k++;

    return k === tokens.length;
  });
}
