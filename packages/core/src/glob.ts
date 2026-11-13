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
