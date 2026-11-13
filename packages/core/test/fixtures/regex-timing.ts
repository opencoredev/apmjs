// The adversarial timing harness for regexes over package text, shared by regex-linear.test.ts (every literal) and
// runtime-regex.test.ts (every pattern built at runtime). A backtracking engine makes some shapes quadratic or worse;
// this builds inputs made of the characters such shapes need, times each regex on them, and times it again at twice
// the length: about twice the time when linear, four times when quadratic.

/** Characters the shapes need: word characters, `$`, digits, blanks, quotes, slashes and brackets. */
const ALPHABET = ["a", "$", "9", " ", "\n", "'", '"', "`", ".", "(", ",", "=", "\\", "/", "_", ":", "[", "x", "+", "-"];

/** What may sit between a word the pattern names and a long run after it: `for (` then n blanks, say. */
const JOINS = ["", " ", "(", " (", ".", "=", ":", "["];

/** The runs that follow one word: blanks, newlines, tabs, word characters, digits, quotes, dots. */
const RUNS = [" ", "\n", "\t", "a", "$", "9", "'", "."];

/** The words a pattern names, read after its escapes are dropped (`\bfor` names "for", not "bfor"). */
function wordsOf(re: RegExp): string[] {
  return [...new Set(re.source.replace(/\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)/g, " ").match(/[A-Za-z_]{3,}/g) ?? [])];
}

/** Long repeats of one character or a pair, and the pattern's first words repeated with what may follow them. */
export function repeats(re: RegExp, n: number): string[] {
  const out: string[] = [];

  for (const a of ALPHABET) out.push(a.repeat(n));

  for (let i = 0; i < ALPHABET.length; i++) for (let j = i + 1; j < ALPHABET.length; j++) out.push(`${ALPHABET[i] ?? ""}${ALPHABET[j] ?? ""}`.repeat(n / 2));

  for (const w of wordsOf(re).slice(0, 4)) {
    for (const tail of [" ", "(", ".", "a$", "  ", "\\x41"]) out.push(`${w}${tail}`.repeat(Math.floor(n / (w.length + tail.length))));
  }

  return out;
}

/**
 * One start, then one long run: every word the pattern names, a join, n of one character and a character that ends
 * nothing (`for (` + n blanks + `!`). A pattern that splits the run among adjacent quantifiers is quadratic from that
 * one start, which repeats of the whole input do not show.
 */
export function prefixRuns(re: RegExp, n: number): string[] {
  const out: string[] = [];

  for (const w of wordsOf(re)) for (const j of JOINS) for (const c of RUNS) out.push(`${w}${j}${c.repeat(n)}!`);

  return out;
}

/** Milliseconds `re` (made global) takes to find every match in `s`, stopping after 100,000 matches. */
export function ms(re: RegExp, s: string): number {
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  const t = performance.now();
  let k = 0;

  for (const _ of s.matchAll(g)) if (++k > 100_000) break;

  return performance.now() - t;
}

/**
 * The inputs `make` builds at which `re` grows faster than its input, described. A linear pattern reads 16,000
 * characters in well under a millisecond; only a slow one is timed again, best of two, at twice the length.
 */
export function slowOn(where: string, re: RegExp, make: (re: RegExp, n: number) => string[], n = 16_000): string[] {
  const slow: string[] = [];
  const once = make(re, n);
  let twiceAll: string[] | null = null;

  once.forEach((s, i) => {
    if (ms(re, s) < 8) return;
    twiceAll ??= make(re, n * 2);
    const twice = twiceAll[i] ?? "";
    const a = Math.min(ms(re, s), ms(re, s));
    const b = Math.min(ms(re, twice), ms(re, twice));

    if (b > 3 * a && b > 8) slow.push(`${where} on ${JSON.stringify(s.slice(0, 12))}…: ${a.toFixed(1)} ms, then ${b.toFixed(1)} ms at twice the length`);
  });

  return slow;
}
