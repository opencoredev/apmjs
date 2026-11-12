// Where each character of a C-family or Python file sits: code, a string that is the argument of a call that runs or
// loads it, an ordinary string, or a comment. JavaScript and TypeScript are parsed instead (parse.ts, js.ts). Pure.

/**
 * The languages this lexer reads. `data` is JSON and type declarations: node parses JSON and never runs it, and a
 * `.d.ts` file only describes code, so everything in them is a string. `plain` is read raw.
 */
export type Lang = "c" | "python" | "data" | "plain";

/**
 * - `code`: executable text.
 * - `kept`: a string the code hands to something that runs or loads it: `system("...")`, `subprocess.run("...")`.
 * - `string`: any other string.
 * - `excluded`: a comment.
 * - `raw`: the lexer could not follow this file, so nothing is known and every match counts.
 */
export type Region = "code" | "kept" | "string" | "excluded" | "raw";

type Range = [number, number];

export type Lexed = {
  /** The region holding `index`. */
  region: (index: number) => Region;
};

/** Whether `index` falls inside one of the sorted, disjoint `ranges`. */
function inRanges(ranges: readonly Range[], index: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;

  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = ranges[mid];

    if (!r) return false;

    if (index < r[0]) hi = mid - 1;
    else if (index >= r[1]) lo = mid + 1;
    else return true;
  }

  return false;
}

/** Calls whose string arguments name what is run or loaded. Matched against the word just before `(`. */
const DANGER_CALLS = new Set([
  // C, C#, Go, Rust, Java
  "system",
  "popen",
  "_popen",
  "execl",
  "execlp",
  "execle",
  "execv",
  "execvp",
  "execve",
  "ShellExecute",
  "ShellExecuteA",
  "ShellExecuteW",
  "ShellExecuteEx",
  "CreateProcess",
  "CreateProcessA",
  "CreateProcessW",
  "WinExec",
  "Command",
  "exec",
  // Python
  "Popen",
  "run",
  "call",
  "check_output",
  "check_call",
  "urlopen",
  "__import__",
  "import_module",
  "b64decode",
  "compile",
  "eval",
  "open",
]);

type Lists = { comments: Range[]; strings: Range[]; kept: Range[] };

/** The end of the quoted string starting at `i` (past its closing quote, or at the end of the line when it has none). */
function stringEnd(text: string, i: number, quote: string): number {
  for (let j = i + 1; j < text.length; j++) {
    const c = text[j];

    if (c === "\\") j++;
    else if (c === quote) return j + 1;
    else if (c === "\n") return j;
  }

  return text.length;
}

/**
 * Lexes the C family: `//` and block comments, strings and character literals. A `//` comment ends at the end of its
 * line even after a backslash, so a file that also runs as JavaScript cannot hide code on the next line. Brackets
 * are only tracked to see which strings a call takes: the preprocessor (`#if` ... `#else`) leaves them unbalanced
 * in ordinary C, so an unbalanced bracket is not a reason to give up.
 */
function lexC(text: string): Lists | null {
  const lists: Lists = { comments: [], strings: [], kept: [] };
  const brackets: { danger: boolean }[] = [];
  let word: string | null = null;
  let i = 0;

  while (i < text.length) {
    const ch = text[i] ?? "";

    if (ch === "/" && text[i + 1] === "/") {
      const nl = text.indexOf("\n", i);
      const end = nl < 0 ? text.length : nl;

      lists.comments.push([i, end]);
      i = end;
    } else if (ch === "/" && text[i + 1] === "*") {
      const close = text.indexOf("*/", i + 2);

      // an unclosed block comment is a syntax error, so it counts as code
      if (close < 0) i += 2;
      else {
        lists.comments.push([i, close + 2]);
        i = close + 2;
      }
    } else if (ch === "'" || ch === '"') {
      const end = stringEnd(text, i, ch);

      (brackets.at(-1)?.danger ? lists.kept : lists.strings).push([i, end]);
      i = end;
      word = null;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      const callee = ch === "(" && word !== null && DANGER_CALLS.has(word);
      brackets.push({ danger: callee || (brackets.at(-1)?.danger ?? false) });
      word = null;
      i++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      brackets.pop();
      word = null;
      i++;
    } else if (/\w/.test(ch)) {
      let j = i + 1;

      while (j < text.length && /\w/.test(text[j] ?? "")) j++;
      word = text.slice(i, j);
      i = j;
    } else {
      if (!/\s/.test(ch)) word = null;
      i++;
    }
  }

  return lists;
}

/** Lexes Python: `#` comments, quoted and triple-quoted strings. */
function lexPython(text: string): Lists | null {
  const lists: Lists = { comments: [], strings: [], kept: [] };
  const brackets: { danger: boolean }[] = [];
  let word: string | null = null;
  let i = 0;

  while (i < text.length) {
    const ch = text[i] ?? "";

    if (ch === "#") {
      const nl = text.indexOf("\n", i);
      const end = nl < 0 ? text.length : nl;

      lists.comments.push([i, end]);
      i = end;
    } else if (ch === "'" || ch === '"') {
      const triple = text.startsWith(ch.repeat(3), i);
      let end: number;

      if (triple) {
        const close = text.indexOf(ch.repeat(3), i + 3);

        if (close < 0) return null;
        end = close + 3;
      } else end = stringEnd(text, i, ch);

      (brackets.at(-1)?.danger ? lists.kept : lists.strings).push([i, end]);
      i = end;
      word = null;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      const callee = ch === "(" && word !== null && DANGER_CALLS.has(word);
      brackets.push({ danger: callee || (brackets.at(-1)?.danger ?? false) });
      word = null;
      i++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      if (!brackets.pop()) return null;
      word = null;
      i++;
    } else if (/\w/.test(ch)) {
      let j = i + 1;

      while (j < text.length && /\w/.test(text[j] ?? "")) j++;
      word = text.slice(i, j);
      i = j;
    } else {
      if (!/\s/.test(ch)) word = null;
      i++;
    }
  }

  return brackets.length === 0 ? lists : null;
}

/** Lexes `text` as `lang`. A file the lexer cannot follow, and `plain` files, are `raw` everywhere: every match counts. */
export function lex(text: string, lang: Lang): Lexed {
  if (lang === "data") return { region: () => "string" };
  const lists = lang === "c" ? lexC(text) : lang === "python" ? lexPython(text) : null;

  if (!lists) return { region: () => "raw" };

  return {
    region: (index) => {
      if (inRanges(lists.comments, index)) return "excluded";

      if (inRanges(lists.kept, index)) return "kept";

      return inRanges(lists.strings, index) ? "string" : "code";
    },
  };
}
