// Where each character of a source file sits: code, a string that is a module specifier or the argument of a
// dangerous call, an ordinary string, or text that never runs (a comment, a regex literal's body). Pure and linear.

/**
 * The languages apm can lex. `data` is JSON and type declarations: node parses JSON and never runs it, and a
 * `.d.ts` file only describes code. Anything else is read raw, with every match counted.
 */
export type Lang = "js" | "jsx" | "c" | "python" | "data" | "plain";

/**
 * - `code`: executable text.
 * - `kept`: a string the code hands to something that loads or runs it: `require('x')`, `from 'x'`,
 *   `exec('...')`, `fetch('...')`, `eval('...')`, `readFileSync('...')`.
 * - `string`: any other string or template text.
 * - `excluded`: a comment, or the body of a regex literal.
 * - `raw`: the lexer could not follow this file, so nothing is known and every match counts.
 */
export type Region = "code" | "kept" | "string" | "excluded" | "raw";

export type Range = [number, number];

export type Lexed = {
  /** Every comment, sure or not, in order. */
  comments: Range[];
  /** The region holding `index`. */
  region: (index: number) => Region;
};

/** The language a file is lexed as: by extension, then by a node/bun/deno shebang. */
export function langOf(path: string, text: string): Lang {
  if (/\.(?:json|d\.[cm]?ts)$/i.test(path)) return "data";

  if (/\.[cm]?[jt]s$/i.test(path)) return "js";

  if (/\.[jt]sx$/i.test(path)) return "jsx";

  if (/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|cs|java|go|rs|swift|kt|m|mm)$/i.test(path)) return "c";

  if (/\.py$/i.test(path)) return "python";

  if (!/\.[^/]+$/.test(path) && /^#!.*\b(?:node|bun|deno)\b/.test(text)) return "js";

  return "plain";
}

/** Whether `index` falls inside one of the sorted, disjoint `ranges`. */
export function inRanges(ranges: readonly Range[], index: number): boolean {
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

/** Whether the line holding `index` starts like a comment: `* ...` inside a JSDoc block, `// ...`, `/* ...` or `# ...`. */
export function onCommentLine(text: string, index: number): boolean {
  const start = text.lastIndexOf("\n", index - 1) + 1;

  return /^\s*(?:\*|\/\/|\/\*|#)/.test(text.slice(start, Math.min(index, start + 200)));
}

/** Words after which a `/` starts a regular expression, not a division. */
const REGEX_AFTER_WORD = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await", "default"]);

/** A `(` after these opens a statement header; the `)` that closes it is followed by a statement, so `/` is a regex. */
const HEADER_WORDS = new Set(["if", "while", "for", "with", "catch", "switch"]);

/** After these, `{` opens a block. */
const BLOCK_WORDS = new Set(["else", "do", "try", "finally"]);

/** Calls whose string arguments name what is loaded or run. Matched against the word just before `(`. */
const DANGER_CALLS = new Set([
  "require",
  "import",
  "spawn",
  "spawnSync",
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "fork",
  "execa",
  "execaSync",
  "execaCommand",
  "execaCommandSync",
  "fetch",
  "eval",
  "Function",
  "setTimeout",
  "setInterval",
  "setImmediate",
  "runInThisContext",
  "runInNewContext",
  "runInContext",
  "Script",
  "compileFunction",
  "_compile",
  "readFile",
  "readFileSync",
  "createReadStream",
  "openSync",
  "existsSync",
  "accessSync",
  "statSync",
  "atob",
  "Command",
  "sendBeacon",
  "WebSocket",
  "EventSource",
  "XMLHttpRequest",
  // C, C#, Python
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
  "Popen",
  "check_output",
  "check_call",
  "urlopen",
  "__import__",
  "import_module",
  "b64decode",
  "compile",
]);

/** Methods that load, read or join paths when called on an object: `path.join(home, '.npmrc')`, `Buffer.from(b64, 'base64')`. */
const DANGER_METHODS = new Set(["join", "resolve", "get", "request", "open", "from", "access", "stat", "Start", "run", "call", "urlopen", "post"]);

/** Tags whose template text is a command: `` $`curl ...` `` (zx, Bun.$). */
const DANGER_TAGS = new Set(["$", "sh", "exec", "execa", "execaCommand", "spawn"]);

type BraceKind = "block" | "expr" | "unknown";

type Bracket = { ch: "(" | "[" | "{"; danger: boolean; header: boolean; brace: BraceKind };

type CodeFrame = { kind: "code"; brackets: Bracket[] };

type TemplateFrame = { kind: "template"; kept: boolean; chunk: number };

/**
 * What came just before the current position, for deciding what `/` and `{` mean.
 * `word` carries whether it followed a `.`, so `x.return` is not the keyword.
 */
type Prev =
  | { t: "start" }
  | { t: "word"; w: string; dotted: boolean }
  | { t: "value" }
  | { t: "close-paren"; header: boolean }
  | { t: "close-bracket" }
  | { t: "close-brace"; brace: BraceKind }
  | { t: "incdec" }
  | { t: "punct"; p: string };

type Lists = { comments: Range[]; sure: Range[]; regex: Range[]; strings: Range[]; kept: Range[] };

function slashStartsRegex(prev: Prev): boolean | "unknown" {
  switch (prev.t) {
    case "start":
    case "punct":
      return true;
    case "word":
      return !prev.dotted && REGEX_AFTER_WORD.has(prev.w);
    case "value":
    case "close-bracket":
    case "incdec":
      return false;
    case "close-paren":
      return prev.header;
    case "close-brace":
      return prev.brace === "block" ? true : prev.brace === "expr" ? false : "unknown";
    default: {
      const _exhaustive: never = prev;

      return _exhaustive;
    }
  }
}

function braceKind(prev: Prev): BraceKind {
  switch (prev.t) {
    case "start":
    case "close-brace":
      return "block";
    case "close-paren":
      return prev.header ? "block" : "unknown";
    case "word":
      if (prev.dotted) return "unknown";

      if (BLOCK_WORDS.has(prev.w)) return "block";

      return REGEX_AFTER_WORD.has(prev.w) ? "expr" : "unknown";
    case "punct":
      if (prev.p === ";" || prev.p === "{") return "block";

      return prev.p === "=>" || prev.p === ":" ? "unknown" : "expr";
    case "value":
    case "close-bracket":
    case "incdec":
      return "unknown";
    default: {
      const _exhaustive: never = prev;

      return _exhaustive;
    }
  }
}

/** The end of the regex literal starting at `i` (just past its closing `/` and flags), or -1 when there is none on this line. */
function regexEnd(text: string, i: number): number {
  let inClass = false;

  for (let j = i + 1; j < text.length; j++) {
    const c = text[j];

    if (c === "\n" || c === "\r") return -1;

    if (c === "\\") j++;
    else if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    else if (c === "/" && !inClass) {
      let k = j + 1;

      while (k < text.length && /[a-z]/i.test(text[k] ?? "")) k++;

      return k;
    }
  }

  return -1;
}

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

function isWordChar(c: string): boolean {
  const code = c.charCodeAt(0);

  // identifiers may hold any non-ASCII letter and \u escapes; reading them as punctuation would turn `é / x / y` into a regex
  return /[\w$\\]/.test(c) || (code > 127 && !/\s/.test(c));
}

/**
 * Lexes JavaScript, TypeScript and (with `c`) the C family. Returns null when the lexer lost its place: a bracket
 * closed that was never opened, a template or bracket still open at the end, or a `/` after a `}` that could be
 * either a regex or a division. Then nothing it recorded can be trusted and the caller reads the file raw.
 */
function lexCLike(text: string, c: boolean): Lists | null {
  const lists: Lists = { comments: [], sure: [], regex: [], strings: [], kept: [] };
  const stack: (CodeFrame | TemplateFrame)[] = [{ kind: "code", brackets: [] }];
  let prev: Prev = { t: "start" };
  let i = 0;

  if (text.startsWith("#!")) {
    const nl = text.indexOf("\n");
    const end = nl < 0 ? text.length : nl;

    lists.comments.push([0, end]);
    lists.sure.push([0, end]);
    i = end;
  }

  const code = (): CodeFrame | null => {
    const top = stack[stack.length - 1];

    return top?.kind === "code" ? top : null;
  };

  const inDanger = (): boolean => {
    const top = code()?.brackets.at(-1);

    return top?.danger ?? false;
  };

  const stringIsKept = (): boolean => inDanger() || (prev.t === "word" && !prev.dotted && (prev.w === "from" || prev.w === "import"));

  while (i < text.length) {
    const top = stack[stack.length - 1];
    const ch = text[i] ?? "";

    if (!top) return null;

    if (top.kind === "template") {
      if (ch === "\\") i += 2;
      else if (ch === "`") {
        (top.kept ? lists.kept : lists.strings).push([top.chunk, i + 1]);
        stack.pop();
        i++;
        prev = { t: "value" };
      } else if (ch === "$" && text[i + 1] === "{") {
        (top.kept ? lists.kept : lists.strings).push([top.chunk, i]);
        stack.push({ kind: "code", brackets: [] });
        i += 2;
        prev = { t: "punct", p: "{" };
      } else i++;

      continue;
    }

    if (ch === "/" && text[i + 1] === "/") {
      const nl = text.indexOf("\n", i);
      const end = nl < 0 ? text.length : nl;

      lists.comments.push([i, end]);
      lists.sure.push([i, end]);
      i = end;
    } else if (ch === "/" && text[i + 1] === "*") {
      const close = text.indexOf("*/", i + 2);

      // an unclosed block comment is a syntax error, so it counts as code
      if (close < 0) {
        i += 2;
        prev = { t: "punct", p: "/*" };
      } else {
        lists.comments.push([i, close + 2]);
        lists.sure.push([i, close + 2]);
        i = close + 2;
      }
    } else if (ch === "/") {
      const regex = c ? false : slashStartsRegex(prev);
      const end = regex === false ? -1 : regexEnd(text, i);

      // a `/` that could start either is the one place this lexer would have to guess
      if (regex === "unknown" && end > 0) return null;

      if (end > 0) {
        lists.regex.push([i, end]);
        i = end;
        prev = { t: "value" };
      } else {
        i++;
        prev = { t: "punct", p: "/" };
      }
    } else if (ch === "'" || ch === '"') {
      const end = stringEnd(text, i, ch);

      (stringIsKept() ? lists.kept : lists.strings).push([i, end]);
      i = end;
      prev = { t: "value" };
    } else if (ch === "`" && !c) {
      const tagged = prev.t === "word" && DANGER_TAGS.has(prev.w);

      stack.push({ kind: "template", kept: tagged || stringIsKept(), chunk: i });
      i++;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      const frame = code();

      if (!frame) return null;
      const parentDanger = inDanger();
      const word = prev.t === "word" ? prev : null;

      if (ch === "(") {
        const callee = word !== null && (DANGER_CALLS.has(word.w) || (word.dotted && DANGER_METHODS.has(word.w)));
        frame.brackets.push({ ch, danger: callee || parentDanger, header: word !== null && !word.dotted && HEADER_WORDS.has(word.w), brace: "expr" });
      } else if (ch === "[") {
        frame.brackets.push({ ch, danger: parentDanger || (word?.w === "env" && word.dotted), header: false, brace: "expr" });
      } else {
        const brace = braceKind(prev);
        // a function body or block inside a dangerous call's arguments is not itself an argument
        frame.brackets.push({ ch, danger: brace === "expr" && parentDanger, header: false, brace });
      }

      i++;
      prev = { t: "punct", p: ch };
    } else if (ch === ")" || ch === "]" || ch === "}") {
      const frame = code();

      if (!frame) return null;

      if (ch === "}" && frame.brackets.length === 0 && stack.length > 1) {
        // the end of a template's ${...}
        stack.pop();
        const tpl = stack[stack.length - 1];

        if (tpl?.kind !== "template") return null;
        tpl.chunk = i;
        i++;
        continue;
      }

      const open = frame.brackets.pop();

      if (!open || open.ch !== (ch === ")" ? "(" : ch === "]" ? "[" : "{")) return null;
      i++;
      prev = ch === ")" ? { t: "close-paren", header: open.header } : ch === "]" ? { t: "close-bracket" } : { t: "close-brace", brace: open.brace };
    } else if ((ch === "+" || ch === "-") && text[i + 1] === ch) {
      i += 2;
      prev = { t: "incdec" };
    } else if (ch === "=" && text[i + 1] === ">") {
      i += 2;
      prev = { t: "punct", p: "=>" };
    } else if (isWordChar(ch)) {
      let j = i + 1;

      while (j < text.length && isWordChar(text[j] ?? "")) j++;
      const dotted: boolean = prev.t === "punct" && (prev.p === "." || prev.p === "?.");

      prev = { t: "word", w: text.slice(i, j), dotted };
      i = j;
    } else {
      if (!/\s/.test(ch)) prev = ch === "?" && text[i + 1] === "." ? { t: "punct", p: "?." } : { t: "punct", p: ch };
      i += ch === "?" && text[i + 1] === "." ? 2 : 1;
    }
  }

  const last = stack[0];

  if (stack.length !== 1 || last?.kind !== "code" || last.brackets.length > 0) return null;

  return lists;
}

/** Lexes Python: `#` comments, quoted and triple-quoted strings. No regex literals, no templates. */
function lexPython(text: string): Lists | null {
  const lists: Lists = { comments: [], sure: [], regex: [], strings: [], kept: [] };
  const brackets: { ch: string; danger: boolean }[] = [];
  let word: { w: string; dotted: boolean } | null = null;
  let lastPunct = "";
  let i = 0;

  while (i < text.length) {
    const ch = text[i] ?? "";

    if (ch === "#") {
      const nl = text.indexOf("\n", i);
      const end = nl < 0 ? text.length : nl;

      lists.comments.push([i, end]);
      lists.sure.push([i, end]);
      i = end;
    } else if (ch === "'" || ch === '"') {
      const triple = text.startsWith(ch.repeat(3), i);
      let end: number;

      if (triple) {
        const close = text.indexOf(ch.repeat(3), i + 3);

        if (close < 0) return null;
        end = close + 3;
      } else end = stringEnd(text, i, ch);
      const kept = brackets.at(-1)?.danger ?? false;

      (kept ? lists.kept : lists.strings).push([i, end]);
      i = end;
      word = null;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      const callee = ch === "(" && word !== null && (DANGER_CALLS.has(word.w) || (word.dotted && DANGER_METHODS.has(word.w)));
      brackets.push({ ch, danger: callee || (brackets.at(-1)?.danger ?? false) });
      word = null;
      i++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      if (!brackets.pop()) return null;
      word = null;
      i++;
    } else if (/\w/.test(ch)) {
      let j = i + 1;

      while (j < text.length && /\w/.test(text[j] ?? "")) j++;
      word = { w: text.slice(i, j), dotted: lastPunct === "." };
      lastPunct = "";
      i = j;
    } else {
      if (!/\s/.test(ch)) {
        lastPunct = ch;
        word = null;
      }

      i++;
    }
  }

  return brackets.length === 0 ? lists : null;
}

/**
 * Lexes `text` as `lang`. A file the lexer cannot follow, and `plain` and `jsx` files, read as `raw` everywhere
 * except comments on lines that start like one; JSX text such as `<p>it's http://x</p>` would otherwise
 * open strings and comments that are not there.
 */
export function lex(text: string, lang: Lang): Lexed {
  if (lang === "data") return { comments: [], region: () => "string" };

  const lists = lang === "js" ? lexCLike(text, false) : lang === "c" ? lexCLike(text, true) : lang === "python" ? lexPython(text) : null;

  if (!lists) {
    // read raw: a comment only hides what is on a line that starts like a comment
    const comments = lang === "plain" || lang === "python" ? [] : (lexCLike(text, false)?.comments ?? looseComments(text));

    return {
      comments,
      region: (index) => (inRanges(comments, index) && onCommentLine(text, index) ? "excluded" : "raw"),
    };
  }

  return {
    comments: lists.comments,
    region: (index) => {
      if (inRanges(lists.sure, index) || inRanges(lists.regex, index)) return "excluded";

      if (inRanges(lists.kept, index)) return "kept";

      return inRanges(lists.strings, index) ? "string" : "code";
    },
  };
}

/** Comments found without trusting anything else: every `//` to the end of its line and every closed block comment. */
function looseComments(text: string): Range[] {
  const out: Range[] = [];
  let i = text.indexOf("/");

  while (i >= 0 && i < text.length) {
    const next = text[i + 1];
    let end = -1;

    if (next === "/") {
      const nl = text.indexOf("\n", i);
      end = nl < 0 ? text.length : nl;
    } else if (next === "*") {
      const close = text.indexOf("*/", i + 2);

      // with no closing `*/` left, no later `/*` can close either
      if (close < 0) break;
      end = close + 2;
    }

    if (end > 0) out.push([i, end]);
    i = text.indexOf("/", end > 0 ? end : i + 1);
  }

  return out;
}

/** The [start, end) offsets of every comment in JavaScript or TypeScript source. */
export function commentRanges(text: string): Range[] {
  return lex(text, "js").comments;
}
