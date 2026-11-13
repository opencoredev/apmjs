// Parses JavaScript and TypeScript with maintained parsers: acorn (with acorn-jsx) for JavaScript and JSX, and
// Babel's parser with its TypeScript and ESTree plugins for TypeScript. Both give ESTree nodes with source offsets,
// and every comment's range. A file no parser accepts is not guessed at: the caller reads it raw. Pure.
import { parse as parseBabel, type ParserPlugin } from "@babel/parser";
import { Parser, type Options, type Program } from "acorn";
import jsx from "acorn-jsx";
import { charge, chargeText, MeterExhausted } from "./meter.ts";

/** How a file is parsed: by extension, then by content (a `.js` file holding JSX). */
export type Dialect = "js" | "jsx" | "ts" | "tsx";

/** The two ECMAScript goals. CommonJS runs as a script (with `return` allowed at the top); ES modules as a module. */
export type Goal = "script" | "module";

export type Range = [number, number];

/** One way the file parsed: the program, every comment's range, and the goal and dialect it parsed under. */
export type Parsed = { program: Program; comments: Range[]; goal: Goal; dialect: Dialect };

/**
 * How parsing went: every program was handed over (`parsed`), no parser accepted the file (`syntax`), or a parser
 * stopped at one of its own limits before it could say either: too many tokens or bytes to hold as a tree
 * (`too-large`), or nesting deep enough to exhaust the stack (`too-deep`). Only `syntax` is a verdict on the file; the
 * two limits leave it unread, which makes an analysis incomplete (source.ts).
 */
export type ParseOutcome = "parsed" | "syntax" | "too-large" | "too-deep";

/**
 * The most tokens one file may have and still be parsed into a tree. acorn's tree costs 90 to 95 bytes a token in V8
 * (measured on sass.dart.js and next's webpack bundle), so this keeps a tree near 45 MB inside the Worker's 128 MB
 * alongside the tarball (at most 48 MB inflated). Larger files, nearly always bundles, are read raw.
 */
export const MAX_PARSED_TOKENS = 480_000;

/** Babel's tree costs about three times acorn's, so TypeScript files are capped by size: about 40 MB of tree. */
export const MAX_PARSED_TS_BYTES = 1024 * 1024;

const JsxParser = Parser.extend(jsx());

/** Units of meter one acorn token costs (meter.ts): reading it and building its share of the tree. */
const PARSE_UNITS_PER_TOKEN = 4;

/**
 * Units Babel is charged per character of a try, as text passes (CHARS_PER_UNIT characters a unit): Babel builds about
 * three times acorn's tree, and a file has up to one token a character.
 */
const BABEL_PASSES = 64;

class TooLarge extends Error {}

/** A parser's recursion ran out of stack: a limit of the parser, not a syntax error in the file. */
class TooDeep extends Error {}

function acornParse(text: string, goal: Goal, withJsx: boolean): Parsed | "syntax" {
  const comments: Range[] = [];
  let tokens = 0;

  const options: Options = {
    ecmaVersion: "latest",
    sourceType: goal,
    allowHashBang: true,
    // node wraps CommonJS in a function, so `return` at the top of a file is allowed
    allowReturnOutsideFunction: goal === "script",
    onComment: (_block, _text, start, end) => {
      chargeText("parse", end - start);
      comments.push([start, end]);
    },
    onToken: () => {
      // a token read and its share of the tree built: what the parse costs grows with tokens, not characters
      charge("parse", PARSE_UNITS_PER_TOKEN);

      if (++tokens > MAX_PARSED_TOKENS) throw new TooLarge();
    },
  };

  // the scan over the characters, which a run of blanks or one long string makes larger than its tokens
  chargeText("parse", text.length);

  try {
    const program = (withJsx ? JsxParser : Parser).parse(text, options);

    return { program, comments, goal, dialect: withJsx ? "jsx" : "js" };
  } catch (e) {
    if (e instanceof TooLarge || e instanceof MeterExhausted) throw e;

    // a stack too deep for acorn's recursion says nothing about the syntax: node may well run the file. V8 throws a
    // RangeError for it, and nothing else in the parsers does
    if (e instanceof RangeError) throw new TooDeep();

    return "syntax";
  }
}

/**
 * Decorators come in two dialects that one Babel parse cannot take at once: TypeScript's `experimentalDecorators`
 * (`@dec export class`, parameter decorators) and the standard proposal (`export @dec class`). The legacy one is tried
 * first, as most TypeScript that ships decorators was written for it.
 */
const DECORATORS: readonly ParserPlugin[] = ["decorators-legacy", "decorators"];

function babelParse(text: string, goal: Goal, base: readonly ParserPlugin[], dialect: Dialect): Parsed | "syntax" {
  for (const decorators of DECORATORS) {
    // Babel has no token hook: a try is charged for the most it can read, every character as a token
    chargeText("parse", text.length, BABEL_PASSES);

    try {
      const file = parseBabel(text, { sourceType: goal, plugins: [...base, decorators], allowReturnOutsideFunction: goal === "script", attachComment: false, errorRecovery: false });
      const comments: Range[] = (file.comments ?? []).map((c) => [c.start ?? 0, c.end ?? 0]);
      const program: unknown = file.program;

      if (!isProgram(program)) return "syntax";

      // Babel keeps a hashbang as the program's interpreter, not as a comment; it is one all the same
      const hashbang = file.program.interpreter;

      if (hashbang?.start != null && hashbang.end != null) comments.unshift([hashbang.start, hashbang.end]);

      return { program, comments, goal, dialect };
    } catch (e) {
      if (e instanceof MeterExhausted) throw e;

      if (e instanceof RangeError) throw new TooDeep();
      // the other decorator dialect, if any, is tried next
    }
  }

  return "syntax";
}

/**
 * With its estree plugin Babel emits ESTree nodes, the shape acorn's types describe, under a Program root. TypeScript
 * adds node types acorn does not list; js.ts reads only the ones that carry runtime code and passes over the rest.
 */
function isProgram(v: unknown): v is Program {
  return v instanceof Object && "type" in v && v.type === "Program" && "body" in v && Array.isArray(v.body);
}

/** Whether a comment is an HTML-like one (`<!--`, or `-->` at the start of a line), which only scripts have. */
function hasHtmlComment(text: string, comments: readonly Range[]): boolean {
  charge("parse", comments.length);

  return comments.some(([start]) => text.startsWith("<!--", start) || text.startsWith("-->", start));
}

/**
 * Reads one program. Returns true when the reader saw something a module would read differently (`await` used as
 * a name), so the file is read as a module too.
 */
export type ReadEach = (p: Parsed) => boolean;

/** Runs a parse, turning a parser limit it hit into its outcome. */
function limited(parse: () => ParseOutcome): ParseOutcome {
  try {
    return parse();
  } catch (e) {
    if (e instanceof TooLarge) return "too-large";

    if (e instanceof TooDeep) return "too-deep";
    throw e;
  }
}

function parseTs(text: string, withJsx: boolean, each: ReadEach): ParseOutcome {
  if (text.length > MAX_PARSED_TS_BYTES) return "too-large";

  return limited(() => parseTsUnlimited(text, withJsx, each));
}

function parseTsUnlimited(text: string, withJsx: boolean, each: ReadEach): ParseOutcome {
  const base: ParserPlugin[] = withJsx ? ["estree", "typescript", "jsx"] : ["estree", "typescript"];

  for (const goal of ["module", "script"] as const) {
    const p = babelParse(text, goal, base, withJsx ? "tsx" : "ts");

    if (p === "syntax") continue;

    // TypeScript has no HTML-like comments, so a parse that needed one is a parse of something else
    if (hasHtmlComment(text, p.comments)) return "syntax";
    each(p);

    return alsoAsJs(text, each);
  }

  return "syntax";
}

/**
 * A TypeScript file that is valid JavaScript as well runs as JavaScript wherever nothing strips its types (node
 * before type stripping loads `require('./x.ts')` as JavaScript), and the two can mean different code:
 * `f<import('child_process').T>(0)` is a call with a type argument in TypeScript and loads child_process in
 * JavaScript. So when acorn accepts the file its JavaScript programs are read too, the same way a `.js` file's are.
 */
function alsoAsJs(text: string, each: ReadEach): ParseOutcome {
  const script = acornParse(text, "script", false);

  if (script !== "syntax") {
    if (each(script) || hasHtmlComment(text, script.comments)) {
      const module = acornParse(text, "module", false);

      if (module !== "syntax") each(module);
    }

    return "parsed";
  }

  const module = acornParse(text, "module", false);

  if (module !== "syntax") each(module);

  return "parsed";
}

/**
 * JavaScript acorn rejects but Babel reads: decorators, which acorn does not parse. Babel's tree costs three times
 * acorn's, so this is held to the TypeScript size cap. Flow is not enabled: its type annotations would read as code.
 */
function parseJsWithBabel(text: string, each: ReadEach): ParseOutcome {
  // acorn, which reads all of the JavaScript node runs, rejected the file: its verdict stands, and Babel only adds the
  // decorator dialect node does not run, so skipping it on a large file leaves nothing node would run unread
  if (text.length > MAX_PARSED_TS_BYTES) return "syntax";

  for (const goal of ["module", "script"] as const) {
    const p = babelParse(text, goal, ["estree", "jsx"], "jsx");

    if (p === "syntax") continue;
    each(p);

    return "parsed";
  }

  return "syntax";
}

/**
 * Parses `text` as `dialect` and hands each program to `each`, one at a time, so only one tree is held at once.
 * JavaScript is tried as a script first (CommonJS, and old browser scripts with their HTML-like comments), then as a
 * module, then, for a `.js` file, with JSX. Two things parse in both goals but mean different code: an HTML-like
 * comment (`x <!-- y` hides the rest of the line in a script, and is `x < !--y` in a module) and `await` (a name in
 * a script, so `await (f)(x)` calls `await`; an operator in a module, which calls `f`). A script with either is
 * parsed as a module too and both programs are read: node runs `.mjs` and `"type": "module"` files as modules.
 * JavaScript acorn rejects is offered to Babel (decorators). Nothing is guessed: when no goal accepts the file the
 * outcome is `syntax`, and the caller reads it token by token and raw.
 */
export function parseEach(text: string, dialect: Dialect, each: ReadEach): ParseOutcome {
  if (dialect === "ts" || dialect === "tsx") return parseTs(text, dialect === "tsx", each);

  return limited(() => parseJs(text, dialect, each));
}

function parseJs(text: string, dialect: Dialect, each: ReadEach): ParseOutcome {
  for (const withJsx of dialect === "jsx" ? [true] : [false, true]) {
    const script = acornParse(text, "script", withJsx);

    if (script !== "syntax") {
      const html = hasHtmlComment(text, script.comments);
      const twice = each(script) || html;

      if (twice) {
        const module = acornParse(text, "module", withJsx);

        if (module !== "syntax") each(module);
      }

      return "parsed";
    }

    const module = acornParse(text, "module", withJsx);

    if (module !== "syntax") {
      each(module);

      return "parsed";
    }
  }

  return parseJsWithBabel(text, each);
}
