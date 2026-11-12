// Parses JavaScript and TypeScript with maintained parsers: acorn (with acorn-jsx) for JavaScript and JSX, and
// Babel's parser with its TypeScript and ESTree plugins for TypeScript. Both give ESTree nodes with source offsets,
// and every comment's range. A file no parser accepts is not guessed at: the caller reads it raw. Pure.
import { parse as parseBabel, type ParserPlugin } from "@babel/parser";
import { Parser, type Options, type Program } from "acorn";
import jsx from "acorn-jsx";

/** How a file is parsed: by extension, then by content (a `.js` file holding JSX). */
export type Dialect = "js" | "jsx" | "ts" | "tsx";

/** The two ECMAScript goals. CommonJS runs as a script (with `return` allowed at the top); ES modules as a module. */
export type Goal = "script" | "module";

export type Range = [number, number];

/** One way the file parsed: the program, every comment's range, and the goal and dialect it parsed under. */
export type Parsed = { program: Program; comments: Range[]; goal: Goal; dialect: Dialect };

/** How parsing went: every program was handed over (`parsed`), no parser accepted the file, or it is too large to hold as a tree. */
export type ParseOutcome = "parsed" | "syntax" | "too-large";

/**
 * The most tokens one file may have and still be parsed into a tree. acorn's tree costs 90 to 95 bytes a token in V8
 * (measured on sass.dart.js and next's webpack bundle), so this keeps a tree near 45 MB inside the Worker's 128 MB
 * alongside the tarball (at most 48 MB inflated). Larger files, nearly always bundles, are read raw.
 */
export const MAX_PARSED_TOKENS = 480_000;

/** Babel's tree costs about three times acorn's, so TypeScript files are capped by size: about 40 MB of tree. */
export const MAX_PARSED_TS_BYTES = 1024 * 1024;

const JsxParser = Parser.extend(jsx());

class TooLarge extends Error {}

function acornParse(text: string, goal: Goal, withJsx: boolean): Parsed | "syntax" {
  const comments: Range[] = [];
  let tokens = 0;

  const options: Options = {
    ecmaVersion: "latest",
    sourceType: goal,
    allowHashBang: true,
    // node wraps CommonJS in a function, so `return` at the top of a file is allowed
    allowReturnOutsideFunction: goal === "script",
    onComment: (_block, _text, start, end) => comments.push([start, end]),
    onToken: () => {
      if (++tokens > MAX_PARSED_TOKENS) throw new TooLarge();
    },
  };

  try {
    const program = (withJsx ? JsxParser : Parser).parse(text, options);

    return { program, comments, goal, dialect: withJsx ? "jsx" : "js" };
  } catch (e) {
    if (e instanceof TooLarge) throw e;

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
    try {
      const file = parseBabel(text, { sourceType: goal, plugins: [...base, decorators], allowReturnOutsideFunction: goal === "script", attachComment: false, errorRecovery: false });
      const comments: Range[] = (file.comments ?? []).map((c) => [c.start ?? 0, c.end ?? 0]);
      const program: unknown = file.program;

      if (!isProgram(program)) return "syntax";

      return { program, comments, goal, dialect };
    } catch {
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
  return comments.some(([start]) => text.startsWith("<!--", start) || text.startsWith("-->", start));
}

/**
 * Reads one program. Returns true when the reader saw something a module would read differently (`await` used as
 * a name), so the file is read as a module too.
 */
export type ReadEach = (p: Parsed) => boolean;

function parseTs(text: string, withJsx: boolean, each: ReadEach): ParseOutcome {
  if (text.length > MAX_PARSED_TS_BYTES) return "too-large";
  const base: ParserPlugin[] = withJsx ? ["estree", "typescript", "jsx"] : ["estree", "typescript"];

  for (const goal of ["module", "script"] as const) {
    const p = babelParse(text, goal, base, withJsx ? "tsx" : "ts");

    if (p === "syntax") continue;

    // TypeScript has no HTML-like comments, so a parse that needed one is a parse of something else
    if (hasHtmlComment(text, p.comments)) return "syntax";
    each(p);

    return "parsed";
  }

  return "syntax";
}

/**
 * JavaScript acorn rejects but Babel reads: decorators, which acorn does not parse. Babel's tree costs three times
 * acorn's, so this is held to the TypeScript size cap. Flow is not enabled: its type annotations would read as code.
 */
function parseJsWithBabel(text: string, each: ReadEach): ParseOutcome {
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

  try {
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
  } catch (e) {
    if (e instanceof TooLarge) return "too-large";
    throw e;
  }

  return parseJsWithBabel(text, each);
}
