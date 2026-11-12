// Small helpers over parsed programs, shared by the reader (js.ts) and the flow analysis (flow.ts). Pure.
import type { AnyNode } from "acorn";

/** Stands for a piece of a string apm cannot know (`'curl ' + url`), so the rest can still be read. */
export const UNKNOWN = "__apm__";

/** Every object under a parsed program that has a string `type` and a numeric `start` is a node the parser built. */
function isParsedNode(v: unknown): v is AnyNode {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the one place parser output is told apart from the plain data (positions, regex flags) it carries
  return v instanceof Object && "type" in v && typeof v.type === "string" && "start" in v && typeof v.start === "number";
}

/** A node's child nodes, in source order: every field holding a node or a list of nodes. */
export function childNodes(n: AnyNode): AnyNode[] {
  const out: AnyNode[] = [];

  for (const v of Object.values(n)) {
    if (Array.isArray(v)) {
      for (const x of v) if (isParsedNode(x)) out.push(x);
    } else if (isParsedNode(v)) out.push(v);
  }

  return out;
}

/** Unwraps what does not change a value: TypeScript casts and assertions, `a?.b` chains. */
export function unwrap(n: AnyNode): AnyNode {
  let cur = n;

  for (;;) {
    if (cur.type === "ChainExpression") cur = cur.expression;
    else if (cur.type === "TSAsExpression" || cur.type === "TSSatisfiesExpression" || cur.type === "TSNonNullExpression" || cur.type === "TSTypeAssertion" || cur.type === "TSInstantiationExpression") cur = cur.expression;
    else return cur;
  }
}

export function isFunctionNode(n: AnyNode): boolean {
  return n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression" || n.type === "ClassExpression";
}
