// Runs a small pure decoder function a program defines (`function g(h){return h.replace(/../g, m =>
// String.fromCharCode(parseInt(m, 16)))}`) on the strings it is called with, so apm reads the names malware hides
// behind it (`require(g('6178696f73'))` is `require('axios')`). Only expressions over strings, numbers and arrays:
// string and array methods, String.fromCharCode, parseInt, atob and Buffer decoding, arithmetic, and callbacks of
// those. No property writes, no loops, no other calls: anything else is unsupported. A step budget, length caps and a
// call depth bound it, and it says when one of them stopped it (exhausted), which the analysis reports as code it did
// not finish reading. Regexes run only from a subset apm can prove linear (safeRegexCost), and their work is charged to
// the step budget, so no input can make it slow. Pure.
import type { AnyNode, CallExpression, Identifier } from "acorn";

type Env = ReadonlyMap<string, Value>;

/** A string or a number apm knows, as the reader hands it over. */
export type Known = { kind: "text"; value: string } | { kind: "number"; value: number };

/** A value the decoder works with; `bytes` is a Buffer, held as latin1 text. */
type Value =
  | { k: "str"; v: string }
  | { k: "num"; v: number }
  | { k: "bool"; v: boolean }
  | { k: "nothing" }
  | { k: "list"; v: Value[] }
  | { k: "fn"; node: AnyNode; env: Env }
  | { k: "bytes"; latin1: string }
  /** `cost`: characters one attempt at matching compares at most (safeRegexCost). */
  | { k: "re"; re: RegExp; cost: number };

/** What the decoder needs from the reader: a constant's string or number, and the local function a callee names. */
export type DecodeHost = {
  constant: (id: Identifier) => Known | null;
  localFunction: (callee: AnyNode) => AnyNode | null;
};

/** What running a decoder came to: its string, a program apm does not run (unsupported), or a limit it hit (exhausted). */
export type DecodeResult = { kind: "decoded"; value: string } | { kind: "unsupported" } | { kind: "exhausted"; limit: string };

/** Steps one decoder call may take, shared with the regex work it does. */
export const MAX_DECODER_STEPS = 200_000;
const MAX_CHARS = 64 * 1024;
const MAX_CALL_DEPTH = 4;

/** The longest fixed match a decoder regex may describe, in characters. */
const MAX_REGEX_WIDTH = 64;

const NOTHING: Value = { k: "nothing" };

/** The program does something the decoder does not run. */
class Unsupported extends Error {}

/** The decoder stopped at one of its limits; `limit` says which. */
class Exhausted extends Error {
  constructor(readonly limit: string) {
    super(limit);
  }
}

const LIMITS = {
  steps: `more than ${MAX_DECODER_STEPS} steps`,
  chars: `more than ${MAX_CHARS / 1024} KB of text`,
  depth: `calls nested more than ${MAX_CALL_DEPTH} deep`,
  builtin: "an argument list or nesting larger than the runtime takes",
} as const;

/** Steps the decoder may still take: this call's, and what the caller's allowance has left, whichever is smaller. */
type State = { steps: number; max: number; depth: number; host: DecodeHost };

function spend(state: State, n: number): void {
  state.steps += n;

  if (state.steps > state.max) throw new Exhausted(LIMITS.steps);
}

/**
 * What one attempt at matching costs, in characters compared, when `pattern` is in the subset apm runs; null when it
 * is not. The subset: single characters, escapes (no back-references), `.` and classes, each once, an exact `{n}`
 * times (n at most 99) or, for one atom in the whole pattern, optional; `^`, `$`, `\b` and `\B` anywhere. No groups,
 * alternation, lookarounds, open-ended or ranged repeats, lazy quantifiers or second optional atom. Such a pattern is a
 * fixed sequence of one-character tests with at most one choice, so a backtracking engine tries at most two paths of
 * at most MAX_REGEX_WIDTH characters from each start: linear in the input. Anything else is refused, not risked.
 */
export function safeRegexCost(pattern: string, flags: string): number | null {
  if (/[^gimsuy]/.test(flags) || new Set(flags).size !== flags.length) return null;
  let width = 0;
  let optional = 0;
  let i = 0;

  while (i < pattern.length) {
    const c = pattern[i] ?? "";
    let atom = true;

    if (c === "^" || c === "$") {
      atom = false;
      i++;
    } else if (c === "\\") {
      const e = pattern[i + 1];

      // a back-reference, a named one, a property escape (it takes braces) or a trailing backslash
      if (e === undefined || /[1-9kpP]/.test(e)) return null;

      if (e === "b" || e === "B") atom = false;
      i += 2;
    } else if (c === "[") {
      let j = i + 1;

      if (pattern[j] === "]") return null;

      for (; j < pattern.length && pattern[j] !== "]"; j++) {
        if (pattern[j] === "\\") j++;
        // a nested class or a set operation (only under the v flag, which is refused) never reaches here
        else if (pattern[j] === "[") return null;
      }

      if (j >= pattern.length) return null;
      i = j + 1;
    } else if ("()|*+?{}]".includes(c)) return null;
    else i++;

    let times = 1;
    const q = pattern[i];

    if (q === "{") {
      const m = /^\{(\d{1,2})\}/.exec(pattern.slice(i));

      if (!m || !atom) return null;
      times = Number(m[1]);
      i += m[0].length;
    } else if (q === "?") {
      if (!atom || ++optional > 1) return null;
      i++;
    }

    // a quantifier on a quantifier ("{2}?", "??", "{2}{3}") or a stray one after an assertion
    if (pattern[i] === "?" || pattern[i] === "{" || pattern[i] === "*" || pattern[i] === "+") return null;

    if (atom) width += times;

    if (width > MAX_REGEX_WIDTH) return null;
  }

  return Math.max(1, width) * (optional + 1);
}

const str = (v: string): Value => ({ k: "str", v });
const num = (v: number): Value => ({ k: "num", v });
const known = (v: Known): Value => (v.kind === "text" ? str(v.value) : num(v.value));

/**
 * The string `fn` returns for `args`, run as a pure decoder. `allowance` is the steps the caller still lets decoders
 * take (a file's budget across every call); what this call takes is subtracted from it.
 */
export function runDecoder(fn: AnyNode, args: readonly Known[], host: DecodeHost, allowance: { steps: number } = { steps: MAX_DECODER_STEPS }): DecodeResult {
  if (allowance.steps <= 0) return { kind: "exhausted", limit: LIMITS.steps };
  const state: State = { steps: 0, max: Math.min(MAX_DECODER_STEPS, allowance.steps), depth: 0, host };

  try {
    const out = call(fn, args.map(known), new Map(), state);

    if (out.k !== "str") return { kind: "unsupported" };

    return out.v.length <= MAX_CHARS ? { kind: "decoded", value: out.v } : { kind: "exhausted", limit: LIMITS.chars };
  } catch (e) {
    if (e instanceof Exhausted) return { kind: "exhausted", limit: e.limit };

    // a builtin refusing an argument list too long, or a stack too deep: a size limit, not a program apm does not run
    if (e instanceof RangeError) return { kind: "exhausted", limit: LIMITS.builtin };

    // Unsupported, or a builtin refusing its input (a bad encoding, a malformed URI escape): not a decoder apm runs
    return { kind: "unsupported" };
  } finally {
    allowance.steps -= state.steps;
  }
}

/** A function's parameters (plain names only) and body, or null for any other node or a parameter apm cannot bind. */
function parts(fn: AnyNode): { params: Identifier[]; body: AnyNode } | null {
  if (fn.type !== "FunctionDeclaration" && fn.type !== "FunctionExpression" && fn.type !== "ArrowFunctionExpression") return null;

  if (fn.async || fn.generator) return null;
  const params: Identifier[] = [];

  for (const p of fn.params) {
    if (p.type !== "Identifier") return null;
    params.push(p);
  }

  return { params, body: fn.body };
}

function call(fn: AnyNode, args: readonly Value[], outer: Env, state: State): Value {
  const f = parts(fn);

  if (!f) throw new Unsupported();

  if (state.depth >= MAX_CALL_DEPTH) throw new Exhausted(LIMITS.depth);
  const env = new Map(outer);

  f.params.forEach((p, i) => env.set(p.name, args[i] ?? NOTHING));
  state.depth++;

  try {
    const body = f.body;

    if (body.type !== "BlockStatement") return evaluate(body, env, state);

    // `const x = …;` declarations, then `return …;`
    for (const st of body.body) {
      if (st.type === "ReturnStatement") return st.argument ? evaluate(st.argument, env, state) : NOTHING;

      if (st.type !== "VariableDeclaration" || st.kind === "var") throw new Unsupported();

      for (const d of st.declarations) {
        if (d.id.type !== "Identifier" || !d.init) throw new Unsupported();
        env.set(d.id.name, evaluate(d.init, env, state));
      }
    }

    throw new Unsupported();
  } finally {
    state.depth--;
  }
}

function text(v: Value): string {
  switch (v.k) {
    case "str":
      return v.v;
    case "num":
    case "bool":
      return String(v.v);
    case "nothing":
      return "undefined";
    case "list":
      return joined(
        v.v.map((x) => (x.k === "nothing" ? "" : text(x))),
        ",",
      );
    case "bytes":
      return Buffer.from(v.latin1, "latin1").toString("utf8");
    case "fn":
    case "re":
      throw new Unsupported();
    default: {
      const _exhaustive: never = v;

      return _exhaustive;
    }
  }
}

function number(v: Value): number {
  if (v.k === "num") return v.v;

  if (v.k === "str" || v.k === "bool") return Number(v.v);
  throw new Unsupported();
}

function truthy(v: Value): boolean {
  switch (v.k) {
    case "str":
      return v.v !== "";
    case "num":
      return v.v !== 0 && !Number.isNaN(v.v);
    case "bool":
      return v.v;
    case "nothing":
      return false;
    default:
      return true;
  }
}

function capped(s: string): Value {
  if (s.length > MAX_CHARS) throw new Exhausted(LIMITS.chars);

  return str(s);
}

function list(v: Value[]): Value {
  if (v.length > MAX_CHARS) throw new Exhausted(LIMITS.chars);

  return { k: "list", v };
}

/** Joins pieces, refusing before it builds a string longer than the decoder may hold. */
function joined(pieces: readonly string[], sep: string): string {
  let total = Math.max(0, pieces.length - 1) * sep.length;

  for (const p of pieces) {
    total += p.length;

    if (total > MAX_CHARS) throw new Exhausted(LIMITS.chars);
  }

  return pieces.join(sep);
}

function literal(n: Extract<AnyNode, { type: "Literal" }>): Value {
  if ("regex" in n && n.regex) {
    const cost = safeRegexCost(n.regex.pattern, n.regex.flags);

    if (cost === null) throw new Unsupported();

    return { k: "re", re: new RegExp(n.regex.pattern, n.regex.flags), cost };
  }

  const raw = n.raw ?? "";

  if (raw.startsWith("'") || raw.startsWith('"')) return str(String(n.value));

  if (raw === "true" || raw === "false") return { k: "bool", v: raw === "true" };

  if (raw === "null" || ("bigint" in n && n.bigint)) return NOTHING;

  return num(Number(n.value));
}

function evaluate(n: AnyNode, env: Env, state: State): Value {
  spend(state, 1);

  switch (n.type) {
    case "Literal":
      return literal(n);
    case "Identifier": {
      const bound = env.get(n.name);

      if (bound) return bound;

      if (n.name === "undefined") return NOTHING;
      const c = state.host.constant(n);

      if (c === null) throw new Unsupported();

      return known(c);
    }

    case "TemplateLiteral": {
      let out = "";

      n.quasis.forEach((q, i) => {
        out += q.value.cooked ?? q.value.raw;
        const e = n.expressions[i];

        if (e) out += text(evaluate(e, env, state));
      });

      return capped(out);
    }

    case "ArrayExpression":
      return list(n.elements.map((e) => (e && e.type !== "SpreadElement" ? evaluate(e, env, state) : NOTHING)));
    case "ArrowFunctionExpression":
    case "FunctionExpression":
      return { k: "fn", node: n, env };
    case "UnaryExpression": {
      const v = evaluate(n.argument, env, state);

      if (n.operator === "-") return num(-number(v));

      if (n.operator === "+") return num(number(v));

      if (n.operator === "~") return num(~number(v));

      if (n.operator === "!") return { k: "bool", v: !truthy(v) };
      throw new Unsupported();
    }

    case "BinaryExpression": {
      if (n.left.type === "PrivateIdentifier") throw new Unsupported();

      return binary(n.operator, evaluate(n.left, env, state), evaluate(n.right, env, state));
    }

    case "ConditionalExpression":
      return truthy(evaluate(n.test, env, state)) ? evaluate(n.consequent, env, state) : evaluate(n.alternate, env, state);
    case "MemberExpression": {
      if (n.object.type === "Super") throw new Unsupported();
      const obj = evaluate(n.object, env, state);
      const key = n.computed ? evaluate(n.property, env, state) : n.property.type === "Identifier" ? str(n.property.name) : NOTHING;
      const items = obj.k === "str" ? obj.v.split("").map(str) : obj.k === "list" ? obj.v : null;

      if (items && key.k === "str" && key.v === "length") return num(items.length);

      if (items && key.k === "num") return items[key.v] ?? NOTHING;
      throw new Unsupported();
    }

    case "CallExpression":
      return callExpr(n, env, state);
    case "ChainExpression":
      return evaluate(n.expression, env, state);
    default:
      throw new Unsupported();
  }
}

function binary(op: string, a: Value, b: Value): Value {
  switch (op) {
    case "+":
      return a.k === "num" && b.k === "num" ? num(a.v + b.v) : capped(text(a) + text(b));
    case "-":
      return num(number(a) - number(b));
    case "*":
      return num(number(a) * number(b));
    case "/":
      return num(number(a) / number(b));
    case "%":
      return num(number(a) % number(b));
    case "^":
      return num(number(a) ^ number(b));
    case "&":
      return num(number(a) & number(b));
    case "|":
      return num(number(a) | number(b));
    case "<<":
      return num(number(a) << number(b));
    case ">>":
      return num(number(a) >> number(b));
    case ">>>":
      return num(number(a) >>> number(b));
    default:
      throw new Unsupported();
  }
}

function invoke(f: Value, args: readonly Value[], state: State): Value {
  if (f.k !== "fn") throw new Unsupported();

  return call(f.node, args, f.env, state);
}

/** A Buffer encoding the decoder accepts, from what the program passes (utf8 when it passes none). */
function encoding(v: Value | undefined): BufferEncoding {
  const e = v === undefined || v.k === "nothing" ? "utf8" : text(v);

  switch (e) {
    case "hex":
    case "base64":
    case "ascii":
    case "latin1":
      return e;
    case "binary":
      return "latin1";
    case "utf8":
    case "utf-8":
      return "utf8";
    default:
      throw new Unsupported();
  }
}

function callExpr(n: CallExpression, env: Env, state: State): Value {
  if (n.callee.type === "Super") throw new Unsupported();
  const args: Value[] = [];

  for (const a of n.arguments) {
    if (a.type === "SpreadElement") throw new Unsupported();
    args.push(evaluate(a, env, state));
  }

  const callee = n.callee;
  const a0 = args[0] ?? NOTHING;
  const a1 = args[1];

  // String.fromCharCode and Buffer.from
  if (callee.type === "MemberExpression" && !callee.computed && callee.object.type === "Identifier" && callee.property.type === "Identifier" && !env.has(callee.object.name)) {
    const name = `${callee.object.name}.${callee.property.name}`;

    if (name === "String.fromCharCode") return capped(String.fromCharCode(...args.flatMap((a) => (a.k === "list" ? a.v.map(number) : [number(a)]))));

    if (name === "Buffer.from") {
      if (a0.k === "list") return { k: "bytes", latin1: String.fromCharCode(...a0.v.map((x) => number(x) & 255)) };

      return { k: "bytes", latin1: Buffer.from(text(a0), encoding(a1)).toString("latin1") };
    }
  }

  if (callee.type === "Identifier") {
    const bound = env.get(callee.name);

    if (bound) return invoke(bound, args, state);

    switch (callee.name) {
      case "parseInt":
        return num(Number.parseInt(text(a0), a1 === undefined ? 10 : number(a1)));
      case "Number":
        return num(number(a0));
      case "String":
        return str(text(a0));
      case "atob":
        return str(Buffer.from(text(a0), "base64").toString("latin1"));
      case "decodeURIComponent":
        return str(decodeURIComponent(text(a0)));
      case "unescape":
        return str(unescape(text(a0)));
      default: {
        const fn = state.host.localFunction(callee);

        if (!fn) throw new Unsupported();

        return call(fn, args, new Map(), state);
      }
    }
  }

  if (callee.type !== "MemberExpression" || callee.computed || callee.property.type !== "Identifier" || callee.object.type === "Super") throw new Unsupported();
  const recv = evaluate(callee.object, env, state);
  const method = callee.property.name;

  switch (recv.k) {
    case "bytes":
      if (method !== "toString") throw new Unsupported();

      return capped(Buffer.from(recv.latin1, "latin1").toString(encoding(args[0])));
    case "num":
      if (method !== "toString") throw new Unsupported();

      return str(recv.v.toString(args[0] === undefined ? 10 : number(a0)));
    case "str":
      return stringMethod(recv.v, method, args, state);
    case "list":
      return arrayMethod(recv.v, method, args, state);
    default:
      throw new Unsupported();
  }
}

/** Argument `i` as a number, or undefined when the program passes none. */
function index(a: readonly Value[], i: number): number | undefined {
  const v = a[i];

  return v === undefined || v.k === "nothing" ? undefined : number(v);
}

function stringMethod(s: string, method: string, a: readonly Value[], state: State): Value {
  switch (method) {
    case "replace":
    case "replaceAll": {
      const [pat, rep] = a;
      const target = pat?.k === "re" ? pat.re : pat?.k === "str" ? pat.v : null;

      if (target === null || rep === undefined) throw new Unsupported();

      // matching tries every start, each at most `cost` characters: charged before the engine runs
      if (pat?.k === "re") spend(state, Math.ceil(((s.length + 1) * pat.cost) / 16));
      const fixed = rep.k === "fn" ? null : text(rep);

      // `$&`, `$'` and the like copy parts of the input per match, which the output count below cannot see coming
      if (fixed?.includes("$")) throw new Unsupported();
      // the output is counted as it is built, so a replacement that grows it stops before the string is made
      let out = s.length;

      const replacer = (m: string): string => {
        spend(state, 4);
        const piece = rep.k === "fn" ? text(invoke(rep, [str(m)], state)) : (fixed ?? "");
        out += piece.length - m.length;

        if (out > MAX_CHARS) throw new Exhausted(LIMITS.chars);

        return piece;
      };

      return capped(method === "replace" ? s.replace(target, replacer) : s.replaceAll(target, replacer));
    }

    case "split": {
      const sep = a[0];

      if (sep?.k !== "str") throw new Unsupported();

      return list(s.split(sep.v).map(str));
    }

    case "slice":
      return str(s.slice(index(a, 0), index(a, 1)));
    case "substring":
      return str(s.substring(index(a, 0) ?? 0, index(a, 1)));
    case "substr":
      return str(s.substr(index(a, 0) ?? 0, index(a, 1)));
    case "charCodeAt":
      return num(s.charCodeAt(index(a, 0) ?? 0));
    case "codePointAt":
      return num(s.codePointAt(index(a, 0) ?? 0) ?? Number.NaN);
    case "charAt":
      return str(s.charAt(index(a, 0) ?? 0));
    case "toString":
      return str(s);
    case "trim":
      return str(s.trim());
    case "toLowerCase":
      return str(s.toLowerCase());
    case "toUpperCase":
      return str(s.toUpperCase());
    case "concat":
      return capped(s + a.map(text).join(""));
    default:
      throw new Unsupported();
  }
}

function arrayMethod(arr: Value[], method: string, a: readonly Value[], state: State): Value {
  switch (method) {
    case "join": {
      const sep = a[0];

      return str(
        joined(
          arr.map((x) => (x.k === "nothing" ? "" : text(x))),
          sep === undefined || sep.k === "nothing" ? "," : text(sep),
        ),
      );
    }

    case "reverse":
      return list([...arr].reverse());
    case "slice":
      return list(arr.slice(index(a, 0), index(a, 1)));
    case "concat":
      return list([...arr, ...a.flatMap((x) => (x.k === "list" ? x.v : [x]))]);
    case "map": {
      const f = a[0];

      if (f === undefined) throw new Unsupported();

      return list(arr.map((x, i) => invoke(f, [x, num(i)], state)));
    }

    default:
      throw new Unsupported();
  }
}
