// Runs a small pure decoder function a program defines (`function g(h){return h.replace(/../g, m =>
// String.fromCharCode(parseInt(m, 16)))}`) on the strings it is called with, so apm reads the names malware hides
// behind it (`require(g('6178696f73'))` is `require('axios')`). Only expressions over strings, numbers and arrays:
// string and array methods, String.fromCharCode, parseInt, atob and Buffer decoding, arithmetic, and callbacks of
// those. No property writes, no loops, no other calls: anything else gives up. A step budget and length caps bound
// it, and only regexes without groups or open-ended repeats run, so no input can make it slow. Pure.
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
  | { k: "re"; re: RegExp };

/** What the decoder needs from the reader: a constant's string or number, and the local function a callee names. */
export type DecodeHost = {
  constant: (id: Identifier) => Known | null;
  localFunction: (callee: AnyNode) => AnyNode | null;
};

const MAX_STEPS = 200_000;
const MAX_CHARS = 64 * 1024;
const MAX_CALL_DEPTH = 4;

/**
 * Regexes the decoder runs: characters, escapes and classes, each repeated at most a fixed one- or two-digit count or
 * made optional. No groups, alternation or open-ended repeats, so matching stays linear in the input.
 */
const SAFE_REGEX = /^(?:(?:[^()|+*\\{}?[\]]|\\.|\[(?:[^\]\\]|\\.)*\])(?:\{\d{1,2}\}|\?)?)*$/;

const NOTHING: Value = { k: "nothing" };

class GiveUp extends Error {}

type State = { steps: number; depth: number; host: DecodeHost };

const str = (v: string): Value => ({ k: "str", v });
const num = (v: number): Value => ({ k: "num", v });
const known = (v: Known): Value => (v.kind === "text" ? str(v.value) : num(v.value));

/** The string `fn` returns for `args`, or null when apm cannot run it as a pure decoder. */
export function runDecoder(fn: AnyNode, args: readonly Known[], host: DecodeHost): string | null {
  const state: State = { steps: 0, depth: 0, host };

  try {
    const out = call(fn, args.map(known), new Map(), state);

    return out.k === "str" && out.v.length <= MAX_CHARS ? out.v : null;
  } catch {
    // GiveUp, or a builtin refusing its input (a too-long argument list, a bad encoding): not a decoder apm runs
    return null;
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

  if (!f || state.depth >= MAX_CALL_DEPTH) throw new GiveUp();
  const env = new Map(outer);

  f.params.forEach((p, i) => env.set(p.name, args[i] ?? NOTHING));
  state.depth++;

  try {
    const body = f.body;

    if (body.type !== "BlockStatement") return evaluate(body, env, state);

    // `const x = …;` declarations, then `return …;`
    for (const st of body.body) {
      if (st.type === "ReturnStatement") return st.argument ? evaluate(st.argument, env, state) : NOTHING;

      if (st.type !== "VariableDeclaration" || st.kind === "var") throw new GiveUp();

      for (const d of st.declarations) {
        if (d.id.type !== "Identifier" || !d.init) throw new GiveUp();
        env.set(d.id.name, evaluate(d.init, env, state));
      }
    }

    throw new GiveUp();
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
      return v.v.map((x) => (x.k === "nothing" ? "" : text(x))).join(",");
    case "bytes":
      return Buffer.from(v.latin1, "latin1").toString("utf8");
    case "fn":
    case "re":
      throw new GiveUp();
    default: {
      const _exhaustive: never = v;

      return _exhaustive;
    }
  }
}

function number(v: Value): number {
  if (v.k === "num") return v.v;

  if (v.k === "str" || v.k === "bool") return Number(v.v);
  throw new GiveUp();
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
  if (s.length > MAX_CHARS) throw new GiveUp();

  return str(s);
}

function list(v: Value[]): Value {
  if (v.length > MAX_CHARS) throw new GiveUp();

  return { k: "list", v };
}

function literal(n: Extract<AnyNode, { type: "Literal" }>): Value {
  if ("regex" in n && n.regex) {
    if (!SAFE_REGEX.test(n.regex.pattern) || /[^gimsuy]/.test(n.regex.flags)) throw new GiveUp();

    return { k: "re", re: new RegExp(n.regex.pattern, n.regex.flags) };
  }

  const raw = n.raw ?? "";

  if (raw.startsWith("'") || raw.startsWith('"')) return str(String(n.value));

  if (raw === "true" || raw === "false") return { k: "bool", v: raw === "true" };

  if (raw === "null" || ("bigint" in n && n.bigint)) return NOTHING;

  return num(Number(n.value));
}

function evaluate(n: AnyNode, env: Env, state: State): Value {
  if (++state.steps > MAX_STEPS) throw new GiveUp();

  switch (n.type) {
    case "Literal":
      return literal(n);
    case "Identifier": {
      const bound = env.get(n.name);

      if (bound) return bound;

      if (n.name === "undefined") return NOTHING;
      const c = state.host.constant(n);

      if (c === null) throw new GiveUp();

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
      throw new GiveUp();
    }

    case "BinaryExpression": {
      if (n.left.type === "PrivateIdentifier") throw new GiveUp();

      return binary(n.operator, evaluate(n.left, env, state), evaluate(n.right, env, state));
    }

    case "ConditionalExpression":
      return truthy(evaluate(n.test, env, state)) ? evaluate(n.consequent, env, state) : evaluate(n.alternate, env, state);
    case "MemberExpression": {
      if (n.object.type === "Super") throw new GiveUp();
      const obj = evaluate(n.object, env, state);
      const key = n.computed ? evaluate(n.property, env, state) : n.property.type === "Identifier" ? str(n.property.name) : NOTHING;
      const items = obj.k === "str" ? obj.v.split("").map(str) : obj.k === "list" ? obj.v : null;

      if (items && key.k === "str" && key.v === "length") return num(items.length);

      if (items && key.k === "num") return items[key.v] ?? NOTHING;
      throw new GiveUp();
    }

    case "CallExpression":
      return callExpr(n, env, state);
    case "ChainExpression":
      return evaluate(n.expression, env, state);
    default:
      throw new GiveUp();
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
      throw new GiveUp();
  }
}

function invoke(f: Value, args: readonly Value[], state: State): Value {
  if (f.k !== "fn") throw new GiveUp();

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
      throw new GiveUp();
  }
}

function callExpr(n: CallExpression, env: Env, state: State): Value {
  if (n.callee.type === "Super") throw new GiveUp();
  const args: Value[] = [];

  for (const a of n.arguments) {
    if (a.type === "SpreadElement") throw new GiveUp();
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

        if (!fn) throw new GiveUp();

        return call(fn, args, new Map(), state);
      }
    }
  }

  if (callee.type !== "MemberExpression" || callee.computed || callee.property.type !== "Identifier" || callee.object.type === "Super") throw new GiveUp();
  const recv = evaluate(callee.object, env, state);
  const method = callee.property.name;

  switch (recv.k) {
    case "bytes":
      if (method !== "toString") throw new GiveUp();

      return capped(Buffer.from(recv.latin1, "latin1").toString(encoding(args[0])));
    case "num":
      if (method !== "toString") throw new GiveUp();

      return str(recv.v.toString(args[0] === undefined ? 10 : number(a0)));
    case "str":
      return stringMethod(recv.v, method, args, state);
    case "list":
      return arrayMethod(recv.v, method, args, state);
    default:
      throw new GiveUp();
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

      if (target === null || rep === undefined) throw new GiveUp();

      if (rep.k === "fn") {
        const replacer = (m: string): string => {
          state.steps += 4;

          return text(invoke(rep, [str(m)], state));
        };

        return capped(method === "replace" ? s.replace(target, replacer) : s.replaceAll(target, replacer));
      }

      return capped(method === "replace" ? s.replace(target, text(rep)) : s.replaceAll(target, text(rep)));
    }

    case "split": {
      const sep = a[0];

      if (sep?.k !== "str") throw new GiveUp();

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
      throw new GiveUp();
  }
}

function arrayMethod(arr: Value[], method: string, a: readonly Value[], state: State): Value {
  switch (method) {
    case "join": {
      const sep = a[0];

      return capped(arr.map((x) => (x.k === "nothing" ? "" : text(x))).join(sep === undefined || sep.k === "nothing" ? "," : text(sep)));
    }

    case "reverse":
      return list([...arr].reverse());
    case "slice":
      return list(arr.slice(index(a, 0), index(a, 1)));
    case "concat":
      return list([...arr, ...a.flatMap((x) => (x.k === "list" ? x.v : [x]))]);
    case "map": {
      const f = a[0];

      if (f === undefined) throw new GiveUp();

      return list(arr.map((x, i) => invoke(f, [x, num(i)], state)));
    }

    default:
      throw new GiveUp();
  }
}
