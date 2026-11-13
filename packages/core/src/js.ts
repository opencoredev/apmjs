// Reads a parsed JavaScript or TypeScript program: what it calls, loads, reads and evaluates, and what each string
// it holds is for. A string's role comes from where the code uses it: a module specifier loads a module, text passed
// to eval, Function or vm runs as code, a command passed to exec or spawn runs as a shell command, a path passed to a
// read is read, and a URL or request body is sent. Each role confirms only what fits it. What the tree reads only
// adds to the floor (apm-score-v3's text rules over the program's code), and never removes from it. Pure; nothing
// is run.
import type { AnyNode, CallExpression, Expression, Identifier, Literal, MemberExpression, NewExpression, Node, Pattern, Program, SpreadElement, TaggedTemplateExpression, TemplateLiteral } from "acorn";
import { childNodes, isFunctionNode, UNKNOWN, unwrap } from "./ast.ts";
import { Allowance, charge, chargeNow, chargeText, CHARS_PER_UNIT, inPhase } from "./meter.ts";
import { MAX_DECODER_STEPS, runDecoder, type Known } from "./decode.ts";
import { Flow, FlowExhausted, limitOf, MAX_FLOW_WORK, PRECISION_BOUNDS, type Bound, type CallSite, type Exports, type FlowRead, type Label, type Sink } from "./flow.ts";
import { parseEach, type Dialect, type ParseOutcome, type Parsed, type Range } from "./parse.ts";
import { scanTextRules } from "./textrules.ts";
import {
  escapedTextAt,
  lineOf,
  longBase64Text,
  moduleSignal,
  namedSignal,
  NEAR,
  printable,
  ruleHits,
  stringMatches,
  TOKEN_NAMES,
  whyOf,
  type Capability,
  type CodeSignal,
  type Confidence,
  type Hidden,
  type How,
  type TextFinding,
  type Where,
} from "./rules.ts";

// TypeScript and JSX nodes that carry runtime code. Other TS* nodes are types, erased before anything runs.
interface TsExpression extends Node {
  type: "TSAsExpression" | "TSSatisfiesExpression" | "TSNonNullExpression" | "TSTypeAssertion" | "TSInstantiationExpression";
  expression: Expression;
}

interface TsImportEquals extends Node {
  type: "TSImportEqualsDeclaration";
  id: Identifier;
  importKind?: "type" | "value";
  moduleReference: AnyNode;
}

interface TsExternalModuleReference extends Node {
  type: "TSExternalModuleReference";
  expression: Expression;
}

interface TsParameterProperty extends Node {
  type: "TSParameterProperty";
  parameter: Pattern;
}

interface JsxText extends Node {
  type: "JSXText";
  value: string;
}

interface TsModuleDeclaration extends Node {
  type: "TSModuleDeclaration";
  id: AnyNode;
}

interface TsEnumDeclaration extends Node {
  type: "TSEnumDeclaration";
  id: Identifier;
}

/** A class method's overload signature (`fetch(u: string): Promise<R>;`): Babel's value for a method with no body. */
interface TsEmptyBody extends Node {
  type: "TSEmptyBodyFunctionExpression";
}

declare module "acorn" {
  interface NodeTypes {
    apm: TsExpression | TsImportEquals | TsExternalModuleReference | TsParameterProperty | JsxText | TsModuleDeclaration | TsEnumDeclaration | TsEmptyBody;
  }
}

/** A string literal's value. Its source starts with a quote; a number, regex, boolean or null does not. */
function stringValue(n: Literal): string | null {
  const q = n.raw?.[0];

  return q === "'" || q === '"' ? String(n.value) : null;
}

/** A number literal's value (not a bigint). */
function numberValue(n: Literal): number | null {
  return n.raw !== undefined && /^\.?\d/.test(n.raw) && n.bigint === undefined ? Number(n.value) : null;
}

/**
 * The TypeScript nodes TypeScript's emit drops whole: annotations and every type, interfaces, type aliases, overload
 * and `declare function` signatures, abstract members, index signatures, `implements` and `export as namespace`.
 * A TypeScript node not listed here (an enum, a namespace, a parameter property, `import x = require()`, `export =`,
 * a cast, or a node type this list does not know) is read as code.
 */
const ERASED_TS: ReadonlySet<string> = new Set([
  "TSTypeAnnotation",
  "TSTypeParameterDeclaration",
  "TSTypeParameterInstantiation",
  "TSTypeParameter",
  "TSInterfaceDeclaration",
  "TSInterfaceBody",
  "TSInterfaceHeritage",
  "TSClassImplements",
  "TSExpressionWithTypeArguments",
  "TSTypeAliasDeclaration",
  "TSDeclareFunction",
  "TSDeclareMethod",
  "TSEmptyBodyFunctionExpression",
  "TSAbstractMethodDefinition",
  "TSIndexSignature",
  "TSNamespaceExportDeclaration",
  "TSPropertySignature",
  "TSMethodSignature",
  "TSCallSignatureDeclaration",
  "TSConstructSignatureDeclaration",
  // the types themselves
  "TSAnyKeyword",
  "TSBigIntKeyword",
  "TSBooleanKeyword",
  "TSIntrinsicKeyword",
  "TSNeverKeyword",
  "TSNullKeyword",
  "TSNumberKeyword",
  "TSObjectKeyword",
  "TSStringKeyword",
  "TSSymbolKeyword",
  "TSUndefinedKeyword",
  "TSUnknownKeyword",
  "TSVoidKeyword",
  "TSThisType",
  "TSFunctionType",
  "TSConstructorType",
  "TSTypeReference",
  "TSTypePredicate",
  "TSTypeQuery",
  "TSTypeLiteral",
  "TSArrayType",
  "TSTupleType",
  "TSNamedTupleMember",
  "TSOptionalType",
  "TSRestType",
  "TSUnionType",
  "TSIntersectionType",
  "TSConditionalType",
  "TSInferType",
  "TSParenthesizedType",
  "TSTypeOperator",
  "TSIndexedAccessType",
  "TSMappedType",
  "TSTemplateLiteralType",
  "TSLiteralType",
  "TSImportType",
]);

/** Abstract fields TypeScript also drops, unless one holds an initializer, which is read as code. */
const ABSTRACT_FIELDS: ReadonlySet<string> = new Set(["TSAbstractPropertyDefinition", "TSAbstractAccessorProperty"]);

/**
 * Type-only syntax: what TypeScript's emit drops whole (`ERASED_TS`), a `declare` statement or field, `import type`
 * and `export type`, and an overload signature in a class (a method with no body). Nothing in it runs.
 */
function isTypeOnly(n: AnyNode): boolean {
  if (ERASED_TS.has(n.type)) return true;

  if (ABSTRACT_FIELDS.has(n.type)) return !("value" in n) || n.value === null || n.value === undefined;

  if (n.type === "MethodDefinition" && childNodes(n).some((c) => c.type === "TSEmptyBodyFunctionExpression")) return true;

  if ("declare" in n && n.declare === true) return true;

  if ("importKind" in n && n.importKind === "type") return true;

  return "exportKind" in n && n.exportKind === "type";
}

// ---------- what a name or expression refers to ----------

/**
 * - `global`: a global and a path in it (`fetch`, `process.env`, `Bun.spawn`); `""` is the global object itself.
 * - `module`: a module and a member path in it (`child_process` and `exec`).
 * - `local`: a value this file makes (a function, class, object, array or literal), so not a platform API. `obj` is
 *   the node that made it, when its members can be read (an object literal, an array, a class, a function, a Proxy,
 *   `Object.create(…)`), and the binding that holds it, whose later writes (`obj.x = …`) are members too.
 * - `unknown`: anything else; `name` is its last property or identifier and `owner` the name before that.
 * `built` says a property name on the way was joined or decoded from pieces.
 */
export type Ref =
  | { kind: "global"; path: string; built: boolean }
  | { kind: "module"; spec: string; path: string; built: boolean }
  | { kind: "local"; fn: boolean; obj: LocalObj | null }
  /** `limit`: the reader stopped resolving here at a precision bound, so the value was cut, not merely unknown. */
  | { kind: "unknown"; name: string | null; owner: string | null; built: boolean; limit: Bound | null };

/** A value this file makes, read through the node that made it; `instance` is an object a local class constructs. */
type LocalObj = { node: AnyNode; binding: Binding | null; instance: boolean };

const GLOBAL_OBJECTS: ReadonlySet<string> = new Set(["globalThis", "global", "window", "self"]);

/** A property name in a pattern or a write: known as written, or a computed key apm works out when it is read. */
type Key = { kind: "name"; name: string } | { kind: "computed"; node: AnyNode };

/** Where a declared name gets its value. `default` is a pattern's default (`{ run = eval } = obj`): either side. */
export type Origin =
  | { kind: "value"; init: Expression }
  | { kind: "member"; base: Expression; path: Key[] }
  | { kind: "module"; spec: string; path: string }
  | { kind: "local"; node: AnyNode }
  | { kind: "default"; inner: Origin; fallback: AnyNode }
  | { kind: "opaque" };

/**
 * A write to a member of a declared value, found anywhere in the file: `obj.x = v` and `Reflect.set(obj, 'x', v)`
 * (`set`), `Object.defineProperty(obj, 'x', descriptor)` (`define`), `Object.assign(obj, source)` (`spread`),
 * `Object.setPrototypeOf(obj, proto)` (`proto`).
 */
type Write = { kind: "set"; key: Key; value: AnyNode | null } | { kind: "define"; key: Key; descriptor: AnyNode | null } | { kind: "spread"; source: AnyNode } | { kind: "proto"; value: AnyNode };

/**
 * One declaration of a name in one scope. Only a name declared once there and never assigned is resolved.
 * `constant` is a `const` or an import, which nothing (not even another script or a direct eval) can reassign;
 * `refs` are the identifiers that read it, filled in once the whole program is indexed.
 */
export type Binding = { name: string; count: number; assigned: boolean; constant: boolean; origin: Origin; writes: Write[]; scope: Scope; refs: Identifier[] };

/**
 * A lexical scope. `function` scopes take `var` and parameters; `block` scopes take `let`, `const`, classes and
 * functions declared in a block; `with` stands for a `with` statement's body, where any name may be a property of
 * the object instead of the binding outside it.
 */
type Scope = { parent: Scope | null; kind: "function" | "block" | "with"; names: Map<string, Binding>; declared: Set<string> };

/**
 * The program's scopes: the scope every identifier sits in, the outermost one, the names assigned that no scope
 * declares, and every name declared in any scope (a free name with the same spelling as one of them may still reach
 * it: a TypeScript namespace merged with another, or a function a sloppy-mode block declares).
 */
type Scopes = { scopeOf: Map<AnyNode, Scope>; root: Scope; assignedFree: Set<string>; declared: ReadonlySet<string> };

function newScope(parent: Scope | null, kind: Scope["kind"]): Scope {
  return { parent, kind, names: new Map(), declared: parent?.declared ?? new Set() };
}

function varScope(s: Scope): Scope {
  let cur = s;

  while (cur.kind !== "function" && cur.parent) {
    charge("scope", 1);
    cur = cur.parent;
  }

  return cur;
}

function declare(scope: Scope, name: string, origin: Origin, constant = false): void {
  const had = scope.names.get(name);

  scope.declared.add(name);

  if (had) {
    had.count++;
    had.constant = had.constant && constant;
  } else scope.names.set(name, { name, count: 1, assigned: false, constant, origin, writes: [], scope, refs: [] });
}

function propertyName(key: AnyNode, computed: boolean): string | null {
  if (!computed && key.type === "Identifier") return key.name;

  if (key.type === "Literal") {
    const v = stringValue(key) ?? numberValue(key);

    return v === null ? null : String(v);
  }

  return null;
}

function keyOf(key: AnyNode, computed: boolean): Key | null {
  const name = propertyName(key, computed);

  if (name !== null) return { kind: "name", name };

  return computed && key.type !== "PrivateIdentifier" ? { kind: "computed", node: key } : null;
}

/** The origin of one property of a value: `{ a } = init` gives `init.a`. */
function memberOrigin(origin: Origin, key: Key | null): Origin {
  if (key === null) return { kind: "opaque" };

  switch (origin.kind) {
    case "value":
      return { kind: "member", base: origin.init, path: [key] };
    case "member":
      return { kind: "member", base: origin.base, path: [...origin.path, key] };
    case "module":
      return key.kind === "name" ? { kind: "module", spec: origin.spec, path: origin.path ? `${origin.path}.${key.name}` : key.name } : { kind: "opaque" };
    case "default":
      return memberOrigin(origin.inner, key);
    case "local":
    case "opaque":
      return { kind: "opaque" };
    default: {
      const _exhaustive: never = origin;

      return _exhaustive;
    }
  }
}

function bindPattern(scope: Scope, p: AnyNode, origin: Origin, constant = false): void {
  switch (p.type) {
    case "Identifier":
      declare(scope, p.name, origin, constant);
      break;
    case "ObjectPattern":
      for (const prop of p.properties) {
        if (prop.type === "RestElement") bindPattern(scope, prop.argument, { kind: "opaque" }, constant);
        else bindPattern(scope, prop.value, memberOrigin(origin, keyOf(prop.key, prop.computed)), constant);
      }

      break;
    case "AssignmentPattern":
      bindPattern(scope, p.left, { kind: "default", inner: origin, fallback: p.right }, constant);
      break;
    case "ArrayPattern":
      p.elements.forEach((el, i) => {
        if (el?.type === "RestElement") bindPattern(scope, el.argument, { kind: "opaque" }, constant);
        else if (el) bindPattern(scope, el, memberOrigin(origin, { kind: "name", name: String(i) }), constant);
      });

      break;
    case "RestElement":
      bindPattern(scope, p.argument, { kind: "opaque" }, constant);
      break;
    case "TSParameterProperty":
      bindPattern(scope, p.parameter, { kind: "opaque" });
      break;
    default:
      break;
  }
}

/** The identifiers a pattern assigns to (`[a, b] = …`, `({ a } = …)`). */
function assignedNames(p: AnyNode, out: Identifier[]): void {
  switch (p.type) {
    case "Identifier":
      out.push(p);
      break;
    case "ObjectPattern":
      for (const prop of p.properties) assignedNames(prop.type === "RestElement" ? prop.argument : prop.value, out);
      break;
    case "ArrayPattern":
      for (const el of p.elements) if (el) assignedNames(el, out);
      break;
    case "AssignmentPattern":
      assignedNames(p.left, out);
      break;
    case "RestElement":
      assignedNames(p.argument, out);
      break;
    default:
      break;
  }
}

/** `Object.assign`, `Object.defineProperty`, `Reflect.set` and their kin: a call that writes members of its first argument. */
function writeOf(n: CallExpression): { target: Identifier; write: Write } | null {
  const callee = unwrap(n.callee);

  if (callee.type !== "MemberExpression" || callee.computed || callee.object.type !== "Identifier" || callee.property.type !== "Identifier") return null;
  const api = `${callee.object.name}.${callee.property.name}`;
  const [target, a1, a2] = n.arguments;

  if (target?.type !== "Identifier") return null;
  const key = a1 && a1.type !== "SpreadElement" ? keyOf(a1, true) : null;
  const third = a2 && a2.type !== "SpreadElement" ? a2 : null;

  switch (api) {
    case "Object.assign":
      return a1 && a1.type !== "SpreadElement" ? { target, write: { kind: "spread", source: a1 } } : null;
    case "Object.defineProperty":
    case "Reflect.defineProperty":
      return key ? { target, write: { kind: "define", key, descriptor: third } } : null;
    case "Reflect.set":
      return key ? { target, write: { kind: "set", key, value: third } } : null;
    case "Object.setPrototypeOf":
    case "Reflect.setPrototypeOf":
      return a1 && a1.type !== "SpreadElement" ? { target, write: { kind: "proto", value: a1 } } : null;
    case "Object.defineProperties":
      return { target, write: { kind: "set", key: { kind: "computed", node: target }, value: null } };
    default:
      return null;
  }
}

function functionBody(fn: AnyNode): AnyNode[] {
  if (fn.type !== "FunctionDeclaration" && fn.type !== "FunctionExpression" && fn.type !== "ArrowFunctionExpression") return [];

  return fn.body.type === "BlockStatement" ? fn.body.body : [fn.body];
}

/**
 * Builds the program's scopes: each declaration goes to the scope it belongs to (`var` and parameters to the
 * function, `let`, `const`, classes and block functions to the block), and every identifier is mapped to the scope
 * it sits in, so a reference finds the binding that covers it and no other. Type-only syntax is skipped: an ambient
 * `declare` or a type's parameter declares nothing that runs.
 */
function buildScopes(program: Program): Scopes {
  const root = newScope(null, "function");
  const scopeOf = new Map<AnyNode, Scope>();
  const assigned: Identifier[] = [];
  const writes: { target: Identifier; write: Write }[] = [];
  const stack: [AnyNode, Scope][] = [[program, root]];

  const push = (scope: Scope, nodes: readonly (AnyNode | null | undefined)[]): void => {
    charge("scope", nodes.length);

    for (const c of nodes) if (c) stack.push([c, scope]);
  };

  const fnScope = (n: AnyNode & { params: AnyNode[] }, scope: Scope): Scope => {
    const inner = newScope(scope, "function");

    for (const p of n.params) bindPattern(inner, p, { kind: "opaque" });

    return inner;
  };

  for (let item = stack.pop(); item; item = stack.pop()) {
    const [n, scope] = item;

    charge("scope", 2);

    if (isTypeOnly(n)) continue;

    switch (n.type) {
      case "Identifier":
        scopeOf.set(n, scope);
        continue;
      case "VariableDeclaration": {
        const target = n.kind === "var" ? varScope(scope) : scope;

        const constant = n.kind !== "var" && n.kind !== "let";

        for (const d of n.declarations) bindPattern(target, d.id, d.init ? { kind: "value", init: d.init } : { kind: "opaque" }, constant);
        break;
      }

      case "FunctionDeclaration": {
        if (n.id) declare(scope, n.id.name, { kind: "local", node: n });
        const inner = fnScope(n, scope);
        push(scope, [n.id]);
        push(inner, [...n.params, ...n.body.body]);
        continue;
      }

      case "FunctionExpression": {
        const inner = fnScope(n, scope);

        if (n.id) declare(inner, n.id.name, { kind: "local", node: n });
        push(inner, [n.id, ...n.params, ...n.body.body]);
        continue;
      }

      case "ArrowFunctionExpression":
        push(fnScope(n, scope), [...n.params, ...functionBody(n)]);
        continue;
      case "ClassDeclaration":
      case "ClassExpression": {
        const inner = newScope(scope, "block");

        if (n.id) declare(n.type === "ClassDeclaration" ? scope : inner, n.id.name, { kind: "local", node: n });
        push(inner, childNodes(n));
        continue;
      }

      case "BlockStatement":
      case "ForStatement":
      case "SwitchStatement":
        push(newScope(scope, "block"), childNodes(n));
        continue;
      case "ForInStatement":
      case "ForOfStatement":
        if (n.left.type !== "VariableDeclaration") assignedNames(n.left, assigned);
        push(newScope(scope, "block"), childNodes(n));
        continue;
      case "StaticBlock":
        push(newScope(scope, "function"), n.body);
        continue;
      case "CatchClause": {
        const inner = newScope(scope, "block");

        if (n.param) bindPattern(inner, n.param, { kind: "opaque" });
        push(inner, [n.param, ...n.body.body]);
        continue;
      }

      case "WithStatement":
        push(scope, [n.object]);
        push(newScope(scope, "with"), [n.body]);
        continue;
      case "TSModuleDeclaration":
        if (n.id.type === "Identifier") declare(scope, n.id.name, { kind: "local", node: n });
        push(newScope(scope, "function"), childNodes(n));
        continue;
      case "TSEnumDeclaration":
        declare(scope, n.id.name, { kind: "local", node: n });
        push(newScope(scope, "block"), childNodes(n));
        continue;
      case "ImportDeclaration": {
        const spec = stringValue(n.source);

        if (spec === null) break;

        for (const s of n.specifiers) {
          if (isTypeOnly(s)) continue;
          const path = s.type === "ImportSpecifier" ? (propertyName(s.imported, false) ?? "") : "";
          declare(scope, s.local.name, { kind: "module", ...moduleOf(spec, path) }, true);
        }

        break;
      }

      case "TSImportEqualsDeclaration": {
        const ref = n.moduleReference;
        const spec = ref.type === "TSExternalModuleReference" && ref.expression.type === "Literal" ? stringValue(ref.expression) : null;

        declare(scope, n.id.name, spec !== null ? { kind: "module", ...moduleOf(spec, "") } : { kind: "opaque" });
        break;
      }

      case "AssignmentExpression": {
        const left = n.left;

        if (left.type === "MemberExpression" && left.object.type === "Identifier") {
          const key = keyOf(left.property, left.computed);

          if (key) writes.push({ target: left.object, write: { kind: "set", key, value: n.operator === "=" ? n.right : null } });
        } else assignedNames(left, assigned);

        break;
      }

      case "UpdateExpression":
        if (n.argument.type === "Identifier") assigned.push(n.argument);
        break;
      case "CallExpression": {
        const w = writeOf(n);

        if (w) writes.push(w);
        break;
      }

      default:
        break;
    }

    push(scope, childNodes(n));
  }

  const assignedFree = new Set<string>();

  for (const id of assigned) {
    const b = lookup(scopeOf, id);

    if (b === null) assignedFree.add(id.name);
    else if (b !== "dynamic") b.assigned = true;
  }

  for (const { target, write } of writes) {
    const b = lookup(scopeOf, target);

    if (b !== null && b !== "dynamic") b.writes.push(write);
  }

  return { scopeOf, root, assignedFree, declared: root.declared };
}

/**
 * The binding an identifier refers to: the nearest scope around it that declares the name. `dynamic` when a `with`
 * body sits between the two (the name may be a property of the `with` object), null when no scope declares it.
 */
function lookup(scopeOf: ReadonlyMap<AnyNode, Scope>, id: Identifier): Binding | "dynamic" | null {
  let crossedWith = false;

  for (let s = scopeOf.get(id) ?? null; s; s = s.parent) {
    // one scope looked in: a name used deep inside nested functions climbs every one of them
    chargeNow(1);
    const b = s.names.get(id.name);

    if (b) return crossedWith ? "dynamic" : b;

    if (s.kind === "with") crossedWith = true;
  }

  return null;
}

/** A module specifier as apm names it: without `node:`, with `fs/promises` read as `fs` and its `promises` member. */
type ModulePath = { spec: string; path: string };

function moduleOf(spec: string, path: string): ModulePath {
  const s = spec.replace(/^node:/, "");
  const join = (prefix: string): string => (path ? `${prefix}.${path}` : prefix);

  if (s === "fs/promises" || s === "dns/promises") return { spec: s.slice(0, s.indexOf("/")), path: join("promises") };

  if (s === "graceful-fs" || s === "fs-extra") return { spec: "fs", path };

  return { spec: s, path };
}

/** The dotted name of a reference: `fetch`, `child_process.exec`, `process.env`. Unknown references give their last name. */
function nameOf(r: Ref): string {
  switch (r.kind) {
    case "global":
      return r.path;
    case "module":
      return r.path ? `${r.spec}.${r.path}` : r.spec;
    case "local":
      return "";
    case "unknown":
      return r.name ?? "";
    default: {
      const _exhaustive: never = r;

      return _exhaustive;
    }
  }
}

function lastName(r: Ref): string {
  const n = nameOf(r);

  return n.slice(n.lastIndexOf(".") + 1);
}

/** The name a member was read from: `vm` in `vm.runInNewContext`, whether `vm` is a free name or one apm cannot follow. */
function ownerOf(r: Ref): string | null {
  if (r.kind === "unknown") return r.owner;

  if (r.kind !== "global") return null;
  const parts = r.path.split(".");

  return parts.length >= 2 ? (parts.at(-2) ?? null) : null;
}

/** Not a value this file defines and not a module apm knows: what it is can only be told by its name. */
function byName(r: Ref): boolean {
  return r.kind === "unknown" || r.kind === "global";
}

// ---------- strings the code builds ----------

/**
 * A string value apm can work out without running anything: a literal, a template, pieces joined with `+`, a
 * constant it was assigned to, or a payload decoded with atob, Buffer.from, String.fromCharCode or URI escapes.
 * `exact` is false when a piece is unknown (then `value` holds UNKNOWN for it). `pieces` counts the literal pieces it
 * was built from, and `via` names the encoding a decoded value was in.
 */
type Str = { value: string; exact: boolean; how: "as written" | "after joining strings" | "decoded"; pieces: number; via: string | null; numeric: boolean };

const HOW_RANK = { "as written": 0, "after joining strings": 1, decoded: 2 } as const;

function strongerHow(a: Str["how"], b: Str["how"]): Str["how"] {
  return HOW_RANK[a] >= HOW_RANK[b] ? a : b;
}

const ESCAPE = /\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]+\})/;

/** Base64 that a decoder or a reader would take for a payload: 16+ characters, mixing cases and digits. */
const BASE64 = /^[A-Za-z0-9+/]{16,}={0,2}$/;

/** Words worth matching in a string; most strings hold none, and are passed over without running every rule. */
const INTERESTING = /child_process|curl|wget|powershell|\|\s*\w*sh\b|\.npmrc|\.ssh|id_(?:rsa|ed25519|ecdsa)|\.aws|\.git-credentials|\.docker|Login Data|gcloud|_TOKEN|_SECRET_/;

const TOKEN_RE = /\b(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN)\b/;

/** How much decoded text one file may produce, and how much code held in strings it may have read as code. */
const MAX_DECODED_BYTES = 256 * 1024;

/** How long a function apm runs as a decoder may be, in characters of source. */
const MAX_DECODER_CHARS = 2000;

/** Steps every decoder run in one file may take together (decode.ts counts them): ten calls at their own limit. */
const MAX_FILE_DECODER_STEPS = 10 * MAX_DECODER_STEPS;

/** How deep code held in a string is followed: code that evaluates code that evaluates code. */
const MAX_EVAL_DEPTH = 3;

/**
 * What one file's reading may spend, shared by every program and every string it evaluates: decoded text, and the
 * limits it ran into. A limit never hides anything: what was past it is read as unknown, so only the text rules (the
 * floor every finding starts from) judge it, and the limit is named in the score's not-checked list.
 */
type Budget = {
  decoded: number;
  notes: Set<string>;
  decoder: Allowance;
  /** Constant strings the file's reading may build (constant folding), carved out of the meter. */
  fold: Allowance;
  /** Limits a nested reading (code run from a string) hit that make the file incomplete, for the outer reader. */
  stopped: string[];
};

/**
 * Characters of constant strings one file's reading may build, all strings together: a million, and 16 for each
 * character of the file. A string is built from pieces the file holds, so ordinary code builds about as much as it
 * holds; `const s1=s0+s0` doubled 23 times builds 16 million characters from 435 bytes.
 */
const FOLD_BASE_CHARS = 1024 * 1024;
const FOLD_CHARS_PER_CHAR = 16;

function foldUnits(fileChars: number): number {
  return Math.ceil((FOLD_BASE_CHARS + FOLD_CHARS_PER_CHAR * fileChars) / CHARS_PER_UNIT);
}

/**
 * Why a reading stopped short, as the not-checked list names it, followed by the files. Past each limit the text rules
 * judged the code; the website says so once ("apm read those files with its text rules") and lists these as details.
 */
const LIMIT_NOTES = {
  candidates: PRECISION_BOUNDS.candidates,
  returns: PRECISION_BOUNDS.returns,
  thisWrites: PRECISION_BOUNDS.thisWrites,
  depth: PRECISION_BOUNDS.depth,
  evalDepth: "code run from a string more than 3 levels deep",
  decoded: "more than 256 KB of decoded text in one file",
  fold: "constant strings built past the file's allowance (a million characters and 16 for each of the file's)",
  flow: PRECISION_BOUNDS.steps,
  assignments: PRECISION_BOUNDS.assignments,
} as const;

/** Every reading-limit note, word for word: the fixed part of a "<limit> (<files>)" not-checked entry. */
export const READING_LIMITS: readonly string[] = Object.values(LIMIT_NOTES);

/**
 * Where a string sits, which decides what it can confirm:
 * - `code`: run as JavaScript (eval, Function, vm, string timers). It is read as code.
 * - `shell`: run as a command (exec, spawn, Bun.$). Shell text and credential paths in it are confirmed.
 * - `read`: a path a read opens. A credential path in it is confirmed.
 * - `request`: a URL or request body. It is sent, not run, so it confirms nothing beyond the request itself.
 * - `plain`: anything else. What it names is possible at most.
 * - `none`: already read where it is used; its strings are not read again.
 */
export type Role = "code" | "shell" | "read" | "request" | "plain" | "none";

/** How strong a piece of evidence is, so a file cites a call before an import and an import before a string. */
const STRENGTH = { string: 0, load: 1, reference: 2, call: 3 } as const;

type Strength = (typeof STRENGTH)[keyof typeof STRENGTH];

type Hit = { id: CodeSignal; at: number; how: How; strength: Strength } & ({ confidence: "confirmed" } | { confidence: "possible"; why: string });

function hitOf(id: CodeSignal, at: number, strength: Strength, how: How, confidence: Confidence, why: string): Hit {
  return confidence === "confirmed" ? { id, at, how, strength, confidence } : { id, at, how, strength, confidence, why };
}

function ranHow(how: Str["how"]): How {
  if (how === "decoded") return "decoded, then run";

  return how === "after joining strings" ? "joined, then run" : "run from a string";
}

const SHELL_CP: ReadonlySet<string> = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"]);

/** Names distinctive enough to count as running a command whatever object they are called on, as before v5. */
const SHELL_NAMES: ReadonlySet<string> = new Set(["execSync", "execFileSync", "spawnSync"]);

const SHELL_GLOBALS: ReadonlySet<string> = new Set(["Bun.spawn", "Bun.spawnSync", "Bun.$", "Deno.Command", "Deno.run"]);

const BINDINGS: ReadonlySet<string> = new Set(["process.binding", "process._linkedBinding", "process.dlopen", "internalBinding"]);

/**
 * Internal bindings that only read type helpers and constants. Any other binding (spawn_sync, process_wrap, fs,
 * contextify) can start processes, touch files or run code, and so does one apm cannot name.
 */
const HARMLESS_BINDINGS = /^(?:util|types|natives|buffer|constants|config|errors|symbols|url|string_decoder|uv)$/;

/** Calls whose arguments are commands even when apm cannot tell what they are called on (execa, zx's `$`). */
const COMMAND_ARGS: ReadonlySet<string> = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork", "execa", "execaSync", "execaCommand", "execaCommandSync", "$"]);

const VM_EVAL: ReadonlySet<string> = new Set(["runInThisContext", "runInNewContext", "runInContext", "compileFunction", "Script", "SourceTextModule"]);

const INSPECTOR = /^(?:node:)?inspector(?:\/promises)?$/;

/** Inspector protocol methods that run code they are handed. */
const INSPECTOR_EVAL = /^(?:Runtime\.(?:evaluate|compileScript|runScript|callFunctionOn)|Debugger\.evaluateOnCallFrame)$/;

const READS: ReadonlySet<string> = new Set(["readFile", "readFileSync", "createReadStream", "open", "openSync", "copyFile", "copyFileSync", "cp", "cpSync", "readTextFile", "readTextFileSync"]);

const NET_CTORS: ReadonlySet<string> = new Set(["XMLHttpRequest", "WebSocket", "EventSource", "RTCPeerConnection"]);

const TIMERS: ReadonlySet<string> = new Set(["setTimeout", "setInterval", "setImmediate"]);

const DECODERS: ReadonlySet<string> = new Set(["atob", "Buffer.from", "String.fromCharCode", "decodeURIComponent", "decodeURI", "unescape", "String"]);

const STRING_METHODS: ReadonlySet<string> = new Set(["toString", "trim", "concat", "join", "split", "reverse", "slice", "replace", "toLowerCase", "toUpperCase"]);

const PATH_BUILDERS: ReadonlySet<string> = new Set(["join", "resolve", "normalize", "homedir"]);

const DNS_CALL = /^(?:promises\.)?(?:resolve\w*|lookup\w*|reverse)$/;

/** The helpers TypeScript, Babel, SWC and esbuild wrap a require in: each returns the module (or its namespace). */
const INTEROP = /^_*(?:interop_?require_?(?:default|wildcard)|import(?:Default|Star)|toESM|toCommonJS)$/i;

/** An `async` function that is not a generator: calling it gives a Promise of what it returns. */
function isAsyncFunction(n: AnyNode): boolean {
  return (n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression" || n.type === "FunctionDeclaration") && n.async && !n.generator;
}

/** A generator (`function*`, `async function*`): calling it gives a generator object. */
function isGenerator(n: AnyNode): boolean {
  return (n.type === "FunctionExpression" || n.type === "FunctionDeclaration") && n.generator;
}

function decodeBase64(s: string): string | null {
  const body = s.replace(/=+$/, "");

  if (!/^[A-Za-z0-9+/_-]*$/.test(body) || body.length % 4 === 1) return null;

  return Buffer.from(body.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("latin1");
}

/** An argument in the position it is passed at; null for a hole (`[, x]`). */
type Slot = AnyNode | null;

/** Arguments placed in their positions, and the argument nodes apm could not place (read as plain values). */
type Placed = { slots: Slot[]; others: AnyNode[] };

function isGlobal(r: Ref, path: string): boolean {
  return r.kind === "global" && r.path === path;
}

/**
 * What a call invokes and with which arguments. `refs` are every callee the expression can be (`(a || b)(x)` is
 * either); `slots` are the arguments in their positions, through `f.call`, `f.apply`, `Reflect.apply`,
 * `Reflect.construct`, `f.bind(that, a)` and spreads of arrays apm can read; `others` are the remaining argument
 * nodes (a `this` value, an array apm could not read), read as plain values.
 */
type Invoked = { refs: Ref[]; isNew: boolean; slots: Slot[]; others: AnyNode[] };

/** The most values one expression is read as; past this the rest are one unknown value, never dropped. */
const MAX_CANDIDATES = 6;

/** The most `return` statements of one function, and `this.x = …` writes of one constructor, read before the rest are unknown. */
const MAX_RETURNS = 32;
const MAX_THIS_WRITES = 8;

const UNKNOWN_REF: Ref = { kind: "unknown", name: null, owner: null, built: false, limit: null };

function unknownNamed(name: string | null, owner: string | null = null, built = false, limit: Bound | null = null): Ref {
  return { kind: "unknown", name, owner, built, limit };
}

/** The unknown value that stands for what the reader did not resolve past a precision bound. */
function cutRef(limit: Bound): Ref {
  return { kind: "unknown", name: null, owner: null, built: false, limit };
}

/** How much a reference says, for when one has to stand for several: a platform API, then a module, then a name. */
function rankOf(r: Ref): number {
  switch (r.kind) {
    case "global":
      return r.path ? 5 : 4;
    case "module":
      return 4;
    case "unknown":
      return r.name ? 2 : 1;
    case "local":
      return 0;
    default: {
      const _exhaustive: never = r;

      return _exhaustive;
    }
  }
}

function refKey(r: Ref): string {
  return r.kind === "local" ? "" : `${r.kind}:${nameOf(r)}:${r.kind === "unknown" ? `${r.owner ?? ""}:${r.limit ?? ""}` : ""}:${String(r.built)}`;
}

/**
 * The distinct references in `refs`, local values kept apart by the node that made them. Past MAX_CANDIDATES the rest
 * are one unknown value (and `notes` says so): an unknown callee confirms nothing and proves nothing harmless, so what
 * was not followed is left to the text rules.
 */
function distinct(refs: readonly Ref[], notes?: Set<string>): Ref[] {
  chargeNow(1 + refs.length);
  const out: Ref[] = [];
  const seen = new Set<string>();
  const nodes = new Set<AnyNode | null>();

  for (const r of refs) {
    if (r.kind === "local") {
      const node = r.obj?.node ?? null;

      if (nodes.has(node)) continue;
      nodes.add(node);
    } else {
      const k = refKey(r);

      if (seen.has(k)) continue;
      seen.add(k);
    }

    if (out.length >= MAX_CANDIDATES) {
      out.push(cutRef("candidates"));
      notes?.add(LIMIT_NOTES.candidates);
      break;
    }

    out.push(r);
  }

  return out.length > 0 ? out : [UNKNOWN_REF];
}

/** The one reference that stands for several: the one that says the most, the first of equals. */
function pick(refs: readonly Ref[]): Ref {
  let best: Ref = refs[0] ?? UNKNOWN_REF;

  for (const r of refs) if (rankOf(r) > rankOf(best)) best = r;

  return best;
}

/** Whether an expression is truthy (true), falsy (false), or apm cannot tell (null). */
function truthiness(n: AnyNode): boolean | null {
  const t = unwrap(n);

  switch (t.type) {
    case "Literal":
      return "regex" in t && t.regex ? true : Boolean(t.value);
    case "Identifier":
      return t.name === "undefined" ? false : null;
    case "UnaryExpression": {
      if (t.operator === "void") return false;

      if (t.operator !== "!") return null;
      const inner = truthiness(t.argument);

      return inner === null ? null : !inner;
    }

    case "TemplateLiteral":
      return t.expressions.length === 0 ? Boolean(t.quasis[0]?.value.cooked) : null;
    case "ObjectExpression":
    case "ArrayExpression":
    case "FunctionExpression":
    case "ArrowFunctionExpression":
    case "ClassExpression":
      return true;
    default:
      return null;
  }
}

/** Whether an expression is null or undefined (true), is neither (false), or apm cannot tell (null). */
function nullishness(n: AnyNode): boolean | null {
  const t = unwrap(n);

  switch (t.type) {
    case "Literal":
      return t.value === null && !("regex" in t && t.regex);
    case "Identifier":
      return t.name === "undefined" ? true : null;
    case "UnaryExpression":
      return t.operator === "void" ? true : null;
    case "TemplateLiteral":
    case "ObjectExpression":
    case "ArrayExpression":
    case "FunctionExpression":
    case "ArrowFunctionExpression":
    case "ClassExpression":
      return false;
    default:
      return null;
  }
}

/** The operands a logical or conditional expression can evaluate to, by what apm can tell of its test. */
function operands(n: AnyNode): AnyNode[] | null {
  if (n.type === "LogicalExpression") {
    const test = n.operator === "??" ? nullishness(n.left) : truthiness(n.left);

    if (test === null) return [n.left, n.right];

    // `a || b` is a when a is truthy; `a && b` is b when a is truthy; `a ?? b` is b when a is nullish
    const takesRight = n.operator === "||" ? !test : test;

    return [takesRight ? n.right : n.left];
  }

  if (n.type === "ConditionalExpression") {
    const test = truthiness(n.test);

    return test === null ? [n.consequent, n.alternate] : [test ? n.consequent : n.alternate];
  }

  return null;
}

/** Expressions found under a limit, and whether there were more than it allows (then the rest are unknown). */
type Found = { nodes: AnyNode[]; more: boolean };

/** The expressions a function's own `return` statements give (not those of functions inside it), up to `max`. */
function returnedBy(fn: AnyNode, max = MAX_RETURNS): Found {
  if (fn.type === "ArrowFunctionExpression" && fn.body.type !== "BlockStatement") return { nodes: [fn.body], more: false };
  const out: AnyNode[] = [];
  const stack: AnyNode[] = [...functionBody(fn)];

  for (let n = stack.pop(); n; n = stack.pop()) {
    if (n.type === "ReturnStatement") {
      if (!n.argument) continue;

      if (out.length >= max) return { nodes: out, more: true };
      out.push(n.argument);
      continue;
    }

    if (isFunctionNode(n) || n.type === "FunctionDeclaration" || n.type === "ClassDeclaration" || isTypeOnly(n)) continue;
    stack.push(...childNodes(n));
  }

  return { nodes: out, more: false };
}

/** The values a constructor assigns to `this.prop` in its own body (not in functions inside it), up to MAX_THIS_WRITES. */
function thisWrites(fn: AnyNode, prop: string): Found {
  const out: AnyNode[] = [];
  const stack: AnyNode[] = [...functionBody(fn)];

  for (let n = stack.pop(); n; n = stack.pop()) {
    if (n.type === "AssignmentExpression" && n.operator === "=" && n.left.type === "MemberExpression" && n.left.object.type === "ThisExpression" && propertyName(n.left.property, n.left.computed) === prop) {
      if (out.length >= MAX_THIS_WRITES) return { nodes: out, more: true };
      out.push(n.right);
    }

    if (n.type === "FunctionExpression" || n.type === "FunctionDeclaration" || n.type === "ClassDeclaration" || n.type === "ClassExpression" || isTypeOnly(n)) continue;
    stack.push(...childNodes(n));
  }

  return { nodes: out, more: false };
}

const ROLE_RANK: Record<Role, number> = { none: 0, plain: 1, request: 2, read: 3, shell: 4, code: 5 };

/** One callee's reading of a call: what each argument is for, by position, and for the rest. */
type Plan = { roles: Role[]; rest: Role | "inherit" };


// ---------- the floor: the text rules over the whole program ----------
//
// Every parsed program is also read by the text rules over its whole text, as apm-score-v3 read every file: comments,
// regex bodies and TypeScript types included, because `String(fn)`, `re.source` and a file reading its own source give
// that text back at runtime, and it can be run or used as data from there (apm-score-v9). Every match stands,
// confirmed. The tree adds what it sees and chooses citations; it removes nothing. The parse only says which matches sit
// in a comment, a regex body or erased TypeScript, so the evidence line can name it.

/** The text of one program that does not run as written: its comments, regex literal bodies and erased TypeScript. */
type LeftOut = { comments: readonly Range[]; regexes: Range[]; types: Range[] };

function leftOutOf(program: Program, comments: readonly Range[]): LeftOut {
  const out: LeftOut = { comments, regexes: [], types: [] };
  const stack: [AnyNode, AnyNode | null][] = [[program, null]];

  for (let item = stack.pop(); item; item = stack.pop()) {
    const [n, parent] = item;

    if (n !== program && isTypeOnly(n)) {
      out.types.push([n.start, n.end]);
      continue;
    }

    // `await /x/` is a regex in a module and a division in a script, where `await` is a name: that text is code
    if (n.type === "Literal" && "regex" in n && n.regex && parent?.type !== "AwaitExpression") out.regexes.push([n.start, n.end]);

    for (const c of childNodes(n)) stack.push([c, n]);
  }

  out.types.sort((a, b) => a[0] - b[0]);
  out.regexes.sort((a, b) => a[0] - b[0]);

  return out;
}

/** Whether all of `[start, end)` sits inside one of the sorted ranges (which may nest). */
function withinOne(ranges: readonly Range[], start: number, end: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  let found = -1;

  while (lo <= hi) {
    const mid = (lo + hi) >> 1;

    if ((ranges[mid]?.[0] ?? Number.POSITIVE_INFINITY) <= start) {
      found = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }

  for (let i = found; i >= 0 && i > found - 64; i--) {
    const r = ranges[i];

    if (r && start >= r[0] && end <= r[1]) return true;
  }

  return false;
}

/** The left-out text `index` sits in, in one program. */
function hiddenIn(l: LeftOut, index: number): Hidden | undefined {
  if (withinOne(l.comments, index, index + 1)) return "comment";

  if (withinOne(l.regexes, index, index + 1)) return "regex";

  return withinOne(l.types, index, index + 1) ? "type" : undefined;
}

/**
 * The text rules over a whole program's text, every match confirmed. A match is said to sit in a comment, a regex or
 * a type only when every program the text parsed to puts it there (a TypeScript file that is also JavaScript runs its
 * "types" as code where nothing strips them).
 */
function floorOf(text: string, programs: readonly LeftOut[]): TextFinding[] {
  return scanTextRules(text, { hidden: hiddenOf(programs), encoded: true });
}

/** What left-out text `index` sits in: a comment, a regex or a type only when every program the text parsed to puts it there. */
function hiddenOf(programs: readonly LeftOut[]): (index: number) => Hidden | undefined {
  return (index) => {
    const kinds = programs.map((l) => hiddenIn(l, index));

    return kinds.every((k) => k !== undefined) ? kinds[0] : undefined;
  };
}

/** One program, read once. Findings go to `hits`; module paths and loads apm cannot follow go to `paths` and `dynamic`. */
class Reader {
  readonly hits: Hit[] = [];
  readonly paths = new Set<string>();
  readonly loads = new Set<string>();
  readonly dynamic: number[] = [];
  /** Strings the program passes to exec, spawn and the like, as it builds them. */
  readonly commands: { at: number; value: string }[] = [];
  /** Every call read, with what each argument is for, for the flow analysis (flow.ts). */
  readonly sites: CallSite[] = [];
  /**
   * Code the program holds as text: `run` is a string it hands an evaluator, `held` a string that reads as a program and
   * is used some other way (a builtin the package redefines can run it). score.ts reads each one as a program.
   */
  readonly executed: Executed[] = [];
  /** Strings kept as data: what a module exports, an object property's value, an array element (see `markData`). */
  private readonly dataStrings = new Set<AnyNode>();
  /** Code it runs that apm did not read: longer than a held program may be, even with its padding squeezed out. */
  readonly unread: { at: number; why: string }[] = [];
  /** Where values go (flow.ts); read for the outermost program only, since score.ts reads code held in strings itself. */
  flow: FlowRead = NO_FLOW;
  private readonly scopes: Scopes;
  private readonly strCache = new Map<AnyNode, Str | null>();
  private readonly bindingCache = new Map<Binding, Ref[]>();
  private readonly returnCache = new Map<AnyNode, Ref[]>();
  private readonly resolveCache = new Map<AnyNode, Ref[]>();
  private readonly memberCache = new Map<AnyNode, Map<string, Ref[]>>();
  private readonly envDumps: number[] = [];
  private readonly netCalls: { at: number; confidence: Confidence }[] = [];
  /** Set when the program uses `await` as a name: a module reads the same text as the operator. */
  sawAwaitName = false;
  private hexCount = 0;
  private hexFirst = -1;
  private resolving = 0;

  constructor(
    private readonly program: Program,
    private readonly depth: number,
    private readonly budget: Budget,
  ) {
    this.scopes = inPhase("scope", () => buildScopes(program));
  }

  read(): void {
    inPhase("read", () => {
      this.markData();
      this.visit(this.program, "plain");
    });

    for (const at of this.envDumps) {
      const near = this.netCalls.filter((c) => Math.abs(c.at - at) <= NEAR);

      if (near.length === 0) continue;
      const confidence: Confidence = near.some((c) => c.confidence === "confirmed") ? "confirmed" : "possible";
      this.add("credential-access", at, STRENGTH.call, "as written", confidence, "reads the whole environment next to a call apm could not identify");
    }

    if (this.hexCount >= 20) this.add("obfuscated", this.hexFirst, STRENGTH.reference, "as written", "confirmed", "");

    if (this.depth > 0) return;

    try {
      this.flow = inPhase("flow", () =>
        new Flow({
          program: this.program,
          calls: this.sites,
          refsOf: (n) => this.resolveAll(n),
          bindingOf: (id) => this.bindingOf(id),
          str: (n) => this.str(n),
          // the flow follows every return: each is read once per function, so no bound is needed there
          returnedBy: (fn) => returnedBy(fn, Number.POSITIVE_INFINITY).nodes,
          limit: (bound) => this.budget.notes.add(PRECISION_BOUNDS[bound]),
        }).read(),
      );

      // text the program writes to a file and then loads runs as code
      for (const w of this.flow.ranWritten) this.hold(w.at, w.code, "run");
    } catch (e) {
      // a value chain deep enough to exhaust the stack, or more work than the budget, is not followed: the text rules
      // still read the file, and the analysis says it did not follow where values go here
      if (!(e instanceof RangeError) && !(e instanceof FlowExhausted)) throw e;
      this.budget.notes.add(LIMIT_NOTES.flow);
      this.unread.push({ at: 0, why: e instanceof FlowExhausted ? `apm stopped following where values go at its work budget (${MAX_FLOW_WORK / 1_000_000} million steps)` : "values nested too deep for apm to follow where they go" });
    }
  }

  /**
   * The strings a program keeps as data: what a module exports (`module.exports = "..."`, `exports.x = ...`,
   * `export default ...`, `export const x = ...`), and the strings in object and array literals it exports that way,
   * also through a constant (`module.exports = { examples }`). A literal with a method or function in it is not data,
   * since its own code can run what it holds; a string handed to a call apm cannot name is not either.
   */
  private markData(): void {
    const roots: AnyNode[] = [];
    const stack: AnyNode[] = [this.program];

    for (let n = stack.pop(); n; n = stack.pop()) {
      if (n.type === "ExportDefaultDeclaration") roots.push(n.declaration);
      else if (n.type === "ExportNamedDeclaration" && n.declaration?.type === "VariableDeclaration") {
        for (const d of n.declaration.declarations) if (d.init) roots.push(d.init);
      } else if (n.type === "AssignmentExpression" && n.left.type === "MemberExpression") {
        let root: AnyNode = n.left;

        while (root.type === "MemberExpression") root = root.object;

        if (root.type === "Identifier" && (root.name === "module" || root.name === "exports") && this.bindingOf(root) === null) roots.push(n.right);
      }

      stack.push(...childNodes(n));
    }

    const seen = new Set<AnyNode>();
    const isFn = (v: AnyNode): boolean => isFunctionNode(v) || v.type === "FunctionDeclaration";

    const mark = (v: AnyNode, depth: number): void => {
      const t = unwrap(v);

      if (depth > 4 || seen.has(t)) return;
      seen.add(t);

      switch (t.type) {
        case "Literal":
        case "TemplateLiteral":
        case "BinaryExpression":
          this.dataStrings.add(t);

          return;
        case "Identifier": {
          const init = this.constInit(t);

          if (init) mark(init, depth + 1);

          return;
        }

        case "ObjectExpression": {
          const values = t.properties.flatMap((p) => (p.type === "Property" ? [p] : []));
          const code = t.properties.some((p) => p.type === "SpreadElement") || values.some((p) => p.kind !== "init" || p.method || isFn(unwrap(p.value)));

          // strings beside a method are not data; an object of examples and helpers (`{ examples, render }`) is
          for (const p of values) {
            const value = unwrap(p.value);
            const str = value.type === "Literal" || value.type === "TemplateLiteral" || value.type === "BinaryExpression";

            if (!(code && str)) mark(p.value, depth + 1);
          }

          return;
        }

        case "ArrayExpression":
          for (const e of t.elements) if (e && e.type !== "SpreadElement") mark(e, depth + 1);

          return;
        default:
          return;
      }
    };

    for (const r of roots) mark(r, 0);
  }

  private add(id: CodeSignal, at: number, strength: Strength, how: How, confidence: Confidence, why: string): void {
    this.hits.push(hitOf(id, at, strength, how, confidence, why));

    // a string that mentions curl is not a request; only calls and module loads count as the network next to an env dump
    if (id === "network" && strength >= STRENGTH.load) this.netCalls.push({ at, confidence });
  }

  /** Whether resolving has gone deeper than it may; past this a value is unknown, and the limit is noted. */
  private tooDeep(): boolean {
    if (this.resolving <= 24) return false;
    this.budget.notes.add(LIMIT_NOTES.depth);

    return true;
  }

  // ----- resolving names -----

  /** The binding an identifier refers to, in the scope it sits in. */
  private bindingOf(id: Identifier): Binding | "dynamic" | null {
    return lookup(this.scopes.scopeOf, id);
  }

  /** The value a constant holds: a name declared once in its scope, with a value, and never assigned. */
  private constInit(id: Identifier): Expression | null {
    const b = this.bindingOf(id);

    return b !== null && b !== "dynamic" && b.count === 1 && !b.assigned && b.origin.kind === "value" && b.origin.init !== id ? b.origin.init : null;
  }

  /** Every value `n` can be, as far as apm can tell: several for `a || b`, `c ? a : b`, a getter, or a written member. */
  private resolveAll(n: AnyNode): Ref[] {
    const node = unwrap(n);
    const cached = this.resolveCache.get(node);

    if (cached) return cached;

    if (this.tooDeep()) return [cutRef("depth")];
    chargeNow(2);
    // a value that refers back to itself reads as unknown
    this.resolveCache.set(node, [UNKNOWN_REF]);
    this.resolving++;

    try {
      const refs = distinct(this.resolveNode(node), this.budget.notes);
      this.resolveCache.set(node, refs);

      return refs;
    } finally {
      this.resolving--;
    }
  }

  /** The one value that stands for what `n` can be (see `pick`). */
  private resolve(n: AnyNode): Ref {
    return pick(this.resolveAll(n));
  }

  private resolveIdentifier(id: Identifier): Ref[] {
    const b = this.bindingOf(id);

    // a name no scope declares is the global; so is one a `with` body may read from its object
    if (b === null || b === "dynamic") {
      if (b === null && this.scopes.assignedFree.has(id.name)) return [unknownNamed(id.name)];

      return [{ kind: "global", path: GLOBAL_OBJECTS.has(id.name) ? "" : id.name, built: false }];
    }

    const cached = this.bindingCache.get(b);

    if (cached) return cached;
    // a value that refers to itself reads as its name
    this.bindingCache.set(b, [unknownNamed(b.name)]);
    const refs = b.count !== 1 || b.assigned ? [unknownNamed(b.name)] : this.originRefs(b.origin, b);
    this.bindingCache.set(b, refs);

    return refs;
  }

  private originRefs(o: Origin, b: Binding): Ref[] {
    switch (o.kind) {
      case "local":
        return [{ kind: "local", fn: o.node.type === "FunctionDeclaration" || o.node.type === "ClassDeclaration" || isFunctionNode(o.node), obj: { node: o.node, binding: b, instance: false } }];
      case "module":
        return [{ kind: "module", spec: o.spec, path: o.path, built: false }];
      case "opaque":
        return [unknownNamed(b.name)];
      case "value": {
        const init = unwrap(o.init);

        return this.resolveAll(o.init).map((r) => {
          // the binding that holds a value this file makes also holds the writes made to it later
          if (r.kind === "local" && r.obj && r.obj.binding === null && (r.obj.node === init || r.obj.instance)) return { ...r, obj: { ...r.obj, binding: b } };

          return r.kind === "unknown" && r.name === null ? unknownNamed(b.name, null, r.built, r.limit) : r;
        });
      }

      case "member": {
        let refs = this.resolveAll(o.base);

        for (const k of o.path) {
          const key = this.keyName(k);

          refs = key === null ? [unknownNamed(b.name)] : distinct(refs.flatMap((r) => this.memberAll(r, key.name, key.built)), this.budget.notes);
        }

        return refs;
      }

      case "default":
        return [...this.originRefs(o.inner, b), ...this.resolveAll(o.fallback)];
      default: {
        const _exhaustive: never = o;

        return _exhaustive;
      }
    }
  }

  private keyName(k: Key): { name: string; built: boolean } | null {
    if (k.kind === "name") return { name: k.name, built: false };
    const s = this.str(k.node);

    return s?.exact && !s.numeric ? { name: s.value, built: s.how !== "as written" } : s?.exact ? { name: s.value, built: false } : null;
  }

  /** Every value `base[prop]` can be. A local value's members are read from the node that made it and the writes to it. */
  private memberAll(base: Ref, prop: string, built: boolean): Ref[] {
    if (base.kind !== "local") return [member(base, prop, built)];

    if (prop === "constructor") return [member(base, prop, built)];
    const obj = base.obj;

    if (!obj) return [{ kind: "local", fn: false, obj: null }];
    const key = `${obj.instance ? "i" : "v"}:${obj.binding?.name ?? ""}:${prop}`;
    const byKey = this.memberCache.get(obj.node) ?? new Map<string, Ref[]>();
    const cached = byKey.get(key);

    if (cached) return cached;

    if (this.tooDeep()) return [unknownNamed(prop, null, false, "depth")];
    this.memberCache.set(obj.node, byKey);
    byKey.set(key, [unknownNamed(prop)]);
    this.resolving++;

    try {
      const out = [...(this.ownMember(obj.node, prop, obj.instance) ?? [])];

      for (const w of obj.binding?.writes ?? []) out.push(...this.writtenMember(w, prop, obj.binding?.name ?? null));
      const refs = out.length > 0 ? distinct(out, this.budget.notes) : [{ kind: "local", fn: false, obj: null } satisfies Ref];
      byKey.set(key, refs);

      return refs;
    } finally {
      this.resolving--;
    }
  }

  /** What a write to a local value makes `prop` (nothing when it writes another member). */
  private writtenMember(w: Write, prop: string, owner: string | null): Ref[] {
    switch (w.kind) {
      case "set": {
        const key = this.keyName(w.key);

        if (key !== null && key.name !== prop) return [];

        // a key apm cannot work out may be this one: what it holds is told by name
        if (key === null || w.value === null) return [unknownNamed(prop, owner)];

        return this.resolveAll(w.value);
      }

      case "define": {
        const key = this.keyName(w.key);

        if (key !== null && key.name !== prop) return [];

        if (key === null || w.descriptor === null) return [unknownNamed(prop, owner)];

        return this.described(w.descriptor, prop, owner);
      }

      case "spread":
        return this.resolveAll(w.source).flatMap((r) => (r.kind === "local" ? (r.obj ? (this.ownMember(r.obj.node, prop) ?? []) : []) : this.memberAll(r, prop, false)));
      case "proto":
        return this.resolveAll(w.value).flatMap((r) => this.memberAll(r, prop, false));
      default: {
        const _exhaustive: never = w;

        return _exhaustive;
      }
    }
  }

  /** What a property descriptor (`{ value }` or `{ get }`) makes a property read give. */
  private described(descriptor: AnyNode, prop: string, owner: string | null): Ref[] {
    const d = unwrap(descriptor);

    if (d.type !== "ObjectExpression") return [unknownNamed(prop, owner)];
    const value = this.ownMember(d, "value") ?? [];
    const getters = this.ownMember(d, "get") ?? [];

    return [...value, ...getters.flatMap((g) => this.calledRefs(g, prop, owner))];
  }

  /** What calling a function value gives: what its own returns give, or, when apm cannot read it, a value told by `prop`. */
  private calledRefs(fn: Ref, prop: string, owner: string | null): Ref[] {
    if (fn.kind !== "local" || !fn.obj) return [unknownNamed(prop, owner)];

    return this.returnsOf(fn.obj.node).map((r) => (r.kind === "unknown" ? unknownNamed(prop, owner, r.built, r.limit) : r));
  }

  /** What a function's returns give, cached per function. */
  private returnsOf(fn: AnyNode): Ref[] {
    const cached = this.returnCache.get(fn);

    if (cached) return cached;
    this.returnCache.set(fn, [UNKNOWN_REF]);
    const returned = returnedBy(fn);

    if (returned.more) this.budget.notes.add(LIMIT_NOTES.returns);
    const all = [...returned.nodes.flatMap((r) => this.resolveAll(r)), ...(returned.more ? [cutRef("returns")] : [])];
    const refs = all.length === 0 ? [{ kind: "local", fn: false, obj: null } satisfies Ref] : distinct(all, this.budget.notes);
    this.returnCache.set(fn, refs);

    return refs;
  }

  /**
   * A member of the value a node makes: an object literal's property, getter or spread (later ones win, so they are
   * read first), its `__proto__`; an array's element; a class's static member; any member of a Proxy whose `get`
   * trap apm can read; a member of `Object.create(proto)`. Null when the node does not have the member.
   */
  private ownMember(node: AnyNode, prop: string, instance = false): Ref[] | null {
    // spreads, prototypes and superclasses can refer back to themselves
    if (this.tooDeep()) return [unknownNamed(prop, null, false, "depth")];
    this.resolving++;

    try {
      return this.ownMemberOf(node, prop, instance);
    } finally {
      this.resolving--;
    }
  }

  private ownMemberOf(node: AnyNode, prop: string, instance: boolean): Ref[] | null {
    switch (node.type) {
      case "ObjectExpression": {
        const out: Ref[] = [];
        let proto: AnyNode | null = null;

        for (const p of node.properties.toReversed()) {
          if (p.type === "SpreadElement") {
            for (const r of this.resolveAll(p.argument)) {
              const own = r.kind === "local" ? (r.obj ? this.ownMember(r.obj.node, prop) : null) : this.memberAll(r, prop, false);

              if (own) out.push(...own);
            }

            continue;
          }

          const key = p.computed ? this.keyName({ kind: "computed", node: p.key }) : { name: propertyName(p.key, false) ?? "", built: false };

          if (!p.computed && !p.shorthand && p.kind === "init" && key?.name === "__proto__") {
            proto ??= p.value;
            continue;
          }

          if (key === null) {
            out.push(unknownNamed(prop));
            continue;
          }

          if (key.name !== prop) continue;

          if (p.kind === "get") return [...out, ...this.calledRefs({ kind: "local", fn: true, obj: { node: p.value, binding: null, instance: false } }, prop, null)];

          if (p.kind === "init") return [...out, ...this.resolveAll(p.value)];
        }

        if (proto) out.push(...this.resolveAll(proto).flatMap((r) => this.memberAll(r, prop, false)));

        return out.length > 0 ? out : null;
      }

      case "ArrayExpression": {
        const el = /^\d+$/.test(prop) ? node.elements[Number(prop)] : undefined;

        return el && el.type !== "SpreadElement" ? this.resolveAll(el) : null;
      }

      case "ClassDeclaration":
      case "ClassExpression": {
        // static members on the class; methods, getters, fields and `this.x = …` in the constructor on an instance
        for (const m of node.body.body.toReversed()) {
          if (m.type !== "MethodDefinition" && m.type !== "PropertyDefinition") continue;

          if (m.static === instance || m.key.type === "PrivateIdentifier" || propertyName(m.key, m.computed) !== prop) continue;

          if (m.type === "MethodDefinition") return m.kind === "get" ? this.calledRefs({ kind: "local", fn: true, obj: { node: m.value, binding: null, instance: false } }, prop, null) : [{ kind: "local", fn: true, obj: { node: m.value, binding: null, instance: false } }];

          return m.value ? this.resolveAll(m.value) : null;
        }

        if (instance) {
          const ctor = node.body.body.find((m) => m.type === "MethodDefinition" && m.kind === "constructor");
          const set = ctor?.type === "MethodDefinition" ? thisWrites(ctor.value, prop) : { nodes: [], more: false };

          if (set.more) this.budget.notes.add(LIMIT_NOTES.thisWrites);

          if (set.nodes.length > 0) return [...set.nodes.flatMap((v) => this.resolveAll(v)), ...(set.more ? [cutRef("thisWrites")] : [])];
        }

        // inherited: from a class this file defines, or told by name from one it does not
        if (!node.superClass) return null;

        return this.resolveAll(node.superClass).flatMap((r) => (r.kind === "local" && r.obj ? (this.ownMember(r.obj.node, prop, instance) ?? []) : instance ? [unknownNamed(prop)] : this.memberAll(r, prop, false)));
      }

      case "NewExpression": {
        // new Proxy(target, { get() { return … } }): every member is what the trap returns
        const handler = node.arguments[1];

        if (!handler || handler.type === "SpreadElement") return [unknownNamed(prop)];
        const traps = this.resolveAll(handler).flatMap((h) => (h.kind === "local" && h.obj ? (this.ownMember(h.obj.node, "get") ?? []) : []));

        return traps.length > 0 ? traps.flatMap((t) => this.calledRefs(t, prop, null)) : [unknownNamed(prop)];
      }

      case "CallExpression": {
        // Object.create(proto): members come from the prototype
        const proto = node.arguments[0];

        return proto && proto.type !== "SpreadElement" ? this.resolveAll(proto).flatMap((r) => this.memberAll(r, prop, false)) : null;
      }

      default:
        return null;
    }
  }

  private memberKey(n: MemberExpression): { name: string; built: boolean } | null {
    if (!n.computed) return n.property.type === "Identifier" ? { name: n.property.name, built: false } : null;
    // `o[['post']]`: a one-element array key is that element's string
    const prop = n.property.type === "ArrayExpression" && n.property.elements.length === 1 && n.property.elements[0] && n.property.elements[0].type !== "SpreadElement" ? n.property.elements[0] : n.property;
    const s = prop.type === "PrivateIdentifier" ? null : this.str(prop);

    return s?.exact && !s.numeric ? { name: s.value, built: s.how !== "as written" } : s?.exact ? { name: s.value, built: false } : null;
  }

  private resolveNode(n: AnyNode): Ref[] {
    const branches = operands(n);

    if (branches) return branches.flatMap((b) => this.resolveAll(b));

    switch (n.type) {
      case "Identifier":
        return this.resolveIdentifier(n);
      case "MemberExpression": {
        if (n.object.type === "Super") return [UNKNOWN_REF];
        const key = this.memberKey(n);
        const object = unwrap(n.object);

        // (function () {}).constructor and (async () => {}).constructor are Function
        if (key?.name === "constructor" && isFunctionNode(object)) return [{ kind: "global", path: "Function", built: key.built }];
        const bases = this.resolveAll(object);

        if (!key) return bases.map((base) => unknownNamed(null, base.kind === "unknown" ? base.name : lastName(base) || null));

        return bases.flatMap((base) => this.memberAll(base, key.name, key.built));
      }

      case "SequenceExpression": {
        const last = n.expressions.at(-1);

        return last ? this.resolveAll(last) : [UNKNOWN_REF];
      }

      case "AwaitExpression": {
        // awaiting an async function's call gives what it returns; awaiting anything else gives that value
        const arg = unwrap(n.argument);

        if (arg.type !== "CallExpression" || arg.callee.type === "Super") return this.resolveAll(n.argument);

        return this.resolveAll(arg.callee).flatMap((c) => (c.kind === "local" && c.obj && isAsyncFunction(c.obj.node) ? this.returnsOf(c.obj.node) : this.resolveCall(arg, [c])));
      }

      case "AssignmentExpression":
        return n.operator === "=" ? this.resolveAll(n.right) : [UNKNOWN_REF];
      case "CallExpression":
        return this.resolveCall(n);
      case "NewExpression": {
        const made = this.resolveAll(n.callee);

        // a Module instance has the same _compile that runs code as `module` does
        if (made.some((m) => m.kind === "module" && m.spec === "module" && (m.path === "" || m.path === "Module"))) return [{ kind: "global", path: "module", built: false }];

        if (made.some((m) => m.kind === "global" && m.path === "Proxy")) return [{ kind: "local", fn: false, obj: { node: n, binding: null, instance: false } }];
        // an instance of a class this file defines has the class's methods, getters and fields
        const classes = made.flatMap((m) => (m.kind === "local" && m.obj && (m.obj.node.type === "ClassDeclaration" || m.obj.node.type === "ClassExpression") ? [m.obj.node] : []));

        return classes.length > 0 ? classes.map((node): Ref => ({ kind: "local", fn: false, obj: { node, binding: null, instance: true } })) : [UNKNOWN_REF];
      }

      case "ImportExpression": {
        const s = this.str(n.source);

        return [s?.exact ? { kind: "module", ...moduleOf(s.value, ""), built: s.how !== "as written" } : UNKNOWN_REF];
      }

      case "FunctionExpression":
      case "ArrowFunctionExpression":
      case "ClassExpression":
        return [{ kind: "local", fn: true, obj: { node: n, binding: null, instance: false } }];
      case "ObjectExpression":
      case "ArrayExpression":
        return [{ kind: "local", fn: false, obj: { node: n, binding: null, instance: false } }];
      case "Literal":
      case "TemplateLiteral":
        return [{ kind: "local", fn: false, obj: null }];
      default:
        return [UNKNOWN_REF];
    }
  }

  private resolveCall(n: CallExpression, callees?: readonly Ref[]): Ref[] {
    if (n.callee.type === "Super") return [UNKNOWN_REF];
    const target = unwrap(n.callee);

    // Function('return this')() is the global object
    if ((target.type === "CallExpression" || target.type === "NewExpression") && target.callee.type !== "Super" && target.arguments.length === 1) {
      const body = target.arguments[0] && target.arguments[0].type !== "SpreadElement" ? this.str(target.arguments[0]) : null;

      if (body?.exact && body.value.trim() === "return this" && this.resolveAll(target.callee).some((r) => r.kind === "global" && r.path === "Function")) return [{ kind: "global", path: "", built: false }];
    }

    // eval.bind(null) is eval
    if (target.type === "MemberExpression" && !target.computed && target.property.type === "Identifier" && target.property.name === "bind" && target.object.type !== "Super") return this.resolveAll(target.object);
    const arg = n.arguments[0];
    const argNode = arg && arg.type !== "SpreadElement" ? arg : null;
    // compilers wrap a require in an interop helper that returns the same module (often defined in the same file,
    // so it is matched by the name it is called by)
    const helper = target.type === "Identifier" ? target.name : target.type === "MemberExpression" && !target.computed && target.property.type === "Identifier" ? target.property.name : "";

    if (INTEROP.test(helper) && argNode) {
      const inner = this.resolveAll(argNode).filter((r) => r.kind === "module");

      if (inner.length > 0) return inner;
    }

    const out: Ref[] = [];

    for (const callee of callees ?? this.resolveAll(n.callee)) {
      const name = nameOf(callee);

      if (isRequire(callee) && argNode) {
        const s = this.str(argNode);

        out.push(s?.exact ? { kind: "module", ...moduleOf(s.value, ""), built: s.how !== "as written" } : UNKNOWN_REF);
      } else if (callee.kind === "global" && name === "Object.getPrototypeOf" && argNode && isFunctionNode(unwrap(argNode))) out.push({ kind: "local", fn: true, obj: null });
      else if ((callee.kind === "global" && name === "createRequire") || (callee.kind === "module" && name === "module.createRequire")) out.push({ kind: "global", path: "require", built: false });
      else if (callee.kind === "global" && name === "Reflect.get" && argNode) {
        // Reflect.get(globalThis, 'fetch') is globalThis.fetch
        const key = n.arguments[1] && n.arguments[1].type !== "SpreadElement" ? this.keyName({ kind: "computed", node: n.arguments[1] }) : null;

        out.push(...(key ? this.resolveAll(argNode).flatMap((r) => this.memberAll(r, key.name, key.built)) : [UNKNOWN_REF]));
      } else if (callee.kind === "global" && name === "Object.create") out.push({ kind: "local", fn: false, obj: { node: n, binding: null, instance: false } });
      // an async function's call gives a Promise and a generator's a generator object, not what they return: calling
      // that value throws, so it runs nothing (`await` and `.next()` are what reach the returned value)
      else if (callee.kind === "local" && callee.obj && (isAsyncFunction(callee.obj.node) || isGenerator(callee.obj.node))) out.push({ kind: "local", fn: false, obj: null });
      else if (callee.kind === "local" && callee.obj && (isFunctionNode(callee.obj.node) || callee.obj.node.type === "FunctionDeclaration")) out.push(...this.returnsOf(callee.obj.node));
      else out.push(UNKNOWN_REF);
    }

    return out;
  }

  // ----- working out strings -----

  private str(n: AnyNode): Str | null {
    const cached = this.strCache.get(n);

    if (cached !== undefined) return cached;
    chargeNow(2);
    this.strCache.set(n, null);
    const s = this.tooDeep() ? null : this.strNode(n);
    this.strCache.set(n, s);

    return s;
  }

  private strNode(n: AnyNode): Str | null {
    switch (n.type) {
      case "Literal":
        // code read from a string apm only partly knew holds UNKNOWN where the unknown piece was
        const text = stringValue(n);

        if (text !== null) return { value: text, exact: !text.includes(UNKNOWN), how: ESCAPE.test(n.raw ?? "") ? "after joining strings" : "as written", pieces: text ? 1 : 0, via: null, numeric: false };
        const num = numberValue(n);

        return num === null ? null : { value: String(num), exact: true, how: "as written", pieces: 0, via: null, numeric: true };
      case "TemplateLiteral":
        return this.strTemplate(n);
      case "BinaryExpression": {
        if (n.operator !== "+" || n.left.type === "PrivateIdentifier") return null;
        const l = this.str(n.left);
        const r = this.str(n.right);

        if ((!l || l.numeric) && (!r || r.numeric)) return null;
        const a = l ?? unknownStr();
        const b = r ?? unknownStr();

        if (!this.folds(a.value.length + b.value.length, n.start)) return null;

        return { value: a.value + b.value, exact: a.exact && b.exact, how: strongerHow(strongerHow(a.how, b.how), "after joining strings"), pieces: a.pieces + b.pieces, via: a.via ?? b.via, numeric: false };
      }

      case "Identifier": {
        const init = this.constInit(n);

        if (!init) return null;
        this.resolving++;

        try {
          return this.str(init);
        } finally {
          this.resolving--;
        }
      }

      case "CallExpression":
        return this.strCall(n);
      case "MemberExpression":
        return this.regexSource(n) ?? this.arrayElement(n);
      case "ChainExpression":
      case "TSAsExpression":
      case "TSSatisfiesExpression":
      case "TSNonNullExpression":
      case "TSTypeAssertion":
        return this.str(n.expression);
      default:
        return null;
    }
  }

  /** `table[1]`: an element of an array literal (or a constant holding one), by an index apm knows. */
  private arrayElement(n: MemberExpression): Str | null {
    if (!n.computed || n.object.type === "Super" || n.property.type === "PrivateIdentifier") return null;
    const key = this.str(n.property);

    if (!key?.exact || !/^\d+$/.test(key.value)) return null;
    const parts = this.arrayStrings(n.object);

    return parts?.[Number(key.value)] ?? null;
  }

  /** `/…/.source`, also through a constant holding the regex: the pattern's text, which code can hand to an evaluator. */
  private regexSource(n: MemberExpression): Str | null {
    if (n.computed || n.property.type !== "Identifier" || n.property.name !== "source" || n.object.type === "Super") return null;
    const target = unwrap(n.object);
    const literal = target.type === "Identifier" ? this.constInit(target) : target;
    const re = literal && literal.type === "Literal" && "regex" in literal ? literal.regex : null;

    return re ? { value: re.pattern, exact: true, how: "as written", pieces: 1, via: null, numeric: false } : null;
  }

  private strTemplate(n: TemplateLiteral): Str | null {
    let value = "";
    let exact = true;
    let how: Str["how"] = n.expressions.length > 0 ? "after joining strings" : "as written";
    let pieces = 0;
    let via: string | null = null;
    let known = false;

    for (let i = 0; i < n.quasis.length; i++) {
      const q = n.quasis[i];

      if (!q) continue;
      const cooked = q.value.cooked ?? q.value.raw;

      if (!this.folds(value.length + cooked.length, n.start)) return null;
      value += cooked;

      if (cooked) {
        pieces++;
        known = true;
      }

      if (ESCAPE.test(q.value.raw)) how = strongerHow(how, "after joining strings");
      const e = n.expressions[i];

      if (!e) continue;
      const s = this.str(e);

      if (s) {
        if (!this.folds(value.length + s.value.length, n.start)) return null;
        value += s.value;
        pieces += s.pieces;
        how = strongerHow(how, s.how);
        via ??= s.via;
        known = true;

        if (!s.exact) exact = false;
      } else {
        value += UNKNOWN;
        exact = false;
      }
    }

    return known ? { value, exact, how, pieces, via, numeric: false } : null;
  }

  /**
   * A decoded string the file's decoded-text budget still has room for. Past the budget it is null, and the code
   * decoded it at `at` is code apm did not read: the file is incomplete.
   */
  private decoded(value: string | null, from: Str, via: string, at: number): Str | null {
    if (value === null) return null;

    // the whole result must fit: one large decode cannot go past what is left
    if (value.length > this.budget.decoded) {
      this.budget.notes.add(LIMIT_NOTES.decoded);
      this.stop(at, `decodes ${via} past the ${MAX_DECODED_BYTES / 1024} KB of decoded text apm reads in one file, so what it decodes there was not read`);

      return null;
    }

    this.budget.decoded -= value.length;

    return { value, exact: true, how: "decoded", pieces: from.pieces, via, numeric: false };
  }

  /**
   * Runs a built-in decoder (`atob`, `Buffer.from(…, 'base64' | 'hex')`, URI decoding) on `from` once the file's
   * decoded-text budget has room for what it can give, which is never longer than its input: so the check comes before
   * the decode does any work, and a decode past the budget is code apm did not read, which makes the file incomplete.
   */
  private decodedBy(from: Str, via: string, at: number, decode: () => string | null): Str | null {
    if (from.value.length > this.budget.decoded) {
      this.budget.notes.add(LIMIT_NOTES.decoded);
      this.stop(at, `decodes ${via} past the ${MAX_DECODED_BYTES / 1024} KB of decoded text apm reads in one file, so what it decodes there was not read`);

      return null;
    }

    chargeText("decode", from.value.length, 3);

    return this.decoded(decode(), from, via, at);
  }

  /** A limit that leaves code unread: the file is incomplete. A nested reading hands it to the outer one. */
  private stop(at: number, why: string): void {
    if (this.depth > 0) {
      if (this.budget.stopped.length < MAX_EXECUTED) this.budget.stopped.push(why);
    } else if (this.unread.length < MAX_EXECUTED && !this.unread.some((u) => u.why === why)) this.unread.push({ at, why });
  }

  /**
   * Charges building a constant string of `chars` characters to the file's folding allowance (and so the meter) before
   * it is built. Past the allowance the string is unknown and the file is incomplete: `const s1=s0+s0` doubled 23
   * times would build 8 MB from 435 bytes.
   */
  private folds(chars: number, at: number): boolean {
    const units = Math.ceil(chars / CHARS_PER_UNIT) + 1;

    if (this.budget.fold.fits(units)) {
      this.budget.fold.take(units);

      return true;
    }

    this.budget.notes.add(LIMIT_NOTES.fold);
    this.stop(at, "builds constant strings past what apm works out in one file (a million characters and 16 for each of the file's), so the strings past that are not known");

    return false;
  }

  private strCall(n: CallExpression): Str | null {
    if (n.callee.type === "Super") return null;
    const decoded = this.localDecoded(n);

    if (decoded) return decoded;
    const callee = this.resolve(n.callee);
    const name = callee.kind === "global" ? callee.path : "";
    const args = n.arguments.filter((a): a is Expression => a.type !== "SpreadElement");
    const a0 = args[0] ? this.str(args[0]) : null;

    if (name === "atob") return a0?.exact ? this.decodedBy(a0, "base64", n.start, () => decodeBase64(a0.value)) : null;

    if (name === "Buffer.from") {
      if (!a0?.exact) return null;
      const enc = args[1] ? this.str(args[1]) : null;

      if (!enc) return a0;

      if (enc.value === "base64" || enc.value === "base64url") return this.decodedBy(a0, "base64", n.start, () => decodeBase64(a0.value));

      if (enc.value === "hex") return this.decodedBy(a0, "hex", n.start, () => (/^(?:[0-9a-fA-F]{2})+$/.test(a0.value) ? Buffer.from(a0.value, "hex").toString("latin1") : null));

      return a0;
    }

    if (name === "String.fromCharCode") return this.charCodes(n.arguments, n.start);

    if (name === "decodeURIComponent" || name === "decodeURI" || name === "unescape") {
      if (!a0?.exact) return null;

      return this.decodedBy(a0, "URI escapes", n.start, () => {
        try {
          return name === "unescape" ? unescape(a0.value) : decodeURIComponent(a0.value);
        } catch {
          return null;
        }
      });
    }

    if (name === "String") return a0;
    const target = unwrap(n.callee);

    if (target.type !== "MemberExpression" || target.computed || target.property.type !== "Identifier" || target.object.type === "Super") return null;
    const method = target.property.name;

    // String.fromCharCode.apply(null, codes)
    if (method === "apply" && nameOf(this.resolve(target.object)) === "String.fromCharCode") return this.charCodes(n.arguments.slice(1), n.start);

    if (method === "join") {
      const parts = this.arrayStrings(target.object);

      if (!parts) return null;
      const sep = a0?.exact ? a0.value : ",";

      // the length is known before the string is built: charged first, and refused past the file's allowance
      if (!this.folds(parts.reduce((k, p) => k + p.value.length, 0) + sep.length * Math.max(0, parts.length - 1), n.start)) return null;

      return { value: parts.map((p) => p.value).join(sep), exact: parts.every((p) => p.exact), how: "after joining strings", pieces: parts.reduce((k, p) => k + p.pieces, 0), via: null, numeric: false };
    }

    const base = this.str(target.object);

    if (!base) return null;

    switch (method) {
      case "toString":
      case "valueOf":
      case "trim":
        return base;
      case "concat": {
        let out = base;

        for (const a of args) {
          const s = this.str(a);

          if (!this.folds(out.value.length + (s?.value ?? UNKNOWN).length, n.start)) return null;
          out = { value: out.value + (s?.value ?? UNKNOWN), exact: out.exact && (s?.exact ?? false), how: "after joining strings", pieces: out.pieces + (s?.pieces ?? 0), via: out.via, numeric: false };
        }

        return out;
      }

      default:
        return null;
    }
  }

  /** `re.exec(s)` and `re.test(s)` on a regex literal, a constant holding one or `new RegExp(…)`: not a command. */
  private isRegexMethod(n: CallExpression | NewExpression): boolean {
    const callee = n.callee.type === "Super" ? null : unwrap(n.callee);

    if (callee?.type !== "MemberExpression" || callee.object.type === "Super") return false;
    let recv: AnyNode | null = unwrap(callee.object);

    if (recv.type === "Identifier") recv = this.constInit(recv);

    if (!recv) return false;

    return (recv.type === "Literal" && "regex" in recv && recv.regex !== undefined) || ((recv.type === "NewExpression" || recv.type === "CallExpression") && recv.callee.type === "Identifier" && recv.callee.name === "RegExp");
  }

  /** A small function this file defines, called with strings or numbers apm knows: what it returns, run (decode.ts). */
  private localDecoded(n: CallExpression): Str | null {
    const fn = this.localFunctionOf(n.callee);

    if (!fn || fn.end - fn.start > MAX_DECODER_CHARS || n.arguments.length === 0) return null;
    const args: Known[] = [];
    let pieces = 0;

    for (const a of n.arguments) {
      const s = a.type === "SpreadElement" ? null : this.str(a);

      if (!s?.exact) return null;
      args.push(s.numeric ? { kind: "number", value: Number(s.value) } : { kind: "text", value: s.value });
      pieces += s.pieces;
    }

    const run = runDecoder(
      fn,
      args,
      {
        constant: (id) => {
          const s = this.str(id);

          if (!s?.exact) return null;

          return s.numeric ? { kind: "number", value: Number(s.value) } : { kind: "text", value: s.value };
        },
        localFunction: (callee) => this.localFunctionOf(callee),
      },
      this.budget.decoder,
    );

    // what a decoder returns is unknown when apm stopped, not because the program hides nothing: the analysis says so,
    // as it does for code it does not read
    const stopped = (limit: string): null => {
      this.stop(n.start, `calls a decoder function it defines, which apm stopped running at its limit (${limit}), so what it returns was not read`);

      return null;
    };

    switch (run.kind) {
      case "decoded":
        // the file's decoded-text budget refusing the result is a limit too
        return this.decoded(run.value, { value: "", exact: true, how: "as written", pieces, via: null, numeric: false }, "a decoder function it defines", n.start) ?? stopped(LIMIT_NOTES.decoded);
      case "unsupported":
        return null;
      case "exhausted":
        return stopped(run.limit);
      default: {
        const _exhaustive: never = run;

        return _exhaustive;
      }
    }
  }

  private localFunctionOf(callee: AnyNode): AnyNode | null {
    if (callee.type === "Super") return null;
    const r = this.resolve(callee);
    const node = r.kind === "local" && r.obj ? r.obj.node : null;

    return node && (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") ? node : null;
  }

  /** The strings of an array literal (or a constant holding one), or of `'abc'.split('').reverse()`. */
  private arrayStrings(n: AnyNode): Str[] | null {
    const target = unwrap(n);

    if (target.type === "Identifier") {
      const init = this.constInit(target);

      return init ? this.arrayStrings(init) : null;
    }

    if (target.type === "ArrayExpression") {
      const out: Str[] = [];

      for (const el of target.elements) {
        if (!el || el.type === "SpreadElement") return null;
        const s = this.str(el);

        if (!s) return null;
        out.push(s);
      }

      return out;
    }

    // 'ssecorp_dlihc'.split('').reverse()
    if (target.type === "CallExpression" && target.callee.type === "MemberExpression" && !target.callee.computed && target.callee.property.type === "Identifier" && target.callee.object.type !== "Super") {
      const method = target.callee.property.name;
      const inner = target.callee.object;

      if (method === "reverse") return this.arrayStrings(inner)?.toReversed() ?? null;
      const arg = target.arguments[0];

      if (method === "split" && arg && arg.type !== "SpreadElement") {
        const s = this.str(inner);
        const sep = this.str(arg);

        if (!s?.exact || !sep?.exact) return null;

        return s.value.split(sep.value).map((value) => ({ value, exact: true, how: "after joining strings", pieces: 1, via: null, numeric: false }));
      }
    }

    return null;
  }

  private numbers(n: AnyNode): number[] | null {
    const target = unwrap(n);

    if (target.type === "Identifier") {
      const init = this.constInit(target);

      return init ? this.numbers(init) : null;
    }

    if (target.type !== "ArrayExpression") return null;
    const out: number[] = [];

    for (const el of target.elements) {
      const v = el?.type === "Literal" ? numberValue(el) : null;

      if (v === null) return null;
      out.push(v);
    }

    return out;
  }

  private charCodes(args: readonly AnyNode[], at: number): Str | null {
    let codes: number[] | null = [];

    if (args.length === 1 && args[0]?.type === "SpreadElement") codes = this.numbers(args[0].argument);
    else if (args.length === 1 && args[0]) {
      const one = args[0].type === "Literal" ? numberValue(args[0]) : null;

      codes = this.numbers(args[0]) ?? (one === null ? null : [one]);
    }
    else {
      for (const a of args) {
        const v = a.type === "Literal" ? numberValue(a) : null;

        if (v === null) return null;
        codes.push(v);
      }
    }

    if (!codes || codes.length === 0) return null;
    chargeNow(codes.length);

    if (codes.some((c) => c < 0 || c > 0xffff)) return null;
    const from: Str = { value: "", exact: true, how: "as written", pieces: codes.length, via: null, numeric: false };

    // built in pieces, never cut: spreading more arguments than the engine takes would throw, and a cut string would
    // read as all the code there is
    let built = "";

    for (let i = 0; i < codes.length; i += 32_768) built += String.fromCharCode(...codes.slice(i, i + 32_768));

    return this.decoded(built, from, "char codes", at);
  }

  // ----- reading strings by role -----

  private stringAt(s: Str, n: AnyNode, role: Role, raw: string | null): void {
    if (role === "none" || s.numeric) return;
    const at = n.start;

    // the tests below each read the string once
    chargeText("read", s.value.length + (raw?.length ?? 0), 8);

    if (raw !== null && escapedTextAt(raw) >= 0) this.add("obfuscated", at, STRENGTH.string, "as written", "confirmed", "");

    if (role === "code") {
      this.evaluate(s, at);

      return;
    }

    const sure = role === "shell";

    if (s.exact && isHeldCode(s.value)) this.hold(at, s.value, this.dataStrings.has(n) ? "data" : "held");

    // what the program hands a shell or a process, for the risk signals that read commands (apm-score-v10)
    if (role === "shell") {
      if (this.commands.length < MAX_COMMANDS) this.commands.push({ at, value: s.value.slice(0, MAX_COMMAND_CHARS) });

      // a command past either bound is one the risk signals did not read in full: the file is incomplete, not clean
      if (this.commands.length >= MAX_COMMANDS && !this.commands.some((c) => c.at === at)) this.stop(at, `hands more than ${MAX_COMMANDS} commands to a shell or a process, more than apm reads in one file`);
      else if (s.value.length > MAX_COMMAND_CHARS) this.stop(at, `hands a shell or a process a command of ${s.value.length} characters, more than the ${MAX_COMMAND_CHARS} apm reads`);
    }

    // a dangerous name built from pieces or decoded: `'chi' + 'ld_process'`, `'\x65xec'`
    if (s.exact && s.how !== "as written") {
      const id = namedSignal(s.value);

      if (id) {
        const why = `builds "${s.value.slice(0, 40)}" from pieces, but apm did not see it loaded or called`;
        this.add(id, at, STRENGTH.string, s.how, sure ? "confirmed" : "possible", why);
        this.add("obfuscated", at, STRENGTH.string, s.how, sure ? "confirmed" : "possible", why);
      }
    }

    if (s.how === "decoded") {
      this.decodedText(s, at, role);

      return;
    }

    this.textOf(s.value, at, role, s.how);

    // a payload that is still encoded: decoded here only to see what it hides; apm did not see the code decode it
    if (BASE64.test(s.value) && /[0-9+/=]/.test(s.value)) {
      // decoded only while the budget has room for all of it (a base64 string decodes to three quarters of its length)
      const room = Math.ceil((s.value.length * 3) / 4) <= this.budget.decoded;

      if (room) chargeText("decode", s.value.length, 3);
      const plain = room ? decodeBase64(s.value) : null;

      if (!room) this.budget.notes.add(LIMIT_NOTES.decoded);
      else if (plain && printable(plain)) {
        this.budget.decoded -= plain.length;
        this.decodedText({ value: plain, exact: true, how: "decoded", pieces: 1, via: "base64", numeric: false }, at, "plain");
      }

      if (longBase64Text(s.value)) {
        const confidence: Confidence = role === "plain" || role === "request" ? "possible" : "confirmed";
        this.add("obfuscated", at, STRENGTH.string, "as written", confidence, "a long base64 string decodes to text, but apm did not see code load or run it");
      }
    }
  }

  /** Keeps code held in a string for score.ts to read, within the file's decoded-text budget. */
  private hold(at: number, code: string, origin: Executed["origin"]): void {
    if (this.depth > 0) return;

    if (code.length > MAX_HELD_CHARS) chargeText("held", code.length, 2);
    const held = code.length > MAX_HELD_CHARS ? squeeze(code) : code;

    // code it runs is never dropped unread: past either limit, the analysis says so
    if (this.executed.length >= MAX_EXECUTED || held.length > MAX_HELD_CHARS) {
      if (origin === "run" && this.unread.length < MAX_EXECUTED) this.unread.push({ at, why: held.length > MAX_HELD_CHARS ? `runs ${held.length} characters of code from a string, more than the ${MAX_HELD_CHARS / 1024} KB apm reads` : `runs code from more than ${MAX_EXECUTED} strings, more than apm reads` });

      return;
    }

    this.executed.push({ at, code: held, origin });
  }

  /** The `name` and `text` rules on a string, and token names, each as sure as the string's role allows. */
  private textOf(value: string, at: number, role: Role, how: Str["how"]): void {
    if (!INTERESTING.test(value)) return;

    for (const m of stringMatches(value)) {
      let confidence: Confidence = "possible";

      if (role === "shell" && m.kind === "text") confidence = "confirmed";
      else if (role === "read" && m.id === "credential-access") confidence = "confirmed";
      const why = role === "request" ? "sits in a request's URL or body, which is sent, not run" : whyOf(m.id, m.kind);
      this.add(m.id, at, STRENGTH.string, how, confidence, why);
    }

    if (TOKEN_RE.test(value)) this.add("credential-access", at, STRENGTH.string, how, role === "shell" ? "confirmed" : "possible", "names a token variable, but apm did not see it read from the environment");
  }

  /** Every rule on text decoded from a payload, as sure as the role of the place it is used. */
  private decodedText(s: Str, at: number, role: Role): void {
    const found: { id: Capability; confirmed: boolean }[] = [];

    for (const h of ruleHits(s.value, "decoded", new Set())) if (h.id !== "obfuscated") found.push({ id: h.id, confirmed: h.confidence === "confirmed" });
    const named = namedSignal(s.value);

    if (named) found.push({ id: named, confirmed: true });

    if (found.length === 0) return;
    const why = `decoded from ${s.via ?? "an encoding"} in a string that apm did not see code run`;

    for (const f of found) {
      const sure = f.confirmed && (role === "shell" || (role === "read" && f.id === "credential-access"));
      this.add(f.id, at, STRENGTH.string, "decoded", sure ? "confirmed" : "possible", why);
    }

    this.add("obfuscated", at, STRENGTH.string, "decoded", role === "shell" ? "confirmed" : "possible", why);
  }

  /** Code held in a string that the program runs: read as code, so what it does is confirmed the same way. */
  private evaluate(s: Str, at: number): void {
    const id = s.exact && s.how !== "as written" ? namedSignal(s.value) : null;

    if (s.exact) this.hold(at, s.value, "run");

    if (id) {
      this.add(id, at, STRENGTH.string, s.how, "possible", `builds "${s.value.slice(0, 40)}" for eval, but apm did not see it called`);
      this.add("obfuscated", at, STRENGTH.call, s.how, "confirmed", "");
    }

    const inner = innerHits(s.value, this.depth + 1, this.budget);
    const how = ranHow(s.how);

    for (const h of inner.hits) this.hits.push({ ...h, at, how });

    for (const p of inner.paths) {
      this.paths.add(p);
      this.loads.add(p);
    }

    if (inner.dynamic) this.dynamic.push(at);

    if (inner.hits.length > 0 && (s.how === "decoded" || (s.how === "after joining strings" && s.pieces >= 2))) this.add("obfuscated", at, STRENGTH.call, s.how, "confirmed", "");
  }

  // ----- visiting -----

  private visit(n: AnyNode, role: Role): void {
    if (isTypeOnly(n)) return;

    switch (n.type) {
      case "Literal": {
        const s = this.str(n);

        if (s && !s.numeric) this.stringAt(s, n, role, n.raw ?? null);

        return;
      }

      case "TemplateLiteral": {
        const s = this.str(n);

        if (s) this.stringAt(s, n, role, n.quasis.map((q) => q.value.raw).join(""));

        // the strings were read as part of the template's value; what is not a string (a call) is read on its own
        for (const e of n.expressions) this.visit(e, s || role === "code" ? "none" : role);

        return;
      }

      case "BinaryExpression": {
        if (n.operator === "+") {
          const s = this.str(n);

          if (s) {
            this.stringAt(s, n, role, null);

            for (const side of [n.left, n.right]) if (side.type !== "PrivateIdentifier") this.visit(side, this.str(side) || role === "code" ? "none" : role);

            return;
          }
        }

        this.visitAll(n, "plain");

        return;
      }

      case "CallExpression":
      case "NewExpression":
        this.visitCall(n, role);

        return;
      case "TaggedTemplateExpression":
        this.visitTag(n, role);

        return;
      case "ImportExpression": {
        this.load(n.source, n.start);
        this.visit(n.source, "none");

        return;
      }

      case "ImportDeclaration":
      case "ExportAllDeclaration": {
        const spec = stringValue(n.source);

        if (spec !== null) this.loadAt(literalStr(spec), n.source.start);

        return;
      }

      case "ExportNamedDeclaration": {
        const spec = n.source ? stringValue(n.source) : null;

        if (n.source && spec !== null) this.loadAt(literalStr(spec), n.source.start);

        if (n.declaration) this.visit(n.declaration, "plain");

        return;
      }

      case "TSImportEqualsDeclaration": {
        const ref = n.moduleReference;

        if (ref.type === "TSExternalModuleReference") this.load(ref.expression, ref.start);

        return;
      }

      case "MemberExpression":
        this.visitMember(n, "plain");

        return;
      case "Identifier":
        this.identifier(n, true);

        return;
      case "VariableDeclarator":
        if (n.init) {
          this.aliasOf(n.init);

          if (n.id.type === "ObjectPattern" && nameOf(this.resolve(n.init)) === "process.env") this.envPattern(n.id);
          this.visit(n.init, "plain");
        }

        this.visit(n.id, "plain");

        return;
      case "AssignmentExpression":
        this.aliasOf(n.right);
        this.visitAll(n, "plain");

        return;
      case "ForInStatement":
        if (nameOf(this.resolve(n.right)) === "process.env") this.envDumps.push(n.start);
        this.visitAll(n, "plain");

        return;
      case "Property":
        if (n.computed) this.visit(n.key, "plain");
        else if (n.key.type === "Identifier") this.identifier(n.key, false);
        else this.visit(n.key, "plain");
        this.visit(n.value, "plain");

        return;
      case "ArrayExpression":
        for (const el of n.elements) if (el) this.visit(el, role);

        return;
      case "UnaryExpression":
        // `typeof eval` asks whether it exists; it hands nothing on
        if (n.operator === "typeof" && n.argument.type === "Identifier") this.identifier(n.argument, false);
        else this.visit(n.argument, "plain");

        return;
      case "ConditionalExpression":
        this.visit(n.test, "plain");
        this.visit(n.consequent, role);
        this.visit(n.alternate, role);

        return;
      case "LogicalExpression":
        this.visit(n.left, role);
        this.visit(n.right, role);

        return;
      case "SequenceExpression":
        n.expressions.forEach((e, i) => this.visit(e, i === n.expressions.length - 1 ? role : "plain"));

        return;
      case "SpreadElement":
      case "AwaitExpression":
        this.visit(n.argument, role);

        return;
      case "ChainExpression":
      case "TSAsExpression":
      case "TSSatisfiesExpression":
      case "TSNonNullExpression":
      case "TSTypeAssertion":
      case "TSInstantiationExpression":
        this.visit(n.expression, role);

        return;
      case "JSXText":
        this.textOf(n.value, n.start, "plain", "as written");

        return;
      default:
        this.visitAll(n, "plain");
    }
  }

  private visitAll(n: AnyNode, role: Role): void {
    for (const c of childNodes(n)) this.visit(c, role);
  }

  /** A name where it is read: `value` is false for a property key or a callee, which are not values passed on. */
  private identifier(n: Identifier, value: boolean): void {
    if (n.name === "await") this.sawAwaitName = true;

    // eval handed on as a value (`run(eval, code)`, `{ go: eval }`) runs code wherever it is called, which apm may not see
    if (value && n.name === "eval" && this.bindingOf(n) === null) this.add("eval", n.start, STRENGTH.reference, "as written", "possible", "passes eval on as a value, and apm did not follow where it is called");

    if (/^_0x[0-9a-f]{4,}$/.test(n.name)) {
      if (this.hexFirst < 0) this.hexFirst = n.start;
      this.hexCount++;
    }

    if (TOKEN_NAMES.has(n.name)) this.add("credential-access", n.start, STRENGTH.string, "as written", "possible", "names a token variable, but apm did not see it read from the environment");

    if (n.name === "XMLHttpRequest" && this.bindingOf(n) === null) this.add("network", n.start, STRENGTH.reference, "as written", "possible", "refers to XMLHttpRequest without creating one");
  }

  /** `x = require`, `x = globalThis.Function`, `x = eval`: a way to run code kept under another name. */
  private aliasOf(value: AnyNode): void {
    const v = unwrap(value);

    if (v.type !== "Identifier" && v.type !== "MemberExpression" && v.type !== "SequenceExpression") return;
    const r = this.resolve(v);

    if (r.kind !== "global") return;

    if (r.path === "require") this.add("eval", v.start, STRENGTH.reference, "as written", "possible", "keeps require under another name, so apm cannot read what it loads");
    // `const F = Function` is how code names the constructor for instanceof checks; reaching it through the
    // global object is not. A call through either alias is read as a call to Function.
    else if ((r.path === "Function" || r.path === "eval") && v.type !== "Identifier") this.add("eval", v.start, STRENGTH.reference, "as written", "possible", `keeps a reference to ${r.path} without calling it`);
  }

  private envPattern(p: AnyNode): void {
    if (p.type !== "ObjectPattern") return;

    for (const prop of p.properties) {
      if (prop.type === "RestElement") continue;
      const key = prop.computed ? this.str(prop.key) : null;
      const name = key?.exact ? key.value : propertyName(prop.key, prop.computed);

      if (name && TOKEN_NAMES.has(name)) this.add("credential-access", prop.start, STRENGTH.reference, key && key.how !== "as written" ? key.how : "as written", "confirmed", "");
    }
  }

  private visitMember(n: MemberExpression, objectRole: Role): void {
    const key = this.memberKey(n);
    const r = this.resolve(n);
    const name = nameOf(r);
    const last = lastName(r);
    const at = n.start;

    if (r.kind === "global" && SHELL_GLOBALS.has(name)) this.add("shell-exec", at, STRENGTH.reference, "as written", "confirmed", "");

    if ((r.kind === "module" && r.spec === "vm" && VM_EVAL.has(r.path)) || (byName(r) && ownerOf(r) === "vm" && VM_EVAL.has(last))) this.add("eval", at, STRENGTH.reference, "as written", "confirmed", "");

    if (name.endsWith("Module.prototype._compile")) this.add("eval", at, STRENGTH.reference, "as written", "confirmed", "");

    if (r.kind === "global" && r.path === "require" && n.object.type !== "Super" && this.resolve(n.object).kind === "global") {
      this.add("eval", at, STRENGTH.reference, "as written", "possible", "reaches require through the global object");
    }

    if (key && n.object.type !== "Super" && TOKEN_NAMES.has(key.name)) {
      const env = nameOf(this.resolve(n.object));

      if (env === "process.env" || env === "Bun.env") {
        this.add("credential-access", at, STRENGTH.reference, key.built ? "after joining strings" : "as written", "confirmed", "");

        if (key.built) this.add("obfuscated", at, STRENGTH.reference, "after joining strings", "confirmed", "");
      }
    }

    // a member name built from pieces: hiding a name is obfuscation; what it names is confirmed only once it is called
    if (key?.built) {
      const id = namedSignal(key.name);

      if (id) {
        this.add("obfuscated", n.property.start, STRENGTH.reference, "after joining strings", "confirmed", "");
        this.add(id, n.property.start, STRENGTH.string, "after joining strings", "possible", `builds "${key.name}" from pieces, but apm did not see it called`);
      }
    }

    if (n.object.type !== "Super") this.visit(n.object, objectRole);

    if (n.computed) this.visit(n.property, key ? "none" : "plain");
  }

  private load(arg: AnyNode | undefined, at: number): void {
    if (!arg || arg.type === "SpreadElement") {
      this.dynamic.push(at);

      return;
    }

    const s = this.str(arg);

    if (s?.exact) {
      this.loadAt(s, arg.start);

      return;
    }

    const dir = this.dirnamePath(arg);

    if (dir) {
      this.paths.add(dir);
      this.loads.add(dir);

      return;
    }

    const target = unwrap(arg);

    if (target.type === "CallExpression" && target.callee.type !== "Super" && nameOf(this.resolve(target.callee)) === "require.resolve") {
      const inner = target.arguments[0] ? this.str(target.arguments[0]) : null;

      if (inner?.exact) return;
    }

    this.dynamic.push(at);
  }

  private loadAt(s: Str, at: number): void {
    const id = moduleSignal(s.value);

    if (id) this.add(id, at, STRENGTH.load, s.how, "confirmed", "");
    // a debugger session can run code (`Runtime.evaluate`); profilers and debuggers load it to read, not to run
    else if (INSPECTOR.test(s.value)) this.add("eval", at, STRENGTH.load, s.how, "possible", "loads inspector, whose sessions can run code, but apm did not see one asked to");

    if (s.how !== "as written" && (id || namedSignal(s.value))) this.add("obfuscated", at, STRENGTH.load, s.how, "confirmed", "");

    if (/^\.\.?\//.test(s.value)) {
      this.paths.add(s.value);
      this.loads.add(s.value);
    }
  }

  /** `path.join(__dirname, 'lib', 'x')`, `__dirname + '/x'` and `` `${__dirname}/x` ``: a file next to this one. */
  private dirnamePath(n: AnyNode): string | null {
    const t = unwrap(n);

    if (t.type === "CallExpression" && t.callee.type === "MemberExpression" && !t.callee.computed && t.callee.property.type === "Identifier" && (t.callee.property.name === "join" || t.callee.property.name === "resolve")) {
      const [first, ...rest] = t.arguments;

      if (first?.type !== "Identifier" || first.name !== "__dirname" || rest.length === 0) return null;
      const segs = rest.map((a) => (a.type === "SpreadElement" ? null : this.str(a)));

      return segs.every((x) => x?.exact) ? `./${segs.map((x) => x?.value ?? "").join("/")}` : null;
    }

    if (t.type === "BinaryExpression" && t.operator === "+" && t.left.type === "Identifier" && t.left.name === "__dirname") {
      const s = this.str(t.right);

      return s?.exact && s.value.startsWith("/") ? `.${s.value}` : null;
    }

    if (t.type === "TemplateLiteral" && t.expressions[0]?.type === "Identifier" && t.expressions[0].name === "__dirname" && t.quasis[0]?.value.cooked === "" && t.expressions.length === 1) {
      const tail = t.quasis[1]?.value.cooked ?? "";

      return tail.startsWith("/") ? `.${tail}` : null;
    }

    return null;
  }

  private visitTag(n: TaggedTemplateExpression, role: Role): void {
    const r = this.resolve(n.tag);
    const name = nameOf(r);

    if (r.kind === "global" && SHELL_GLOBALS.has(name)) this.add("shell-exec", n.start, STRENGTH.call, "as written", "confirmed", "");
    const command = r.kind !== "local" && (COMMAND_ARGS.has(lastName(r)) || name === "Bun.$" || lastName(r) === "sh");
    this.visit(n.tag, "plain");
    this.visit(n.quasi, command ? "shell" : name === "String.raw" ? role : "plain");
  }

  private sinkArg(arg: AnyNode, role: Role): void {
    const s = arg.type === "SpreadElement" ? null : this.str(arg);

    if (s && !s.numeric && (role === "code" || role === "shell" || role === "read" || role === "request")) {
      this.stringAt(s, arg, role, arg.type === "Literal" ? (arg.raw ?? null) : null);
      this.visit(arg, "none");

      return;
    }

    this.visit(arg, role);
  }

  private visitCall(n: CallExpression | NewExpression, role: Role): void {
    if (n.callee.type === "Super") {
      for (const a of n.arguments) this.visit(a, "plain");

      return;
    }

    const call = this.invoked(n);
    const at = unwrap(n.callee).start;
    const isMethod = unwrap(n.callee).type === "MemberExpression";
    const first = call.slots[0] ?? null;
    const firstStr = first ? this.str(first) : null;
    // every callee the expression can be reads the call its own way; each argument takes the strongest role any gives it
    const plans = call.refs.map((r) => this.plan({ r, n, call, role, at, isMethod, first, firstStr }));

    // a call that is handed eval itself (`run(eval, code)`) most likely runs what else it is handed
    const handsEval = call.slots.some((slot) => slot !== null && unwrap(slot).type === "Identifier" && isGlobal(this.resolve(slot), "eval"));

    const roleOf = (i: number): Role => {
      let best: Role = handsEval ? "code" : "none";

      for (const p of plans) {
        const r = p.roles[i] ?? (p.rest === "inherit" ? role : p.rest);

        if (ROLE_RANK[r] > ROLE_RANK[best]) best = r;
      }

      return best;
    };

    const dir = this.dirnamePath(n);

    if (dir) this.paths.add(dir);
    const callee = unwrap(n.callee);

    if (callee.type === "MemberExpression") this.visitMember(callee, plans.some((p) => p.rest === "inherit") ? role : "plain");
    else if (callee.type === "Identifier") this.identifier(callee, false);
    else this.visit(callee, "plain");

    for (const a of call.others) this.visit(a, "plain");
    call.slots.forEach((slot, i) => slot && this.sinkArg(slot, roleOf(i)));

    if (this.depth === 0) this.sites.push({ node: n, slots: call.slots, roles: call.slots.map((_, i) => roleOf(i)), network: plans.some((p) => p.rest === "request"), limit: limitOf(call.refs) });
  }

  /** What one callee does with a call: the signals it confirms, and what each argument is for. */
  private plan(c: { r: Ref; n: CallExpression | NewExpression; call: Invoked; role: Role; at: number; isMethod: boolean; first: Slot; firstStr: Str | null }): Plan {
    const { r, n, call, role, at, isMethod, first, firstStr } = c;
    const isNew = call.isNew;
    const name = nameOf(r);
    const last = lastName(r);
    const isLocal = r.kind === "local";
    let roles: Role[] = [];
    let rest: Role | "inherit" = "plain";
    let effect = true;

    if (!isNew && isRequire(r)) {
      this.load(first ?? undefined, n.start);
      roles = ["none"];
    } else if (r.kind === "global" && name === "require.resolve") {
      if (firstStr?.exact && /^\.\.?\//.test(firstStr.value)) this.paths.add(firstStr.value);
    } else if (r.kind === "global" && name === "eval") {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if (r.kind === "global" && name === "Function") {
      const returnsThis = call.slots.length === 1 && firstStr?.exact && firstStr.value.trim() === "return this";

      if (!returnsThis) {
        this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
        rest = "code";
      }
    } else if (r.kind === "global" && TIMERS.has(name) && first && (firstStr || first.type === "TemplateLiteral")) {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if ((r.kind === "module" && r.spec === "vm" && VM_EVAL.has(r.path)) || (byName(r) && (last === "runInThisContext" || last === "runInNewContext" || (ownerOf(r) === "vm" && VM_EVAL.has(last))))) {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if (name === "module._compile" || name.endsWith("Module.prototype._compile") || (r.kind === "unknown" && last === "_compile" && r.owner === "module")) {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if (isMethod && last === "post" && firstStr?.exact && INSPECTOR_EVAL.test(firstStr.value)) {
      // an inspector session asked to evaluate, compile or call code runs what it is handed
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
    } else if (isNew && isWorker(r)) {
      // `new Worker(code, { eval: true })` runs its first argument as JavaScript in a new thread
      const evals = workerEvals(call.slots[1] ?? null);

      if (evals === "yes" || (evals === "unknown" && r.kind === "module")) {
        this.add("eval", at, STRENGTH.call, "as written", evals === "yes" ? "confirmed" : "possible", "starts a Worker with options apm cannot read; with eval: true it runs its first argument as code");
        roles = ["code"];
      }
    } else if ((r.kind === "module" && r.spec === "child_process" && SHELL_CP.has(r.path)) || (r.kind === "global" && SHELL_GLOBALS.has(name)) || (!isLocal && r.kind !== "module" && SHELL_NAMES.has(last))) {
      this.add("shell-exec", at, STRENGTH.call, "as written", "confirmed", "");
      rest = "shell";
    } else if (r.kind === "global" && BINDINGS.has(name)) {
      // process.binding('spawn_sync') starts processes; process.binding('util') only reads type helpers (old lodash)
      const binding = firstStr?.exact ? firstStr.value : null;

      if (name === "process.dlopen" || binding === null || !HARMLESS_BINDINGS.test(binding)) this.add("shell-exec", at, STRENGTH.call, "as written", "confirmed", "");
    } else if (!isLocal && r.kind !== "module" && COMMAND_ARGS.has(last) && last !== "$" && !this.isRegexMethod(n)) {
      rest = "shell";
      effect = false;
    } else if (byName(r) && last === "fetch") {
      rest = "request";

      if (!(firstStr && firstStr.value.trimStart().startsWith("data:"))) {
        // fetch, globalThis.fetch and a fetch passed in are requests; `config.fetch` is a method apm cannot identify
        const sure = (r.kind === "global" && r.path === "fetch") || !isMethod;
        this.add("network", at, STRENGTH.call, "as written", sure ? "confirmed" : "possible", "calls a method named fetch on an object apm cannot identify");
      }
    } else if (isHttpCall(r) || (isNew && !isLocal && NET_CTORS.has(last)) || (!isLocal && last === "sendBeacon") || isDnsCall(r)) {
      this.add("network", at, STRENGTH.call, "as written", "confirmed", "");
      rest = "request";
    } else if ((r.kind === "module" && r.spec === "fs" && READS.has(last)) || (r.kind === "global" && (name === "Bun.file" || name.startsWith("Deno.read"))) || (byName(r) && READS.has(last) && (ownerOf(r) !== null || last.startsWith("read") || last === "createReadStream"))) {
      roles = ["read"];
      effect = false;
    } else if (r.kind === "unknown" && last === "eval" && isMethod) {
      this.add("eval", at, STRENGTH.call, "as written", "possible", "calls a method named eval on an object apm cannot identify");
    } else if (r.kind === "global" && name === "JSON.stringify" && first && nameOf(this.resolve(first)) === "process.env") {
      this.add("credential-access", at, STRENGTH.call, "as written", "confirmed", "");
    } else if (r.kind === "global" && /^Object\.(?:keys|entries|values)$/.test(name) && first && nameOf(this.resolve(first)) === "process.env") {
      this.envDumps.push(n.start);
    } else if ((r.kind === "global" && DECODERS.has(name)) || (isMethod && STRING_METHODS.has(last))) {
      rest = role === "code" ? "none" : "inherit";
      effect = false;
    } else if (isMethod && PATH_BUILDERS.has(last) && (role === "read" || role === "shell")) {
      rest = "inherit";
      effect = false;
    } else effect = false;

    // a callee named by joining pieces (`cp['ex' + 'ec'](...)`, `g['fe' + 'tch'](...)`) and then called
    if (r.kind !== "local" && r.built) {
      const id = namedSignal(last);

      if (id || effect) this.add("obfuscated", at, STRENGTH.call, "after joining strings", "confirmed", "");

      // the name was hidden and then called: what it names is used, even when apm also read what the call does
      if (id) this.add(id, at, STRENGTH.call, "after joining strings", "confirmed", "");
    }

    return { roles, rest };
  }

  /**
   * The arguments `list` passes, in position: a spread of an array apm can read (`...args` where `const args = […]`)
   * puts its elements in place. Past a spread apm cannot read, positions are unknown: the rest are `others`.
   */
  private placed(list: readonly (AnyNode | null)[]): Placed {
    const slots: Slot[] = [];
    const others: AnyNode[] = [];
    let open = true;

    for (const a of list) {
      if (a === null) {
        // a hole keeps its place
        if (open) slots.push(null);
        continue;
      }

      if (!open) {
        others.push(a);
        continue;
      }

      if (a.type !== "SpreadElement") {
        slots.push(a);
        continue;
      }

      const elements = this.arrayElements(a.argument);

      if (elements) {
        slots.push(...elements);

        // an array written in place is read through its elements; a name holding one is read as well
        if (unwrap(a.argument).type !== "ArrayExpression") others.push(a);
      } else {
        others.push(a);
        open = false;
      }
    }

    return { slots, others };
  }

  /** The elements of an array literal, or of a constant holding one, with holes kept in place. Null when apm cannot read it. */
  private arrayElements(n: AnyNode): Slot[] | null {
    const t = unwrap(n);

    if (t.type === "Identifier") {
      const init = this.constInit(t);

      if (!init || this.tooDeep()) return null;
      this.resolving++;

      try {
        return this.arrayElements(init);
      } finally {
        this.resolving--;
      }
    }

    if (t.type !== "ArrayExpression") return null;

    return this.placed(t.elements).slots;
  }

  /** An argument list passed as one array (`f.apply(that, list)`, `Reflect.apply(f, that, list)`). */
  private listed(list: AnyNode | undefined): Placed {
    if (!list || list.type === "SpreadElement") return { slots: [], others: list ? [list] : [] };
    const slots = this.arrayElements(list);

    if (!slots) return { slots: [], others: [list] };

    return { slots, others: unwrap(list).type === "ArrayExpression" ? [] : [list] };
  }

  /** `f.bind(that, a)`, also through a constant (`const g = f.bind(that, a)`): what is bound, and the arguments bound with it. */
  private bound(n: AnyNode, depth = 0): { target: AnyNode; args: AnyNode[] } | null {
    const t = unwrap(n);

    if (depth > 8) return null;

    if (t.type === "Identifier") {
      const init = this.constInit(t);

      return init ? this.bound(init, depth + 1) : null;
    }

    if (t.type !== "CallExpression" || t.callee.type === "Super") return null;
    const callee = unwrap(t.callee);

    if (callee.type !== "MemberExpression" || callee.computed || callee.property.type !== "Identifier" || callee.property.name !== "bind" || callee.object.type === "Super") return null;
    const inner = this.bound(callee.object, depth + 1) ?? { target: callee.object, args: [] };

    return { target: inner.target, args: [...inner.args, ...t.arguments.slice(1)] };
  }

  /**
   * What a call invokes and with which arguments. `f.call(that, a)`, `f.apply(that, [a])`, `Reflect.apply(f, that,
   * [a])`, `Reflect.construct(F, [a])` and `f.bind(that, a)()` invoke `f` (or construct `F`) with `a`.
   */
  private invoked(n: CallExpression | NewExpression): Invoked {
    const isNew = n.type === "NewExpression";
    const direct = this.resolveAll(n.callee);
    const plain = (): Invoked => ({ refs: direct, isNew, ...this.placed(n.arguments) });
    const b = isNew ? null : this.bound(n.callee);

    if (b) {
      const bound = this.placed(b.args);
      const given = this.placed(n.arguments);

      // the bound arguments come first; the callee expression (which holds them) is read on its own
      return { refs: this.resolveAll(b.target), isNew, slots: [...bound.slots, ...given.slots], others: given.others };
    }

    if (!isNew && direct.some((r) => r.kind === "global" && (r.path === "Reflect.apply" || r.path === "Reflect.construct"))) {
      const construct = direct.some((r) => r.kind === "global" && r.path === "Reflect.construct");
      const [fn, second, third, ...more] = n.arguments;

      if (!fn || fn.type === "SpreadElement") return plain();
      const list = this.listed(construct ? second : third);
      const rest = construct ? [third, ...more] : [second, ...more];

      return { refs: this.resolveAll(fn), isNew: construct, slots: list.slots, others: [fn, ...rest.filter((x): x is Expression | SpreadElement => x !== undefined), ...list.others] };
    }

    const target = unwrap(n.callee);

    if (isNew || target.type !== "MemberExpression" || target.object.type === "Super") return plain();
    const key = this.memberKey(target);

    if (key?.name !== "call" && key?.name !== "apply") return plain();
    const inner = this.resolveAll(target.object);

    // an object of this file with its own `call` method, or a value apm cannot name, is called as itself
    if (inner.every((r) => r.kind === "local" || (r.kind === "unknown" && r.name === null))) return plain();
    const [that, ...rest] = n.arguments;
    const others = that ? [that] : [];

    if (key.name === "call") {
      const args = this.placed(rest);

      return { refs: inner, isNew, slots: args.slots, others: [...others, ...args.others] };
    }

    const list = this.listed(rest[0]);

    return { refs: inner, isNew, slots: list.slots, others: [...others, ...list.others, ...rest.slice(1)] };
  }

}

function literalStr(value: string): Str {
  return { value, exact: true, how: "as written", pieces: 1, via: null, numeric: false };
}

function unknownStr(): Str {
  return { value: UNKNOWN, exact: false, how: "as written", pieces: 0, via: null, numeric: false };
}

function member(base: Ref, prop: string, built: boolean): Ref {
  switch (base.kind) {
    case "global":
      if (prop === "constructor" && base.path === "Function") return base;

      return { kind: "global", path: base.path ? `${base.path}.${prop}` : prop, built: base.built || built };
    case "module":
      // a CommonJS module's default export is the module itself (`_fs.default.readFileSync`)
      if (prop === "default" && base.path === "") return { ...base, built: base.built || built };

      return { kind: "module", spec: base.spec, path: base.path ? `${base.path}.${prop}` : prop, built: base.built || built };
    case "local":
      // a function's constructor is Function; any other value's constructor (Array, Object, String) is a function
      if (prop === "constructor") return base.fn ? { kind: "global", path: "Function", built } : { kind: "local", fn: true, obj: null };

      return { kind: "local", fn: false, obj: null };
    case "unknown":
      // x.constructor.constructor is Function, whatever x is
      if (prop === "constructor" && base.name === "constructor") return { kind: "global", path: "Function", built: base.built || built };

      return { kind: "unknown", name: prop, owner: base.name, built: base.built || built, limit: base.limit };
    default: {
      const _exhaustive: never = base;

      return _exhaustive;
    }
  }
}

/** Globals that load a module by name, as require does. */
const LOADERS: ReadonlySet<string> = new Set([
  "require",
  "module.require",
  "require.main.require",
  "process.mainModule.require",
  "process.getBuiltinModule",
  "Module._load",
  "module.constructor._load",
]);

/** A module loader (`require`, `process.getBuiltinModule`, `Module._load`), and a `require` passed in as a parameter, the way bundles and module wrappers pass it. */
function isRequire(r: Ref): boolean {
  if (r.kind === "unknown") return r.name === "require" && r.owner === null;

  return (r.kind === "global" && LOADERS.has(r.path)) || (r.kind === "module" && r.spec === "module" && r.path === "_load");
}

function isHttpCall(r: Ref): boolean {
  const last = lastName(r);

  if (last !== "get" && last !== "request") return false;

  if (r.kind === "module") return (r.spec === "http" || r.spec === "https") && (r.path === "get" || r.path === "request");

  const owner = ownerOf(r);

  return byName(r) && (owner === "http" || owner === "https");
}

function isDnsCall(r: Ref): boolean {
  if (r.kind === "module") return r.spec === "dns" && DNS_CALL.test(r.path);

  if (r.kind === "global") return r.path.startsWith("dns.") && DNS_CALL.test(r.path.slice(4));

  return r.kind === "unknown" && (r.owner === "dns" || r.owner === "promises") && DNS_CALL.test(r.name ?? "");
}

/** node's `worker_threads.Worker`, however it is reached, or a global `Worker` (Bun, Deno and browsers have one). */
function isWorker(r: Ref): boolean {
  if (r.kind === "module") return r.spec === "worker_threads" && r.path === "Worker";

  return r.kind === "global" ? r.path === "Worker" : r.kind === "unknown" && lastName(r) === "Worker" && r.owner === "worker_threads";
}

/**
 * Whether a Worker's options run its first argument as code: `yes` for `{ eval: true }`, `no` for no options or an
 * object literal with no `eval` key or a literal false one, `unknown` for anything apm cannot read.
 */
function workerEvals(options: AnyNode | null): "yes" | "no" | "unknown" {
  if (options === null) return "no";
  const o = unwrap(options);

  if (o.type !== "ObjectExpression") return "unknown";
  let out: "yes" | "no" | "unknown" = "no";

  for (const p of o.properties) {
    if (p.type === "SpreadElement" || p.computed) {
      out = "unknown";
      continue;
    }

    const key = p.key.type === "Identifier" ? p.key.name : p.key.type === "Literal" ? String(p.key.value) : null;

    if (key !== "eval") continue;
    const v = unwrap(p.value);

    if (v.type !== "Literal") return "unknown";

    return v.value ? "yes" : "no";
  }

  return out;
}

// ---------- the result ----------

/**
 * `paths`: relative paths a file names in a way apm can follow (loads, `require.resolve`, `path.join(__dirname, ...)`),
 * each read in turn. `loads`: the ones it loads with require or import, which node runs as JavaScript whatever their
 * extension. `dynamic`: loads whose target apm cannot work out.
 */
export type Imports = { paths: string[]; loads: string[]; dynamic: Where[] };

/**
 * A parsed file's reading: its findings (the tree's and the floor's, the stronger of each signal), what it loads,
 * and the limits it ran into (`notes`).
 */
/** A string a parsed program passes to a process: what it holds, and the line it is cited at. */
export type Command = { line: number; snippet: string; value: string };

/** A value that reached a call that runs, sends or reads it (flow.ts), cited at the call. */
export type FlowFinding = { kind: Sink["kind"]; line: number; snippet: string; labels: Label[] };

/**
 * Code a file holds as text, for score.ts to read as a program: `run`, a string it hands an evaluator; `recovered`, its
 * own source (a function, a regex, the file) turned back into text and run, with comment and regex delimiters taken
 * out so what they held reads as the code it becomes; `held`, a string that reads as a program and is used otherwise
 * (handed to a call apm cannot name, which may run it); `data`, such a string kept only as data (`markData`).
 */
export type ExecutedCode = { line: number; snippet: string; code: string; origin: "run" | "recovered" | "held" | "data" };

/** Code a file runs that apm did not read (too long even squeezed), cited at the call that runs it. */
export type Unread = { line: number; snippet: string; why: string };

/** An environment variable read by name (`*` when the name is built at runtime), or the whole object used (`null`). */
export type EnvRead = { line: number; snippet: string; name: string | null };

export type JsScan =
  | {
      kind: "parsed";
      findings: TextFinding[];
      imports: Imports;
      notes: string[];
      hidden: (index: number) => Hidden | undefined;
      commands: Command[];
      flows: FlowFinding[];
      exports: Exports;
      executed: ExecutedCode[];
      env: EnvRead[];
      /** Code the file runs that apm did not read, which makes the analysis incomplete. */
      unread: Unread[];
    }
  | { kind: "failed"; reason: Exclude<ParseOutcome, "parsed"> };

/** What reading one program found, as plain data, so the tree it came from can be let go. */
type Read = { hits: Hit[]; leftOut: LeftOut; paths: string[]; loads: string[]; dynamic: number[]; awaitName: boolean; commands: { at: number; value: string }[]; flow: FlowRead; executed: Executed[]; unread: { at: number; why: string }[] };

/** At most this many commands per program, each cut to this many characters: enough to read what a command does. */
const MAX_COMMANDS = 200;
const MAX_COMMAND_CHARS = 4000;

/** Code a program holds as text, and where (see Reader.executed). */
type Executed = { at: number; code: string; origin: "run" | "held" | "data" };

/** At most this many held programs per file, each at most this long; score.ts reads them within its own byte budget. */
const MAX_EXECUTED = 50;
const MAX_HELD_CHARS = 256 * 1024;

/** Names a string that reads as a program must call: a builtin that reaches the network, a process, a file or code. */
const HELD_NAMES = /\b(?:fetch|require|getBuiltinModule|import|process|Bun|Deno|eval|Function|XMLHttpRequest|WebSocket)\b/;

/** A string that reads as a program that does something: long enough, naming such a builtin, with a call in it. */
function isHeldCode(s: string): boolean {
  const open = s.indexOf("(");

  return s.length >= 12 && open > 0 && s.lastIndexOf(")") > open && HELD_NAMES.test(s);
}

const NO_FLOW: FlowRead = { sinks: [], recovered: [], exports: new Map(), env: [], ranWritten: [] };

/** Reads every program `text` parses to, one at a time. Null when no parser accepted it or a tree was too large or too deep. */
function readText(text: string, dialect: Dialect, depth: number, budget: Budget): { outcome: "parsed"; reads: Read[] } | { outcome: Exclude<ParseOutcome, "parsed"> } {
  const reads: Read[] = [];
  let deep = false;

  const outcome = parseEach(text, dialect, (p) => {
    const r = readProgram(p, depth, budget);

    if (!r) {
      deep = true;

      return false;
    }

    reads.push(r);

    return r.awaitName;
  });

  if (outcome !== "parsed") return { outcome };

  // a tree deep enough to exhaust the reader's stack is not read at all rather than half read, and says so
  return deep ? { outcome: "too-deep" } : { outcome, reads };
}

type Inner = { hits: Hit[]; paths: string[]; dynamic: boolean };

function floorHit(f: TextFinding): Hit {
  return hitOf(f.id, 0, STRENGTH.string, f.how, f.confidence, f.confidence === "possible" ? f.why : "");
}

/** Code held in a string, read as code (the tree and its floor) when it parses, and raw (every match counts) when it does not. */
function innerHits(code: string, depth: number, budget: Budget): Inner {
  if (depth > MAX_EVAL_DEPTH) budget.notes.add(LIMIT_NOTES.evalDepth);
  else if (budget.decoded <= 0) budget.notes.add(LIMIT_NOTES.decoded);

  if (depth <= MAX_EVAL_DEPTH && budget.decoded > 0) {
    budget.decoded -= code.length;
    chargeText("held", code.length);
    const r = readText(code, "js", depth, budget);

    if (r.outcome === "parsed") {
      return {
        hits: [...r.reads.flatMap((x) => x.hits), ...floorOf(code, r.reads.map((x) => x.leftOut)).map(floorHit)],
        paths: r.reads.flatMap((x) => x.loads),
        dynamic: r.reads.some((x) => x.dynamic.length > 0),
      };
    }
  }

  return { hits: ruleHits(code, "as written", new Set()).map((f) => hitOf(f.id, 0, STRENGTH.call, "as written", f.confidence, f.confidence === "possible" ? f.why : "")), paths: [], dynamic: false };
}

function readProgram(p: Parsed, depth: number, budget: Budget): Read | null {
  try {
    const r = new Reader(p.program, depth, budget);

    r.read();

    return { hits: r.hits, leftOut: leftOutOf(p.program, p.comments), paths: [...r.paths], loads: [...r.loads], dynamic: r.dynamic, awaitName: r.sawAwaitName, commands: r.commands, flow: r.flow, executed: r.executed, unread: r.unread };
  } catch (e) {
    if (e instanceof RangeError) return null;
    throw e;
  }
}

/** The best hit of each signal: confirmed before possible, then the strongest evidence, then the first in the file. */
function bestPerSignal(hits: readonly Hit[]): Hit[] {
  const best = new Map<CodeSignal, Hit>();

  for (const h of hits) {
    const b = best.get(h.id);

    if (!b) {
      best.set(h.id, h);
      continue;
    }

    const better = h.confidence !== b.confidence ? h.confidence === "confirmed" : h.strength !== b.strength ? h.strength > b.strength : h.at < b.at;

    if (better) best.set(h.id, h);
  }

  return [...best.values()];
}

/**
 * Reads one JavaScript or TypeScript file. `failed` when no parser accepted it or it is too large to hold as a tree;
 * the caller then reads it raw, the way apm-score-v3 read every file.
 */
export function scanJs(text: string, dialect: Dialect): JsScan {
  const budget: Budget = { decoded: MAX_DECODED_BYTES, notes: new Set(), decoder: new Allowance("decode", MAX_FILE_DECODER_STEPS), fold: new Allowance("fold", foldUnits(text.length)), stopped: [] };
  const r = readText(text, dialect, 0, budget);

  if (r.outcome !== "parsed") return { kind: "failed", reason: r.outcome };

  const toFinding = (h: Hit): TextFinding => {
    const where = lineOf(text, h.at);

    return h.confidence === "confirmed" ? { id: h.id, ...where, how: h.how, confidence: "confirmed" } : { id: h.id, ...where, how: h.how, confidence: "possible", why: h.why };
  };

  const precise = bestPerSignal(r.reads.flatMap((x) => x.hits)).map((h): TextFinding => ({ ...toFinding(h), tree: true }));
  const floor = floorOf(text, r.reads.map((x) => x.leftOut));
  const findings: TextFinding[] = [];

  // the tree's confirmed finding cites the call; the floor's stands where the tree confirmed nothing
  for (const id of ["shell-exec", "network", "credential-access", "eval", "obfuscated"] as const) {
    const sure = (list: readonly TextFinding[]): TextFinding | undefined => list.find((f) => f.id === id && f.confidence === "confirmed");
    const best = sure(precise) ?? sure(floor) ?? precise.find((f) => f.id === id);

    if (best) findings.push(best);
  }

  // every path, however many: a file a cut list left out would be read as one nothing loads
  const paths = [...new Set(r.reads.flatMap((x) => x.paths))];
  const loads = [...new Set(r.reads.flatMap((x) => x.loads))];

  const dynamic = [...new Set(r.reads.flatMap((x) => x.dynamic))]
    .sort((a, b) => a - b)
    .slice(0, 5)
    .map((at) => lineOf(text, at));

  // a script read as a module too gives each command twice
  const commands = [...new Map(r.reads.flatMap((x) => x.commands).map((c) => [`${c.at} ${c.value}`, c])).values()].map((c) => ({ ...lineOf(text, c.at), value: c.value }));

  // a script read as a module too gives each flow, each held program and each read twice
  const once = <T>(list: readonly T[], key: (x: T) => string): T[] => [...new Map(list.map((x) => [key(x), x])).values()];
  const flows = once(r.reads.flatMap((x) => x.flow.sinks), (f) => `${f.kind} ${f.at} ${f.labels.join(",")}`).map((f) => ({ kind: f.kind, ...lineOf(text, f.at), labels: f.labels }));
  const exports = new Map<string, Label[]>();

  for (const x of r.reads) for (const [name, labels] of x.flow.exports) exports.set(name, [...new Set([...(exports.get(name) ?? []), ...labels])]);
  const env = once(r.reads.flatMap((x) => x.flow.env), (e) => `${e.at} ${e.name ?? ""}`).map((e) => ({ ...lineOf(text, e.at), name: e.name }));
  const executed: ExecutedCode[] = once(r.reads.flatMap((x) => x.executed), (e) => `${e.at} ${e.origin}`).map((e) => ({ ...lineOf(text, e.at), code: e.code, origin: e.origin }));
  const leftOut = r.reads[0]?.leftOut;

  const unread: Unread[] = once(r.reads.flatMap((x) => x.unread), (u) => `${u.at}`).map((u) => ({ ...lineOf(text, u.at), why: u.why }));

  // a limit code run from a string hit, cited at the file's first line since that code has no line of its own here
  for (const why of new Set(budget.stopped)) unread.push({ ...lineOf(text, 0), why: `code it runs from a string ${why}` });

  for (const rec of once(r.reads.flatMap((x) => x.flow.recovered), (x) => `${x.at} ${x.ranges.join(";")}`)) {
    for (const [from, to] of rec.ranges) {
      const got = leftOut ? recoveredText(text, leftOut, from, to) : null;

      if (got === null) continue;

      if (got === "too-long" || executed.length >= MAX_EXECUTED + 10) unread.push({ ...lineOf(text, rec.at), why: got === "too-long" ? `runs text it recovers from its own source that is longer than the ${MAX_RECOVERED_CHARS / 1024} KB apm reads, even with padding squeezed out` : "runs more recovered source than apm reads" });
      else executed.push({ ...lineOf(text, rec.at), code: got.code, origin: "recovered" });
    }
  }


  return { kind: "parsed", findings, imports: { paths, loads, dynamic }, notes: [...budget.notes], hidden: hiddenOf(r.reads.map((x) => x.leftOut)), commands, flows, exports, executed, env, unread };
}

/** How much of a file's own source one recovery is read as code, once runs of whitespace are squeezed to one. */
const MAX_RECOVERED_CHARS = 256 * 1024;

/** Runs of whitespace squeezed to one space, or one newline where the run held one: what padding hides behind goes. */
export function squeeze(code: string): string {
  return code.replace(/\s{2,}/g, (m) => (m.includes("\n") ? "\n" : " "));
}

/**
 * The text a program gets back from its own source between `from` and `to`, as code: the comment and regex delimiters
 * in it are blanked, so what a comment or a regex body held reads as the code it becomes once sliced out and run, and
 * padding is squeezed out. Null when nothing in the range was left out of the program as written (then it is code apm
 * already read), or when what was left out names no network, process, credential or code call (comments that are
 * prose); `too-long` when what it would run is longer than apm reads even squeezed, which the caller reports.
 */
function recoveredText(text: string, l: LeftOut, from: number, to: number): { code: string } | "too-long" | null {
  // what the comments and regex bodies in the range hold; recovered text matters only when they name a dangerous call
  const pieces: string[] = [];
  const blanks: Range[] = [];

  // every comment and regex is looked at for each range, and the range's text is copied, blanked and squeezed
  charge("held", l.comments.length + l.regexes.length);
  chargeText("held", to - from, 4);

  for (const [a, b] of l.comments) {
    if (a < from || b > to) continue;
    pieces.push(squeeze(text.slice(a, b)));

    if (text.startsWith("/*", a)) blanks.push([a, a + 2], [b - 2, b]);
    else blanks.push([a, a + (text.startsWith("<!--", a) ? 4 : text.startsWith("-->", a) ? 3 : 2)]);
  }

  for (const [a, b] of l.regexes) {
    if (a < from || b > to) continue;
    pieces.push(text.slice(a, b));
    blanks.push([a, a + 1], [text.lastIndexOf("/", b - 1), b]);
  }

  if (pieces.length === 0 || !scanTextRules(pieces.join("\n")).some((f) => f.confidence === "confirmed")) return null;
  let out = "";
  let cursor = from;

  for (const [a, b] of blanks.sort((x, y) => x[0] - y[0])) {
    if (a < cursor) continue;
    out += text.slice(cursor, a) + " ".repeat(b - a);
    cursor = b;
  }

  const code = squeeze(out + text.slice(cursor, to));

  return code.length > MAX_RECOVERED_CHARS ? "too-long" : { code };
}
