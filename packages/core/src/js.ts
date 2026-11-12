// Reads a parsed JavaScript or TypeScript program: what it calls, loads, reads and evaluates, and what each string
// it holds is for. A string's role comes from where the code uses it: a module specifier loads a module, text passed
// to eval, Function or vm runs as code, a command passed to exec or spawn runs as a shell command, a path passed to a
// read is read, and a URL or request body is sent. Each role confirms only what fits it. Pure; nothing is run.
import type { AnyNode, CallExpression, Expression, Identifier, Literal, MemberExpression, NewExpression, Node, Pattern, Program, SpreadElement, TaggedTemplateExpression, TemplateLiteral } from "acorn";
import { parseEach, type Dialect, type Parsed } from "./parse.ts";
import {
  escapedTextAt,
  lineOf,
  longBase64Text,
  moduleSignal,
  namedSignal,
  NEAR,
  printable,
  RAW,
  ruleHits,
  stringMatches,
  TOKEN_NAMES,
  whyOf,
  type Capability,
  type CodeSignal,
  type Confidence,
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

declare module "acorn" {
  interface NodeTypes {
    apm: TsExpression | TsImportEquals | TsExternalModuleReference | TsParameterProperty | JsxText;
  }
}

/** The TypeScript nodes that run: casts and assertions wrap an expression, enums and namespaces make objects, `import x = require()` loads. */
const RUNTIME_TS: ReadonlySet<string> = new Set([
  "TSAsExpression",
  "TSSatisfiesExpression",
  "TSNonNullExpression",
  "TSTypeAssertion",
  "TSInstantiationExpression",
  "TSEnumDeclaration",
  "TSEnumBody",
  "TSEnumMember",
  "TSModuleDeclaration",
  "TSModuleBlock",
  "TSParameterProperty",
  "TSExportAssignment",
  "TSImportEqualsDeclaration",
  "TSExternalModuleReference",
]);

/** Every object under a parsed program that has a string `type` and a numeric `start` is a node the parser built. */
function isParsedNode(v: unknown): v is AnyNode {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the one place parser output is told apart from the plain data (positions, regex flags) it carries
  return v instanceof Object && "type" in v && typeof v.type === "string" && "start" in v && typeof v.start === "number";
}

/** A node's child nodes, in source order: every field holding a node or a list of nodes. */
function childNodes(n: AnyNode): AnyNode[] {
  const out: AnyNode[] = [];

  for (const v of Object.values(n)) {
    if (Array.isArray(v)) {
      for (const x of v) if (isParsedNode(x)) out.push(x);
    } else if (isParsedNode(v)) out.push(v);
  }

  return out;
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

/** Type-only syntax (annotations, interfaces, `declare` statements, `import type`): erased, so nothing in it runs. */
function isTypeOnly(n: AnyNode): boolean {
  if (n.type.startsWith("TS") && !RUNTIME_TS.has(n.type)) return true;

  if ("declare" in n && n.declare === true) return true;

  if ("importKind" in n && n.importKind === "type") return true;

  return "exportKind" in n && n.exportKind === "type";
}

// ---------- what a name or expression refers to ----------

/**
 * - `global`: a global and a path in it (`fetch`, `process.env`, `Bun.spawn`); `""` is the global object itself.
 * - `module`: a module and a member path in it (`child_process` and `exec`).
 * - `local`: a value this file makes (a function, class, object, array or literal), so not a platform API.
 * - `unknown`: anything else; `name` is its last property or identifier and `owner` the name before that.
 * `built` says a property name on the way was joined or decoded from pieces.
 */
type Ref =
  | { kind: "global"; path: string; built: boolean }
  | { kind: "module"; spec: string; path: string; built: boolean }
  | { kind: "local"; fn: boolean }
  | { kind: "unknown"; name: string | null; owner: string | null; built: boolean };

const GLOBAL_OBJECTS: ReadonlySet<string> = new Set(["globalThis", "global", "window", "self"]);

/** Where a declared name gets its value. */
type Origin =
  | { kind: "value"; init: Expression }
  | { kind: "member"; base: Expression; path: string[] }
  | { kind: "module"; spec: string; path: string }
  | { kind: "local" }
  | { kind: "opaque" };

/** Every declaration of one name in the file. Only a name declared once and never assigned is resolved. */
type Binding = { count: number; assigned: boolean; origin: Origin };

type Bindings = Map<string, Binding>;

function declare(b: Bindings, name: string, origin: Origin): void {
  const had = b.get(name);

  if (had) had.count++;
  else b.set(name, { count: 1, assigned: false, origin });
}

function assign(b: Bindings, name: string): void {
  const had = b.get(name);

  if (had) had.assigned = true;
  else b.set(name, { count: 0, assigned: true, origin: { kind: "opaque" } });
}

function propertyName(key: AnyNode, computed: boolean): string | null {
  if (!computed && key.type === "Identifier") return key.name;

  if (key.type === "Literal") {
    const v = stringValue(key) ?? numberValue(key);

    return v === null ? null : String(v);
  }

  return null;
}

function bindPattern(b: Bindings, p: AnyNode, origin: Origin): void {
  switch (p.type) {
    case "Identifier":
      declare(b, p.name, origin);
      break;
    case "ObjectPattern":
      for (const prop of p.properties) {
        if (prop.type === "RestElement") {
          bindPattern(b, prop.argument, { kind: "opaque" });
          continue;
        }

        const key = propertyName(prop.key, prop.computed);
        let inner: Origin = { kind: "opaque" };

        if (key !== null) {
          if (origin.kind === "value") inner = { kind: "member", base: origin.init, path: [key] };
          else if (origin.kind === "member") inner = { kind: "member", base: origin.base, path: [...origin.path, key] };
          else if (origin.kind === "module") inner = { kind: "module", spec: origin.spec, path: origin.path ? `${origin.path}.${key}` : key };
        }

        bindPattern(b, prop.value, inner);
      }

      break;
    case "AssignmentPattern":
      bindPattern(b, p.left, origin);
      break;
    case "ArrayPattern":
      for (const el of p.elements) if (el) bindPattern(b, el, { kind: "opaque" });
      break;
    case "RestElement":
      bindPattern(b, p.argument, { kind: "opaque" });
      break;
    case "TSParameterProperty":
      bindPattern(b, p.parameter, { kind: "opaque" });
      break;
    default:
      break;
  }
}

function assignPattern(b: Bindings, p: AnyNode): void {
  switch (p.type) {
    case "Identifier":
      assign(b, p.name);
      break;
    case "ObjectPattern":
      for (const prop of p.properties) assignPattern(b, prop.type === "RestElement" ? prop.argument : prop.value);
      break;
    case "ArrayPattern":
      for (const el of p.elements) if (el) assignPattern(b, el);
      break;
    case "AssignmentPattern":
      assignPattern(b, p.left);
      break;
    case "RestElement":
      assignPattern(b, p.argument);
      break;
    default:
      break;
  }
}

/** Every name the program declares or assigns, with where its value comes from. */
function collectBindings(program: Program): Bindings {
  const b: Bindings = new Map();
  const stack: AnyNode[] = [program];

  for (let n = stack.pop(); n; n = stack.pop()) {
    switch (n.type) {
      case "VariableDeclarator":
        bindPattern(b, n.id, n.init ? { kind: "value", init: n.init } : { kind: "opaque" });
        break;
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        if ("id" in n && n.id) declare(b, n.id.name, { kind: "local" });

        for (const p of n.params) bindPattern(b, p, { kind: "opaque" });
        break;
      case "ClassDeclaration":
      case "ClassExpression":
        if (n.id) declare(b, n.id.name, { kind: "local" });
        break;
      case "CatchClause":
        if (n.param) bindPattern(b, n.param, { kind: "opaque" });
        break;
      case "ImportDeclaration":
        const spec = stringValue(n.source);

        if (isTypeOnly(n) || spec === null) break;

        for (const s of n.specifiers) {
          if (isTypeOnly(s)) continue;
          const path = s.type === "ImportSpecifier" ? (propertyName(s.imported, false) ?? "") : "";
          declare(b, s.local.name, { kind: "module", ...moduleOf(spec, path) });
        }

        break;
      case "TSImportEqualsDeclaration": {
        const ref = n.moduleReference;

        const spec = ref.type === "TSExternalModuleReference" && ref.expression.type === "Literal" ? stringValue(ref.expression) : null;

        if (spec !== null) declare(b, n.id.name, { kind: "module", ...moduleOf(spec, "") });
        else declare(b, n.id.name, { kind: "opaque" });
        break;
      }

      case "AssignmentExpression":
        assignPattern(b, n.left);
        break;
      case "UpdateExpression":
        if (n.argument.type === "Identifier") assign(b, n.argument.name);
        break;
      case "ForInStatement":
      case "ForOfStatement":
        if (n.left.type !== "VariableDeclaration") assignPattern(b, n.left);
        break;
      default:
        break;
    }

    stack.push(...childNodes(n));
  }

  return b;
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

/** Stands for a piece of a string apm cannot know (`'curl ' + url`), so the rest can still be read. */
const UNKNOWN = "__apm__";

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

/** How deep code held in a string is followed: code that evaluates code that evaluates code. */
const MAX_EVAL_DEPTH = 3;

type Budget = { decoded: number };

/**
 * Where a string sits, which decides what it can confirm:
 * - `code`: run as JavaScript (eval, Function, vm, string timers). It is read as code.
 * - `shell`: run as a command (exec, spawn, Bun.$). Shell text and credential paths in it are confirmed.
 * - `read`: a path a read opens. A credential path in it is confirmed.
 * - `request`: a URL or request body. It is sent, not run, so it confirms nothing beyond the request itself.
 * - `plain`: anything else. What it names is possible at most.
 * - `none`: already read where it is used; its strings are not read again.
 */
type Role = "code" | "shell" | "read" | "request" | "plain" | "none";

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

const READS: ReadonlySet<string> = new Set(["readFile", "readFileSync", "createReadStream", "open", "openSync", "copyFile", "copyFileSync", "cp", "cpSync", "readTextFile", "readTextFileSync"]);

const NET_CTORS: ReadonlySet<string> = new Set(["XMLHttpRequest", "WebSocket", "EventSource", "RTCPeerConnection"]);

const TIMERS: ReadonlySet<string> = new Set(["setTimeout", "setInterval", "setImmediate"]);

const DECODERS: ReadonlySet<string> = new Set(["atob", "Buffer.from", "String.fromCharCode", "decodeURIComponent", "decodeURI", "unescape", "String"]);

const STRING_METHODS: ReadonlySet<string> = new Set(["toString", "trim", "concat", "join", "split", "reverse", "slice", "replace", "toLowerCase", "toUpperCase"]);

const PATH_BUILDERS: ReadonlySet<string> = new Set(["join", "resolve", "normalize", "homedir"]);

const DNS_CALL = /^(?:promises\.)?(?:resolve\w*|lookup\w*|reverse)$/;

/** The helpers TypeScript, Babel, SWC and esbuild wrap a require in: each returns the module (or its namespace). */
const INTEROP = /^_*(?:interop_?require_?(?:default|wildcard)|import(?:Default|Star)|toESM|toCommonJS)$/i;

/** Unwraps what does not change a value: TypeScript casts and assertions, `a?.b` chains. */
function unwrap(n: AnyNode): AnyNode {
  let cur = n;

  for (;;) {
    if (cur.type === "ChainExpression") cur = cur.expression;
    else if (cur.type === "TSAsExpression" || cur.type === "TSSatisfiesExpression" || cur.type === "TSNonNullExpression" || cur.type === "TSTypeAssertion" || cur.type === "TSInstantiationExpression") cur = cur.expression;
    else return cur;
  }
}

function isFunctionNode(n: AnyNode): boolean {
  return n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression" || n.type === "ClassExpression";
}

function decodeBase64(s: string): string | null {
  const body = s.replace(/=+$/, "");

  if (!/^[A-Za-z0-9+/_-]*$/.test(body) || body.length % 4 === 1) return null;

  return Buffer.from(body.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("latin1");
}

/** What a call invokes, with which arguments; `list` is the array literal holding them for `apply` forms. */
type Invoked = { r: Ref; args: (Expression | SpreadElement)[]; isNew: boolean; list: AnyNode | null };

/** One program, read once. Findings go to `hits`; module paths and loads apm cannot follow go to `paths` and `dynamic`. */
class Reader {
  readonly hits: Hit[] = [];
  readonly paths = new Set<string>();
  readonly loads = new Set<string>();
  readonly dynamic: number[] = [];
  private readonly bindings: Bindings;
  private readonly strCache = new Map<AnyNode, Str | null>();
  private readonly identCache = new Map<string, Ref>();
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
    this.bindings = collectBindings(program);
  }

  read(): void {
    this.visit(this.program, "plain");

    for (const at of this.envDumps) {
      const near = this.netCalls.filter((c) => Math.abs(c.at - at) <= NEAR);

      if (near.length === 0) continue;
      const confidence: Confidence = near.some((c) => c.confidence === "confirmed") ? "confirmed" : "possible";
      this.add("credential-access", at, STRENGTH.call, "as written", confidence, "reads the whole environment next to a call apm could not identify");
    }

    if (this.hexCount >= 20) this.add("obfuscated", this.hexFirst, STRENGTH.reference, "as written", "confirmed", "");
  }

  private add(id: CodeSignal, at: number, strength: Strength, how: How, confidence: Confidence, why: string): void {
    this.hits.push(hitOf(id, at, strength, how, confidence, why));

    // a string that mentions curl is not a request; only calls and module loads count as the network next to an env dump
    if (id === "network" && strength >= STRENGTH.load) this.netCalls.push({ at, confidence });
  }

  // ----- resolving names -----

  private resolve(n: AnyNode): Ref {
    if (this.resolving > 24) return { kind: "unknown", name: null, owner: null, built: false };
    this.resolving++;

    try {
      return this.resolveNode(unwrap(n));
    } finally {
      this.resolving--;
    }
  }

  private resolveIdentifier(name: string): Ref {
    const cached = this.identCache.get(name);

    if (cached) return cached;
    const r = this.resolveBinding(name);
    this.identCache.set(name, r);

    return r;
  }

  private resolveBinding(name: string): Ref {
    const b = this.bindings.get(name);

    if (!b) return GLOBAL_OBJECTS.has(name) ? { kind: "global", path: "", built: false } : { kind: "global", path: name, built: false };

    if (b.count !== 1 || b.assigned) return { kind: "unknown", name, owner: null, built: false };
    const o = b.origin;

    switch (o.kind) {
      case "local":
        return { kind: "local", fn: true };
      case "module":
        return { kind: "module", spec: o.spec, path: o.path, built: false };
      case "opaque":
        return { kind: "unknown", name, owner: null, built: false };
      case "value": {
        const r = this.resolve(o.init);

        return r.kind === "unknown" && r.name === null ? { kind: "unknown", name, owner: null, built: r.built } : r;
      }

      case "member": {
        let r = this.resolve(o.base);

        for (const p of o.path) r = member(r, p, false);

        return r;
      }

      default: {
        const _exhaustive: never = o;

        return _exhaustive;
      }
    }
  }

  private memberKey(n: MemberExpression): { name: string; built: boolean } | null {
    if (!n.computed) return n.property.type === "Identifier" ? { name: n.property.name, built: false } : null;
    const s = n.property.type === "PrivateIdentifier" ? null : this.str(n.property);

    return s?.exact && !s.numeric ? { name: s.value, built: s.how !== "as written" } : null;
  }

  private resolveNode(n: AnyNode): Ref {
    switch (n.type) {
      case "Identifier":
        return this.resolveIdentifier(n.name);
      case "MemberExpression": {
        if (n.object.type === "Super") return { kind: "unknown", name: null, owner: null, built: false };
        const key = this.memberKey(n);
        const object = unwrap(n.object);

        // (function () {}).constructor and (async () => {}).constructor are Function
        if (key?.name === "constructor" && isFunctionNode(object)) return { kind: "global", path: "Function", built: key.built };
        const base = this.resolve(object);

        if (!key) return { kind: "unknown", name: null, owner: base.kind === "unknown" ? base.name : lastName(base) || null, built: false };

        return member(base, key.name, key.built);
      }

      case "SequenceExpression": {
        const last = n.expressions.at(-1);

        return last ? this.resolve(last) : { kind: "unknown", name: null, owner: null, built: false };
      }

      case "AwaitExpression":
        return this.resolve(n.argument);
      case "AssignmentExpression":
        return n.operator === "=" ? this.resolve(n.right) : { kind: "unknown", name: null, owner: null, built: false };
      case "LogicalExpression": {
        // `custom || fetch`: a fallback is what the code reaches for when the first value is missing, so a side apm
        // knows (a module, a local value) wins, then the side that names a platform API
        const left = this.resolve(n.left);
        const right = this.resolve(n.right);

        if (left.kind === "module" || left.kind === "local") return left;

        return right.kind === "unknown" ? left : right;
      }

      case "CallExpression":
        return this.resolveCall(n);
      case "NewExpression": {
        // a Module instance has the same _compile that runs code as `module` does
        const made = this.resolve(n.callee);

        return made.kind === "module" && made.spec === "module" && (made.path === "" || made.path === "Module") ? { kind: "global", path: "module", built: false } : { kind: "unknown", name: null, owner: null, built: false };
      }

      case "ImportExpression": {
        const s = this.str(n.source);

        return s?.exact ? { kind: "module", ...moduleOf(s.value, ""), built: s.how !== "as written" } : { kind: "unknown", name: null, owner: null, built: false };
      }

      case "FunctionExpression":
      case "ArrowFunctionExpression":
      case "ClassExpression":
        return { kind: "local", fn: true };
      case "ObjectExpression":
      case "ArrayExpression":
      case "Literal":
      case "TemplateLiteral":
        return { kind: "local", fn: false };
      default:
        return { kind: "unknown", name: null, owner: null, built: false };
    }
  }

  private resolveCall(n: CallExpression): Ref {
    if (n.callee.type === "Super") return { kind: "unknown", name: null, owner: null, built: false };
    const callee = this.resolve(n.callee);
    const name = nameOf(callee);
    const arg = n.arguments[0];

    if (isRequire(callee) && arg && arg.type !== "SpreadElement") {
      const s = this.str(arg);

      if (s?.exact) return { kind: "module", ...moduleOf(s.value, ""), built: s.how !== "as written" };
    }

    if (callee.kind === "global" && name === "Object.getPrototypeOf" && arg && arg.type !== "SpreadElement" && isFunctionNode(unwrap(arg))) return { kind: "local", fn: true };

    // compilers wrap a require in an interop helper that returns the same module
    const written = unwrap(n.callee);
    const helper = written.type === "Identifier" ? written.name : written.type === "MemberExpression" && !written.computed && written.property.type === "Identifier" ? written.property.name : "";

    // (often defined in the same file, so it is matched by the name it is called by)
    if (INTEROP.test(helper) && arg && arg.type !== "SpreadElement") {
      const inner = this.resolve(arg);

      if (inner.kind === "module") return inner;
    }

    if ((callee.kind === "global" && name === "createRequire") || (callee.kind === "module" && name === "module.createRequire")) return { kind: "global", path: "require", built: false };
    const target = unwrap(n.callee);

    // eval.bind(null) is eval
    if (target.type === "MemberExpression" && !target.computed && target.property.type === "Identifier" && target.property.name === "bind" && target.object.type !== "Super") return this.resolve(target.object);

    return { kind: "unknown", name: null, owner: null, built: false };
  }

  // ----- working out strings -----

  private str(n: AnyNode): Str | null {
    const cached = this.strCache.get(n);

    if (cached !== undefined) return cached;
    this.strCache.set(n, null);
    const s = this.resolving > 24 ? null : this.strNode(n);
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

        return { value: a.value + b.value, exact: a.exact && b.exact, how: strongerHow(strongerHow(a.how, b.how), "after joining strings"), pieces: a.pieces + b.pieces, via: a.via ?? b.via, numeric: false };
      }

      case "Identifier": {
        const b = this.bindings.get(n.name);

        if (!b || b.count !== 1 || b.assigned || b.origin.kind !== "value") return null;
        this.resolving++;

        try {
          return this.str(b.origin.init);
        } finally {
          this.resolving--;
        }
      }

      case "CallExpression":
        return this.strCall(n);
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

  private decoded(value: string | null, from: Str, via: string): Str | null {
    if (value === null || this.budget.decoded <= 0) return null;
    this.budget.decoded -= value.length;

    return { value, exact: true, how: "decoded", pieces: from.pieces, via, numeric: false };
  }

  private strCall(n: CallExpression): Str | null {
    if (n.callee.type === "Super") return null;
    const callee = this.resolve(n.callee);
    const name = callee.kind === "global" ? callee.path : "";
    const args = n.arguments.filter((a): a is Expression => a.type !== "SpreadElement");
    const a0 = args[0] ? this.str(args[0]) : null;

    if (name === "atob") return a0?.exact ? this.decoded(decodeBase64(a0.value), a0, "base64") : null;

    if (name === "Buffer.from") {
      if (!a0?.exact) return null;
      const enc = args[1] ? this.str(args[1]) : null;

      if (!enc) return a0;

      if (enc.value === "base64" || enc.value === "base64url") return this.decoded(decodeBase64(a0.value), a0, "base64");

      if (enc.value === "hex") return /^(?:[0-9a-fA-F]{2})+$/.test(a0.value) ? this.decoded(Buffer.from(a0.value, "hex").toString("latin1"), a0, "hex") : null;

      return a0;
    }

    if (name === "String.fromCharCode") return this.charCodes(n.arguments);

    if (name === "decodeURIComponent" || name === "decodeURI" || name === "unescape") {
      if (!a0?.exact) return null;

      try {
        return this.decoded(name === "unescape" ? unescape(a0.value) : decodeURIComponent(a0.value), a0, "URI escapes");
      } catch {
        return null;
      }
    }

    if (name === "String") return a0;
    const target = unwrap(n.callee);

    if (target.type !== "MemberExpression" || target.computed || target.property.type !== "Identifier" || target.object.type === "Super") return null;
    const method = target.property.name;

    // String.fromCharCode.apply(null, codes)
    if (method === "apply" && nameOf(this.resolve(target.object)) === "String.fromCharCode") return this.charCodes(n.arguments.slice(1));

    if (method === "join") {
      const parts = this.arrayStrings(target.object);

      if (!parts) return null;
      const sep = a0?.exact ? a0.value : ",";

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

          out = { value: out.value + (s?.value ?? UNKNOWN), exact: out.exact && (s?.exact ?? false), how: "after joining strings", pieces: out.pieces + (s?.pieces ?? 0), via: out.via, numeric: false };
        }

        return out;
      }

      default:
        return null;
    }
  }

  /** The strings of an array literal (or a constant holding one), or of `'abc'.split('').reverse()`. */
  private arrayStrings(n: AnyNode): Str[] | null {
    const target = unwrap(n);

    if (target.type === "Identifier") {
      const b = this.bindings.get(target.name);

      return b && b.count === 1 && !b.assigned && b.origin.kind === "value" && b.origin.init !== target ? this.arrayStrings(b.origin.init) : null;
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
      const b = this.bindings.get(target.name);

      return b && b.count === 1 && !b.assigned && b.origin.kind === "value" ? this.numbers(b.origin.init) : null;
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

  private charCodes(args: readonly AnyNode[]): Str | null {
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

    if (!codes || codes.length === 0 || codes.some((c) => c < 0 || c > 0xffff)) return null;
    const from: Str = { value: "", exact: true, how: "as written", pieces: codes.length, via: null, numeric: false };

    return this.decoded(String.fromCharCode(...codes.slice(0, 65536)), from, "char codes");
  }

  // ----- reading strings by role -----

  private stringAt(s: Str, n: AnyNode, role: Role, raw: string | null): void {
    if (role === "none" || s.numeric) return;
    const at = n.start;

    if (raw !== null && escapedTextAt(raw) >= 0) this.add("obfuscated", at, STRENGTH.string, "as written", "confirmed", "");

    if (role === "code") {
      this.evaluate(s, at);

      return;
    }

    const sure = role === "shell";

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
      const plain = decodeBase64(s.value);

      if (plain && printable(plain) && this.budget.decoded > 0) {
        this.budget.decoded -= plain.length;
        this.decodedText({ value: plain, exact: true, how: "decoded", pieces: 1, via: "base64", numeric: false }, at, "plain");
      }

      if (longBase64Text(s.value)) {
        const confidence: Confidence = role === "plain" || role === "request" ? "possible" : "confirmed";
        this.add("obfuscated", at, STRENGTH.string, "as written", confidence, "a long base64 string decodes to text, but apm did not see code load or run it");
      }
    }
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

    for (const h of ruleHits(s.value, "decoded", new Set(), RAW)) if (h.id !== "obfuscated") found.push({ id: h.id, confirmed: h.confidence === "confirmed" });
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
        this.identifier(n);

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
        else if (n.key.type === "Identifier") this.identifier(n.key);
        else this.visit(n.key, "plain");
        this.visit(n.value, "plain");

        return;
      case "ArrayExpression":
        for (const el of n.elements) if (el) this.visit(el, role);

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

  private identifier(n: Identifier): void {
    if (n.name === "await") this.sawAwaitName = true;

    if (/^_0x[0-9a-f]{4,}$/.test(n.name)) {
      if (this.hexFirst < 0) this.hexFirst = n.start;
      this.hexCount++;
    }

    if (TOKEN_NAMES.has(n.name)) this.add("credential-access", n.start, STRENGTH.string, "as written", "possible", "names a token variable, but apm did not see it read from the environment");

    if (n.name === "XMLHttpRequest" && !this.bindings.has(n.name)) this.add("network", n.start, STRENGTH.reference, "as written", "possible", "refers to XMLHttpRequest without creating one");
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
    const { r, args, isNew } = call;
    const name = nameOf(r);
    const last = lastName(r);
    const at = unwrap(n.callee).start;
    const first = args[0];
    const firstStr = first && first.type !== "SpreadElement" ? this.str(first) : null;
    const isLocal = r.kind === "local";
    const isMethod = unwrap(n.callee).type === "MemberExpression";
    let roles: Role[] = [];
    let rest: Role | "inherit" = "plain";
    let effect = true;

    if (!isNew && isRequire(r)) {
      this.load(first, n.start);
      roles = ["none"];
    } else if (r.kind === "global" && name === "require.resolve") {
      if (firstStr?.exact && /^\.\.?\//.test(firstStr.value)) this.paths.add(firstStr.value);
    } else if (r.kind === "global" && name === "eval") {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if (r.kind === "global" && name === "Function") {
      const returnsThis = args.length === 1 && firstStr?.exact && firstStr.value.trim() === "return this";

      if (!returnsThis) {
        this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
        rest = "code";
      }
    } else if (r.kind === "global" && TIMERS.has(name) && first && first.type !== "SpreadElement" && (firstStr || first.type === "TemplateLiteral")) {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if ((r.kind === "module" && r.spec === "vm" && VM_EVAL.has(r.path)) || (byName(r) && (last === "runInThisContext" || last === "runInNewContext" || (ownerOf(r) === "vm" && VM_EVAL.has(last))))) {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if (name === "module._compile" || name.endsWith("Module.prototype._compile") || (r.kind === "unknown" && last === "_compile" && r.owner === "module")) {
      this.add("eval", at, STRENGTH.call, "as written", "confirmed", "");
      roles = ["code"];
    } else if ((r.kind === "module" && r.spec === "child_process" && SHELL_CP.has(r.path)) || (r.kind === "global" && SHELL_GLOBALS.has(name)) || (!isLocal && r.kind !== "module" && SHELL_NAMES.has(last))) {
      this.add("shell-exec", at, STRENGTH.call, "as written", "confirmed", "");
      rest = "shell";
    } else if (r.kind === "global" && BINDINGS.has(name)) {
      // process.binding('spawn_sync') starts processes; process.binding('util') only reads type helpers (old lodash)
      const binding = firstStr?.exact ? firstStr.value : null;

      if (name === "process.dlopen" || binding === null || !HARMLESS_BINDINGS.test(binding)) this.add("shell-exec", at, STRENGTH.call, "as written", "confirmed", "");
    } else if (!isLocal && r.kind !== "module" && COMMAND_ARGS.has(last) && last !== "$") {
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
    } else if (r.kind === "global" && name === "JSON.stringify" && first && first.type !== "SpreadElement" && nameOf(this.resolve(first)) === "process.env") {
      this.add("credential-access", at, STRENGTH.call, "as written", "confirmed", "");
    } else if (r.kind === "global" && /^Object\.(?:keys|entries|values)$/.test(name) && first && first.type !== "SpreadElement" && nameOf(this.resolve(first)) === "process.env") {
      this.envDumps.push(n.start);
    } else if ((r.kind === "global" && DECODERS.has(name)) || (isMethod && STRING_METHODS.has(last))) {
      rest = role === "code" ? "none" : "inherit";
      effect = false;
    } else if (isMethod && PATH_BUILDERS.has(last) && (role === "read" || role === "shell")) {
      rest = "inherit";
      effect = false;
    } else effect = false;

    // a callee named by joining pieces (`cp['ex' + 'ec'](...)`, `g['fe' + 'tch'](...)`) and then called
    if (r.kind !== "local" && "built" in r && r.built) {
      const id = namedSignal(last);

      if (id || effect) this.add("obfuscated", at, STRENGTH.call, "after joining strings", "confirmed", "");

      // the name was hidden and then called: what it names is used, even when apm also read what the call does
      if (id) this.add(id, at, STRENGTH.call, "after joining strings", "confirmed", "");
    }

    const dir = this.dirnamePath(n);

    if (dir) this.paths.add(dir);
    const callee = unwrap(n.callee);

    if (callee.type === "MemberExpression") this.visitMember(callee, rest === "inherit" ? role : "plain");
    else this.visit(callee, "plain");

    const roleOf = (i: number): Role => roles[i] ?? (rest === "inherit" ? role : rest);

    if (call.list) {
      // f.apply(that, [a, b]) and Reflect.apply(f, that, [a, b]): the array holds the arguments
      for (const a of n.arguments) {
        if (a === call.list && a.type === "ArrayExpression") a.elements.forEach((el, i) => el && this.sinkArg(el, roleOf(i)));
        else this.visit(a, "plain");
      }

      return;
    }

    const shift = n.arguments.length - args.length;

    n.arguments.forEach((a, i) => (i < shift ? this.visit(a, "plain") : this.sinkArg(a, roleOf(i - shift))));
  }

  /**
   * What a call invokes and with which arguments. `f.call(that, a)`, `f.apply(that, [a])`, `Reflect.apply(f, that,
   * [a])` and `Reflect.construct(F, [a])` invoke `f` (or construct `F`) with `a`; `list` is the array literal that
   * holds the arguments, when they come as one.
   */
  private invoked(n: CallExpression | NewExpression): Invoked {
    const direct = this.resolve(n.callee);
    const plain = { r: direct, args: n.arguments, isNew: n.type === "NewExpression", list: null };
    const elements = (a: AnyNode | undefined): (Expression | SpreadElement)[] => (a?.type === "ArrayExpression" ? a.elements.filter((e): e is Expression | SpreadElement => e !== null) : []);
    const target = unwrap(n.callee);

    if (n.type === "CallExpression" && direct.kind === "global" && (direct.path === "Reflect.apply" || direct.path === "Reflect.construct")) {
      const [fn, second, third] = n.arguments;

      if (!fn || fn.type === "SpreadElement") return plain;
      const list = direct.path === "Reflect.apply" ? third : second;

      return { r: this.resolve(fn), args: elements(list), isNew: direct.path === "Reflect.construct", list: list ?? null };
    }

    if (n.type !== "CallExpression" || target.type !== "MemberExpression" || target.object.type === "Super") return plain;
    const key = this.memberKey(target);

    if (key?.name !== "call" && key?.name !== "apply") return plain;
    const inner = this.resolve(target.object);

    if (inner.kind === "local" || (inner.kind === "unknown" && inner.name === null)) return plain;

    if (key.name === "call") return { r: inner, args: n.arguments.slice(1), isNew: false, list: null };

    return { r: inner, args: elements(n.arguments[1]), isNew: false, list: n.arguments[1] ?? null };
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
      if (prop === "constructor") return base.fn ? { kind: "global", path: "Function", built } : { kind: "local", fn: true };

      return { kind: "local", fn: false };
    case "unknown":
      // x.constructor.constructor is Function, whatever x is
      if (prop === "constructor" && base.name === "constructor") return { kind: "global", path: "Function", built: base.built || built };

      return { kind: "unknown", name: prop, owner: base.name, built: base.built || built };
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

// ---------- the result ----------

/**
 * `paths`: relative paths a file names in a way apm can follow (loads, `require.resolve`, `path.join(__dirname, ...)`),
 * each read in turn. `loads`: the ones it loads with require or import, which node runs as JavaScript whatever their
 * extension. `dynamic`: loads whose target apm cannot work out.
 */
export type Imports = { paths: string[]; loads: string[]; dynamic: Where[] };

export type JsScan = { kind: "parsed"; findings: TextFinding[]; imports: Imports } | { kind: "failed"; reason: "syntax" | "too-large" };

/** What reading one program found, as plain data, so the tree it came from can be let go. */
type Read = { hits: Hit[]; paths: string[]; loads: string[]; dynamic: number[]; awaitName: boolean };

/** Reads every program `text` parses to, one at a time. Null when no parser accepted it or a tree was too large or too deep. */
function readText(text: string, dialect: Dialect, depth: number, budget: Budget): { outcome: "parsed"; reads: Read[] } | { outcome: "syntax" | "too-large" } {
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

  // a tree deep enough to exhaust the stack is read raw rather than half read
  return deep ? { outcome: "too-large" } : { outcome, reads };
}

type Inner = { hits: Hit[]; paths: string[]; dynamic: boolean };

/** Code held in a string, read as code when it parses and raw (every match counts) when it does not. */
function innerHits(code: string, depth: number, budget: Budget): Inner {
  if (depth <= MAX_EVAL_DEPTH && budget.decoded > 0) {
    budget.decoded -= code.length;
    const r = readText(code, "js", depth, budget);

    if (r.outcome === "parsed") return { hits: r.reads.flatMap((x) => x.hits), paths: r.reads.flatMap((x) => x.loads), dynamic: r.reads.some((x) => x.dynamic.length > 0) };
  }

  return { hits: ruleHits(code, "as written", new Set(), RAW).map((f) => hitOf(f.id, 0, STRENGTH.call, "as written", f.confidence, f.confidence === "possible" ? f.why : "")), paths: [], dynamic: false };
}

function readProgram(p: Parsed, depth: number, budget: Budget): Read | null {
  const r = new Reader(p.program, depth, budget);

  try {
    r.read();
  } catch (e) {
    if (e instanceof RangeError) return null;
    throw e;
  }

  return { hits: r.hits, paths: [...r.paths], loads: [...r.loads], dynamic: r.dynamic, awaitName: r.sawAwaitName };
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
  const r = readText(text, dialect, 0, { decoded: MAX_DECODED_BYTES });

  if (r.outcome !== "parsed") return { kind: "failed", reason: r.outcome };

  const findings = bestPerSignal(r.reads.flatMap((x) => x.hits)).map((h): TextFinding => {
    const where = lineOf(text, h.at);

    return h.confidence === "confirmed" ? { id: h.id, ...where, how: h.how, confidence: "confirmed" } : { id: h.id, ...where, how: h.how, confidence: "possible", why: h.why };
  });

  const paths = [...new Set(r.reads.flatMap((x) => x.paths))].slice(0, 500);
  const loads = [...new Set(r.reads.flatMap((x) => x.loads))].slice(0, 500);

  const dynamic = [...new Set(r.reads.flatMap((x) => x.dynamic))]
    .sort((a, b) => a - b)
    .slice(0, 5)
    .map((at) => lineOf(text, at));

  return { kind: "parsed", findings, imports: { paths, loads, dynamic } };
}
