// Where values go in one parsed program (apm-score-v10): what a value carries (the whole environment, a credential
// file's path or contents, what a network response gave, the program's own source) and which call it reaches (one that
// runs code, starts a process, sends a request or reads a file). Names are resolved with the reader's scopes (js.ts),
// so an alias (`const run = eval`), a destructured import, a callback's parameter, a function's return and a value
// another file exports are followed; what apm cannot follow carries nothing, and the text rules stay the floor. Pure.
import type { AnyNode, CallExpression, Identifier, NewExpression, Program } from "acorn";
import { childNodes, isFunctionNode, UNKNOWN, unwrap } from "./ast.ts";
import { CREDENTIAL_NAME, secretFamily } from "./facts.ts";
import type { Binding, Ref, Role } from "./js.ts";

/**
 * What a value carries:
 * - `env`: the whole environment object, or a copy or serialization of it (one variable is not);
 * - `env-key`: a name taken from the environment while looping over it, so `process.env[key]` is any variable;
 * - `cred-path`: a path that names a credential file (`~/.npmrc`, `.ssh/id_rsa`), however it was built;
 * - `cred`: what reading such a path gives;
 * - `net`: what a network response gave (its body, a chunk, a parsed JSON);
 * - `conn`: a request or connection the program can write to;
 * - `secret:<family>`: one secret variable of a family stealers go for (`secret:npm`);
 * - `src:<start>:<end>`: this program's own source text between two offsets (a function, a class, a regex, the file);
 * - `import:<spec>#<name>`: the export `name` of the relative module `spec` (`#` alone for the module value itself),
 *   with `+` after it for a named member taken from that export; worked out once every file is read (score.ts);
 * - `read:<label>`: what reading a path that carries `<label>` gives, worked out the same way.
 */
export type Label = "env" | "env-key" | "cred-path" | "cred" | "net" | "conn" | `secret:${string}` | `src:${number}:${number}` | `import:${string}` | `read:${string}`;

type Labels = ReadonlySet<Label>;

const NONE: Labels = new Set();

/** One call the reader read, with what each argument is for (see `Role` in js.ts) and whether it makes a request. */
export type CallSite = { node: CallExpression | NewExpression; slots: readonly (AnyNode | null)[]; roles: readonly Role[]; network: boolean };

/** What the flow analysis needs from the reader: its program, its calls and its name resolution. */
export type FlowHost = {
  program: Program;
  calls: readonly CallSite[];
  refsOf: (n: AnyNode) => readonly Ref[];
  bindingOf: (id: Identifier) => Binding | "dynamic" | null;
  str: (n: AnyNode) => { value: string; exact: boolean } | null;
  returnedBy: (fn: AnyNode) => readonly AnyNode[];
  /** Called when a value is followed further than the analysis goes; past it the value carries nothing. */
  limit: () => void;
};

/**
 * A value that reached a call that does something with it: `code` runs it, `shell` runs it as a whole command,
 * `request` sends it, `read` opens it as a path. `labels` is what it carried.
 */
export type Sink = { kind: "code" | "shell" | "request" | "read"; at: number; labels: Label[] };

/** Source text of this program that it turns back into a string and runs (or hands a call apm cannot name). */
export type Recovered = { at: number; ranges: [number, number][] };

/** An environment variable read by name (`*` for a name built at runtime), or the whole object used (`null`). */
export type EnvUse = { at: number; name: string | null };

/** What a module exports, by name: `""` for the module value itself (what `require` gives, whole). */
export type Exports = ReadonlyMap<string, readonly Label[]>;

export type FlowRead = { sinks: Sink[]; recovered: Recovered[]; exports: Exports; env: EnvUse[] };

/** How many steps one value is followed through before it is taken to carry nothing. */
const MAX_DEPTH = 32;

/** Calls that hand back what they are given, whole: serializers, encoders, copies, path builders. */
const PASS_GLOBALS: ReadonlySet<string> = new Set([
  "JSON.stringify",
  "JSON.parse",
  "String",
  "Buffer.from",
  "Buffer.concat",
  "btoa",
  "atob",
  "encodeURIComponent",
  "encodeURI",
  "escape",
  "unescape",
  "decodeURIComponent",
  "decodeURI",
  "Object.entries",
  "Object.keys",
  "Object.values",
  "Object.assign",
  "Object.fromEntries",
  "Object.getOwnPropertyNames",
  "structuredClone",
  "Array.from",
  "Array.of",
  "Promise.resolve",
  "Promise.all",
  "Promise.allSettled",
  "Promise.race",
  "Promise.any",
  "URLSearchParams",
  "Blob",
  "File",
  "FormData",
  "Request",
  "Response",
  "TextEncoder",
]);

/** Modules whose functions hand back what they are given (path builders, encoders, compressors, formatters). */
const PASS_MODULES: ReadonlySet<string> = new Set(["path", "querystring", "util", "zlib", "url", "buffer", "string_decoder"]);

/** Modules whose calls make requests: every argument of every call is sent. */
const HTTP_CLIENTS: ReadonlySet<string> = new Set(["axios", "got", "node-fetch", "undici", "superagent", "needle", "request", "ky", "ofetch", "cross-fetch", "isomorphic-fetch", "phin", "centra", "bent", "make-fetch-happen", "minipass-fetch", "ws"]);

/** Globals that load a module by its name. */
const LOADERS: ReadonlySet<string> = new Set(["require", "module.require", "require.main.require", "process.mainModule.require", "process.getBuiltinModule"]);

/** Methods that write to a request or connection. */
const WRITES: ReadonlySet<string> = new Set(["write", "end", "send"]);

/** Methods whose callbacks receive what the receiver resolves to or emits. */
const CALLBACK_METHODS: ReadonlySet<string> = new Set(["then", "catch", "finally", "on", "once", "addListener", "addEventListener", "forEach", "map", "flatMap", "filter", "reduce", "some", "every", "find"]);

/** Methods that combine their receiver with their arguments. */
const COMBINE_METHODS: ReadonlySet<string> = new Set(["concat", "replace", "replaceAll", "padStart", "padEnd", "push", "unshift", "append", "set"]);

/** Programs that run their arguments as a command or a script. */
const INTERPRETER = /^(?:.*[/\\])?(?:(?:ba|z|da|k|c|tc)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|node|bun|deno|python[0-9.]*|perl|ruby|php|osascript)$/i;

/** What a command can hold around the downloaded part and still be only that part: a shell and its flag, quotes. */
const WRAPPER_ONLY = /^\s*(?:(?:\S*[/\\])?(?:(?:ba|z|da)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\s+(?:-c|\/c|-Command|-e|-EncodedCommand|-NoProfile)?\s*)?["'`]*\s*["'`]*\s*$/i;

/** The label for a relative module's value (`path` empty) or one of its exports, and a deeper member of that. */
function importLabel(spec: string, path: string): Label {
  if (path === "" || path === "default") return `import:${spec}#`;
  const [first, ...rest] = path.split(".");

  return rest.length > 0 ? `import:${spec}#${first ?? ""}+` : `import:${spec}#${first ?? ""}`;
}

function rel(spec: string): boolean {
  return spec.startsWith("./") || spec.startsWith("../");
}

function union(...sets: Labels[]): Set<Label> {
  const out = new Set<Label>();

  for (const s of sets) for (const l of s) out.add(l);

  return out;
}

function without(set: Labels, drop: (l: Label) => boolean): Set<Label> {
  const out = new Set<Label>();

  for (const l of set) if (!drop(l)) out.add(l);

  return out;
}

/** Whether a label is resolved later, across files. */
export function isSymbolic(l: Label): boolean {
  return l.startsWith("import:") || l.startsWith("read:");
}

function propName(n: AnyNode): string | null {
  if (n.type === "Identifier") return n.name;

  return n.type === "Literal" && (n.raw?.[0] === "'" || n.raw?.[0] === '"') ? String(n.value) : null;
}

/** The labels a call that does not hand its arguments back whole still passes on: what data a helper may return. */
function passedThrough(l: Label): boolean {
  return l === "net" || l === "cred" || l === "cred-path" || l.startsWith("secret:") || isSymbolic(l);
}

/** Reads where values go in one program. Built once per program, after the reader has visited it. */
export class Flow {
  private readonly memo = new Map<AnyNode, Labels>();
  private readonly bindingMemo = new Map<Binding, Labels>();
  private readonly returnMemo = new Map<AnyNode, Labels>();
  private readonly assigns = new Map<Binding, AnyNode[]>();
  private readonly params = new Map<Binding, { fn: AnyNode; index: number; whole: boolean; fallback: AnyNode | null }>();
  private readonly loops = new Map<Binding, { right: AnyNode; keys: boolean }>();
  private readonly siteOf = new Map<AnyNode, CallSite>();
  private readonly callsOf = new Map<AnyNode, CallSite[]>();
  private readonly callsByBinding = new Map<Binding, CallSite[]>();
  private readonly callbacksOf = new Map<AnyNode, CallSite[]>();
  private readonly exported: { name: string; node: AnyNode }[] = [];
  private readonly envUses: EnvUse[] = [];
  private depth = 0;
  /** Whether the program has any way to turn its own source into a string (String, toString, .source, its own path). */
  private mayRecover = false;

  constructor(private readonly host: FlowHost) {
    for (const site of host.calls) this.siteOf.set(site.node, site);
    this.index();
  }

  read(): FlowRead {
    return { sinks: this.sinks(), recovered: this.mayRecover ? this.recovered() : [], exports: this.exports(), env: [...this.envUses, ...this.envReads()].slice(0, 200) };
  }

  // ----- indexing the program once -----

  private index(): void {
    const stack: [AnyNode, AnyNode | null][] = [[this.host.program, null]];

    for (let item = stack.pop(); item; item = stack.pop()) {
      const [n, parent] = item;

      this.indexNode(n, parent);

      for (const c of childNodes(n)) stack.push([c, n]);
    }

    for (const site of this.host.calls) {
      const callee = unwrap(site.node.callee);

      if (callee.type === "Identifier") {
        const b = this.host.bindingOf(callee);

        if (b !== null && b !== "dynamic") this.callsByBinding.set(b, [...(this.callsByBinding.get(b) ?? []), site]);
      }

      for (const fn of this.localFunctions(callee)) this.callsOf.set(fn, [...(this.callsOf.get(fn) ?? []), site]);

      for (const slot of site.slots) {
        if (!slot) continue;

        for (const fn of this.localFunctions(slot)) this.callbacksOf.set(fn, [...(this.callbacksOf.get(fn) ?? []), site]);
      }
    }
  }

  private indexNode(n: AnyNode, parent: AnyNode | null): void {
    if (n.type === "MetaProperty" || (n.type === "Identifier" && (n.name === "String" || n.name === "toString" || n.name === "source" || n.name === "__filename" || n.name === "argv"))) this.mayRecover = true;

    switch (n.type) {
      case "AssignmentExpression":
        if (n.left.type === "Identifier") this.assignTo(n.left, n.right);
        else if (n.left.type === "MemberExpression") this.exportTo(n.left, n.right);

        return;
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        n.params.forEach((p, index) => this.param(n, p, index));

        return;
      case "ForOfStatement":
      case "ForInStatement": {
        const left = n.left.type === "VariableDeclaration" ? n.left.declarations[0]?.id : n.left;

        if (left?.type === "Identifier") {
          const b = this.host.bindingOf(left);

          if (b !== null && b !== "dynamic") this.loops.set(b, { right: n.right, keys: n.type === "ForInStatement" });
        }

        return;
      }

      case "ExportDefaultDeclaration":
        this.exported.push({ name: "default", node: n.declaration });

        return;
      case "ExportNamedDeclaration":
        if (n.declaration?.type === "VariableDeclaration") for (const d of n.declaration.declarations) if (d.init && d.id.type === "Identifier") this.exported.push({ name: d.id.name, node: d.init });

        if (n.declaration?.type === "FunctionDeclaration" && n.declaration.id) this.exported.push({ name: n.declaration.id.name, node: n.declaration });

        for (const s of n.specifiers) if (s.local.type === "Identifier" && !n.source) this.exported.push({ name: propName(s.exported) ?? s.local.name, node: s.local });

        return;
      case "MemberExpression":
        if (parent?.type === "MemberExpression" && parent.object === n) return;
        this.envUse(n, parent);

        return;
      case "Identifier":
        if (parent?.type === "MemberExpression" && (parent.object === n || (parent.property === n && !parent.computed))) return;

        if (parent?.type === "Property" && parent.key === n && !parent.computed) return;
        this.envUse(n, parent);

        return;
      default:
        return;
    }
  }

  private assignTo(id: Identifier, value: AnyNode): void {
    const b = this.host.bindingOf(id);

    if (b !== null && b !== "dynamic") this.assigns.set(b, [...(this.assigns.get(b) ?? []), value]);
  }

  private param(fn: AnyNode, p: AnyNode, index: number): void {
    const fallback = p.type === "AssignmentPattern" ? p.right : null;
    const target = p.type === "AssignmentPattern" ? p.left : p.type === "RestElement" ? p.argument : p;
    const ids: Identifier[] = [];
    const stack: AnyNode[] = [target];

    for (let x = stack.pop(); x; x = stack.pop()) {
      if (x.type === "Identifier") ids.push(x);
      else if (x.type === "ObjectPattern") stack.push(...x.properties.map((prop) => (prop.type === "RestElement" ? prop.argument : prop.value)));
      else if (x.type === "ArrayPattern") stack.push(...x.elements.filter((el) => el !== null));
      else if (x.type === "AssignmentPattern") stack.push(x.left);
      else if (x.type === "RestElement") stack.push(x.argument);
    }

    for (const id of ids) {
      const b = this.host.bindingOf(id);

      if (b !== null && b !== "dynamic") this.params.set(b, { fn, index, whole: target.type === "Identifier", fallback });
    }
  }

  /**
   * `module.exports = v` (the module value; an object literal's properties are its named exports too),
   * `module.exports.x = v` and `exports.x = v`: where a CommonJS module puts what it exports.
   */
  private exportTo(target: AnyNode, value: AnyNode): void {
    const names: (string | null)[] = [];
    let cur = unwrap(target);
    let found = false;

    while (cur.type === "MemberExpression" && !found) {
      const obj = unwrap(cur.object);
      const name = cur.computed ? null : propName(cur.property);

      if (obj.type === "Identifier" && obj.name === "module" && name === "exports" && this.host.bindingOf(obj) === null) found = true;
      else {
        names.unshift(name);

        if (obj.type === "Identifier" && obj.name === "exports" && this.host.bindingOf(obj) === null) found = true;
        cur = obj;
      }
    }

    if (!found) return;
    const first = names[0];

    if (names.length === 0) {
      this.exported.push({ name: "", node: value });
      const v = unwrap(value);

      if (v.type === "ObjectExpression") for (const p of v.properties) if (p.type === "Property" && !p.computed) this.exported.push({ name: propName(p.key) ?? "", node: p.value });
    } else if (first !== null && first !== undefined) this.exported.push({ name: first, node: value });
  }

  /** An environment variable read by name, or the environment object used whole, for the env capability. */
  private envUse(n: AnyNode, parent: AnyNode | null): void {
    if (this.envUses.length >= 200 || !this.isEnvObject(n)) return;

    if (parent?.type === "MemberExpression" && parent.object === n) return;
    this.envUses.push({ at: n.start, name: null });
  }

  private isEnvObject(n: AnyNode): boolean {
    const t = unwrap(n);

    if (t.type === "Identifier") {
      const b = this.host.bindingOf(t);

      if (b === null || b === "dynamic") return false;
    } else if (t.type !== "MemberExpression" || propName(t.property) !== "env") return false;

    return this.host.refsOf(t).some((r) => r.kind === "global" && (r.path === "process.env" || r.path === "Bun.env"));
  }

  /** Named reads off the environment object, however it is reached (aliases, `globalThis.process.env`, `Bun.env`). */
  private envReads(): EnvUse[] {
    const out: EnvUse[] = [];
    const stack: AnyNode[] = [this.host.program];

    for (let n = stack.pop(); n; n = stack.pop()) {
      if (n.type === "MemberExpression" && out.length < 200 && this.isEnvObject(n.object)) {
        const key = n.computed ? this.host.str(n.property) : null;
        const name = n.computed ? (key?.exact ? key.value : "*") : propName(n.property);

        if (name) out.push({ at: n.start, name });
      }

      stack.push(...childNodes(n));
    }

    return out;
  }

  /** The functions this file defines that a node can be. */
  private localFunctions(n: AnyNode): AnyNode[] {
    const t = unwrap(n);

    if (isFunctionNode(t) && t.type !== "ClassExpression") return [t];

    if (t.type !== "Identifier" && t.type !== "MemberExpression") return [];

    return this.host.refsOf(t).flatMap((r) => (r.kind === "local" && r.obj && (isFunctionNode(r.obj.node) || r.obj.node.type === "FunctionDeclaration") && r.obj.node.type !== "ClassExpression" ? [r.obj.node] : []));
  }

  // ----- what a value carries -----

  taint(n: AnyNode): Labels {
    const node = unwrap(n);
    const cached = this.memo.get(node);

    if (cached) return cached;

    if (this.depth > MAX_DEPTH) {
      this.host.limit();

      return NONE;
    }

    // a value that refers back to itself carries what the rest of it does
    this.memo.set(node, NONE);
    this.depth++;

    try {
      const out = this.taintNode(node);
      this.memo.set(node, out);

      return out;
    } finally {
      this.depth--;
    }
  }

  private taintNode(n: AnyNode): Labels {
    const named = this.namedPath(n);

    switch (n.type) {
      case "Identifier": {
        const b = this.host.bindingOf(n);

        return b !== null && b !== "dynamic" ? union(this.bindingTaint(b), this.refLabels(n)) : this.refLabels(n);
      }

      case "Literal":
      case "TemplateLiteral":
      case "BinaryExpression": {
        const parts = n.type === "TemplateLiteral" ? n.expressions : n.type === "BinaryExpression" && n.operator === "+" && n.left.type !== "PrivateIdentifier" ? [n.left, n.right] : [];

        return union(named, ...parts.map((p) => union(this.taint(p), this.sourceOf(p))));
      }

      case "LogicalExpression":
        return union(this.taint(n.left), this.taint(n.right));
      case "ConditionalExpression":
        return union(this.taint(n.consequent), this.taint(n.alternate));
      case "SequenceExpression": {
        const last = n.expressions.at(-1);

        return last ? this.taint(last) : NONE;
      }

      case "AssignmentExpression":
        return this.taint(n.right);
      case "AwaitExpression":
      case "SpreadElement":
      case "YieldExpression":
        return n.argument ? this.taint(n.argument) : NONE;
      case "ObjectExpression":
        return union(...n.properties.map((p) => (p.type === "SpreadElement" ? this.taint(p.argument) : p.kind === "init" && !p.method ? this.taint(p.value) : NONE)));
      case "ArrayExpression":
        return union(...n.elements.map((e) => (e ? this.taint(e) : NONE)));
      case "MemberExpression": {
        if (n.object.type === "Super") return NONE;
        const key = n.computed ? this.host.str(n.property) : null;
        const name = n.computed ? (key?.exact ? key.value : null) : propName(n.property);
        const regex = name === "source" ? this.regexNode(n.object) : null;

        if (regex) return new Set<Label>([`src:${regex.start}:${regex.end}`]);

        return union(this.memberOf(this.taint(n.object), name, n.computed ? this.taint(n.property) : NONE), this.refLabels(n), named);
      }

      case "CallExpression":
      case "NewExpression":
        return union(this.callTaint(n), named);
      default:
        return NONE;
    }
  }

  /** `cred-path` for a string apm can work out that names a credential file. */
  private namedPath(n: AnyNode): Labels {
    if (n.type !== "Literal" && n.type !== "TemplateLiteral" && n.type !== "BinaryExpression" && n.type !== "CallExpression") return NONE;
    const s = this.host.str(n);

    return s && CREDENTIAL_NAME.test(s.value.split(UNKNOWN).join("/")) ? new Set<Label>(["cred-path"]) : NONE;
  }

  /** What a name resolves to that carries something by itself: the environment object, or a relative module. */
  private refLabels(n: AnyNode): Labels {
    const out = new Set<Label>();

    for (const r of this.host.refsOf(n)) {
      if (r.kind === "global" && (r.path === "process.env" || r.path === "Bun.env")) out.add("env");

      if (r.kind === "module" && rel(r.spec)) out.add(importLabel(r.spec, r.path));
    }

    return out;
  }

  private bindingTaint(b: Binding): Labels {
    const cached = this.bindingMemo.get(b);

    if (cached) return cached;
    this.bindingMemo.set(b, NONE);
    const out = new Set<Label>();

    const add = (labels: Labels): void => {
      for (const l of labels) out.add(l);
    };

    const origin = (o: Binding["origin"]): void => {
      switch (o.kind) {
        case "value":
          add(this.taint(o.init));

          return;
        case "member":
          add(this.memberOf(this.taint(o.base), o.path.length === 1 && o.path[0]?.kind === "name" ? o.path[0].name : null, NONE));

          return;
        case "module":
          if (rel(o.spec)) out.add(importLabel(o.spec, o.path));

          return;
        case "default":
          origin(o.inner);
          add(this.taint(o.fallback));

          return;
        case "local":
        case "opaque":
          return;
        default: {
          const _exhaustive: never = o;

          return _exhaustive;
        }
      }
    };

    origin(b.origin);

    for (const v of this.assigns.get(b) ?? []) add(this.taint(v));
    const p = this.params.get(b);

    if (p) add(this.paramTaint(p));
    const loop = this.loops.get(b);

    if (loop) {
      const right = this.taint(loop.right);

      // `for (k in process.env)` gives the names, which index the whole environment
      if (loop.keys && right.has("env")) out.add("env-key");
      else add(this.memberOf(right, null, NONE));
    }

    this.bindingMemo.set(b, out);

    return out;
  }

  /**
   * What a member of a value carries: one environment variable is not the environment, and a named property of a value
   * that holds a credential path (`config.root` beside `deny: ['.npmrc']`) or of source text (`src.length`) is not that
   * path or text; an element taken by index or in a loop is. The rest stays with the value (`res.data`).
   */
  private memberOf(base: Labels, name: string | null, key: Labels): Set<Label> {
    const named = name !== null && !/^\d+$/.test(name);
    const out = without(base, (l) => l === "env" || l === "env-key" || l === "conn" || (named && (l === "cred-path" || l.startsWith("src:"))));

    // a named member of an import selects that export, and a named member of an export is marked so the credential
    // path rule above applies once the export is known
    if (named) {
      for (const l of base) {
        if (!l.startsWith("import:")) continue;
        const rest = l.slice("import:".length);

        out.delete(l);
        out.add(rest.endsWith("#") ? `import:${rest}${name}` : rest.endsWith("+") ? `import:${rest}` : `import:${rest}+`);
      }
    }

    if (!base.has("env")) return out;
    const family = name === null ? null : secretFamily(name);

    if (family) out.add(`secret:${family}`);

    // `process.env[k]` inside a loop over the environment reads every variable
    if (name === null && key.has("env-key")) out.add("env");

    return out;
  }

  private paramTaint(p: { fn: AnyNode; index: number; whole: boolean; fallback: AnyNode | null }): Labels {
    const out = new Set<Label>();

    const add = (labels: Labels): void => {
      for (const l of labels) out.add(l);
    };

    for (const site of this.callsOf.get(p.fn) ?? []) {
      const arg = site.slots[p.index];

      if (arg) add(this.taint(arg));
    }

    // a callback gets what the call it is passed to hands it: a response, or what its receiver resolves to or emits
    for (const site of this.callbacksOf.get(p.fn) ?? []) {
      if (site.network || this.isHttpClient(site.node)) out.add("net");
      const callee = unwrap(site.node.callee);

      if (callee.type === "MemberExpression" && callee.object.type !== "Super" && CALLBACK_METHODS.has(propName(callee.property) ?? "")) {
        const recv = this.taint(callee.object);

        add(without(recv, (l) => l === "conn"));

        if (recv.has("conn")) out.add("net");
      }
    }

    if (p.fallback) add(this.taint(p.fallback));

    return p.whole ? out : this.memberOf(out, null, NONE);
  }

  /** What a function's returns carry, as one set for every call (calls are not told apart). */
  private returnTaint(fn: AnyNode): Labels {
    const cached = this.returnMemo.get(fn);

    if (cached) return cached;
    this.returnMemo.set(fn, NONE);
    const out = union(...this.host.returnedBy(fn).map((r) => this.taint(r)));
    this.returnMemo.set(fn, out);

    return out;
  }

  private callTaint(n: CallExpression | NewExpression): Labels {
    if (n.callee.type === "Super") return NONE;
    const site = this.siteOf.get(n);
    const callee = unwrap(n.callee);
    const refs = this.host.refsOf(callee);
    const args = n.arguments.map((a) => (a.type === "SpreadElement" ? a.argument : a));
    const argsTaint = (): Labels => union(...args.map((a) => this.taint(a)));
    const out = union(this.refLabels(n));

    const add = (labels: Labels): void => {
      for (const l of labels) out.add(l);
    };

    if (site?.network || this.isHttpClient(n) || (n.type === "NewExpression" && refs.some((r) => r.kind === "global" && /^(?:WebSocket|XMLHttpRequest|EventSource)$/.test(r.path)))) {
      out.add("net");
      out.add("conn");
    }

    // what a read gives: a credential file's contents when its path names one, this program when it reads itself
    const readAt = site?.roles.indexOf("read") ?? -1;
    const readArg = readAt >= 0 ? site?.slots[readAt] : null;

    if (readArg) {
      const path = this.taint(readArg);

      if (path.has("cred-path")) out.add("cred");

      for (const l of path) if (isSymbolic(l)) out.add(`read:${l}`);

      if (this.isOwnPath(readArg)) out.add(`src:0:${this.host.program.end}`);
    }

    if (refs.some((r) => r.kind === "global" && r.path === "Deno.env.toObject")) out.add("env");

    // String(fn), fn.toString(), Function.prototype.toString.call(fn): the source text of a function this file defines
    if (refs.some((r) => r.kind === "global" && r.path === "String") && args[0]) add(this.sourceOf(args[0]));

    if (callee.type === "MemberExpression" && callee.object.type !== "Super") {
      const method = propName(callee.property) ?? "";

      if (method === "toString") add(this.sourceOf(callee.object));

      if ((method === "call" || method === "apply") && this.host.refsOf(callee.object).some((r) => r.kind === "global" && r.path === "Function.prototype.toString") && args[0]) add(this.sourceOf(args[0]));
    }

    const passes = refs.some((r) => (r.kind === "global" && PASS_GLOBALS.has(r.path)) || (r.kind === "module" && PASS_MODULES.has(r.spec)));

    if (passes) add(argsTaint());

    // `new Promise((resolve) => …)`: what resolve is called with
    if (n.type === "NewExpression" && refs.some((r) => r.kind === "global" && r.path === "Promise") && args[0]) add(this.resolvedBy(args[0]));

    for (const fn of this.localFunctions(callee)) add(this.returnTaint(fn));

    if (callee.type === "MemberExpression" && callee.object.type !== "Super") {
      const method = propName(callee.property) ?? "";
      const recv = this.taint(callee.object);

      // a method of a value gives data drawn from it (`res.text()`, `buf.toString('base64')`, `env.map(…)`, `src.slice(…)`)
      add(without(recv, (l) => l === "conn" || (l === "env" && method === "hasOwnProperty")));

      if (recv.has("conn") && !WRITES.has(method)) out.add("net");

      if (method === "then" || method === "catch" || method === "finally") for (const a of args) for (const fn of this.localFunctions(a)) add(this.returnTaint(fn));

      if (COMBINE_METHODS.has(method)) add(argsTaint());
    }

    // any other call may hand back data drawn from its arguments, but not the environment object whole
    if (!passes) add(without(argsTaint(), (l) => !passedThrough(l)));

    return out;
  }

  /** What the first parameter of a Promise executor is called with. */
  private resolvedBy(executor: AnyNode): Labels {
    const out = new Set<Label>();

    for (const fn of this.localFunctions(executor)) {
      const first = fn.type === "FunctionExpression" || fn.type === "ArrowFunctionExpression" || fn.type === "FunctionDeclaration" ? fn.params[0] : undefined;

      if (first?.type !== "Identifier") continue;
      const b = this.host.bindingOf(first);

      if (b === null || b === "dynamic") continue;

      for (const site of this.callsByBinding.get(b) ?? []) for (const s of site.slots) if (s) for (const l of this.taint(s)) out.add(l);
    }

    return out;
  }

  /** The source text a value gives when made a string: a function or class this file defines, or a regex literal. */
  private sourceOf(n: AnyNode): Labels {
    const t = unwrap(n);
    const regex = this.regexNode(t);

    if (regex) return new Set<Label>([`src:${regex.start}:${regex.end}`]);
    const nodes = isFunctionNode(t) ? [t] : t.type === "Identifier" || t.type === "MemberExpression" ? this.host.refsOf(t).flatMap((r) => (r.kind === "local" && r.obj && (isFunctionNode(r.obj.node) || r.obj.node.type === "FunctionDeclaration" || r.obj.node.type === "ClassDeclaration") ? [r.obj.node] : [])) : [];

    return new Set(nodes.map((x): Label => `src:${x.start}:${x.end}`));
  }

  private regexNode(n: AnyNode): AnyNode | null {
    const t = unwrap(n);

    if (t.type === "Literal" && "regex" in t && t.regex) return t;

    if (t.type !== "Identifier") return null;
    const b = this.host.bindingOf(t);

    return b !== null && b !== "dynamic" && b.count === 1 && !b.assigned && b.origin.kind === "value" && b.origin.init !== t ? this.regexNode(b.origin.init) : null;
  }

  /** The program's own file: `__filename`, `import.meta.filename`, `process.argv[1]`, `fileURLToPath(import.meta.url)`. */
  private isOwnPath(n: AnyNode): boolean {
    const t = unwrap(n);

    if (t.type === "MemberExpression" && t.object.type === "MetaProperty") return ["filename", "path", "url"].includes(propName(t.property) ?? "");

    if (t.type === "CallExpression" && t.callee.type !== "Super" && this.host.refsOf(t.callee).some((r) => (r.kind === "global" || r.kind === "module") && r.path.endsWith("fileURLToPath"))) return t.arguments[0] !== undefined && t.arguments[0].type !== "SpreadElement" && this.isOwnPath(t.arguments[0]);

    return this.host.refsOf(t).some((r) => r.kind === "global" && (r.path === "__filename" || r.path === "module.filename" || r.path === "require.main.filename" || r.path === "process.argv.1"));
  }

  private isHttpClient(n: CallExpression | NewExpression): boolean {
    if (n.callee.type === "Super") return false;

    return this.host.refsOf(unwrap(n.callee)).some((r) => r.kind === "module" && HTTP_CLIENTS.has(r.spec));
  }

  // ----- where values end up -----

  private sinks(): Sink[] {
    const out: Sink[] = [];

    const keep = (kind: Sink["kind"], at: number, labels: Labels, relevant: (l: Label) => boolean): void => {
      const list = [...labels].filter(relevant);

      if (list.length > 0 && out.length < 400) out.push({ kind, at, labels: list });
    };

    for (const site of this.host.calls) {
      const n = site.node;

      if (n.callee.type === "Super") continue;
      const callee = unwrap(n.callee);
      const at = callee.start;
      const request = new Set<Label>();

      site.slots.forEach((slot, i) => {
        if (!slot) return;
        const role = site.roles[i];

        if (role === "code") keep("code", at, this.taint(slot), (l) => l === "net" || isSymbolic(l));
        else if (role === "shell" && this.wholeCommand(site, i)) keep("shell", at, this.taint(slot), (l) => l === "net" || isSymbolic(l));
        else if (role === "read") keep("read", at, this.taint(slot), (l) => l === "cred-path" || isSymbolic(l));
        else if (role === "request") for (const l of this.taint(slot)) request.add(l);
      });

      // a request or connection written to, and every argument of an HTTP client's call, is sent
      const writes = callee.type === "MemberExpression" && callee.object.type !== "Super" && WRITES.has(propName(callee.property) ?? "") && this.taint(callee.object).has("conn");

      if (writes || this.isHttpClient(n)) for (const a of n.arguments) for (const l of this.taint(a.type === "SpreadElement" ? a.argument : a)) request.add(l);
      keep("request", at, request, (l) => l === "env" || l === "cred" || l.startsWith("secret:") || isSymbolic(l));
    }

    return out;
  }

  /**
   * Whether the value at slot `i` is the whole command a process runs: the command string itself with nothing around
   * it but a shell and quotes (`exec(body)`, `exec('sh -c "' + body + '"')`), or any argument of an interpreter
   * (`spawn('sh', ['-c', body])`), or the program itself.
   */
  private wholeCommand(site: CallSite, i: number): boolean {
    const slot = site.slots[i];

    if (!slot) return false;

    if (i > 0) {
      const program = site.slots[0] ? this.host.str(site.slots[0]) : null;

      return program?.exact === true && INTERPRETER.test(program.value.trim());
    }

    const s = this.host.str(slot);

    return s === null || (!s.exact && WRAPPER_ONLY.test(s.value.split(UNKNOWN).join("")));
  }

  /** Source text recovered as a string and run, or handed to a member of a module loaded by a name built at runtime. */
  private recovered(): Recovered[] {
    const out: Recovered[] = [];

    for (const site of this.host.calls) {
      const n = site.node;

      if (n.callee.type === "Super") continue;
      const unnamed = this.fromComputedLoad(n.callee, 0);

      site.slots.forEach((slot, i) => {
        if (!slot || (site.roles[i] !== "code" && !unnamed)) return;

        const ranges = [...this.taint(slot)].flatMap((l): [number, number][] => {
          const m = /^src:(\d+):(\d+)$/.exec(l);

          return m ? [[Number(m[1]), Number(m[2])]] : [];
        });

        if (ranges.length > 0 && out.length < 50) out.push({ at: unwrap(n.callee).start, ranges });
      });
    }

    return out;
  }

  /**
   * Whether a callee is reached through a module loaded by a name apm cannot read (`require(process.argv[2])[name]`,
   * `const m = await import(x); m.run`): whatever it is, it may be an evaluator.
   */
  private fromComputedLoad(n: AnyNode, depth: number): boolean {
    const t = unwrap(n);

    if (depth > 8) return false;

    switch (t.type) {
      case "MemberExpression":
        return t.object.type !== "Super" && this.fromComputedLoad(t.object, depth + 1);
      case "AwaitExpression":
        return this.fromComputedLoad(t.argument, depth + 1);
      case "ImportExpression":
        return this.host.str(t.source)?.exact !== true;
      case "Identifier": {
        const b = this.host.bindingOf(t);

        return b !== null && b !== "dynamic" && b.count === 1 && !b.assigned && b.origin.kind === "value" && b.origin.init !== t && this.fromComputedLoad(b.origin.init, depth + 1);
      }

      case "CallExpression": {
        if (t.callee.type === "Super") return false;
        const loader = this.host.refsOf(unwrap(t.callee)).some((r) => (r.kind === "global" && LOADERS.has(r.path)) || (r.kind === "unknown" && r.name === "require" && r.owner === null));
        const arg = t.arguments[0];

        if (loader) return !arg || arg.type === "SpreadElement" || this.host.str(arg)?.exact !== true;

        return this.fromComputedLoad(t.callee, depth + 1);
      }

      default:
        return false;
    }
  }

  /** What the module exports by name, with what its exported functions return; `""` is all of it. */
  private exports(): Exports {
    const out = new Map<string, Label[]>();
    const all = new Set<Label>();

    const of = (n: AnyNode, into: Set<Label>, depth: number): void => {
      for (const l of this.taint(n)) into.add(l);

      for (const fn of n.type === "FunctionDeclaration" ? [n] : this.localFunctions(n)) for (const l of this.returnTaint(fn)) into.add(l);
      const t = unwrap(n);

      if (t.type === "ObjectExpression" && depth < 3) for (const p of t.properties) if (p.type === "Property") of(p.value, into, depth + 1);
    };

    for (const e of this.exported) {
      const labels = new Set<Label>(out.get(e.name) ?? []);

      of(e.node, labels, 0);
      out.set(e.name, [...labels]);

      for (const l of labels) all.add(l);
    }

    out.set("", [...all]);

    return out;
  }
}
