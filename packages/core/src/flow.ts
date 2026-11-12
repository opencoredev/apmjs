// Where values go in one parsed program (apm-score-v10): what a value carries (the whole environment, a credential
// file's path or contents, what a network response gave, the program's own source) and which call it reaches (one that
// runs code, starts a process, sends a request or reads a file). Names are resolved with the reader's scopes (js.ts),
// so an alias (`const run = eval`), a destructured import, a callback's parameter, a function's return and a value
// another file exports are followed; what apm cannot follow carries nothing, and the text rules stay the floor. Pure.
import type { AnyNode, CallExpression, Identifier, MemberExpression, NewExpression, Program } from "acorn";
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
 * - `net-field`: a named field of that (`(await res.json()).version`): code that runs it still runs downloaded code,
 *   but a field put into a longer command is a value, not a command (see `splice`);
 * - `conn`: a request or connection the program can write to;
 * - `secret:<family>`: one secret variable of a family stealers go for (`secret:npm`);
 * - `src:<start>:<end>`: this program's own source text between two offsets (a function, a class, a regex, the file);
 * - `import:<spec>#<name>`: the export `name` of the relative module `spec` (`#` alone for the module value itself),
 *   with `+` after it for a named member taken from that export; worked out once every file is read (score.ts);
 * - `read:<label>`: what reading a path that carries `<label>` gives, worked out the same way;
 * - `param:<fn>:<index>`, with `|<name>` (`|*` for a name apm cannot read) per member taken from it: a parameter of the
 *   function that starts at offset `<fn>`, while its body is read. A call to that function puts what its own argument
 *   carries in its place, so one call's argument never reaches another call's result; a sink in the body takes what
 *   every call passes. These never leave this file (`concrete`).
 */
export type Label = "env" | "env-key" | "cred-path" | "cred" | "net" | "net-field" | "conn" | `secret:${string}` | `src:${number}:${number}` | `import:${string}` | `read:${string}` | `param:${string}`;

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
 * `request` sends it, `read` opens it as a path, `file` runs a program from a file it was written to, `splice` is part
 * of a longer command a shell runs (it may run as a command; apm cannot tell). `labels` is what it carried.
 */
export type Sink = { kind: "code" | "shell" | "request" | "read" | "file" | "splice"; at: number; labels: Label[] };

/** A string the program writes to a file and then loads as code: score.ts reads it as code that runs. */
export type RanWritten = { at: number; code: string };

/** Source text of this program that it turns back into a string and runs (or hands a call apm cannot name). */
export type Recovered = { at: number; ranges: [number, number][] };

/** An environment variable read by name (`*` for a name built at runtime), or the whole object used (`null`). */
export type EnvUse = { at: number; name: string | null };

/** What a module exports, by name: `""` for the module value itself (what `require` gives, whole). */
export type Exports = ReadonlyMap<string, readonly Label[]>;

export type FlowRead = { sinks: Sink[]; recovered: Recovered[]; exports: Exports; env: EnvUse[]; ranWritten: RanWritten[] };

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

/** Members of a response that are its body, so taking one is still what the response gave whole. */
const BODY_NAMES: ReadonlySet<string> = new Set(["data", "body", "text", "content", "contents", "stdout", "payload", "script", "code", "source", "src", "cmd", "command", "response", "responseText", "raw", "chunk", "buffer", "result", "value"]);

/** Methods that put their arguments into the container they are called on (`a.push(x)`, `m.set(k, x)`). */
const MUTATORS: ReadonlySet<string> = new Set(["push", "unshift", "splice", "set", "add", "append", "prepend", "fill"]);

/** Methods that register a listener, whose parameters get what `emit` on the same emitter passes. */
const LISTENS: ReadonlySet<string> = new Set(["on", "once", "addListener", "prependListener", "prependOnceListener"]);

/** Module functions that write a file, given its path and then its data, and the modules they come from. */
const WRITE_FILES: ReadonlySet<string> = new Set(["writeFileSync", "writeFile", "appendFile", "appendFileSync", "outputFile", "outputFileSync"]);
const FS_MODULES: ReadonlySet<string> = new Set(["fs", "fs/promises", "fs-extra", "graceful-fs"]);

/** Programs that send what they are given: every argument they get is a request. */
const NET_TOOL = /^(?:.*[/\\])?(?:curl|wget|nc|ncat|netcat|xh|scp|sftp)(?:\.exe)?$/i;

/** A command line that starts such a program, after the words that only start what follows them. */
const NET_TOOL_COMMAND = /(?:^|[;&|(`]\s*|\$\(\s*)(?:(?:sudo|nohup|setsid|env|exec|command|time|nice)\s+)*(?:\S*\/)?(?:curl|wget|nc|ncat|netcat)(?:\.exe)?\s/i;

/** Words that only start the program named after them. */
const LAUNCH_WORDS: ReadonlySet<string> = new Set(["sudo", "nohup", "setsid", "env", "exec", "command", "nice", "time", "stdbuf"]);

/** Programs that run JavaScript from the file named after them. */
const NODE_LIKE = /^(?:.*[/\\])?(?:node|nodejs|bun|deno|tsx|ts-node)(?:\.exe)?$/i;

/** A parameter label (see `Label`), with the members taken from it; and one read through any number of `read:`. */
const PARAM = /^param:(\d+):(\d+)((?:\|[^|]*)*)$/;
const PARAMISH = /^(?:read:)*param:/;

/** How many members one parameter label records before it stops adding them. */
const MAX_PARAM_PATH = 4;

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

/** Whether a label is resolved later, across files or at each call of the function whose parameter it names. */
function isDeferred(l: Label): boolean {
  return isSymbolic(l) || l.startsWith("param:");
}

/** What reading a path that carries `path` gives: a credential file's contents, or a read worked out later. */
function readOf(path: Labels): Set<Label> {
  const out = new Set<Label>();

  if (path.has("cred-path")) out.add("cred");

  for (const l of path) if (isDeferred(l)) out.add(`read:${l}`);

  return out;
}

/** A parameter or read label rebuilt from its text, so its type is checked. */
function deferredLabel(s: string): Label | null {
  if (s.startsWith("param:")) return `param:${s.slice("param:".length)}`;

  return s.startsWith("read:") ? `read:${s.slice("read:".length)}` : null;
}

/** The path a command line runs, with its leading `./` and quotes taken off, for matching against a written file. */
function normPath(s: string): string {
  return s.trim().replace(/^["'`]+|["'`]+$/g, "").replace(/^(?:\.\/)+/, "");
}

function baseName(s: string): string {
  return s.slice(Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\")) + 1);
}

function propName(n: AnyNode): string | null {
  if (n.type === "Identifier") return n.name;

  return n.type === "Literal" && (n.raw?.[0] === "'" || n.raw?.[0] === '"') ? String(n.value) : null;
}

/** The labels a call that does not hand its arguments back whole still passes on: what data a helper may return. */
function passedThrough(l: Label): boolean {
  return l === "net" || l === "net-field" || l === "cred" || l === "cred-path" || l.startsWith("secret:") || isDeferred(l);
}

/** What a command string carries as the whole command, and as part of a longer one. */
type CommandLabels = { whole: Labels; part: Labels };

/** A parameter: its function, position, whether it is the whole argument, its default, and the key it takes if not. */
type Param = { fn: AnyNode; index: number; whole: boolean; fallback: AnyNode | null; key: string | null };

/** What one target of a write or a run names: the node that gives its path, or the path a command line names. */
type PathRef = { node: AnyNode } | { text: string };

/** What a call runs from a file: JavaScript a loader or an interpreter reads (`js`), or a program (`program`). */
type RunTarget = { path: PathRef; kind: "js" | "program" };

/** Reads where values go in one program. Built once per program, after the reader has visited it. */
export class Flow {
  private readonly memo = new Map<AnyNode, Labels>();
  private readonly bindingMemo = new Map<Binding, Labels>();
  private readonly returnMemo = new Map<AnyNode, Labels>();
  private readonly assigns = new Map<Binding, AnyNode[]>();
  private readonly params = new Map<Binding, Param>();
  private readonly loops = new Map<Binding, { right: AnyNode; keys: boolean }>();
  private readonly siteOf = new Map<AnyNode, CallSite>();
  private readonly callsOf = new Map<AnyNode, CallSite[]>();
  private readonly callsByBinding = new Map<Binding, CallSite[]>();
  private readonly callbacksOf = new Map<AnyNode, CallSite[]>();
  private readonly exported: { name: string; node: AnyNode }[] = [];
  private readonly envUses: EnvUse[] = [];
  /** What is put into each container (by the binding that holds it, aliases merged), and under which member name. */
  private readonly mutations = new Map<Binding, { name: string | null; value: AnyNode }[]>();
  private readonly aliasOf = new Map<Binding, Binding>();
  /** What `emit` passes on each emitter, by the binding that holds it, and for which event (null: apm cannot tell). */
  private readonly emits = new Map<Binding, { event: string | null; args: readonly (AnyNode | null)[] }[]>();
  /** Files the program writes: the path, and what goes into the file. */
  private readonly written: { path: AnyNode; data: AnyNode[] }[] = [];
  private readonly dynamicImports: AnyNode[] = [];
  private readonly fnAt = new Map<number, AnyNode>();
  private readonly restParams = new Set<string>();
  private readonly paramMemo = new Map<string, Labels>();
  private readonly ranWritten: RanWritten[] = [];
  private depth = 0;
  /** Whether the program has any way to turn its own source into a string (String, toString, .source, its own path). */
  private mayRecover = false;

  constructor(private readonly host: FlowHost) {
    for (const site of host.calls) this.siteOf.set(site.node, site);
    this.index();
  }

  read(): FlowRead {
    return { sinks: this.sinks(), recovered: this.mayRecover ? this.recovered() : [], exports: this.exports(), env: [...this.envUses, ...this.envReads()].slice(0, 200), ranWritten: this.ranWritten };
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

      this.indexCall(site);
    }
  }

  /** What a call puts into a container, emits, or writes to a file. */
  private indexCall(site: CallSite): void {
    const n = site.node;

    if (n.callee.type === "Super") return;
    const callee = unwrap(n.callee);
    const refs = this.host.refsOf(callee);
    const slot = (i: number): AnyNode | null => site.slots[i] ?? null;
    const global = (...paths: string[]): boolean => refs.some((r) => r.kind === "global" && paths.includes(r.path));

    if (global("Object.assign")) {
      for (const v of site.slots.slice(1)) if (v) this.mutate(slot(0), null, v);
    } else if (global("Object.defineProperty", "Reflect.set", "Reflect.defineProperty")) {
      const key = slot(1);
      const k = key ? this.host.str(key) : null;
      const v = slot(2);

      if (v) this.mutate(slot(0), k?.exact ? k.value : null, v);
    } else if (callee.type === "MemberExpression" && callee.object.type !== "Super") {
      const method = this.keyName(callee) ?? "";

      if (MUTATORS.has(method) && !refs.some((r) => r.kind === "module")) for (const v of method === "splice" ? site.slots.slice(2) : site.slots) if (v) this.mutate(callee.object, this.firstKey(callee.object), v);

      if (method === "emit") {
        const root = this.rootBinding(callee.object);
        const event = slot(0);
        const e = event ? this.host.str(event) : null;

        if (root) this.emits.set(root, [...(this.emits.get(root) ?? []), { event: e?.exact ? e.value : null, args: site.slots.slice(1) }]);
      }

      // a stream written to: `src.pipe(w)`, `w.write(data)`, `w.end(data)`
      const piped = method === "pipe" ? this.streamPath(slot(0)) : null;

      if (piped) this.written.push({ path: piped, data: [callee.object] });
      const stream = method === "write" || method === "end" ? this.streamPath(callee.object) : null;
      const chunk = slot(0);

      if (stream && chunk) this.written.push({ path: stream, data: [chunk] });
    }

    // `fs.writeFileSync(path, data)` and its kin; `pipeline(src, ..., w)`; `Bun.write(path, data)`
    const fsWrite = refs.some((r) => r.kind === "module" && FS_MODULES.has(r.spec) && WRITE_FILES.has(r.path.split(".").at(-1) ?? "")) || global("Bun.write", "Deno.writeTextFile", "Deno.writeTextFileSync", "Deno.writeFile", "Deno.writeFileSync");

    const path = slot(0);
    const data = slot(1);

    if (fsWrite && path && data) this.written.push({ path, data: [data] });

    if (refs.some((r) => r.kind === "module" && (r.spec === "stream" || r.spec === "stream/promises") && r.path.endsWith("pipeline"))) {
      const last = site.slots.filter((x): x is AnyNode => x !== null);
      const sink = last.length > 1 ? this.streamPath(last.at(-1) ?? null) : null;

      if (sink) this.written.push({ path: sink, data: last.slice(0, -1) });
    }
  }

  /** The path of a file stream (`fs.createWriteStream(path)`), through a constant holding it; null for anything else. */
  private streamPath(n: AnyNode | null): AnyNode | null {
    if (!n) return null;
    const t = unwrap(n);

    if (t.type === "Identifier") {
      const b = this.host.bindingOf(t);

      return b !== null && b !== "dynamic" && b.count === 1 && !b.assigned && b.origin.kind === "value" && b.origin.init !== t ? this.streamPath(b.origin.init) : null;
    }

    if (t.type !== "CallExpression" || t.callee.type === "Super") return null;
    const opens = this.host.refsOf(unwrap(t.callee)).some((r) => r.kind === "module" && FS_MODULES.has(r.spec) && r.path.split(".").at(-1) === "createWriteStream");
    const first = t.arguments[0];

    return opens && first && first.type !== "SpreadElement" ? first : null;
  }

  /** The binding a value is reached through (`a` for `a`, `a.b[0]`), with every alias of it merged into one. */
  private rootBinding(n: AnyNode): Binding | null {
    let t = unwrap(n);

    for (let i = 0; i < 16 && t.type === "MemberExpression" && t.object.type !== "Super"; i++) t = unwrap(t.object);

    if (t.type !== "Identifier") return null;
    const b = this.host.bindingOf(t);

    return b === null || b === "dynamic" ? null : this.find(b);
  }

  /** The member name a path takes first from its binding (`b` for `a.b.c`); null for the binding itself. */
  private firstKey(n: AnyNode): string | null {
    let t = unwrap(n);
    let key: string | null = null;

    for (let i = 0; i < 16 && t.type === "MemberExpression" && t.object.type !== "Super"; i++) {
      key = this.keyName(t) ?? "*";
      t = unwrap(t.object);
    }

    return key === "*" ? null : key;
  }

  private find(b: Binding): Binding {
    let cur = b;

    for (let i = 0, up = this.aliasOf.get(cur); up && i < 10_000; i++, up = this.aliasOf.get(cur)) cur = up;

    return cur;
  }

  /** `const b = a` and `b = a`: one container under two names. */
  private alias(a: AnyNode, b: AnyNode): void {
    const x = unwrap(a);
    const y = unwrap(b);

    if (x.type !== "Identifier" || y.type !== "Identifier") return;
    const bx = this.host.bindingOf(x);
    const by = this.host.bindingOf(y);

    if (bx === null || bx === "dynamic" || by === null || by === "dynamic") return;
    const rx = this.find(bx);
    const ry = this.find(by);

    if (rx !== ry) this.aliasOf.set(rx, ry);
  }

  private mutate(target: AnyNode | null, name: string | null, value: AnyNode): void {
    const root = target ? this.rootBinding(target) : null;

    if (root) this.mutations.set(root, [...(this.mutations.get(root) ?? []), { name, value }]);
  }

  /** A member's name: as written, a computed key apm can work out, or the one string of an array key (`o[['x']]`). */
  private keyName(m: MemberExpression): string | null {
    if (!m.computed) return propName(m.property);
    const p = unwrap(m.property);
    const one = p.type === "ArrayExpression" && p.elements.length === 1 ? p.elements[0] : null;
    const k = this.host.str(one && one.type !== "SpreadElement" ? one : p);

    return k?.exact ? k.value : null;
  }

  private indexNode(n: AnyNode, parent: AnyNode | null): void {
    if (n.type === "MetaProperty" || (n.type === "Identifier" && (n.name === "String" || n.name === "toString" || n.name === "source" || n.name === "__filename" || n.name === "argv"))) this.mayRecover = true;

    switch (n.type) {
      case "AssignmentExpression":
        if (n.left.type === "Identifier") {
          this.assignTo(n.left, n.right);

          if (n.operator === "=") this.alias(n.left, n.right);
        } else if (n.left.type === "MemberExpression") {
          this.exportTo(n.left, n.right);
          this.mutate(n.left.object.type === "Super" ? null : n.left.object, this.firstKey(n.left), n.right);
        }

        return;
      case "VariableDeclarator":
        if (n.init) this.alias(n.id, n.init);

        return;
      case "ImportExpression":
        this.dynamicImports.push(n);

        return;
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        this.fnAt.set(n.start, n);
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

    if (p.type === "RestElement") this.restParams.add(`${fn.start}:${index}`);
    // `({ version }) => …`: each name takes one key of the argument
    const keys = new Map<Identifier, string>();

    if (target.type === "ObjectPattern") {
      for (const prop of target.properties) {
        if (prop.type !== "Property" || prop.computed) continue;
        const v = prop.value.type === "AssignmentPattern" ? prop.value.left : prop.value;
        const k = propName(prop.key);

        if (v.type === "Identifier" && k !== null) keys.set(v, k);
      }
    }

    for (const id of ids) {
      const b = this.host.bindingOf(id);

      if (b !== null && b !== "dynamic") this.params.set(b, { fn, index, whole: target.type === "Identifier", fallback, key: keys.get(id) ?? null });
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
        const name = this.keyName(n);
        const regex = name === "source" ? this.regexNode(n.object) : null;

        if (regex) return new Set<Label>([`src:${regex.start}:${regex.end}`]);

        // the environment as an internal binding holds it: `process.binding('credentials').env`
        if (name === "env" && this.isInternalBinding(n.object)) return new Set<Label>(["env"]);
        // a member of an object or array the program builds is what that member holds, not all the object holds
        const field = name !== null ? this.fieldNodes(n.object, name, 0) : null;

        // a key apm only partly knows that spells a name (`rc[registry + ':_authToken']`) names an entry too
        const partial = name === null && n.computed ? this.host.str(n.property) : null;
        const entry = name !== null ? !/^\d+$/.test(name) : partial !== null && /[A-Za-z_]/.test(partial.value.split(UNKNOWN).join(""));

        if (field) {
          const got = union(...field.map((x) => this.taint(x)), this.refLabels(n), named);

          return entry ? without(got, (l) => l === "cred") : got;
        }

        const got = union(this.memberOf(this.taint(n.object), name, n.computed ? this.taint(n.property) : NONE), this.refLabels(n), named);

        return entry && name === null ? without(got, (l) => l === "cred") : got;
      }

      case "CallExpression":
      case "NewExpression":
        return union(this.callTaint(n), named);
      default:
        return NONE;
    }
  }

  /**
   * The values a named member of an object or array literal can hold: the literal's own property, and what the program
   * puts into that member (or into the container under a name apm cannot read) later. Null when apm cannot tell (a
   * spread, a getter, a computed key it cannot read, a name assigned more than once): then the member carries what the
   * whole value does.
   */
  private fieldNodes(obj: AnyNode, name: string, depth: number): AnyNode[] | null {
    if (depth > 6) return null;
    const t = unwrap(obj);

    switch (t.type) {
      case "ObjectExpression": {
        let found: AnyNode[] = [];

        for (const p of t.properties) {
          if (p.type === "SpreadElement" || p.kind !== "init") return null;
          const key = p.computed ? this.host.str(p.key) : null;
          const k = p.computed ? (key?.exact ? key.value : null) : propName(p.key);

          if (k === null) return null;

          if (k === name) found = [p.value];
        }

        return found;
      }

      case "ArrayExpression": {
        if (!/^\d+$/.test(name)) return null;
        const i = Number(name);

        if (t.elements.slice(0, i + 1).some((e) => e?.type === "SpreadElement")) return null;
        const el = t.elements[i];

        return el ? [el] : [];
      }

      case "Identifier": {
        const b = this.host.bindingOf(t);

        if (b === null || b === "dynamic" || b.count !== 1 || b.assigned || b.origin.kind !== "value" || b.origin.init === t || this.assigns.has(b)) return null;
        const own = this.fieldNodes(b.origin.init, name, depth + 1);

        if (own === null) return null;
        const put = (this.mutations.get(this.find(b)) ?? []).filter((m) => m.name === null || m.name === name).map((m) => m.value);

        return [...own, ...put];
      }

      case "MemberExpression": {
        if (t.object.type === "Super") return null;
        const inner = this.keyName(t);
        const holders = inner === null ? null : this.fieldNodes(t.object, inner, depth + 1);

        if (holders === null) return null;
        const out: AnyNode[] = [];

        for (const h of holders) {
          const got = this.fieldNodes(h, name, depth + 1);

          if (got === null) return null;
          out.push(...got);
        }

        return out;
      }

      default:
        return null;
    }
  }

  private isInternalBinding(n: AnyNode): boolean {
    const t = unwrap(n);

    return t.type === "CallExpression" && t.callee.type !== "Super" && this.host.refsOf(unwrap(t.callee)).some((r) => r.kind === "global" && (r.path === "process.binding" || r.path === "process._linkedBinding"));
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

    // what the program puts into the container this name (or an alias of it) holds
    for (const m of this.mutations.get(this.find(b)) ?? []) add(this.taint(m.value));
    const p = this.params.get(b);

    if (p) {
      // a direct call's argument stands in for the parameter at that call (`instantiate`); callbacks get what the
      // call they are passed to hands them
      const label: Label = `param:${p.fn.start}:${p.index}`;

      out.add(p.whole ? label : `${label}|${encodeURIComponent(p.key ?? "*")}`);
      add(this.paramTaint(p));
    }

    const loop = this.loops.get(b);

    if (loop) {
      const right = this.taint(loop.right);

      // `for (k in process.env)` gives the names, which index the whole environment; a generator gives what it yields
      if (loop.keys && this.concrete(right).has("env")) out.add("env-key");
      else if (!loop.keys && this.iteratesGenerator(loop.right)) add(right);
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
    // a named entry of what a credential file holds (`rc['//registry.npmjs.org/:_authToken']`) is one token, sent the
    // way a CLI sends its own: the file's whole contents, or a line of it taken by index, stay `cred`
    const out = without(base, (l) => l === "env" || l === "env-key" || l === "conn" || (named && (l === "cred-path" || l === "cred" || l.startsWith("src:"))));

    // a member of a parameter is recorded on its label, so each call takes that member of its own argument
    for (const l of base) {
      if (!l.startsWith("param:")) continue;
      out.delete(l);
      out.add(l.split("|").length > MAX_PARAM_PATH ? l : `param:${l.slice("param:".length)}|${encodeURIComponent(name ?? "*")}`);
    }

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

    // a named field of a response (`json.version`) is a value it gave, not its body
    if (named && out.has("net") && !BODY_NAMES.has(name)) {
      out.delete("net");
      out.add("net-field");
    }

    if (!base.has("env")) return out;
    const family = name === null ? null : secretFamily(name);

    if (family) out.add(`secret:${family}`);

    // `process.env[k]` inside a loop over the environment reads every variable
    if (name === null && key.has("env-key")) out.add("env");

    return out;
  }

  private paramTaint(p: Param): Labels {
    const out = new Set<Label>();

    const add = (labels: Labels): void => {
      for (const l of labels) out.add(l);
    };

    // a callback gets what the call it is passed to hands it: a response, what a read gives, what its receiver
    // resolves to, or what `emit` on the same emitter passes
    for (const site of this.callbacksOf.get(p.fn) ?? []) {
      if ((site.network && !this.isAddressLookup(site.node)) || this.isHttpClient(site.node)) out.add("net");
      add(this.readResult(site));
      const callee = unwrap(site.node.callee);

      if (callee.type !== "MemberExpression" || callee.object.type === "Super") continue;
      const method = this.keyName(callee) ?? "";

      if (CALLBACK_METHODS.has(method)) {
        const recv = this.taint(callee.object);

        add(without(recv, (l) => l === "conn"));

        if (this.concrete(recv).has("conn")) out.add("net");
      }

      if (LISTENS.has(method) && site.slots[1] && this.localFunctions(site.slots[1]).includes(p.fn)) add(this.emitted(callee.object, site.slots[0] ?? null, p.index));
    }

    if (p.fallback) add(this.taint(p.fallback));

    return p.whole ? out : this.memberOf(out, p.key, NONE);
  }

  /** What `emit(event, ...)` passes as argument `index` on the emitter `recv` holds, for a listener of `event`. */
  private emitted(recv: AnyNode, event: AnyNode | null, index: number): Labels {
    const root = this.rootBinding(recv);
    const e = event ? this.host.str(event) : null;
    const want = e?.exact ? e.value : null;
    const out = new Set<Label>();

    for (const em of root ? (this.emits.get(root) ?? []) : []) {
      if (want !== null && em.event !== null && em.event !== want) continue;
      const arg = em.args[index];

      if (arg) for (const l of this.taint(arg)) out.add(l);
    }

    return out;
  }

  /**
   * What a function's returns carry (and a generator's yields), with its parameters left as `param:` labels: each call
   * puts its own arguments in their place (`instantiate`), so two calls of one helper are told apart.
   */
  private returnTaint(fn: AnyNode): Labels {
    const cached = this.returnMemo.get(fn);

    if (cached) return cached;
    this.returnMemo.set(fn, NONE);
    const out = union(...this.host.returnedBy(fn).map((r) => this.taint(r)), ...this.yieldsOf(fn).map((y) => this.taint(y)));
    this.returnMemo.set(fn, out);

    return out;
  }

  /** What a generator yields, in its own body (not in functions it defines). */
  private yieldsOf(fn: AnyNode): AnyNode[] {
    if (!("generator" in fn) || fn.generator !== true || !("body" in fn) || !fn.body) return [];
    const out: AnyNode[] = [];
    const stack: AnyNode[] = [fn.body];

    for (let n = stack.pop(); n && out.length < 64; n = stack.pop()) {
      if (n.type === "YieldExpression" && n.argument) out.push(n.argument);

      for (const c of childNodes(n)) if (!isFunctionNode(c) && c.type !== "FunctionDeclaration") stack.push(c);
    }

    return out;
  }

  /** Whether a loop runs over a call of a generator this file defines, so each element is what it yields. */
  private iteratesGenerator(n: AnyNode): boolean {
    const t = unwrap(n);

    return t.type === "CallExpression" && t.callee.type !== "Super" && this.localFunctions(t.callee).some((fn) => "generator" in fn && fn.generator === true);
  }

  /** `labels` with every parameter label resolved by `param` (null keeps it): the members on it taken in turn. */
  private substitute(labels: Labels, param: (fn: number, index: number) => Labels | null): Labels {
    if (![...labels].some((l) => PARAMISH.test(l))) return labels;
    const out = new Set<Label>();

    for (const l of labels) for (const x of this.substituteOne(l, param)) out.add(x);

    return out;
  }

  private substituteOne(l: Label, param: (fn: number, index: number) => Labels | null): Labels {
    if (!PARAMISH.test(l)) return new Set([l]);

    // a read of a path a parameter gives: what reading what the argument carries gives
    if (l.startsWith("read:")) {
      const inner = deferredLabel(l.slice("read:".length));

      return inner ? readOf(this.substituteOne(inner, param)) : new Set([l]);
    }

    const m = PARAM.exec(l);
    const base = m ? param(Number(m[1]), Number(m[2])) : null;

    if (!m || base === null) return new Set([l]);
    let v: Labels = base;

    for (const name of (m[3] ?? "").split("|").slice(1)) v = this.memberOf(v, name === "*" ? null : decodeURIComponent(name), NONE);

    return v;
  }

  /** What `labels`, read in the body of `fn`, carry at one call of it: its parameters are that call's arguments. */
  private instantiate(labels: Labels, fn: AnyNode, site: CallSite | undefined, n: CallExpression | NewExpression): Labels {
    const slots = site?.slots ?? n.arguments.map((a) => (a.type === "SpreadElement" ? a.argument : a));

    return this.substitute(labels, (f, index) => {
      if (f !== fn.start) return null;
      const args = this.restParams.has(`${f}:${index}`) ? slots.slice(index) : [slots[index] ?? null];

      return union(...args.map((a) => (a ? this.taint(a) : NONE)));
    });
  }

  /** What `labels` carry over every call: a parameter carries what any call of its function passes it. */
  private concrete(labels: Labels): Labels {
    return this.substitute(labels, (fn, index) => this.paramConcrete(fn, index));
  }

  private paramConcrete(fn: number, index: number): Labels {
    const key = `${fn}:${index}`;
    const cached = this.paramMemo.get(key);

    if (cached) return cached;
    this.paramMemo.set(key, NONE);
    const node = this.fnAt.get(fn);
    const out = new Set<Label>();

    for (const site of node ? (this.callsOf.get(node) ?? []) : []) {
      const args = this.restParams.has(key) ? site.slots.slice(index) : [site.slots[index] ?? null];

      for (const a of args) if (a) for (const l of this.concrete(this.taint(a))) out.add(l);
    }

    this.paramMemo.set(key, out);

    return out;
  }

  /** What a call that reads a file gives: a credential file's contents, what the program wrote there, its own source. */
  private readResult(site: CallSite | undefined): Labels {
    const readAt = site?.roles.indexOf("read") ?? -1;
    const readArg = readAt >= 0 ? site?.slots[readAt] : null;

    if (!readArg) return NONE;
    const out = readOf(this.taint(readArg));

    for (const w of this.written) if (this.samePath({ node: readArg }, w.path)) for (const d of w.data) for (const l of this.taint(d)) out.add(l);

    if (this.isOwnPath(readArg)) out.add(`src:0:${this.host.program.end}`);

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

    if ((site?.network && !this.isAddressLookup(n)) || this.isHttpClient(n) || (n.type === "NewExpression" && refs.some((r) => r.kind === "global" && /^(?:WebSocket|XMLHttpRequest|EventSource)$/.test(r.path)))) {
      out.add("net");
      out.add("conn");
    }

    // what a read gives: a credential file's contents when its path names one, this program when it reads itself
    add(this.readResult(site));

    if (refs.some((r) => r.kind === "global" && r.path === "Deno.env.toObject")) out.add("env");

    // String(fn), fn.toString(), Function.prototype.toString.call(fn): the source text of a function this file defines
    if (refs.some((r) => r.kind === "global" && r.path === "String") && args[0]) add(this.sourceOf(args[0]));

    if (callee.type === "MemberExpression" && callee.object.type !== "Super") {
      const method = this.keyName(callee) ?? "";

      if (method === "toString") add(this.sourceOf(callee.object));

      if ((method === "call" || method === "apply") && this.host.refsOf(callee.object).some((r) => r.kind === "global" && r.path === "Function.prototype.toString") && args[0]) add(this.sourceOf(args[0]));
    }

    const passes = refs.some((r) => (r.kind === "global" && PASS_GLOBALS.has(r.path)) || (r.kind === "module" && PASS_MODULES.has(r.spec)));

    if (passes) add(argsTaint());

    // `new Promise((resolve) => …)`: what resolve is called with
    if (n.type === "NewExpression" && refs.some((r) => r.kind === "global" && r.path === "Promise") && args[0]) add(this.resolvedBy(args[0]));

    const own = this.localFunctions(callee);

    for (const fn of own) add(this.instantiate(this.returnTaint(fn), fn, site, n));

    if (callee.type === "MemberExpression" && callee.object.type !== "Super") {
      const method = this.keyName(callee) ?? "";
      const recv = this.taint(callee.object);

      // a method of a value gives data drawn from it (`res.text()`, `buf.toString('base64')`, `env.map(…)`, `src.slice(…)`);
      // a method this file defines gives what it returns, not everything else its object holds
      if (own.length === 0) {
        const drawn = without(recv, (l) => l === "conn" || (l === "env" && method === "hasOwnProperty"));
        const params = new Set([...drawn].filter((l) => l.startsWith("param:")));

        // a method of a parameter gives data drawn from the argument, but never the environment object whole
        add(without(drawn, (l) => l.startsWith("param:")));

        if (params.size > 0) add(this.memberOf(params, null, NONE));
      }

      if (this.concrete(recv).has("conn") && !WRITES.has(method)) out.add("net");

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

  /**
   * `dns.lookup`, `resolve4`, `resolve6`, `reverse`: what they give is an address or a host name, not text a server
   * wrote, so it is not downloaded data. A TXT or any other record is (`resolveTxt`), and a lookup still sends its name.
   */
  private isAddressLookup(n: CallExpression | NewExpression): boolean {
    if (n.callee.type === "Super") return false;

    return this.host.refsOf(unwrap(n.callee)).some((r) => r.kind === "module" && r.spec === "dns" && /^(?:promises\.)?(?:lookup|lookupService|resolve4|resolve6|reverse)$/.test(r.path));
  }

  private isHttpClient(n: CallExpression | NewExpression): boolean {
    if (n.callee.type === "Super") return false;

    return this.host.refsOf(unwrap(n.callee)).some((r) => r.kind === "module" && HTTP_CLIENTS.has(r.spec));
  }

  // ----- where values end up -----

  private sinks(): Sink[] {
    const out: Sink[] = [];

    const keep = (kind: Sink["kind"], at: number, labels: Labels, relevant: (l: Label) => boolean): void => {
      const list = [...this.concrete(labels)].filter(relevant);

      if (list.length > 0 && out.length < 400) out.push({ kind, at, labels: list });
    };

    const runs = (l: Label): boolean => l === "net" || l === "net-field" || isSymbolic(l);

    for (const site of this.host.calls) {
      const n = site.node;

      if (n.callee.type === "Super") continue;
      const callee = unwrap(n.callee);
      const at = callee.start;
      const request = new Set<Label>();
      // a program that sends what it is given (`curl --data …`): its arguments are a request, not a command
      const program = site.slots[0] ? this.host.str(site.slots[0]) : null;
      const netTool = program?.exact === true && NET_TOOL.test(program.value.trim());

      site.slots.forEach((slot, i) => {
        if (!slot) return;
        const role = site.roles[i];

        if (role === "code") keep("code", at, this.taint(slot), runs);
        else if (role === "shell") {
          const list = unwrap(slot);
          const parts = list.type === "ArrayExpression" ? list.elements.filter((e): e is NonNullable<typeof e> => e !== null).map((e) => (e.type === "SpreadElement" ? e.argument : e)) : [slot];

          // the program's own argument list, or a command line that starts it; never the options object (`{ env }`)
          for (const part of list.type === "ObjectExpression" ? [] : parts) {
            const text = this.host.str(part);

            if ((netTool && i === 1) || (text !== null && NET_TOOL_COMMAND.test(text.value))) for (const l of this.taint(part)) request.add(l);
          }

          if (i > 0) {
            if (this.wholeCommand(site, i)) keep("shell", at, this.taint(slot), runs);
          } else {
            // a helper's parameter is the command each caller passes, judged by how that caller builds it
            const command = this.commandLabels(slot, 0);

            keep("shell", at, command.whole, runs);

            if (this.runsInShell(site)) keep("splice", at, command.part, (l) => l === "net" || isSymbolic(l));
          }
        } else if (role === "read") keep("read", at, this.taint(slot), (l) => l === "cred-path" || isSymbolic(l));
        else if (role === "request") for (const l of this.taint(slot)) request.add(l);
      });

      // a request or connection written to, and every argument of an HTTP client's call, is sent
      const writes = callee.type === "MemberExpression" && callee.object.type !== "Super" && WRITES.has(this.keyName(callee) ?? "") && this.concrete(this.taint(callee.object)).has("conn");

      if (writes || this.isHttpClient(n)) for (const a of n.arguments) for (const l of this.taint(a.type === "SpreadElement" ? a.argument : a)) request.add(l);
      keep("request", at, request, (l) => l === "env" || l === "cred" || l.startsWith("secret:") || isSymbolic(l));

      // a file the program wrote, then loads as code or runs as a program
      for (const t of this.runTargets(site)) this.ranFile(t, at, keep);
    }

    for (const n of this.dynamicImports) if (n.type === "ImportExpression") this.ranFile({ path: { node: n.source }, kind: "js" }, n.start, keep);

    return out;
  }

  /** A sink for a file the program wrote with downloaded data and then runs; written text it runs is read as code. */
  private ranFile(t: RunTarget, at: number, keep: (kind: Sink["kind"], at: number, labels: Labels, relevant: (l: Label) => boolean) => void): void {
    for (const w of this.written) {
      if (!this.samePath(t.path, w.path)) continue;

      for (const d of w.data) {
        keep(t.kind === "js" ? "code" : "file", at, this.taint(d), (l) => l === "net" || l === "net-field" || isSymbolic(l));
        const text = t.kind === "js" ? this.host.str(d) : null;

        if (text?.exact && this.ranWritten.length < 20) this.ranWritten.push({ at: d.start, code: text.value });
      }
    }
  }

  /** Whether two paths name one file: one binding, or one string apm can work out (by its last part at least). */
  private samePath(a: PathRef, b: AnyNode): boolean {
    if ("node" in a) {
      const x = unwrap(a.node);
      const y = unwrap(b);

      if (x.type === "Identifier" && y.type === "Identifier") {
        const bx = this.host.bindingOf(x);
        const by = this.host.bindingOf(y);

        if (bx !== null && bx !== "dynamic" && bx === by) return true;
      }
    }

    const sa = "node" in a ? this.host.str(a.node) : { value: a.text, exact: !a.text.includes(UNKNOWN) };
    const sb = this.host.str(b);

    if (!sa || !sb) return false;
    const pa = normPath(sa.value);
    const pb = normPath(sb.value);

    if (pa === pb && pa.split(UNKNOWN).join("").length > 0) return true;
    const na = baseName(pa);

    return na.length >= 2 && !na.includes(UNKNOWN) && na === baseName(pb);
  }

  /** The files a call runs: what a loader, `fork` or a Worker loads, what an interpreter is given, the program run. */
  private runTargets(site: CallSite): RunTarget[] {
    const n = site.node;

    if (n.callee.type === "Super") return [];
    const refs = this.host.refsOf(unwrap(n.callee));
    const first = site.slots[0] ?? null;

    if (!first) return [];
    const loads = refs.some((r) => (r.kind === "global" && LOADERS.has(r.path)) || (r.kind === "unknown" && r.name === "require" && r.owner === null) || (r.kind === "module" && r.spec === "child_process" && r.path === "fork") || (r.kind === "module" && r.spec === "worker_threads" && r.path === "Worker") || (r.kind === "global" && r.path === "Worker"));

    if (loads) return [{ path: { node: first }, kind: "js" }];

    if (site.roles[0] !== "shell") return [];
    // `spawn(process.execPath, [file])`, `execFile('node', [file])`: the interpreter runs the file it is given
    const prog = this.host.str(first);
    const execPath = this.host.refsOf(first).some((r) => r.kind === "global" && (r.path === "process.execPath" || r.path === "process.argv0" || r.path === "process.argv.0"));

    if (execPath || (prog?.exact === true && NODE_LIKE.test(prog.value.trim()))) {
      const list = site.slots[1] ? unwrap(site.slots[1]) : null;
      const arg = list?.type === "ArrayExpression" ? list.elements.find((e) => e && e.type !== "SpreadElement" && !this.host.str(e)?.value.startsWith("-")) : null;

      return arg && arg.type !== "SpreadElement" ? [{ path: { node: arg }, kind: "js" }] : [];
    }

    // a variable set to one command or another (`let command = ''; … command = `setsid nohup ./npm …``): each of them
    const texts = prog ? [prog] : this.valuesOf(first).flatMap((v) => this.host.str(v) ?? []);
    const out: RunTarget[] = [{ path: { node: first }, kind: "program" }];

    for (const text of texts.slice(0, 8)) {
      // a command line: the program after the words that only start it (`setsid nohup ./agent -c x`)
      const words = text.value.split(/[\s;&|]+/).filter((w) => w.length > 0);
      let i = 0;

      while (i < words.length - 1 && LAUNCH_WORDS.has(baseName(words[i] ?? ""))) i++;
      const word = words[i] ?? "";

      if (NODE_LIKE.test(word)) {
        const file = words.slice(i + 1).find((w) => !w.startsWith("-"));

        if (file) out.push({ path: { text: file }, kind: "js" });
      } else if (word && words.length > 1) out.push({ path: { text: word }, kind: "program" });
    }

    return out;
  }

  /** The values a name is given: its initializer and every assignment to it (a few at most). */
  private valuesOf(n: AnyNode): AnyNode[] {
    const t = unwrap(n);

    if (t.type !== "Identifier") return [];
    const b = this.host.bindingOf(t);

    if (b === null || b === "dynamic") return [];

    return [...(b.origin.kind === "value" && b.origin.init !== t ? [b.origin.init] : []), ...(this.assigns.get(b) ?? [])].slice(0, 8);
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

  /**
   * What a command string carries as the whole command (`exec(body)`) and as part of a longer one (`exec('echo ' +
   * body)`). A parameter of a function this file calls is each call's argument, judged as that argument is built.
   */
  private commandLabels(slot: AnyNode, depth: number): CommandLabels {
    const t = unwrap(slot);
    const b = t.type === "Identifier" ? this.host.bindingOf(t) : null;
    const p = b !== null && b !== "dynamic" ? this.params.get(b) : undefined;
    const calls = p ? (this.callsOf.get(p.fn) ?? []) : [];

    if (p && p.whole && b !== null && b !== "dynamic" && !this.assigns.has(b) && depth < 4 && calls.length > 0 && !this.restParams.has(`${p.fn.start}:${p.index}`)) {
      const whole = new Set<Label>();
      const part = new Set<Label>();

      // what reaches the parameter other than the calls' arguments (a default, a callback's value) is whole
      for (const l of this.concrete(this.paramTaint(p))) whole.add(l);

      for (const c of calls) {
        const arg = c.slots[p.index];

        if (!arg) continue;
        const inner = this.commandLabels(arg, depth + 1);

        for (const l of inner.whole) whole.add(l);

        for (const l of inner.part) part.add(l);
      }

      return { whole, part };
    }

    const s = this.host.str(slot);
    const whole = s === null || (!s.exact && WRAPPER_ONLY.test(s.value.split(UNKNOWN).join("")));
    const labels = this.concrete(this.taint(slot));

    return whole ? { whole: labels, part: NONE } : { whole: NONE, part: labels };
  }

  /** Whether a process call runs its first argument through a shell: `exec`, `execSync`, or `{ shell: true }`. */
  private runsInShell(site: CallSite): boolean {
    const n = site.node;

    if (n.callee.type === "Super") return false;
    const refs = this.host.refsOf(unwrap(n.callee));

    if (refs.some((r) => (r.kind === "module" && r.spec === "child_process" && (r.path === "exec" || r.path === "execSync")) || (r.kind !== "module" && r.kind !== "local" && /(?:^|\.)(?:exec|execSync)$/.test(r.kind === "global" ? r.path : (r.name ?? ""))))) return true;

    return site.slots.some((slot) => {
      const t = slot ? unwrap(slot) : null;

      return t?.type === "ObjectExpression" && t.properties.some((p) => p.type === "Property" && !p.computed && propName(p.key) === "shell" && !(p.value.type === "Literal" && p.value.value === false));
    });
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

        const ranges = [...this.concrete(this.taint(slot))].flatMap((l): [number, number][] => {
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
      for (const l of this.concrete(this.taint(n))) into.add(l);

      for (const fn of n.type === "FunctionDeclaration" ? [n] : this.localFunctions(n)) for (const l of this.concrete(this.returnTaint(fn))) into.add(l);
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
