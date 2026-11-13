// What a value from another file carries (apm-score-v10): the labels a file's flows hold that name a relative import
// (`import:<spec>#<name>`) or a read of a path another file gives (`read:<label>`), worked out over the whole package
// at once. Each export is one node whose labels only grow, so the work is a fixed point over the export graph: a shared
// re-export DAG costs one visit per edge, not one per path through it, and a cycle ends when nothing new arrives. A
// package-wide work budget bounds it; when the budget runs out the caller is told, and reports the analysis incomplete.
import type { Exports, Label } from "./flow.ts";
import { Allowance } from "./meter.ts";

/** How a relative module specifier in one file names another file of the package, or undefined when it names none. */
export type ResolveModule = (fromPath: string, spec: string) => string | undefined;

/** One label as a term of a file: a label as it is, an export of another file, or a read of a path a term gives. */
type Term = { kind: "label"; label: Label } | { kind: "export"; node: string; deeper: boolean } | { kind: "read"; inner: Term };

type ExportNode = { path: string; name: string; terms: Term[] | null; value: Set<Label>; dependents: Set<string> };

/** Steps (one term looked at once) the whole package may spend resolving labels across files. */
export const MAX_CROSS_FILE_STEPS = 2_000_000;

const IMPORT = /^import:(.*)#([^#]*?)(\+?)$/;

/** Thrown inside the resolution when its allowance is spent; `resolve` catches it, so every step stops there. */
class Spent extends Error {}

export class CrossFile {
  private readonly nodes = new Map<string, ExportNode>();
  private readonly pending: string[] = [];
  private readonly steps: Allowance;
  /** Whether the budget ran out: then some labels were not followed to the end. */
  exhausted = false;

  constructor(
    private readonly exportsOf: (path: string) => Exports | undefined,
    private readonly resolveModule: ResolveModule,
    maxSteps: number = MAX_CROSS_FILE_STEPS,
  ) {
    this.steps = new Allowance("cross-file", maxSteps);
  }

  /**
   * What `labels`, found in the file at `path`, carry once every import and read is followed. Once the allowance is
   * spent (here or in an earlier call) nothing more is followed: what it returns is what it had, and `exhausted` says so.
   */
  resolve(path: string, labels: readonly Label[]): Set<Label> {
    const out = new Set<Label>();

    if (this.exhausted) return out;

    try {
      this.step(1 + labels.length);
      const terms = labels.flatMap((l) => this.term(path, l) ?? []);

      this.settle();

      for (const t of terms) {
        const value = this.evaluate(t);

        this.step(value.size);

        for (const l of value) out.add(l);
      }
    } catch (e) {
      if (!(e instanceof Spent)) throw e;
    }

    return out;
  }

  /** Spends `n` steps of the allowance (and so the meter); past it the resolution stops, at this step. */
  private step(n: number): void {
    if (this.steps.take(n)) return;
    this.exhausted = true;
    this.pending.length = 0;

    throw new Spent();
  }

  private nodeKey(path: string, name: string): string {
    return `${path}\u0000${name}`;
  }

  /** The term for one label in one file, creating the export nodes it refers to; null for an import of no file. */
  private term(path: string, l: Label): Term | null {
    // the label is read by a pattern and its module resolved
    this.step(1 + Math.ceil(l.length / 32));

    if (l.startsWith("import:")) {
      // `import:<spec>#<name>`, and `+` for a named member of that export (which is not a credential path)
      const m = IMPORT.exec(l);
      const target = m ? this.resolveModule(path, m[1] ?? "") : undefined;

      if (!m || target === undefined) return null;
      const exports = this.exportsOf(target);
      const name = m[2] ?? "";
      // an export the module names gives its own labels; any other member of the module value is a named member of it
      const own = exports?.get(name);
      const deeper = m[3] === "+" || (own === undefined && name !== "");

      return { kind: "export", node: this.node(target, own === undefined ? "" : name), deeper };
    }

    if (l.startsWith("read:")) {
      const inner = readOf(l);
      const t = inner ? this.term(path, inner) : null;

      return t ? { kind: "read", inner: t } : null;
    }

    return { kind: "label", label: l };
  }

  private node(path: string, name: string): string {
    const key = this.nodeKey(path, name);

    if (this.nodes.has(key)) return key;
    // its terms are built when it is first settled, so a long chain of re-exports never recurses
    this.nodes.set(key, { path, name, terms: null, value: new Set(), dependents: new Set() });
    this.pending.push(key);

    return key;
  }

  /** Recomputes nodes until none changes or the budget runs out. Every value only grows, so this ends. */
  private settle(): void {
    const queued = new Set(this.pending);

    for (let key = this.pending.pop(); key !== undefined; key = this.pending.pop()) {
      queued.delete(key);
      const n = this.nodes.get(key);

      if (!n) continue;
      this.step(1);

      if (n.terms === null) {
        const terms = (this.exportsOf(n.path)?.get(n.name) ?? []).flatMap((l) => this.term(n.path, l) ?? []);

        n.terms = terms;

        for (const t of terms) {
          this.step(1);

          for (const dep of nodesOf(t)) this.nodes.get(dep)?.dependents.add(key);
        }
      }

      const before = n.value.size;

      for (const t of n.terms) {
        const value = this.evaluate(t);

        // every label of the value is looked at to add it
        this.step(value.size);

        for (const l of value) n.value.add(l);
      }

      if (n.value.size === before) continue;
      this.step(n.dependents.size);

      for (const d of n.dependents) {
        if (queued.has(d)) continue;
        queued.add(d);
        this.pending.push(d);
      }
    }
  }

  private evaluate(t: Term): ReadonlySet<Label> {
    this.step(1);

    switch (t.kind) {
      case "label":
        return new Set([t.label]);
      case "export": {
        const value = this.nodes.get(t.node)?.value ?? new Set<Label>();

        if (!t.deeper || !value.has("cred-path")) return value;
        // a copy of the value, less one label
        this.step(value.size);
        const out = new Set(value);

        out.delete("cred-path");

        return out;
      }

      case "read":
        // a read of a path another file gives: a credential file's contents when that path names one
        return this.evaluate(t.inner).has("cred-path") ? new Set<Label>(["cred"]) : new Set<Label>();
      default: {
        const _exhaustive: never = t;

        return _exhaustive;
      }
    }
  }
}

function nodesOf(t: Term): string[] {
  switch (t.kind) {
    case "label":
      return [];
    case "export":
      return [t.node];
    case "read":
      return nodesOf(t.inner);
    default: {
      const _exhaustive: never = t;

      return _exhaustive;
    }
  }
}

/** The label a `read:` label reads, rebuilt so its type is checked; only these can resolve to a credential path. */
function readOf(l: Label): Label | null {
  const inner = l.slice("read:".length);

  if (inner === "cred-path") return "cred-path";

  if (inner.startsWith("import:")) return `import:${inner.slice("import:".length)}`;

  return inner.startsWith("read:") ? `read:${inner.slice("read:".length)}` : null;
}
