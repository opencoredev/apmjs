// The text of a file the analysis reads as binary (a native executable, a native module by name, an image, a font, an
// archive), read with the same text rules a plain file gets. Production (274d284) read a Mach-O as text: `new
// TextDecoder().decode(bytes)`, then every text rule and fact over that string. That caught shell commands in it, but
// the string took two bytes a character (U+FFFD is past one byte), so a 24 MB executable ended the run.
//
// Here the bytes are decoded exactly as production decoded them, by the same UTF-8 decoder run a chunk at a time (a
// streaming decode equals a whole one, a sequence split across chunks included), and kept one byte a UTF-16 code unit:
// every position, length and newline is production's. A code unit up to U+00FF is kept as itself. One past it cannot be
// held in a byte, so it is held as the one-byte character the rules cannot tell from it (round 4 review of 8f4ced8, P1:
// the views folded vertical tab, form feed and Unicode spaces into a non-space mark, and `curl ... |<VT>sh` went
// unread). No rule, fact or import pattern names a character past U+007F, has the `u` flag or a property escape, or
// counts lines by anything but `\n` (rules.ts, facts.ts, textrules.ts, source.ts), so a regex sees only these classes:
// - a JavaScript space past one byte (U+1680, U+2000 to U+200A, U+202F, U+205F, U+3000, U+FEFF): `\s`, not a line
//   end, not `\w`; held as U+00A0, which is all three;
// - a line or paragraph separator (U+2028, U+2029): `\s` and a line end, which `.` does not match and `[^\n]` does;
//   held as `\r`, which is all of those (only lineOf's snippet trims a final `\r`, and lines are counted by `\n`);
// - anything else past one byte, U+FFFD and lone surrogates included: not `\s`, not `\w`, not a line end, matched by
//   `.` and negated classes, never folded to ASCII by `/i`; held as U+00FF, which is all of those.
// So every rule, fact and import matches at the same positions in the view as in production's text. What differs is
// what evidence quotes: a snippet or name shows the stand-in (a line or paragraph separator shows as production showed
// it, ↵). An import path holding a stand-in gets its real characters from the bytes, so it names exactly the file
// production's path named (Merged, exact).
//
// A second view decodes the bytes with every NUL deleted first, as dash does before it reads a line, so `c\0u\0r\0l`
// reads as `curl`. Both are read with every text rule and fact and their results merged. A view longer than
// MAX_VIEW_CHARS is never cut: the file is reported as too large to read. A streamed read holds such a file as production's
// plan held it, and reads it whole here; one it did not hold is not read (score.ts, planReading).
import { factsOf, type Fact } from "./facts.ts";
import { findingKey, MAX_SCAN_TEMP_BYTES, withKeepLimit } from "./kept.ts";
import { chargeText } from "./meter.ts";
import { forgetText, withSeparators, type TextFinding } from "./rules.ts";
import { scanTextRules } from "./textrules.ts";
import type { Imports } from "./js.ts";
import { importParts, importsOf, joinStrings, type ImportParts } from "./source.ts";

/** The longest view read: 32 Mi code units, one byte each (lib/tsc of the macOS typescript builds is 23 to 27 MB). */
export const MAX_VIEW_CHARS = 32 * 1024 * 1024;

/** What a code unit past U+00FF is held as: the one-byte character the rules cannot tell from it. */
export const STAND_IN = { space: 0xa0, lineEnd: 0x0d, other: 0xff } as const;

/** JavaScript's white space past one byte (ECMA-262 WhiteSpace: USP and ZWNBSP), less the line terminators. */
const WIDE_SPACE = new Set([0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x202f, 0x205f, 0x3000, 0xfeff]);

/** The one-byte character a UTF-16 code unit is held as: itself up to U+00FF, else the stand-in of its class. */
export function heldAs(unit: number): number {
  if (unit <= 0xff) return unit;

  if (unit === 0x2028 || unit === 0x2029) return STAND_IN.lineEnd;

  return WIDE_SPACE.has(unit) ? STAND_IN.space : STAND_IN.other;
}

/** `text` as a view holds it: every code unit past U+00FF replaced by its stand-in. */
export function asView(text: string): string {
  let out = "";
  let from = 0;

  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);

    if (unit <= 0xff) continue;
    out += text.slice(from, i) + String.fromCharCode(heldAs(unit));
    from = i + 1;
  }

  return from === 0 ? text : out + text.slice(from);
}

/** What reading a file's text came to: what the rules found in it and the paths it imports, or that it was too large. */
export type BinaryTextScan =
  | {
      readonly kind: "read";
      /** What the production view found: production's reading of the file, finding for finding and fact for fact. */
      readonly findings: readonly TextFinding[];
      readonly facts: readonly Fact[];
      /**
       * What the NUL-deleted view found that the production view did not (`c\0u\0r\0l`, as dash reads it), apart: the
       * analysis may only add to what production's reading concludes from it, never change it (score.ts, round 14 review
       * of e2b3b8e, P1: a distant dump the second view found took the place of a nearby harvest, and exfiltration went).
       */
      readonly extraFindings: readonly TextFinding[];
      readonly extraFacts: readonly Fact[];
      /** What the production view imports, as production's plain reader found it: its paths, which of them load code, and the loads it computes (round 6 review of fbc6738, P1: the loads were dropped). */
      readonly imports: Imports;
      /**
       * Its reading did not finish (kept.ts): past what it may keep it kept only findings of signals not kept yet, and
       * no more imports, or a list it builds while reading, or the stack, ran out and it stopped. What it found counts;
       * the analysis says it did not finish (`incomplete`), so the install verdict holds it (round 12 review of 7cd0b2b).
       */
      readonly stopped: boolean;
      /**
       * A load in the production view names a path holding a stand-in whose real characters the bytes could not give
       * (one built by joining pieces): which file production's exact path loaded is not known, so the reading did not
       * finish (round 15 review of c139b5b).
       */
      readonly unresolved: boolean;
    }
  | { readonly kind: "too-large"; readonly bytes: number };

/** One view being built: a UTF-8 decoder kept across chunks, and the one-byte text it has decoded. */
class View {
  readonly decoder = new TextDecoder();
  buf = new Uint8Array(0);
  length = 0;
  // where a line or paragraph separator sits, held as `\r`: a snippet shows it as production's did (rules.ts)
  readonly separators: number[] = [];
}

/** The view's text as a string of one-byte characters. */
function latin1(v: View): string {
  return Buffer.from(v.buf.buffer, v.buf.byteOffset, v.length).toString("latin1");
}

/** `chunk` with its NUL bytes deleted, or `chunk` itself when it has none. */
function withoutNul(chunk: Uint8Array): Uint8Array {
  if (!chunk.includes(0)) return chunk;
  const out = new Uint8Array(chunk.length);
  let n = 0;

  for (const b of chunk) if (b !== 0) out[n++] = b;

  return out.subarray(0, n);
}

/** One view of a file, built as its bytes arrive: the production view, or the NUL-deleted one. */
class Views {
  private readonly production: View | null;
  private readonly shell: View | null;
  private tooLarge = false;
  private bytes = 0;

  constructor(which: "production" | "shell", capacity = 0) {
    this.production = which === "shell" ? null : new View();
    this.shell = which === "production" ? null : new View();

    // a file held whole: its views are never longer than its bytes, so each is sized once
    if (capacity > 0 && capacity <= MAX_VIEW_CHARS) for (const v of [this.production, this.shell]) if (v !== null) v.buf = new Uint8Array(capacity);
  }

  push(chunk: Uint8Array): void {
    chargeText("text", chunk.length, 2);
    this.bytes += chunk.length;

    if (this.tooLarge) return;

    if (this.production !== null) this.decode(this.production, chunk, false);

    if (this.shell !== null && !this.tooLarge) this.decode(this.shell, withoutNul(chunk), false);
  }

  /** Each view's text, decoders flushed (a sequence cut off at the end is U+FFFD, as in a whole decode), or too large. */
  finish(): { production: string | null; shell: string | null; separators: { production: readonly number[]; shell: readonly number[] } } | null {
    if (this.production !== null && !this.tooLarge) this.decode(this.production, new Uint8Array(0), true);

    if (this.shell !== null && !this.tooLarge) this.decode(this.shell, new Uint8Array(0), true);

    if (this.tooLarge) return null;

    const out = {
      production: this.production === null ? null : latin1(this.production),
      shell: this.shell === null ? null : latin1(this.shell),
      separators: { production: this.production?.separators ?? [], shell: this.shell?.separators ?? [] },
    };

    this.drop();

    return out;
  }

  get size(): number {
    return this.bytes;
  }

  get refused(): boolean {
    return this.tooLarge;
  }

  private decode(v: View, bytes: Uint8Array, last: boolean): void {
    const text = last ? v.decoder.decode() : v.decoder.decode(bytes, { stream: true });

    if (!this.room(v, text.length)) {
      this.tooLarge = true;
      this.drop();

      return;
    }

    for (let i = 0; i < text.length; i++) {
      const unit = text.charCodeAt(i);

      if (unit === 0x2028 || unit === 0x2029) v.separators.push(v.length);
      v.buf[v.length++] = heldAs(unit);
    }
  }

  /** Grows `v` to take `more` units; false when that passes MAX_VIEW_CHARS. */
  private room(v: View, more: number): boolean {
    const need = v.length + more;

    if (need <= v.buf.length) return true;

    if (need > MAX_VIEW_CHARS) return false;
    const size = Math.min(MAX_VIEW_CHARS, Math.max(need, v.buf.length * 2, 64 * 1024));
    const next = new Uint8Array(size);
    next.set(v.buf.subarray(0, v.length));
    v.buf = next;

    return true;
  }

  /** Lets the views go; what follows is only counted. */
  private drop(): void {
    for (const v of [this.production, this.shell]) if (v !== null) v.buf = new Uint8Array(0);
  }
}

/**
 * The most binaries' views may add to an analysis's result, by keptBytes, all together; each view's reading is charged
 * against what is left as it finds its results (kept.ts). Past it a view keeps only findings of signals it has not kept,
 * and the analysis says the reading did not finish (memory review of 49b35f9, P1: 500 views of 131 KiB each, counted
 * past the budget, ended a Worker; round 12 review of 7cd0b2b: dropping a view's findings there raised its score).
 */
export const MAX_KEPT_VIEW_BYTES = 8 * 1024 * 1024;

/**
 * About how many bytes a read's results take while kept: two a character of each string they hold and a little more an
 * item. What the analysis keeps of a view until its walks are done is held to a budget by it (score.ts): 500 binaries
 * of 2,800 imports each kept whole ended a Worker (round 7 review of dce1655, P1).
 */
export function keptBytes(read: { readonly findings: readonly TextFinding[]; readonly facts: readonly Fact[]; readonly imports?: Imports }): number {
  const strings = (xs: readonly string[]): number => xs.reduce((n, x) => n + 32 + 2 * x.length, 0);
  const items = (xs: readonly object[]): number => xs.reduce((n, x) => n + 64 + 2 * JSON.stringify(x).length, 0);

  return items(read.findings) + items(read.facts) + (read.imports === undefined ? 0 : strings(read.imports.paths) + strings(read.imports.loads) + items(read.imports.dynamic));
}

/**
 * One file's views read into a Merged under a limit of `maxKept` bytes for its results and MAX_SCAN_TEMP_BYTES for each
 * list it builds while reading (kept.ts; round 10 review of c558aff, P1: 60,000 lines of `'child_'+'process';` made
 * 240,000 findings, cloned whole, before any limit was checked, and ended the isolate). What it found is kept however
 * it ended, and a reading that did not finish says so (`stopped`): it is never dropped to come in under a budget (round
 * 12 review of 7cd0b2b: dropping that file's findings raised 65 (C) complete to 100 (P), which installs).
 */
function limited(maxKept: number, data: Uint8Array, read: (merged: Merged) => void): BinaryTextScan {
  const merged = new Merged(data);

  try {
    const outcome = withKeepLimit(Math.max(0, maxKept), MAX_SCAN_TEMP_BYTES, () => read(merged));

    return merged.result(outcome.saturated || outcome.stopped);
  } catch (e) {
    // a pass that ran out of stack (a pattern over a 32 MiB text, round 11 review of ee69d23) stopped the reading: what
    // the passes before it found counts, and the analysis goes on
    if (e instanceof RangeError) return merged.result(true);
    throw e;
  }
}

/** `s` copied out of the string it was sliced from: V8 keeps a whole view alive behind a slice of it. */
const own = (s: string): string => structuredClone(s);

/** A binary's two views read: the production view's findings and facts as production's, and what the NUL-deleted view adds, apart. */
class Merged {
  constructor(private readonly data: Uint8Array) {}

  private unresolved = false;
  private readonly findings: TextFinding[] = [];
  private readonly facts: Fact[] = [];
  private readonly extraFindings: TextFinding[] = [];
  private readonly extraFacts: Fact[] = [];
  // what the production view found, by line and what it says to the scorer, and its facts: the NUL-deleted view's are
  // kept apart, and only where the production view has nothing like them (display only: the analysis scores production's
  // findings on their own, and adds only what these add)
  private readonly saidFindings = new Set<string>();
  private readonly seenFacts = new Set<string>();
  private imports: Imports = { paths: [], loads: [], dynamic: [] };

  /**
   * Reads `text` with every text rule and fact; the production view's imports (as a plain file's are read) go too. Each
   * result is charged as the reading finds it (kept.ts), and each one kept is copied out of the view as it is taken:
   * V8 keeps a whole string alive behind a slice of it, and a view is megabytes.
   */
  add(text: string, production: boolean, separators: readonly number[] = []): void {
    withSeparators(text, separators, () => this.read(text, production));
  }

  /** Reads only the production view's imports, as `add` reads them, and nothing else. */
  addImports(text: string, separators: readonly number[] = []): void {
    withSeparators(text, separators, () => {
      let joined: string | null = null;

      try {
        const join = joinStrings(text);

        joined = join.text;
        const imports = this.exact(importsOf(joined), join.text, join.origin);
        this.imports = { paths: imports.paths.map(own), loads: imports.loads.map(own), dynamic: imports.dynamic.map((d) => structuredClone(d)) };
      } finally {
        forgetText(text);

        if (joined !== null) forgetText(joined);
      }
    });
  }

  private read(text: string, production: boolean): void {
    let joined: string | null = null;

    try {
      // the production view's findings and facts are production's reading of the file, every one, as it gave them
      for (const f of scanTextRules(text)) {
        const said = `${f.line}\u0000${findingKey(f)}`;

        if (production) {
          this.saidFindings.add(said);
          this.findings.push(structuredClone(f));
        } else if (!this.saidFindings.has(said)) {
          this.saidFindings.add(said);
          this.extraFindings.push(structuredClone(f));
        }
      }

      for (const f of factsOf(text)) {
        const key = `${f.kind} ${f.line} ${f.name ?? ""} ${f.near} ${f.text}`;

        if (production) {
          this.seenFacts.add(key);
          this.facts.push(structuredClone(f));
        } else if (!this.seenFacts.has(key)) {
          this.seenFacts.add(key);
          this.extraFacts.push(structuredClone(f));
        }
      }

      if (production) {
        const join = joinStrings(text);

        joined = join.text;
        const imports = this.exact(importsOf(joined), join.text, join.origin);
        this.imports = { paths: imports.paths.map(own), loads: imports.loads.map(own), dynamic: imports.dynamic.map((d) => structuredClone(d)) };
      }
    } finally {
      // the joined copy's line index too (importsOf places a computed load in it): kept, it held a 23 MB copy of
      // lib/tsc's text in the line cache after the read was done (round 10)
      forgetText(text);

      if (joined !== null) forgetText(joined);
    }
  }

  /**
   * `imports` as production's text held them: a path holding a stand-in (STAND_IN) gets the real characters the bytes
   * hold where the view does, so it names exactly the file production's path named, never every file it could stand for
   * (round 15 review of c139b5b, P1: `require('./t字')` matched lib/t漢 by its stand-in, which production's exact path did
   * not, and lib/t漢 was read as JavaScript where production read it as plain text). A path the joining built from
   * pieces is not one span of the view: it is not known, and the reading did not finish (unresolved).
   */
  private exact(imports: Imports, joinedText: string, origin: (index: number) => number): Imports {
    const held = (p: string): boolean => /[\u00a0\r\u00ff]/.test(p);

    if (!imports.paths.some(held)) return imports;
    const parts = importParts(joinedText);

    if (parts.length !== imports.paths.length) {
      this.unresolved = true;

      return imports;
    }

    // each span of the joined text that holds a stand-in, as a span of the view: one the joining did not touch
    const spans: [number, number][] = [];

    const wanted: (ImportParts | null)[] = parts.map((ps, i) => {
      if (!held(imports.paths[i] ?? "")) return null;

      for (const p of ps) {
        if (p.kind === "text") continue;

        const start = origin(p.start);

        for (let k = 1; k < p.end - p.start; k++) if (origin(p.start + k) !== start + k) return [];

        spans.push([start, start + (p.end - p.start)]);
      }

      return ps;
    });

    if (wanted.some((w) => w !== null && w.length === 0)) {
      this.unresolved = true;

      return imports;
    }

    const real = decodeSpans(this.data, spans);
    let next = 0;

    const paths = imports.paths.map((path, i) => {
      const ps = wanted[i];

      if (ps === null || ps === undefined) return path;

      return ps.map((p) => (p.kind === "text" ? p.text : (real[next++] ?? ""))).join("");
    });


    // the loads are the static paths, listed first (importsOf)
    const loads = paths.slice(0, imports.loads.length);

    return { paths, loads, dynamic: imports.dynamic };
  }

  result(stopped: boolean): BinaryTextScan {
    return { kind: "read", findings: this.findings, facts: this.facts, extraFindings: this.extraFindings, extraFacts: this.extraFacts, imports: this.imports, stopped, unresolved: this.unresolved };
  }
}

/**
 * The text production's decoder gave `data` at each of `spans` (code-unit offsets, which are the view's), in their
 * order: one streaming pass, as the view was decoded, keeping only what the spans cover.
 */
function decodeSpans(data: Uint8Array, spans: readonly (readonly [number, number])[]): string[] {
  const out = spans.map(() => "");
  const decoder = new TextDecoder();
  let at = 0;

  const take = (text: string): void => {
    spans.forEach(([start, end], i) => {
      if (end <= at || start >= at + text.length) return;
      out[i] += text.slice(Math.max(0, start - at), Math.min(text.length, end - at));
    });
    at += text.length;
  };

  chargeText("text", data.length, 1);

  for (let i = 0; i < data.length; i += HELD_CHUNK) take(decoder.decode(data.subarray(i, i + HELD_CHUNK), { stream: true }));
  take(decoder.decode());

  return out;
}

/** How much of a file held whole is decoded at a time, so a view grows with its text, not with a copy of the file. */
const HELD_CHUNK = 64 * 1024;

/**
 * One view of a file whose bytes arrive as `chunks`: the production view (`nulDeleted` false) or the NUL-deleted one,
 * or null when it is too large. `capacity`, when the file's size is known, sizes the view once.
 */
export function decodeView(chunks: Iterable<Uint8Array>, nulDeleted = false, capacity = 0): string | null {
  return viewWithSeparators(chunks, nulDeleted, capacity)?.text ?? null;
}

/** decodeView, and where the view holds a line or paragraph separator. */
function viewWithSeparators(chunks: Iterable<Uint8Array>, nulDeleted: boolean, capacity: number): { text: string; separators: readonly number[] } | null {
  const which = nulDeleted ? "shell" : "production";
  const views = new Views(which, capacity);

  for (const chunk of chunks) {
    views.push(chunk);

    if (views.refused) return null;
  }

  const texts = views.finish();
  const text = texts === null ? null : nulDeleted ? texts.shell : texts.production;

  return texts === null || text === null ? null : { text, separators: nulDeleted ? texts.separators.shell : texts.separators.production };
}

/** `data` a HELD_CHUNK at a time. */
function* heldChunks(data: Uint8Array): Generator<Uint8Array> {
  for (let at = 0; at < data.length; at += HELD_CHUNK) yield data.subarray(at, at + HELD_CHUNK);
}

/** One view of a file held whole, decoded a chunk at a time, or null when it is too large. */
function viewOf(data: Uint8Array, which: "production" | "shell"): { text: string; separators: readonly number[] } | null {
  return viewWithSeparators(heldChunks(data), which === "shell", data.length);
}

/**
 * The imports of a file's production view alone, read as scanBinaryText reads them, with no findings or facts: for
 * production's floor walk (score.ts, readLikeV3), which reads the imports of a file it reaches again, as production
 * read them again from its text, after the first walk read the file through its views and let its imports go.
 */
export function scanBinaryImports(data: Uint8Array): BinaryTextScan {
  let tooLarge = false;

  const scan = limited(MAX_KEPT_VIEW_BYTES, data, (merged) => {
    const production = viewOf(data, "production");

    if (production === null) {
      tooLarge = true;

      return;
    }

    merged.addImports(production.text, production.separators);
  });

  return tooLarge ? { kind: "too-large", bytes: data.length } : scan;
}

/**
 * binaryText over a file held whole. The views are built and read one after the other, so only one is held at a time
 * beside the file: 24 MB of a 24 MB lib/tsc, not 48. The NUL-deleted view is read only when the file has a NUL byte;
 * without one it is the production view.
 */
export function scanBinaryText(data: Uint8Array, maxKept: number = MAX_KEPT_VIEW_BYTES): BinaryTextScan {
  let tooLarge = false;

  const scan = limited(maxKept, data, (merged) => {
    let production = viewOf(data, "production");

    if (production === null) {
      tooLarge = true;

      return;
    }

    merged.add(production.text, true, production.separators);
    // let go before the second view is built
    production = null;

    if (data.includes(0)) {
      const shell = viewOf(data, "shell");

      if (shell === null) {
        tooLarge = true;

        return;
      }

      merged.add(shell.text, false, shell.separators);
    }
  });

  return tooLarge ? { kind: "too-large", bytes: data.length } : scan;
}
