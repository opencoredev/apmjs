// Reads an npm packument from a byte stream without holding it whole. vite's full packument is 39 MB of JSON, 35 MB of
// it the `licenseText` each of its 769 versions repeats; read with res.text() and JSON.parse, it took more than the
// Worker's 128 MB and the platform ended the page request that asked for it (exceededMemory).
//
// The reader is a validating JSON scanner: it checks the whole grammar byte by byte, the regions it discards included,
// and accepts exactly what JSON.parse accepts of the text res.text() would give (a leading byte order mark is skipped,
// as the UTF-8 decode does). It keeps only the parts a profile names (KeepProfile): TRIMMED, what the registry reads,
// is the top-level fields in TOP_FIELDS and each version's document without the fields in DROPPED_VERSION_FIELDS.
// Each kept part is parsed on its own with JSON.parse, and duplicate keys resolve as JSON.parse resolves them: the last
// one wins, a second `versions` object included.
//
// What it holds is bounded, and each bound is checked before the memory it guards is taken:
// - maxBytes: bytes read. Reading costs CPU, not memory.
// - maxKeptBytes: the text of the kept parts, the copies it holds until it parses them.
// - maxKeptNodes: values and keys inside the kept parts, and the entries it builds around them: the parsed objects
//   cost memory per node, not per byte (`[[[[]]]]` is 8 bytes of text and 4 arrays).
// - maxDepth: open containers anywhere, discarded ones included. Each costs one byte of a stack that grows to at most
//   this; nothing else is allocated for a container it discards.
// - budget (optional): kept bytes shared with every other read of one request (KeptBudget), so a walk that reads
//   several packuments at once holds no more than it allows in all.
// A packument past any of them is refused as too-large, never held.
import { z } from "zod";

/** Top-level packument fields the registry reads (upstream.ts, UpPackument); everything else is skipped. */
const TOP_FIELDS: ReadonlySet<string> = new Set(["name", "dist-tags", "versions", "time", "description", "readme", "maintainers"]);

/**
 * Version fields never kept for the registry's own reads, because no install, page or score reads them from the
 * packument:
 * - licenseText, readme and readmeFilename: text a full document may repeat in every version (vite: 35 MB of its 39).
 *   npm's abbreviated packument has none of them; a version's readme is shown from its tarball, the package's from
 *   the top-level field. They are left out of every packument apm serves (docs: HTTP API, npm compatibility).
 * - devDependencies: 17 MB of next's 31 MB. npm, pnpm, yarn and bun install a registry dependency's dependencies,
 *   optional and peer dependencies, never its devDependencies, and the scorer reads the tarball's own package.json.
 *   The full packument apm serves (`Accept: application/json`, which `npm view` asks for) reads them separately
 *   (DEV_DEPENDENCIES), so the registry's own reads stay small.
 */
export const DROPPED_VERSION_FIELDS: ReadonlySet<string> = new Set(["licenseText", "readme", "readmeFilename", "devDependencies"]);

/**
 * What a read keeps. `top`: the top-level fields kept; `versions` among them is read into, one version document at a
 * time. `fields`: which fields of each version document are kept, all but some or only some. `otherVersions`: whether a
 * `versions` entry that is not an object (no real packument has one) is kept as it is.
 */
export type KeepProfile = {
  readonly top: ReadonlySet<string>;
  readonly fields: { readonly kind: "except" | "only"; readonly names: ReadonlySet<string> };
  readonly otherVersions: boolean;
};

/** What the registry reads: what JSON.parse gives, minus the top-level fields it never reads and DROPPED_VERSION_FIELDS. */
export const TRIMMED: KeepProfile = { top: TOP_FIELDS, fields: { kind: "except", names: DROPPED_VERSION_FIELDS }, otherVersions: true };

/** Only each version's devDependencies: what the full packument adds back to TRIMMED. */
export const DEV_DEPENDENCIES: KeepProfile = { top: new Set(["versions"]), fields: { kind: "only", names: new Set(["devDependencies"]) }, otherVersions: false };

/** The most of a packument read before it is refused: reading costs CPU, not memory, so this is well past any real one. */
export const MAX_PACKUMENT_BYTES = 160 * 1024 * 1024;

/** The most of a packument kept, as JSON text, before it is refused: what is kept is held parsed. */
export const MAX_KEPT_PACKUMENT_BYTES = 24 * 1024 * 1024;

/**
 * The most values and keys kept from one packument. next keeps 15 MB in 0.8 million nodes, typescript 11 MB in 0.55
 * million, and next's devDependencies alone (DEV_DEPENDENCIES) 17.5 MB in 1.2 million: real packuments reach the kept
 * bytes cap first. Parsed, a node costs V8 16 to 40 bytes beside its text, so a packument built to be cheap as text
 * and dear as objects (`[[],[],...]`) is refused here, at most about 50 MB of objects, before it is parsed.
 */
export const MAX_KEPT_PACKUMENT_NODES = 1_500_000;

/**
 * The deepest nesting read, discarded regions included. Each open container costs one byte, so this is 100 KB at
 * most. A real version document nests a few levels; one built to nest 50,000 levels deep is still read, and served
 * without the field past the limits apm reads (deep-packument.test.ts).
 */
export const MAX_PACKUMENT_DEPTH = 100_000;

export type PackumentLimits = { readonly maxBytes: number; readonly maxKeptBytes: number; readonly maxKeptNodes: number; readonly maxDepth: number };

export const PACKUMENT_LIMITS: PackumentLimits = {
  maxBytes: MAX_PACKUMENT_BYTES,
  maxKeptBytes: MAX_KEPT_PACKUMENT_BYTES,
  maxKeptNodes: MAX_KEPT_PACKUMENT_NODES,
  maxDepth: MAX_PACKUMENT_DEPTH,
};

/**
 * Kept bytes several reads share: one request's walk, say, that reads packuments a few at once and holds every one
 * until it answers. Each read takes from it as it keeps, gives back what it took if it is refused, and leaves what it
 * took taken when it succeeds (the caller holds that packument now). Single-threaded, so reads in flight together
 * see each other's takes. A lease (`lease()`) takes through its parent and gives all it took back at once, for a
 * caller that holds a packument only for a while (one package of a scan).
 */
export class KeptBudget {
  private used = 0;
  readonly limit: number;
  private readonly parent: KeptBudget | null;

  constructor(limit: number, parent: KeptBudget | null = null) {
    this.limit = limit;
    this.parent = parent;
  }

  /** Takes `n` bytes, or nothing and false when that would pass this budget's limit or its parent's. */
  take(n: number): boolean {
    if (this.used + n > this.limit) return false;

    if (this.parent && !this.parent.take(n)) return false;
    this.used += n;

    return true;
  }

  give(n: number): void {
    const back = Math.min(n, this.used);
    this.used -= back;
    this.parent?.give(back);
  }

  /** A budget that takes from this one, with no limit of its own; release() gives back everything it took. */
  lease(): KeptBudget & { release: () => void } {
    const leased = new KeptBudget(Number.POSITIVE_INFINITY, this);

    return Object.assign(leased, { release: () => leased.give(leased.taken) });
  }

  get taken(): number {
    return this.used;
  }

  /** Nothing more fits: a read would be refused at its first kept byte. */
  get exhausted(): boolean {
    return this.used >= this.limit || (this.parent?.exhausted ?? false);
  }
}

/** Which bound a refused packument passed. */
export type TooLargeOver = "read" | "kept" | "nodes" | "depth" | "budget";

/**
 * What reading a packument came to. "ok": the kept fields, as one object. "too-large": it passed a bound (`over`) at
 * `bytes` (or nodes, or levels) of `limit`. "invalid": not JSON, or JSON that is not an object.
 */
export type PackumentRead =
  | { kind: "ok"; body: KeptPackument; bytes: number; keptBytes: number; keptNodes: number }
  | { kind: "too-large"; over: TooLargeOver; bytes: number; limit: number }
  | { kind: "invalid"; reason: string };

/** A JSON value, as JSON.parse gives it. */
export type JsonValue = string | number | boolean | null | readonly JsonValue[] | { readonly [key: string]: JsonValue };

/** What readPackument keeps: the kept top-level fields, and `versions` with each kept version document. */
export type KeptPackument = { readonly [field: string]: JsonValue };

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COLON = 0x3a;
const COMMA = 0x2c;
const OPEN_OBJECT = 0x7b;
const CLOSE_OBJECT = 0x7d;
const OPEN_ARRAY = 0x5b;
const CLOSE_ARRAY = 0x5d;
const MINUS = 0x2d;
const PLUS = 0x2b;
const DOT = 0x2e;
const ZERO = 0x30;
const NINE = 0x39;

const OBJECT = 1;
const ARRAY = 2;

// Where the scanner is. A value: S_VALUE. After `[`: a value or `]`. After `{`: a key or `}`. After `,` in an object:
// a key. After a key: `:`. After a value: `,`, a close, or (the root closed) the end.
const S_VALUE = 0;
const S_VALUE_OR_CLOSE = 1;
const S_KEY_OR_CLOSE = 2;
const S_KEY = 3;
const S_COLON = 4;
const S_AFTER = 5;
const S_STRING = 6;
const S_ESCAPE = 7;
const S_HEX = 8;
const S_NUMBER = 9;
const S_LITERAL = 10;
const S_DONE = 11;
const S_BOM = 12;

// Inside a number: -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
const N_MINUS = 0;
const N_ZERO = 1;
const N_INT = 2;
const N_DOT = 3;
const N_FRACTION = 4;
const N_E = 5;
const N_E_SIGN = 6;
const N_EXPONENT = 7;

const BOM = [0xef, 0xbb, 0xbf] as const;
const TRUE = [0x74, 0x72, 0x75, 0x65] as const;
const FALSE = [0x66, 0x61, 0x6c, 0x73, 0x65] as const;
const NULL = [0x6e, 0x75, 0x6c, 0x6c] as const;

/** The escapes JSON allows after a backslash: " \ / b f n r t, and u with four hex digits. */
const isEscape = (b: number): boolean => b === QUOTE || b === BACKSLASH || b === 0x2f || b === 0x62 || b === 0x66 || b === 0x6e || b === 0x72 || b === 0x74;

const isHex = (b: number): boolean => (b >= ZERO && b <= NINE) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);

const isDigit = (b: number): boolean => b >= ZERO && b <= NINE;

const isSpace = (b: number): boolean => b === 0x20 || b === 0x0a || b === 0x0d || b === 0x09;

/** A value being kept: its bytes so far, where it goes once it ends, and the depth it started at. */
type Capture = { readonly depth: number; readonly into: "top" | "version" | "field" | "key"; readonly name: string; readonly parts: Uint8Array[]; from: number };

class InvalidPackument extends Error {}

class TooLarge extends Error {
  readonly over: TooLargeOver;
  readonly bytes: number;
  readonly limit: number;

  constructor(input: { over: TooLargeOver; bytes: number; limit: number }) {
    super(`packument over ${input.limit} (${input.over})`);
    this.over = input.over;
    this.bytes = input.bytes;
    this.limit = input.limit;
  }
}

const decoder = new TextDecoder();

function joined(parts: readonly Uint8Array[]): string {
  if (parts.length === 1 && parts[0]) return decoder.decode(parts[0]);
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;

  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }

  return decoder.decode(all);
}

function parsed(text: string): JsonValue {
  try {
    // JSON.parse of text only ever gives a JSON value; a schema would walk all of it again
    const value: JsonValue = JSON.parse(text);

    return value;
  } catch {
    // the scanner has checked this text's grammar already, so this is not expected
    throw new InvalidPackument("a kept value is not JSON");
  }
}

class Scanner {
  private state = S_BOM;
  /** The open containers, one byte each (OBJECT or ARRAY); grown on demand, never past maxDepth. */
  private kinds = new Uint8Array(64);
  private depth = 0;
  /** In a string: whether it is an object key. In S_HEX: hex digits still to come. In S_LITERAL: the literal and how far. */
  private stringIsKey = false;
  private hexLeft = 0;
  private literal: readonly number[] = TRUE;
  private literalAt = 0;
  private numberState = N_MINUS;
  private capture: Capture | null = null;
  /** The key of the member being read at the root, in `versions`, and in a version document. */
  private rootKey: string | null = null;
  private versionKey: string | null = null;
  private fieldKey: string | null = null;
  /** Whether the container at depth 2 is the `versions` object, and the one at depth 3 a version document read into. */
  private inVersions = false;
  private inVersion = false;
  private readonly top: [string, JsonValue][] = [];
  private versions: [string, JsonValue][] = [];
  private fields: [string, JsonValue][] = [];
  bytes = 0;
  keptBytes = 0;
  keptNodes = 0;
  /** What this read took from the shared budget, given back if it is refused. */
  taken = 0;

  private readonly limits: PackumentLimits;
  private readonly profile: KeepProfile;
  private readonly budget: KeptBudget | null;

  constructor(input: { limits: PackumentLimits; profile: KeepProfile; budget: KeptBudget | null }) {
    this.limits = input.limits;
    this.profile = input.profile;
    this.budget = input.budget;
  }

  feed(chunk: Uint8Array): void {
    this.bytes += chunk.length;

    if (this.bytes > this.limits.maxBytes) throw new TooLarge({ over: "read", bytes: this.bytes, limit: this.limits.maxBytes });
    const n = chunk.length;

    for (let i = 0; i < n; i++) {
      let b = chunk[i] ?? 0;

      switch (this.state) {
        case S_STRING: {
          // the common case, read in a tight loop: bytes that are neither a quote, a backslash nor a control character
          while (b !== QUOTE && b !== BACKSLASH && b >= 0x20) {
            i++;

            if (i >= n) break;
            b = chunk[i] ?? 0;
          }

          if (i >= n) break;

          if (b === QUOTE) this.stringEnded(chunk, i);
          else if (b === BACKSLASH) this.state = S_ESCAPE;
          else throw new InvalidPackument("a control character in a string");

          break;
        }

        case S_ESCAPE:
          if (b === 0x75) {
            this.state = S_HEX;
            this.hexLeft = 4;
          } else if (isEscape(b)) this.state = S_STRING;
          else throw new InvalidPackument("an invalid escape in a string");

          break;
        case S_HEX:
          if (!isHex(b)) throw new InvalidPackument("an invalid \\u escape in a string");
          this.hexLeft--;

          if (this.hexLeft === 0) this.state = S_STRING;

          break;
        case S_NUMBER:
          if (this.number(b)) break;
          // the byte after a number is read as what follows a value
          this.numberEnded(chunk, i);
          this.after(chunk, i, b);

          break;
        case S_LITERAL:
          if (b !== this.literal[this.literalAt]) throw new InvalidPackument("an invalid literal");
          this.literalAt++;

          if (this.literalAt === this.literal.length) {
            this.state = S_AFTER;
            this.valueEnded(chunk, i + 1);
          }

          break;
        case S_BOM: {
          // the byte order mark the UTF-8 decode of res.text() skips, at the very start only
          const offset = this.bytes - n + i;

          if (offset < BOM.length && b === BOM[offset]) break;

          if (offset > 0 && offset < BOM.length) throw new InvalidPackument("a broken byte order mark");
          this.state = S_VALUE;
          this.value(i, b);

          break;
        }

        case S_VALUE:
          this.value(i, b);

          break;
        case S_VALUE_OR_CLOSE:
          if (b === CLOSE_ARRAY) this.close(chunk, i, ARRAY);
          else this.value(i, b);

          break;
        case S_KEY_OR_CLOSE:
          if (b === CLOSE_OBJECT) this.close(chunk, i, OBJECT);
          else this.key(i, b);

          break;
        case S_KEY:
          this.key(i, b);

          break;
        case S_COLON:
          if (b === COLON) this.state = S_VALUE;
          else if (!isSpace(b)) throw new InvalidPackument("expected a colon after a key");

          break;
        case S_AFTER:
          this.after(chunk, i, b);

          break;
        case S_DONE:
          if (!isSpace(b)) throw new InvalidPackument("text after the packument");

          break;
        default:
          throw new InvalidPackument("unknown scanner state");
      }
    }

    // a value still being kept continues in the next chunk
    if (this.capture) {
      this.keep(chunk.subarray(this.capture.from));
      this.capture.from = 0;
    }
  }

  finish(): KeptPackument {
    if (this.state === S_BOM && this.bytes === 0) throw new InvalidPackument("the packument is empty");

    if (this.state !== S_DONE) throw new InvalidPackument("the packument ends early");

    return Object.fromEntries(this.top);
  }

  /** A value starts with byte `b` at `at`. */
  private value(at: number, b: number): void {
    if (isSpace(b)) return;

    if (b === QUOTE) {
      this.valueStarted(at, null);
      this.stringIsKey = false;
      this.state = S_STRING;
    } else if (b === OPEN_OBJECT || b === OPEN_ARRAY) {
      const kind = b === OPEN_OBJECT ? OBJECT : ARRAY;
      this.valueStarted(at, kind);
      this.open(kind);
    } else if (b === MINUS || isDigit(b)) {
      this.valueStarted(at, null);
      this.numberState = b === MINUS ? N_MINUS : b === ZERO ? N_ZERO : N_INT;
      this.state = S_NUMBER;
    } else if (b === TRUE[0] || b === FALSE[0] || b === NULL[0]) {
      this.valueStarted(at, null);
      this.literal = b === TRUE[0] ? TRUE : b === FALSE[0] ? FALSE : NULL;
      this.literalAt = 1;
      this.state = S_LITERAL;
    } else throw new InvalidPackument("expected a value");
  }

  /** A key's opening quote, or a byte where one must be. */
  private key(at: number, b: number): void {
    if (isSpace(b)) return;

    if (b !== QUOTE) throw new InvalidPackument("expected a key");
    this.stringIsKey = true;
    this.state = S_STRING;

    if (this.capture) {
      this.node();

      return;
    }

    // keys matter only where the reader decides what to keep
    if (this.depth === 1 || (this.depth === 2 && this.inVersions) || (this.depth === 3 && this.inVersion)) {
      this.capture = { depth: this.depth, into: "key", name: "", parts: [], from: at };
    }
  }

  /** What follows a value: a comma, a close, or nothing more once the root closed. */
  private after(chunk: Uint8Array, at: number, b: number): void {
    if (isSpace(b)) return;
    const kind = this.kinds[this.depth - 1];

    if (b === COMMA) {
      if (kind === OBJECT) this.state = S_KEY;
      else if (kind === ARRAY) this.state = S_VALUE;
      else throw new InvalidPackument("a comma outside a container");
    } else if (b === CLOSE_OBJECT) this.close(chunk, at, OBJECT);
    else if (b === CLOSE_ARRAY) this.close(chunk, at, ARRAY);
    else throw new InvalidPackument("expected a comma or a close");
  }

  /** Whether byte `b` continues the number; false when the number ended before it (it must have ended validly). */
  private number(b: number): boolean {
    const digit = isDigit(b);

    switch (this.numberState) {
      case N_MINUS:
        if (!digit) throw new InvalidPackument("a minus sign with no digits");
        this.numberState = b === ZERO ? N_ZERO : N_INT;

        return true;
      case N_ZERO:
        if (b === DOT) this.numberState = N_DOT;
        else if (b === 0x65 || b === 0x45) this.numberState = N_E;
        else return false;

        return true;
      case N_INT:
        if (digit) return true;

        if (b === DOT) this.numberState = N_DOT;
        else if (b === 0x65 || b === 0x45) this.numberState = N_E;
        else return false;

        return true;
      case N_DOT:
        if (!digit) throw new InvalidPackument("a decimal point with no digits after it");
        this.numberState = N_FRACTION;

        return true;
      case N_FRACTION:
        if (digit) return true;

        if (b === 0x65 || b === 0x45) {
          this.numberState = N_E;

          return true;
        }

        return false;
      case N_E:
        if (b === PLUS || b === MINUS) this.numberState = N_E_SIGN;
        else if (digit) this.numberState = N_EXPONENT;
        else throw new InvalidPackument("an exponent with no digits");

        return true;
      case N_E_SIGN:
        if (!digit) throw new InvalidPackument("an exponent with no digits");
        this.numberState = N_EXPONENT;

        return true;
      case N_EXPONENT:
        return digit;
      default:
        throw new InvalidPackument("unknown number state");
    }
  }

  private numberEnded(chunk: Uint8Array, end: number): void {
    this.state = S_AFTER;
    this.valueEnded(chunk, end);
  }

  private stringEnded(chunk: Uint8Array, quoteAt: number): void {
    if (this.stringIsKey) {
      this.state = S_COLON;
      const c = this.capture;

      if (!c || c.into !== "key" || c.depth !== this.depth) return;
      this.keep(chunk.subarray(c.from, quoteAt + 1));
      this.capture = null;
      const key = z.string().safeParse(parsed(joined(c.parts)));

      if (!key.success) throw new InvalidPackument("a key that is not a string");

      if (this.depth === 1) this.rootKey = key.data;
      else if (this.depth === 2) this.versionKey = key.data;
      else this.fieldKey = key.data;

      return;
    }

    this.state = S_AFTER;
    this.valueEnded(chunk, quoteAt + 1);
  }

  private open(kind: number): void {
    if (this.depth >= this.limits.maxDepth) throw new TooLarge({ over: "depth", bytes: this.depth + 1, limit: this.limits.maxDepth });

    if (this.depth >= this.kinds.length) {
      const grown = new Uint8Array(Math.min(this.kinds.length * 2, this.limits.maxDepth));
      grown.set(this.kinds);
      this.kinds = grown;
    }

    this.kinds[this.depth] = kind;
    this.depth++;
    this.state = kind === OBJECT ? S_KEY_OR_CLOSE : S_VALUE_OR_CLOSE;
  }

  private close(chunk: Uint8Array, at: number, kind: number): void {
    if (this.depth === 0 || this.kinds[this.depth - 1] !== kind) throw new InvalidPackument("unbalanced brackets");
    this.depth--;

    if (this.depth === 0) {
      this.state = S_DONE;

      return;
    }

    this.state = S_AFTER;

    if (this.depth === 2 && this.inVersion) {
      this.inVersion = false;
      this.entry(this.versions, this.versionKey, Object.fromEntries(this.fields));
      this.fields = [];

      return;
    }

    if (this.depth === 1 && this.inVersions) {
      this.inVersions = false;
      this.entry(this.top, "versions", Object.fromEntries(this.versions));
      this.versions = [];

      return;
    }

    this.valueEnded(chunk, at + 1);
  }

  /** One more node kept: a value or key inside a kept part, or an entry around one. */
  private node(): void {
    this.keptNodes++;

    if (this.keptNodes > this.limits.maxKeptNodes) throw new TooLarge({ over: "nodes", bytes: this.keptNodes, limit: this.limits.maxKeptNodes });
  }

  private entry(into: [string, JsonValue][], key: string | null, value: JsonValue): void {
    if (key === null) throw new InvalidPackument("a member with no key");
    this.node();
    into.push([key, value]);
  }

  private keep(part: Uint8Array): void {
    if (part.length === 0) return;
    this.keptBytes += part.length;

    if (this.keptBytes > this.limits.maxKeptBytes) throw new TooLarge({ over: "kept", bytes: this.keptBytes, limit: this.limits.maxKeptBytes });

    if (this.budget) {
      if (!this.budget.take(part.length)) throw new TooLarge({ over: "budget", bytes: this.budget.taken + part.length, limit: this.budget.limit });
      this.taken += part.length;
    }

    // a copy: the chunk's buffer is the stream's, and is reused or released after this read
    this.capture?.parts.push(part.slice());
  }

  /**
   * What a value starting here is for: kept, skipped, or (`versions` or a version document) read into. `kind` is the
   * container it opens, null for a string, number or literal.
   */
  private valueStarted(at: number, kind: number | null): void {
    if (this.capture) {
      this.node();

      return;
    }

    const opensObject = kind === OBJECT;

    switch (this.depth) {
      case 0:
        if (!opensObject) throw new InvalidPackument("not a JSON object");

        return;
      case 1: {
        const key = this.rootKey;

        if (key === null || !this.profile.top.has(key)) return;

        if (key === "versions" && opensObject) {
          // a second `versions` replaces the first, as in JSON.parse
          this.inVersions = true;
          this.versions = [];

          return;
        }

        this.startCapture({ at, into: "top", name: key });

        return;
      }

      case 2:
        if (!this.inVersions) return;

        if (opensObject) {
          this.inVersion = true;
          this.fields = [];

          return;
        }

        if (this.profile.otherVersions && this.versionKey !== null) this.startCapture({ at, into: "version", name: this.versionKey });

        return;
      case 3: {
        const key = this.fieldKey;

        if (!this.inVersion || key === null) return;
        const listed = this.profile.fields.names.has(key);

        if (this.profile.fields.kind === "except" ? !listed : listed) this.startCapture({ at, into: "field", name: key });

        return;
      }

      default:
    }
  }

  private startCapture(input: { at: number; into: "top" | "version" | "field"; name: string }): void {
    this.node();
    this.capture = { depth: this.depth, into: input.into, name: input.name, parts: [], from: input.at };
  }

  /** A value ended just before `end`, at the current depth: if it was being kept, it is parsed and put in place. */
  private valueEnded(chunk: Uint8Array, end: number): void {
    const c = this.capture;

    if (!c || c.depth !== this.depth || c.into === "key") return;
    this.keep(chunk.subarray(c.from, end));
    this.capture = null;
    const value = parsed(joined(c.parts));

    switch (c.into) {
      case "top":
        this.top.push([c.name, value]);

        break;
      case "version":
        this.versions.push([c.name, value]);

        break;
      case "field":
        this.fields.push([c.name, value]);

        break;
      default: {
        const _exhaustive: never = c.into;

        return _exhaustive;
      }
    }
  }
}

export type ReadOptions = { readonly limits?: PackumentLimits; readonly profile?: KeepProfile; readonly budget?: KeptBudget | null };

/**
 * Reads a packument's body under `limits`, keeping what `profile` names (TRIMMED by default), and taking what it keeps
 * from `budget` when one is given. Cancels the stream when it stops early.
 */
export async function readPackument(body: ReadableStream<Uint8Array>, options: ReadOptions = {}): Promise<PackumentRead> {
  const scanner = new Scanner({ limits: options.limits ?? PACKUMENT_LIMITS, profile: options.profile ?? TRIMMED, budget: options.budget ?? null });
  const reader = body.getReader();

  try {
    for (;;) {
      const { done, value } = await reader.read();

      if (done) break;
      scanner.feed(value);
    }

    return { kind: "ok", body: scanner.finish(), bytes: scanner.bytes, keptBytes: scanner.keptBytes, keptNodes: scanner.keptNodes };
  } catch (e) {
    // given back before anything awaits, so reads in flight with this one see the room at once
    options.budget?.give(scanner.taken);
    await reader.cancel().catch(() => undefined);

    if (e instanceof TooLarge) return { kind: "too-large", over: e.over, bytes: e.bytes, limit: e.limit };

    if (e instanceof InvalidPackument) return { kind: "invalid", reason: e.message };
    throw e;
  } finally {
    reader.releaseLock();
  }
}
