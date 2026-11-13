// Reads an npm packument from a byte stream without holding it whole. vite's full packument is 39 MB of JSON, 35 MB of
// it the `licenseText` each of its 769 versions repeats; read with res.text() and JSON.parse, it took more than the
// Worker's 128 MB and the platform ended the page request that asked for it (exceededMemory).
//
// The reader is a validating JSON scanner: it checks the whole grammar byte by byte, the regions it discards included,
// and accepts exactly what JSON.parse accepts of the text res.text() would give (a leading byte order mark is skipped,
// as the UTF-8 decode does). It keeps only the parts a profile names (KeepProfile): TRIMMED, what the registry reads,
// is the top-level fields in TOP_FIELDS and each version's document without the fields in DROPPED_VERSION_FIELDS.
// Each kept part is parsed on its own with JSON.parse, and duplicate keys resolve as JSON.parse resolves them: the last
// one wins, a second `versions` object included, and a version a profile does not keep removes an earlier one.
//
// What it holds is bounded, and each bound is checked before the memory it guards is taken:
// - maxBytes: bytes read. Reading costs CPU, not memory.
// - maxKeptBytes: the text of the kept parts, the copies it holds until it parses them.
// - maxKeptNodes: values and keys inside the kept parts, and the entries it builds around them.
// - maxWeight: what the kept parts cost once parsed, as an upper bound on V8's heap (WEIGHTS), the moment of each parse
//   included. Parsed, a value costs memory per node, not per byte: `[[],[],...]` is 3 bytes of text and 20 bytes of
//   heap an array, and objects whose keys come in ever new orders cost V8 a new hidden class each.
// - maxDepth: open containers anywhere, discarded ones included. Each costs nine bytes of stacks that grow to at most
//   this; nothing else is allocated for a container it discards.
// - lease: weight taken from the isolate's memory pool (memory.ts) through the request's lease, so a walk that reads
//   several packuments at once, and every request beside it, hold no more than the pool allows in all. Required: no
//   read happens outside a lease.
// A packument past any of them is refused as too-large, never held. The text it keeps is copied into fixed-size slabs
// (SLAB_BYTES), so what it allocates for a kept part depends on the part's length, never on how many pieces the
// stream delivered it in.
import { z } from "zod";
import type { Lease } from "./memory.ts";

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

/**
 * What JSON.stringify writes for a number, at most ("-1.7976931348623157e+308"): what a number of one digit may grow to
 * when the kept value is serialized again.
 */
const NUMBER_CHARS = 24;

/** The most of a packument read before it is refused: reading costs CPU, not memory, so this is well past any real one. */
export const MAX_PACKUMENT_BYTES = 160 * 1024 * 1024;

/** The most of a packument kept, as JSON text, before it is refused: what is kept is held parsed. */
export const MAX_KEPT_PACKUMENT_BYTES = 24 * 1024 * 1024;

/**
 * The most values and keys kept from one packument. Of the real packuments the reader is checked against, next keeps
 * the most: 0.80 million under TRIMMED, and 1.18 million for its devDependencies alone (DEV_DEPENDENCIES). This bounds
 * the reader's work; the memory a node costs is charged as weight (MAX_PACKUMENT_WEIGHT).
 */
export const MAX_KEPT_PACKUMENT_NODES = 1_500_000;

/**
 * The most one packument may weigh (WEIGHTS): an upper bound on the heap it is held in once parsed, each parse's
 * moment included. In MiB, with the heap workerd holds it in: next 24.5 under TRIMMED (13.4), @types/node 19.6 (12.9),
 * typescript 18.6 (11.4), and next's devDependencies 32.0 (16.9), the most of any real one.
 */
export const MAX_PACKUMENT_WEIGHT = 48 * 1024 * 1024;

/**
 * The deepest nesting read, discarded regions included. Each open container costs nine bytes of the scanner's stacks
 * (its kind, and the hidden class and member count of an object JSON.parse will build), so this is 900 KB at most. A
 * real version document nests a few levels; one built to nest 50,000 levels deep is still read, and served without
 * the field past the limits apm reads (deep-packument.test.ts).
 */
export const MAX_PACKUMENT_DEPTH = 100_000;

export type PackumentLimits = { readonly maxBytes: number; readonly maxKeptBytes: number; readonly maxKeptNodes: number; readonly maxWeight: number; readonly maxDepth: number };

export const PACKUMENT_LIMITS: PackumentLimits = {
  maxBytes: MAX_PACKUMENT_BYTES,
  maxKeptBytes: MAX_KEPT_PACKUMENT_BYTES,
  maxKeptNodes: MAX_KEPT_PACKUMENT_NODES,
  maxWeight: MAX_PACKUMENT_WEIGHT,
  maxDepth: MAX_PACKUMENT_DEPTH,
};

/**
 * What a kept part is charged, in bytes, as an upper bound on what V8 holds it in. Measured in workerd
 * (packument-heap.workerd.test.ts), after a full GC, against the shapes that cost it most for their text:
 * - text: each byte of a kept part while it is held as text, until it is parsed. Once parsed, each byte of a string's
 *   content, twice for a string with a character past U+00FF (V8 holds it two bytes a character). Quotes, commas and
 *   the keys of an object whose hidden class was seen cost nothing parsed.
 * - parse: each byte of a kept part twice more while it is parsed. Held text, the parsed value (charged as it was read)
 *   and this cover what a parse holds at once: the slabs and their joined copy, the joined copy and its decoded
 *   string (two bytes a character at most), or that string and the value parsed from it.
 * - value: a string, number, true, false or null inside a kept part (a short string: 24 bytes of heap; a number V8
 *   boxes, 16).
 * - container: an array or object inside a kept part, or one the reader builds (an empty array: 20 bytes; an empty
 *   object, 32).
 * - key: a member of a kept object, or of one the reader builds: a slot. dictKey: a member of an object with dictAt
 *   members or more, which V8 keeps as a dictionary (an entry of three slots, at half load at most: 52 bytes of heap a
 *   member whose value is `{}`, against 32 below dictAt).
 * - hiddenClass: the first object, in this read, whose keys up to some member come in that order. V8 gives each such order
 *   a hidden class of its own: `[{"k0":0},{"k1":0},...]` is 112 bytes of heap an object, and a version whose only
 *   field has a name of its own 125. The key's text is charged with it. Orders are told apart by a hash of their key
 *   bytes, seeded per read, and the set of hashes is charged here too.
 * Real packuments weigh 1.5 to 1.9 times their heap under TRIMMED (MAX_PACKUMENT_WEIGHT).
 */
export const WEIGHTS = { text: 1, parse: 2, value: 20, container: 40, key: 8, dictKey: 28, dictAt: 128, hiddenClass: 128 } as const;

/** What the `count`th member of an object adds to its weight: past dictAt, the members before it become entries too. */
function memberWeight(count: number): number {
  if (count < WEIGHTS.dictAt) return WEIGHTS.key;

  if (count > WEIGHTS.dictAt) return WEIGHTS.dictKey;

  return WEIGHTS.dictKey + (WEIGHTS.dictAt - 1) * (WEIGHTS.dictKey - WEIGHTS.key);
}

/** The size of the slabs kept text is copied into. */
export const SLAB_BYTES = 64 * 1024;

/**
 * What a read holds while it runs whatever it keeps, taken from its lease for as long as it runs: its slabs (the one
 * being filled and a spare), the network chunk it is reading, its stacks and the stream around it. Measured in
 * workerd through the Upstream layer: 144 KiB a read in flight (memory-pool.workerd.test.ts).
 */
export const READ_OVERHEAD_WEIGHT = 192 * 1024;

/** Which bound a refused packument passed. */
export type TooLargeOver = "read" | "kept" | "nodes" | "weight" | "depth" | "budget";

/**
 * What reading a packument came to. "ok": the kept fields, as one object, and what it weighs (WEIGHTS; what it holds
 * now, the parses' moments left out). `versionCount`: the entries of its `versions`; `versionDocs`: the part of the
 * weight that is the version documents' own objects and members, what a shallow copy of each would weigh.
 * `maxPieceChars`: the most characters JSON.stringify writes for one member of the kept packument (a top-level field
 * with its key, or one `versions` entry with its key): what serializing it a member at a time holds at once.
 * "too-large": it passed a bound (`over`) at `bytes` (or nodes, or levels, or weight) of `limit`. "invalid": not JSON,
 * or JSON that is not an object.
 */
export type PackumentRead =
  | { kind: "ok"; body: KeptPackument; bytes: number; keptBytes: number; keptNodes: number; weight: number; versionCount: number; versionDocs: number; maxPieceChars: number }
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

/**
 * A value being kept: where it goes once it ends, and the depth it started at. Its bytes so far are in the slabs;
 * `bytes` and `numbers` count its text and the numbers in it, which bound what JSON.stringify writes for it.
 */
type Capture = { readonly depth: number; readonly into: "top" | "version" | "field" | "key"; readonly name: string; from: number; bytes: number; numbers: number };

/**
 * The key of a member the reader decides about, once read: its text, or IGNORED when it is longer than any name the
 * profile keeps there, so it was never built as a string.
 */
const IGNORED: unique symbol = Symbol("ignored");

type DecisionKey = string | typeof IGNORED | null;

/** The most bytes a key naming one of `names` can take as JSON text: each character a six-byte \u escape, and quotes. */
const rawKeyMax = (names: ReadonlySet<string>): number => 2 + 6 * Math.max(0, ...[...names].map((n) => n.length));

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

/**
 * The text of the part being kept, copied into slabs of SLAB_BYTES as it arrives: a part delivered a byte at a time
 * takes as many slabs as one delivered whole. take() lets the slabs go once the part is decoded, and keeps one for the
 * next part, so a read of many small parts allocates one slab.
 */
class Slabs {
  private full: Uint8Array[] = [];
  private current: Uint8Array | null = null;
  private used = 0;
  private spare: Uint8Array | null = null;
  /** Bytes appended since the last take(). */
  length = 0;

  append(part: Uint8Array): void {
    let from = 0;

    while (from < part.length) {
      let slab = this.current;

      if (!slab || this.used === SLAB_BYTES) {
        if (slab) this.full.push(slab);
        slab = this.spare ?? new Uint8Array(SLAB_BYTES);
        this.spare = null;
        this.current = slab;
        this.used = 0;
      }

      const n = Math.min(SLAB_BYTES - this.used, part.length - from);
      slab.set(part.subarray(from, from + n), this.used);
      this.used += n;
      from += n;
    }

    this.length += part.length;
  }

  /** Lets the bytes appended since the last take() go without decoding them. */
  discard(): void {
    if (this.current) this.spare = this.current;
    this.full = [];
    this.current = null;
    this.used = 0;
    this.length = 0;
  }

  /** The bytes appended since the last call, as text. */
  take(): string {
    const { full, current, used, length } = this;
    this.full = [];
    this.current = null;
    this.used = 0;
    this.length = 0;

    if (!current) return "";
    // the slab still being filled is the next part's: the text is decoded from it before anything is appended
    this.spare = current;

    if (full.length === 0) return decoder.decode(current.subarray(0, used));
    const all = new Uint8Array(length);
    let at = 0;

    for (const slab of full) {
      all.set(slab, at);
      at += slab.length;
    }

    all.set(current.subarray(0, used), at);
    // the full slabs go before the text is decoded, so they, the joined copy and the text are never held at once
    full.length = 0;

    return decoder.decode(all);
  }
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

const FNV_PRIME = 0x01000193;

/** `h` continued with the UTF-16 code units of `s`: the hidden classes of the objects the reader builds itself. */
function hashString(h: number, s: string): number {
  let out = h;

  for (let i = 0; i < s.length; i++) out = Math.imul(out ^ s.charCodeAt(i), FNV_PRIME);

  return Math.imul(out ^ QUOTE, FNV_PRIME);
}

/** The value of one hex digit (isHex has checked it is one). */
const hexValue = (b: number): number => (b <= NINE ? b - ZERO : (b | 0x20) - 0x61 + 10);

/** Weight is taken from the shared budget in steps of about this much, and always before a parse. */
const FLUSH_WEIGHT = 64 * 1024;

/** A version entry a later occurrence of its key removed (a profile that does not keep it). */
const DROPPED: unique symbol = Symbol("dropped");

type Versions = Map<string, JsonValue | typeof DROPPED>;

function* live(versions: Versions): Generator<[string, JsonValue]> {
  for (const [key, value] of versions) if (value !== DROPPED) yield [key, value];
}

class Scanner {
  private state = S_BOM;
  /** The open containers, one byte each (OBJECT or ARRAY); grown on demand with the stacks beside it, never past maxDepth. */
  private kinds = new Uint8Array(64);
  /** For an object inside a kept part, the hidden class its keys so far give it (WEIGHTS) and its members so far. */
  private classOf = new Int32Array(64);
  private members = new Int32Array(64);
  private depth = 0;
  /** In a string: whether it is an object key. In S_HEX: hex digits still to come. In S_LITERAL: the literal and how far. */
  private stringIsKey = false;
  private hexLeft = 0;
  private hex = 0;
  private literal: readonly number[] = TRUE;
  private literalAt = 0;
  private numberState = N_MINUS;
  private capture: Capture | null = null;
  private readonly slabs = new Slabs();
  /** Where in the stream this chunk starts, and the string being read does. */
  private base = 0;
  private stringStart = 0;
  /** The string being read has a character past U+00FF (V8 holds it two bytes a character). */
  private wide = false;
  /** The string being read is a key inside a kept part: its bytes are hashed into keyHash. */
  private hashing = false;
  private keyHash = 0;
  /** Hidden classes seen in this read, as 30-bit hashes, and the seed that makes them unguessable. */
  private readonly classes = new Set<number>();
  private readonly seed: number;
  /** The hidden classes of the objects the reader builds: the root, the `versions` object and the version document. */
  private topClass: number;
  private versionsClass: number;
  private fieldsClass: number;
  /**
   * The key of the member being read at the root, in `versions`, and in a version document, as long as the reader holds
   * it: each is charged (heldKeys, by depth) from when it is built until the next key at its depth replaces it. Its
   * text's length is kept (keyBytes) for maxPieceChars.
   */
  private rootKey: DecisionKey = null;
  private versionKey: string | null = null;
  private fieldKey: DecisionKey = null;
  private readonly heldKeys = [0, 0, 0, 0];
  /**
   * The charge of keys put in what the reader builds (adoptKey): the root's members until the read ends, `versions`'
   * until it closes (its Map, then the object made from it), and a version document's until it closes.
   */
  private topKeys = 0;
  private versionKeys = 0;
  private docKeys = 0;
  private readonly keyBytes = [0, 0, 0, 0];
  /** The decision key being read: the most bytes it may take before it is known to name nothing kept, and whether it did. */
  private keyLimit = Number.POSITIVE_INFINITY;
  private keyOverlong = false;
  private readonly topKeyMax: number;
  private readonly fieldKeyMax: number;
  /** What JSON.stringify writes for the version document being read, at most; and for any one member, at most. */
  private docChars = 0;
  maxPieceChars = 0;
  /** Whether the container at depth 2 is the `versions` object, and the one at depth 3 a version document read into. */
  private inVersions = false;
  private inVersion = false;
  private readonly top: [string, JsonValue][] = [];
  private versions: Versions = new Map();
  private fields: [string, JsonValue][] = [];
  bytes = 0;
  keptBytes = 0;
  keptNodes = 0;
  weight = 0;
  versionCount = 0;
  versionDocs = 0;
  /** The objects and members of the version documents built so far in this `versions`, and in this document. */
  private docsWeight = 0;
  private docWeight = 0;
  /** Weight charged and not yet taken from the shared budget. */
  private pending = 0;
  /** What this read took from its lease, given back if it is refused. */
  taken = 0;

  private readonly limits: PackumentLimits;
  private readonly profile: KeepProfile;
  private readonly lease: Lease;

  constructor(input: { limits: PackumentLimits; profile: KeepProfile; lease: Lease }) {
    this.limits = input.limits;
    this.profile = input.profile;
    this.lease = input.lease;
    this.topKeyMax = rawKeyMax(input.profile.top);
    this.fieldKeyMax = input.profile.fields.kind === "only" ? rawKeyMax(input.profile.fields.names) : Number.POSITIVE_INFINITY;
    this.seed = crypto.getRandomValues(new Uint32Array(1))[0] ?? 0x811c9dc5;
    this.topClass = this.seed;
    this.versionsClass = this.seed;
    this.fieldsClass = this.seed;
  }

  feed(chunk: Uint8Array): void {
    this.bytes += chunk.length;

    if (this.bytes > this.limits.maxBytes) throw new TooLarge({ over: "read", bytes: this.bytes, limit: this.limits.maxBytes });
    const n = chunk.length;
    this.base = this.bytes - n;

    for (let i = 0; i < n; i++) {
      let b = chunk[i] ?? 0;

      switch (this.state) {
        case S_STRING: {
          if (this.capture === null) {
            // the common case, read in a tight loop: bytes that are neither a quote, a backslash nor a control character
            while (b !== QUOTE && b !== BACKSLASH && b >= 0x20) {
              i++;

              if (i >= n) break;
              b = chunk[i] ?? 0;
            }
          } else {
            // kept: any byte past ASCII may make the string two bytes a character, so it is charged so. A lead byte
            // from 0xc4 starts a character past U+00FF, and a byte that is not valid UTF-8 decodes to U+FFFD, which is
            // too (review of 6862fc7, finding 2). A key's bytes are hashed for its hidden class.
            while (b !== QUOTE && b !== BACKSLASH && b >= 0x20) {
              if (b >= 0x80) this.wide = true;

              if (this.hashing) this.keyHash = Math.imul(this.keyHash ^ b, FNV_PRIME);
              i++;

              if (i >= n) break;
              b = chunk[i] ?? 0;
            }
          }

          if (i >= n) break;

          if (b === QUOTE) this.stringEnded(chunk, i);
          else if (b === BACKSLASH) {
            this.hashByte(b);
            this.state = S_ESCAPE;
          } else throw new InvalidPackument("a control character in a string");

          break;
        }

        case S_ESCAPE:
          this.hashByte(b);

          if (b === 0x75) {
            this.state = S_HEX;
            this.hexLeft = 4;
            this.hex = 0;
          } else if (isEscape(b)) this.state = S_STRING;
          else throw new InvalidPackument("an invalid escape in a string");

          break;
        case S_HEX:
          if (!isHex(b)) throw new InvalidPackument("an invalid \\u escape in a string");
          this.hashByte(b);
          this.hex = this.hex * 16 + hexValue(b);
          this.hexLeft--;

          if (this.hexLeft === 0) {
            if (this.hex > 0xff) this.wide = true;
            this.state = S_STRING;
          }

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
          const offset = this.base + i;

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

    this.flush();
  }

  finish(): KeptPackument {
    if (this.state === S_BOM && this.bytes === 0) throw new InvalidPackument("the packument is empty");

    if (this.state !== S_DONE) throw new InvalidPackument("the packument ends early");

    const kept = Object.fromEntries(this.top);

    // the keys the reader held go with it
    for (let d = 1; d < this.heldKeys.length; d++) this.holdKey(d, 0);
    this.charge(-this.topKeys);
    this.topKeys = 0;
    this.flush();

    return kept;
  }

  private hashByte(b: number): void {
    if (this.hashing) this.keyHash = Math.imul(this.keyHash ^ b, FNV_PRIME);
  }

  /** A string starts at `at`: a key when `isKey`. */
  private stringStarted(at: number, isKey: boolean): void {
    this.stringIsKey = isKey;
    this.stringStart = this.base + at;
    this.wide = false;
    this.state = S_STRING;
  }

  /** A value starts with byte `b` at `at`. */
  private value(at: number, b: number): void {
    if (isSpace(b)) return;

    if (b === QUOTE) {
      this.valueStarted(at, null);
      this.stringStarted(at, false);
    } else if (b === OPEN_OBJECT || b === OPEN_ARRAY) {
      const kind = b === OPEN_OBJECT ? OBJECT : ARRAY;
      this.valueStarted(at, kind);
      this.open(kind);
    } else if (b === MINUS || isDigit(b)) {
      this.valueStarted(at, null);

      if (this.capture) this.capture.numbers++;
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
    this.stringStarted(at, true);

    if (this.capture) {
      // a member of an object JSON.parse builds: its key, and the hidden class its keys so far give the object
      this.node();
      const count = (this.members[this.depth - 1] ?? 0) + 1;
      this.members[this.depth - 1] = count;
      this.charge(memberWeight(count));
      this.hashing = true;
      this.keyHash = this.seed;

      return;
    }

    // keys matter only where the reader decides what to keep. At the root, and in a version document a profile keeps
    // only some fields of, a key is only compared with the names kept there: one longer than any of them can be is
    // not built at all (review of 6862fc7, finding 1)
    if (this.depth === 1 || (this.depth === 2 && this.inVersions) || (this.depth === 3 && this.inVersion)) {
      this.keyLimit = this.keyLimitAt(this.depth);
      this.keyOverlong = false;
      this.capture = { depth: this.depth, into: "key", name: "", from: at, bytes: 0, numbers: 0 };
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
    const c = this.capture;
    // a string inside a kept part, as V8 will hold it: its content, two bytes an input byte when wide
    const content = c && c.into !== "key" ? (this.base + quoteAt - 1 - this.stringStart) * (this.wide ? 2 : 1) * WEIGHTS.text : 0;

    if (this.stringIsKey) {
      this.state = S_COLON;

      if (this.hashing) {
        this.hashing = false;

        // a key is held once for every object of its hidden class
        if (this.keyed(this.depth - 1, Math.imul(this.keyHash ^ QUOTE, FNV_PRIME))) this.charge(content);
      }

      if (!c || c.into !== "key" || c.depth !== this.depth) return;
      this.keep(chunk.subarray(c.from, quoteAt + 1));
      this.capture = null;
      const raw = this.base + quoteAt + 1 - this.stringStart;
      this.keyBytes[this.depth] = raw;

      if (this.keyOverlong) {
        // longer than any name kept here: skipped without ever being a string
        this.keyOverlong = false;
        this.holdKey(this.depth, 0);

        if (this.depth === 1) this.rootKey = IGNORED;
        else this.fieldKey = IGNORED;

        return;
      }

      const wide = this.wide;
      const key = z.string().safeParse(this.parseKept());

      if (!key.success) throw new InvalidPackument("a key that is not a string");
      // held until the next key at this depth replaces it: as V8 holds it, at most two bytes an input byte
      this.holdKey(this.depth, raw * (wide ? 2 : 1) * WEIGHTS.text);

      if (this.depth === 1) this.rootKey = key.data;
      else if (this.depth === 2) this.versionKey = key.data;
      else this.fieldKey = key.data;

      return;
    }

    this.charge(content);
    this.state = S_AFTER;
    this.valueEnded(chunk, quoteAt + 1);
  }

  /** The most bytes a decision key at `depth` may take before it is known to name nothing the profile keeps there. */
  private keyLimitAt(depth: number): number {
    if (depth === 1) return this.topKeyMax;

    if (depth === 3) return this.fieldKeyMax;

    // a version's key is always kept
    return Number.POSITIVE_INFINITY;
  }

  /** The key held at `depth` now weighs `weight`: what the one it replaces was charged is given back. */
  private holdKey(depth: number, weight: number): void {
    const was = this.heldKeys[depth] ?? 0;
    this.heldKeys[depth] = weight;
    this.charge(weight - was);
  }

  /** The key held at `depth` is put in something the reader builds: its charge moves with it (topKeys and the rest). */
  private adoptKey(depth: number): number {
    const weight = this.heldKeys[depth] ?? 0;
    this.heldKeys[depth] = 0;

    return weight;
  }

  /** One member of the kept packument writes at most `chars` characters as JSON (maxPieceChars). */
  private piece(chars: number): void {
    if (chars > this.maxPieceChars) this.maxPieceChars = chars;
  }

  /** What JSON.stringify writes for a kept value at most: its text, and every number in it at its longest. */
  private static valueChars(c: Capture): number {
    return c.bytes + NUMBER_CHARS * c.numbers;
  }

  /** The object at `level` of the stack has one more key, hashed `keyHash`: whether that makes a new hidden class. */
  private keyed(level: number, keyHash: number): boolean {
    const next = Math.imul((this.classOf[level] ?? 0) ^ keyHash, FNV_PRIME);
    this.classOf[level] = next;

    return this.newClass(next);
  }

  /** Whether `hiddenClass` is new in this read; a new one is charged. */
  private newClass(hiddenClass: number): boolean {
    const key = hiddenClass >>> 2;

    if (this.classes.has(key)) return false;
    this.classes.add(key);
    this.charge(WEIGHTS.hiddenClass);

    return true;
  }

  private open(kind: number): void {
    if (this.depth >= this.limits.maxDepth) throw new TooLarge({ over: "depth", bytes: this.depth + 1, limit: this.limits.maxDepth });

    if (this.depth >= this.kinds.length) {
      const size = Math.min(this.kinds.length * 2, this.limits.maxDepth);
      const kinds = new Uint8Array(size);
      kinds.set(this.kinds);
      this.kinds = kinds;
      const classes = new Int32Array(size);
      classes.set(this.classOf);
      this.classOf = classes;
      const members = new Int32Array(size);
      members.set(this.members);
      this.members = members;
    }

    this.kinds[this.depth] = kind;
    // an object JSON.parse builds starts with no keys
    this.classOf[this.depth] = this.seed;
    this.members[this.depth] = 0;
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
      const key = this.versionKey;

      if (key === null) throw new InvalidPackument("a member with no key");
      // the version document, and its entry in `versions`
      this.node();
      this.charge(WEIGHTS.container);
      this.docsWeight += this.docWeight + WEIGHTS.container;
      // `"key":{` and `}`, and a comma before it
      this.piece((this.keyBytes[2] ?? 0) + this.docChars + 3);
      this.versionEntry(key, Object.fromEntries(this.fields));
      this.fields = [];
      // the document's own keys are held by it now (charged as its members), the ones read for it are gone
      this.charge(-this.docKeys);
      this.docKeys = 0;

      return;
    }

    if (this.depth === 1 && this.inVersions) {
      this.inVersions = false;
      this.node();
      this.charge(WEIGHTS.container);
      this.topEntry("versions", Object.fromEntries(live(this.versions)));
      this.versionCount = this.versions.size;
      this.versionDocs = this.docsWeight;
      this.versions = new Map();
      this.charge(-this.versionKeys);
      this.versionKeys = 0;

      return;
    }

    this.valueEnded(chunk, at + 1);
  }

  /** One more node kept: a value or key inside a kept part, or an entry around one. */
  private node(): void {
    this.keptNodes++;

    if (this.keptNodes > this.limits.maxKeptNodes) throw new TooLarge({ over: "nodes", bytes: this.keptNodes, limit: this.limits.maxKeptNodes });
  }

  /** Weight charged (or given back, when negative), checked against maxWeight and taken from the lease in steps. */
  private charge(n: number): void {
    this.weight += n;

    if (this.weight > this.limits.maxWeight) throw new TooLarge({ over: "weight", bytes: this.weight, limit: this.limits.maxWeight });
    this.pending += n;

    if (this.pending >= FLUSH_WEIGHT || this.pending < 0) this.flush();
  }

  /** What was charged since the last flush, taken from the lease (or given back). */
  private flush(): void {
    const n = this.pending;
    this.pending = 0;

    if (n === 0) return;

    if (n < 0) {
      this.lease.give(-n);
      this.taken += n;

      return;
    }

    if (!this.lease.take(n)) throw new TooLarge({ over: "budget", bytes: this.lease.taken + n, limit: this.lease.limit });
    this.taken += n;
  }

  /**
   * The `count`th key of an object the reader builds, and the `hiddenClass` it gives the object: with its text (two
   * bytes a character at most) when that is new.
   */
  private member(key: string, hiddenClass: number, count: number): void {
    this.charge(memberWeight(count));

    if (this.newClass(hiddenClass)) this.charge(2 * key.length * WEIGHTS.text);
  }

  private topEntry(key: string, value: JsonValue): void {
    this.topKeys += this.adoptKey(1);
    this.topClass = hashString(this.topClass, key);
    this.member(key, this.topClass, this.top.length + 1);
    this.top.push([key, value]);
  }

  private versionEntry(key: string, value: JsonValue): void {
    this.versionKeys += this.adoptKey(2);
    this.versionsClass = hashString(this.versionsClass, key);
    this.member(key, this.versionsClass, this.versions.size + 1);
    this.versions.set(key, value);
  }

  private fieldEntry(key: string, value: JsonValue): void {
    this.docKeys += this.adoptKey(3);
    this.fieldsClass = hashString(this.fieldsClass, key);
    this.docWeight += memberWeight(this.fields.length + 1);
    this.member(key, this.fieldsClass, this.fields.length + 1);
    this.fields.push([key, value]);
  }

  private keep(part: Uint8Array): void {
    if (part.length === 0) return;
    const c = this.capture;

    if (c?.into === "key") {
      if (this.keyOverlong) return;

      // a key that cannot name anything kept here: what was copied of it goes, and nothing more is
      if (this.slabs.length + part.length > this.keyLimit) {
        this.keyOverlong = true;
        this.charge(-this.slabs.length * WEIGHTS.text);
        this.slabs.discard();

        return;
      }
    } else {
      if (c) c.bytes += part.length;
      this.keptBytes += part.length;

      if (this.keptBytes > this.limits.maxKeptBytes) throw new TooLarge({ over: "kept", bytes: this.keptBytes, limit: this.limits.maxKeptBytes });
    }

    this.charge(part.length * WEIGHTS.text);
    // a copy: the chunk's buffer is the stream's, and is reused or released after this read
    this.slabs.append(part);
  }

  /**
   * The part kept so far, parsed. The copies the parse holds at once are charged before it; they and the text held
   * until now are given back after (what the parsed value holds was charged as it was read).
   */
  private parseKept(): JsonValue {
    const held = this.slabs.length * WEIGHTS.text;
    const moment = this.slabs.length * WEIGHTS.parse;
    this.charge(moment);
    this.flush();
    const value = parsed(this.slabs.take());
    this.charge(-moment - held);

    return value;
  }

  /**
   * What a value starting here is for: kept, skipped, or (`versions` or a version document) read into. `kind` is the
   * container it opens, null for a string, number or literal.
   */
  private valueStarted(at: number, kind: number | null): void {
    if (this.capture) {
      this.node();
      this.charge(kind === null ? WEIGHTS.value : WEIGHTS.container);

      return;
    }

    const opensObject = kind === OBJECT;

    switch (this.depth) {
      case 0:
        if (!opensObject) throw new InvalidPackument("not a JSON object");

        return;
      case 1: {
        const key = this.rootKey;

        if (key === null || key === IGNORED || !this.profile.top.has(key)) return;

        if (key === "versions" && opensObject) {
          // a second `versions` replaces the first, as in JSON.parse
          this.inVersions = true;
          this.versions = new Map();
          this.versionsClass = this.seed;
          this.docsWeight = 0;

          return;
        }

        if (key === "versions") {
          this.versionCount = 0;
          this.versionDocs = 0;
        }

        this.startCapture({ at, kind, into: "top", name: key });

        return;
      }

      case 2: {
        const key = this.versionKey;

        if (!this.inVersions || key === null) return;

        if (opensObject) {
          this.inVersion = true;
          this.fields = [];
          this.fieldsClass = this.seed;
          this.docWeight = 0;
          this.docChars = 0;

          return;
        }

        if (this.profile.otherVersions) this.startCapture({ at, kind, into: "version", name: key });
        // not kept, yet it replaces an earlier entry of the same key, as in JSON.parse
        else if (this.versions.has(key)) this.versions.set(key, DROPPED);

        return;
      }

      case 3: {
        const key = this.fieldKey;

        if (!this.inVersion || key === null || key === IGNORED) return;
        const listed = this.profile.fields.names.has(key);

        if (this.profile.fields.kind === "except" ? !listed : listed) this.startCapture({ at, kind, into: "field", name: key });

        return;
      }

      default:
    }
  }

  private startCapture(input: { at: number; kind: number | null; into: "top" | "version" | "field"; name: string }): void {
    this.node();
    this.charge(input.kind === null ? WEIGHTS.value : WEIGHTS.container);
    this.capture = { depth: this.depth, into: input.into, name: input.name, from: input.at, bytes: 0, numbers: 0 };
  }

  /** A value ended just before `end`, at the current depth: if it was being kept, it is parsed and put in place. */
  private valueEnded(chunk: Uint8Array, end: number): void {
    const c = this.capture;

    if (!c || c.depth !== this.depth || c.into === "key") return;
    this.keep(chunk.subarray(c.from, end));
    this.capture = null;
    const value = this.parseKept();

    // a member written as `,"key":value`, with the key's text as it was read
    const chars = Scanner.valueChars(c) + 2;

    switch (c.into) {
      case "top":
        this.piece((this.keyBytes[1] ?? 0) + chars);
        this.topEntry(c.name, value);

        break;
      case "version":
        this.piece((this.keyBytes[2] ?? 0) + chars);
        this.versionEntry(c.name, value);

        break;
      case "field":
        this.docChars += (this.keyBytes[3] ?? 0) + chars;
        this.fieldEntry(c.name, value);

        break;
      default: {
        const _exhaustive: never = c.into;

        return _exhaustive;
      }
    }
  }
}

export type ReadOptions = {
  readonly lease: Lease;
  readonly limits?: PackumentLimits;
  readonly profile?: KeepProfile;
  /**
   * Stops the read: the stream is canceled, that cancel is waited for, and only then is the read's charge given back
   * and the read rejected with the signal's reason. Whoever stops a read waits for it to settle before it releases
   * the lease (upstream.ts, joined).
   */
  readonly signal?: AbortSignal;
};

/**
 * Reads a packument's body under `limits`, keeping what `profile` names (TRIMMED by default), and taking what it keeps
 * from `lease`, which must be open. Cancels the stream when it stops early, and settles only once that cancel has.
 */
export async function readPackument(body: ReadableStream<Uint8Array>, options: ReadOptions): Promise<PackumentRead> {
  const { lease } = options;
  lease.assertOpen();
  const signal = options.signal ?? null;

  if (signal?.aborted) {
    await body.cancel(signal.reason).catch(() => undefined);
    throw signal.reason;
  }

  if (!lease.take(READ_OVERHEAD_WEIGHT)) {
    await body.cancel().catch(() => undefined);

    return { kind: "too-large", over: "budget", bytes: lease.taken + READ_OVERHEAD_WEIGHT, limit: lease.limit };
  }

  try {
    return await scan(body, { lease, limits: options.limits ?? PACKUMENT_LIMITS, profile: options.profile ?? TRIMMED, signal });
  } finally {
    lease.give(READ_OVERHEAD_WEIGHT);
  }
}

type ScanOptions = { readonly lease: Lease; readonly limits: PackumentLimits; readonly profile: KeepProfile; readonly signal: AbortSignal | null };

async function scan(body: ReadableStream<Uint8Array>, options: ScanOptions): Promise<PackumentRead> {
  // null once the read has failed: what it built is then unreachable while the stream's cancel is waited for
  let scanner: Scanner | null = new Scanner({ limits: options.limits, profile: options.profile, lease: options.lease });
  const reader = body.getReader();
  const { signal } = options;
  // one cancel, whoever starts it: an abort while a read is pending, or a read that failed. Not a Promise.race of each
  // read against the signal: every race would stay on the signal's promise, and keep its chunk, until the read ends
  let cancelling: Promise<void> | null = null;
  const cancel = (): Promise<void> => (cancelling ??= reader.cancel(signal?.aborted ? signal.reason : undefined).catch(() => undefined));
  const onAbort = (): void => void cancel();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    for (;;) {
      const { done, value } = await reader.read();

      // a pending read the abort canceled ends as done: the read stops, it does not finish
      if (signal?.aborted) throw signal.reason;

      if (done) break;
      scanner.feed(value);
    }

    const kept = scanner.finish();

    return {
      kind: "ok",
      body: kept,
      bytes: scanner.bytes,
      keptBytes: scanner.keptBytes,
      keptNodes: scanner.keptNodes,
      weight: scanner.weight,
      versionCount: scanner.versionCount,
      versionDocs: scanner.versionDocs,
      maxPieceChars: scanner.maxPieceChars,
    };
  } catch (e) {
    // every reference to what the scanner built is dropped first, and its charge is given back only once the cancel
    // has settled: until then the stream (and whatever its source holds) may still refer to the read's memory
    const taken = scanner?.taken ?? 0;
    scanner = null;

    // an error's stack refers to the objects its frames ran on (the scanner, from feed) until it is formatted
    if (e instanceof Error) void e.stack;
    await cancel();
    options.lease.give(taken);

    if (e instanceof TooLarge) return { kind: "too-large", over: e.over, bytes: e.bytes, limit: e.limit };

    if (e instanceof InvalidPackument) return { kind: "invalid", reason: e.message };
    throw e;
  } finally {
    signal?.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
}
