// Reads an npm packument from a byte stream without holding it whole. vite's full packument is 39 MB of JSON, 35 MB of
// it the `licenseText` each of its 769 versions repeats; read with res.text() and JSON.parse, it took more than the
// Worker's 128 MB and the platform ended the page request that asked for it (exceededMemory).
//
// The reader scans the bytes once, structurally (strings, brackets, scalars), and keeps only the parts the registry
// reads: the top-level fields in TOP_FIELDS, and each version's document without the fields in DROPPED_VERSION_FIELDS,
// which no install needs. Each kept part is parsed on its own, so the most it holds is what it
// keeps, and both what it reads and what it keeps are capped.
import { z } from "zod";

/** Top-level packument fields the registry reads (upstream.ts, UpPackument); everything else is skipped. */
const TOP_FIELDS: ReadonlySet<string> = new Set(["name", "dist-tags", "versions", "time", "description", "readme", "maintainers"]);

/**
 * Version fields never kept, because no install, page or score reads them from the packument:
 * - licenseText, readme and readmeFilename: text a full document may repeat in every version (vite: 35 MB of its 39).
 *   npm's abbreviated packument has none of them; a version's readme is shown from its tarball, the package's from
 *   the top-level field.
 * - devDependencies: 17 MB of next's 31 MB. npm, pnpm, yarn and bun install a registry dependency's dependencies,
 *   optional and peer dependencies, never its devDependencies, and the scorer reads the tarball's own package.json.
 */
export const DROPPED_VERSION_FIELDS: ReadonlySet<string> = new Set(["licenseText", "readme", "readmeFilename", "devDependencies"]);

/** The most of a packument read before it is refused: reading costs CPU, not memory, so this is well past any real one. */
export const MAX_PACKUMENT_BYTES = 160 * 1024 * 1024;

/** The most of a packument kept, as JSON text, before it is refused: what is kept is held parsed. */
export const MAX_KEPT_PACKUMENT_BYTES = 24 * 1024 * 1024;

export type PackumentLimits = { readonly maxBytes: number; readonly maxKeptBytes: number };

export const PACKUMENT_LIMITS: PackumentLimits = { maxBytes: MAX_PACKUMENT_BYTES, maxKeptBytes: MAX_KEPT_PACKUMENT_BYTES };

/**
 * What reading a packument came to. "ok": the kept fields, as one object. "too-large": more than `limit` bytes were
 * read ("read") or would have been kept ("kept"); `bytes` is how many when it stopped. "invalid": not a JSON object.
 */
export type PackumentRead =
  | { kind: "ok"; body: KeptPackument; bytes: number; keptBytes: number }
  | { kind: "too-large"; over: "read" | "kept"; bytes: number; limit: number }
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

const isSpace = (b: number): boolean => b === 0x20 || b === 0x0a || b === 0x0d || b === 0x09;

/**
 * Where a container sits: the root object, the `versions` object, one version's document, or anything inside a value
 * that is kept or skipped whole (whose keys do not matter).
 */
type Role = "root" | "versions" | "version" | "inner";

type Frame = { readonly object: boolean; readonly role: Role; expectKey: boolean; key: string | null };

/** A value being kept: its bytes so far, and where it goes once it ends. */
type Capture = { readonly depth: number; readonly into: "top" | "field" | "key"; readonly name: string; parts: Uint8Array[]; from: number };

class InvalidPackument extends Error {}

class TooLarge extends Error {
  readonly over: "read" | "kept";
  readonly bytes: number;
  readonly limit: number;

  constructor(input: { over: "read" | "kept"; bytes: number; limit: number }) {
    super(`packument over ${input.limit} bytes ${input.over}`);
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
    throw new InvalidPackument("a kept value is not JSON");
  }
}

class Scanner {
  private readonly stack: Frame[] = [];
  private inString = false;
  private escaped = false;
  private inScalar = false;
  private capture: Capture | null = null;
  /** The kept fields of the version being read, as entries; null outside a version's document. */
  private fields: [string, JsonValue][] | null = null;
  private readonly top: [string, JsonValue][] = [];
  private readonly versions: [string, JsonValue][] = [];
  private sawRoot = false;
  private sawVersions = false;
  private done = false;
  bytes = 0;
  keptBytes = 0;

  private readonly limits: PackumentLimits;

  constructor(limits: PackumentLimits) {
    this.limits = limits;
  }

  feed(chunk: Uint8Array): void {
    this.bytes += chunk.length;

    if (this.bytes > this.limits.maxBytes) throw new TooLarge({ over: "read", bytes: this.bytes, limit: this.limits.maxBytes });

    for (let i = 0; i < chunk.length; i++) {
      const b = chunk[i] ?? 0;

      if (this.inString) {
        if (this.escaped) this.escaped = false;
        else if (b === BACKSLASH) this.escaped = true;
        else if (b === QUOTE) {
          this.inString = false;
          this.valueEnded(chunk, i + 1, this.stack.length);
        }

        continue;
      }

      if (this.inScalar) {
        if (!(isSpace(b) || b === COMMA || b === CLOSE_OBJECT || b === CLOSE_ARRAY)) continue;
        this.inScalar = false;
        this.valueEnded(chunk, i, this.stack.length);
      }

      if (isSpace(b)) continue;

      if (this.done) throw new InvalidPackument("text after the packument");

      switch (b) {
        case QUOTE: {
          const frame = this.stack.at(-1);

          if (frame?.object === true && frame.expectKey) this.keyStarted(i, frame);
          else this.valueStarted(i, null);
          this.inString = true;

          break;
        }

        case OPEN_OBJECT:
        case OPEN_ARRAY:
          this.valueStarted(i, b === OPEN_OBJECT);

          break;
        case CLOSE_OBJECT:
        case CLOSE_ARRAY: {
          const frame = this.stack.pop();

          if (!frame || frame.object !== (b === CLOSE_OBJECT)) throw new InvalidPackument("unbalanced brackets");
          this.containerEnded(chunk, i + 1, frame);

          break;
        }

        case COLON: {
          const frame = this.stack.at(-1);

          if (frame?.object !== true) throw new InvalidPackument("a colon outside an object");
          frame.expectKey = false;

          break;
        }

        case COMMA: {
          const frame = this.stack.at(-1);

          if (!frame) throw new InvalidPackument("a comma outside a container");

          if (frame.object) {
            frame.expectKey = true;
            frame.key = null;
          }

          break;
        }

        default:
          this.valueStarted(i, null);
          this.inScalar = true;
      }
    }

    // a value still being kept continues in the next chunk
    if (this.capture) {
      this.keep(chunk.subarray(this.capture.from));
      this.capture.from = 0;
    }
  }

  finish(): KeptPackument {
    if (this.inScalar) throw new InvalidPackument("the packument ends inside a value");

    if (!this.done || this.inString || !this.sawRoot) throw new InvalidPackument("the packument ends early");

    return Object.fromEntries(this.sawVersions ? [...this.top.filter(([k]) => k !== "versions"), ["versions", Object.fromEntries(this.versions)]] : this.top);
  }

  private keep(part: Uint8Array): void {
    if (part.length === 0 || !this.capture) return;
    this.keptBytes += part.length;

    if (this.keptBytes > this.limits.maxKeptBytes) throw new TooLarge({ over: "kept", bytes: this.keptBytes, limit: this.limits.maxKeptBytes });
    // a copy: the chunk's buffer is the stream's, and is reused or released after this read
    this.capture.parts.push(part.slice());
  }

  private keyStarted(at: number, frame: Frame): void {
    // keys matter only where the reader decides what to keep
    if (frame.role !== "inner" && !this.capture) this.capture = { depth: this.stack.length, into: "key", name: "", parts: [], from: at };
  }

  /** What a value starting here is for: kept, skipped, or (a container) read into. `object` is null for a non-container. */
  private valueStarted(at: number, object: boolean | null): void {
    const parent = this.stack.at(-1);
    let role: Role = "inner";

    if (!parent) {
      if (this.sawRoot || object !== true) throw new InvalidPackument("not a JSON object");
      this.sawRoot = true;
      role = "root";
    } else if (!this.capture && parent.role !== "inner") {
      const key = parent.object ? parent.key : null;

      if (parent.role === "root" && key !== null && TOP_FIELDS.has(key)) {
        if (key === "versions" && object === true) {
          role = "versions";
          this.sawVersions = true;
        }
        else this.capture = { depth: this.stack.length, into: "top", name: key, parts: [], from: at };
      } else if (parent.role === "versions" && key !== null && object === true) {
        role = "version";
        this.fields = [];
      } else if (parent.role === "version" && key !== null && !DROPPED_VERSION_FIELDS.has(key)) {
        this.capture = { depth: this.stack.length, into: "field", name: key, parts: [], from: at };
      }
    }

    if (object !== null) this.stack.push({ object, role, expectKey: object, key: null });
  }

  /** A string or scalar ended just before `end`, at `depth`. */
  private valueEnded(chunk: Uint8Array, end: number, depth: number): void {
    const c = this.capture;

    if (!c || c.depth !== depth) return;
    this.keep(chunk.subarray(c.from, end));
    this.capture = null;
    const value = parsed(joined(c.parts));

    switch (c.into) {
      case "key": {
        const frame = this.stack.at(-1);

        const key = z.string().safeParse(value);

        if (frame && key.success) frame.key = key.data;

        break;
      }

      case "top":
        this.top.push([c.name, value]);

        break;
      case "field":
        this.fields?.push([c.name, value]);

        break;
      default: {
        const _exhaustive: never = c.into;

        return _exhaustive;
      }
    }
  }

  private containerEnded(chunk: Uint8Array, end: number, frame: Frame): void {
    if (frame.role === "root") {
      this.done = true;

      return;
    }

    if (frame.role === "version") {
      const parent = this.stack.at(-1);

      if (parent?.key != null && this.fields) this.versions.push([parent.key, Object.fromEntries(this.fields)]);
      this.fields = null;

      return;
    }

    this.valueEnded(chunk, end, this.stack.length);
  }
}

/** Reads a packument's body under `limits`, keeping only what the registry reads. Cancels the stream when it stops early. */
export async function readPackument(body: ReadableStream<Uint8Array>, limits: PackumentLimits = PACKUMENT_LIMITS): Promise<PackumentRead> {
  const scanner = new Scanner(limits);
  const reader = body.getReader();

  try {
    for (;;) {
      const { done, value } = await reader.read();

      if (done) break;
      scanner.feed(value);
    }

    return { kind: "ok", body: scanner.finish(), bytes: scanner.bytes, keptBytes: scanner.keptBytes };
  } catch (e) {
    await reader.cancel().catch(() => undefined);

    if (e instanceof TooLarge) return { kind: "too-large", over: e.over, bytes: e.bytes, limit: e.limit };

    if (e instanceof InvalidPackument) return { kind: "invalid", reason: e.message };
    throw e;
  } finally {
    reader.releaseLock();
  }
}
