// Read an npm package tarball (.tgz) into memory. Pure: bytes in, entries out.
// Every header is validated and every limit is enforced, so a hostile archive gets a typed
// error, never a hang or an unbounded allocation.
import { gunzipSync } from "node:zlib";
import { EXECUTABLE_HEAD_BYTES, hasExecutableMagic } from "./executable.ts";
import { chargeText, metered, MeterExhausted, type Meter } from "./meter.ts";

export type TarEntry = { path: string; size: number; mode: number; data: Uint8Array };

/** The most a package may inflate to. npm's own largest packages stay well below this. */
export const MAX_UNPACKED_BYTES = 200 * 1024 * 1024;

/** The most headers (files, directories, long-name and pax records) one tarball may hold. */
export const MAX_TAR_ENTRIES = 100_000;

export type ArchiveErrorKind = "invalid" | "too-large";

/** A gzip or tar stream apm refuses to read. Routes answer "invalid" with 400 and "too-large" with 413. */
export class ArchiveError extends Error {
  constructor(
    readonly kind: ArchiveErrorKind,
    message: string,
  ) {
    super(message);
    this.name = "ArchiveError";
  }
}

export function httpStatusOf(e: ArchiveError): 400 | 413 {
  switch (e.kind) {
    case "invalid":
      return 400;
    case "too-large":
      return 413;
    default: {
      const _exhaustive: never = e.kind;

      return _exhaustive;
    }
  }
}

function hasCode(e: unknown): e is { code: unknown } {
  return typeof e === "object" && e !== null && "code" in e;
}

/**
 * The size a gzip stream says it inflates to: its trailer's ISIZE, the length mod 2^32 of the last member. npm, yarn,
 * pnpm and bun all pack one member, so for a tarball this is its length.
 */
function trailerSize(bytes: Uint8Array): number | null {
  if (bytes.length < 18 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) return null;
  const at = bytes.length - 4;

  return ((bytes[at] ?? 0) | ((bytes[at + 1] ?? 0) << 8) | ((bytes[at + 2] ?? 0) << 16)) + (bytes[at + 3] ?? 0) * 0x1000000;
}

/** Units of meter the inflate of one character costs, against a text pass's one per CHARS_PER_UNIT (meter.ts). */
const GUNZIP_PASSES = 2;

/**
 * Room the inflate gets past the trailer's size. workerd's node:zlib grows its output in steps and refuses a step that
 * would pass maxOutputLength even when the stream itself ends inside it, so a limit of exactly the trailer's size
 * failed real packages (react 19.3.1 at 200192 bytes, tinyglobby 0.2.17 at 46080) as "not valid gzip" on Cloudflare
 * while Bun inflated them. Measured in workerd, a stream needed up to 36 KB more; this leaves several times that.
 */
export const GUNZIP_SLACK_BYTES = 256 * 1024;

/**
 * Inflates gzip, refusing output larger than `maxBytes`. The trailer says how large the output is, so that much is
 * charged to the meter before anything is inflated and the inflate is held to it, plus GUNZIP_SLACK_BYTES the runtime
 * needs: a stream that inflates past what its trailer says is refused as invalid, so the charge covers the work but
 * for at most that slack.
 */
export function gunzipCapped(bytes: Uint8Array, maxBytes: number, meter?: Meter): Uint8Array {
  return metered(meter, () => {
    const size = trailerSize(bytes);

    if (size === null) throw new ArchiveError("invalid", "not valid gzip: no gzip header and trailer");

    if (size > maxBytes) throw new ArchiveError("too-large", `inflates to more than ${Math.floor(maxBytes / (1024 * 1024))} MB`);
    chargeText("gunzip", Math.max(size, bytes.length), GUNZIP_PASSES);
    const overrun = (): ArchiveError => new ArchiveError("invalid", `not valid gzip: it inflates to more than the ${size} bytes its trailer says`);
    let out: Uint8Array;

    try {
      out = new Uint8Array(gunzipSync(bytes, { maxOutputLength: size + GUNZIP_SLACK_BYTES }));
    } catch (e) {
      if (e instanceof RangeError || (hasCode(e) && e.code === "ERR_BUFFER_TOO_LARGE")) throw overrun();

      throw new ArchiveError("invalid", `not valid gzip: ${e instanceof Error ? e.message : String(e)}`);
    }

    // the slack is the runtime's, not the stream's: output past the trailer's size is refused as before
    if (out.length > size) throw overrun();

    return out;
  });
}

function readString(buf: Uint8Array, start: number, len: number): string {
  let end = start;

  while (end < start + len && buf[end] !== 0) end++;

  return new TextDecoder().decode(buf.subarray(start, end));
}

/** A numeric header field: octal digits, padded with spaces or NULs. Null when it is anything else. */
function readOctalField(buf: Uint8Array, start: number, len: number): number | null {
  const s = readString(buf, start, len).trim();

  if (!/^[0-7]{1,12}$/.test(s)) return null;
  const n = parseInt(s, 8);

  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

/** The header checksum: every byte summed with the checksum field read as spaces. Old tars summed signed bytes. */
function checksumMatches(header: Uint8Array, stored: number): boolean {
  let unsigned = 0;
  let signed = 0;

  for (let i = 0; i < 512; i++) {
    const b = i >= 148 && i < 156 ? 0x20 : (header[i] ?? 0);
    unsigned += b;
    signed += b > 127 ? b - 256 : b;
  }

  return stored === unsigned || stored === signed;
}

function invalid(message: string): ArchiveError {
  return new ArchiveError("invalid", message);
}

/** Parses an uncompressed tar. Strips the leading "package/" (or any single top dir) from paths. */
export function readTar(tar: Uint8Array, meter?: Meter): TarEntry[] {
  return metered(meter, () => readTarMetered(tar));
}

function readTarMetered(tar: Uint8Array): TarEntry[] {
  const entries: TarEntry[] = [];
  let off = 0;
  let headers = 0;
  let longName: string | null = null;
  let paxPath: string | null = null;

  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);

    // a header: the zero test, the checksum and the fields each read its 512 bytes once
    chargeText("tar", 512, 4);

    if (header.every((b) => b === 0)) break;
    headers++;

    if (headers > MAX_TAR_ENTRIES) throw new ArchiveError("too-large", `more than ${MAX_TAR_ENTRIES} entries`);
    const stored = readOctalField(header, 148, 8);

    if (stored === null || !checksumMatches(header, stored)) throw invalid(`bad header checksum at byte ${off}`);
    const size = readOctalField(header, 124, 12);

    if (size === null) throw invalid(`bad size field at byte ${off}`);
    const mode = readOctalField(header, 100, 8) ?? 0;
    const name = readString(header, 0, 100);
    const type = String.fromCharCode(header[156] ?? 48);
    const prefix = readString(header, 345, 155);
    const dataStart = off + 512;

    if (dataStart + size > tar.length) throw invalid(`entry "${name}" runs past the end of the archive`);
    const data = tar.subarray(dataStart, dataStart + size);
    // size >= 0, so the offset always moves forward by at least one block
    off = dataStart + Math.ceil(size / 512) * 512;

    if (type === "L") {
      chargeText("tar", data.length);
      longName = readString(data, 0, data.length);
      continue;
    }

    if (type === "x") {
      paxPath = paxPathOf(data, off);
      continue;
    }

    if (type === "g") continue;

    if (type !== "0" && type !== "\0" && type !== "7") {
      longName = null;
      paxPath = null;
      continue;
    }

    let full = paxPath ?? longName ?? (prefix ? `${prefix}/${name}` : name);
    longName = null;
    paxPath = null;
    full = normalizeTarPath(full);
    // the entry's bytes are copied out of the archive
    chargeText("tar", size + full.length);
    entries.push({ path: full, size, mode, data: new Uint8Array(data) });
  }

  return entries;
}

/**
 * Strips the single top-level tar folder (normally `package/`) and normalizes backslashes, redundant `.`, and empty
 * segments so entries like `package/./install.js` and `package/.\install.js` resolve to `install.js` just as npm's
 * `node-tar` extracts them. Preserves a leading `/` and any `..` segments so `ambiguousPaths` still rejects absolute
 * paths and escapes.
 */
function normalizeTarPath(raw: string): string {
  const unix = raw.replaceAll("\\", "/");
  const slash = unix.indexOf("/");
  const stripped = slash >= 0 ? unix.slice(slash + 1) : unix;

  if (stripped.startsWith("/")) return stripped;

  return stripped
    .split("/")
    .filter((s) => s !== "" && s !== ".")
    .join("/");
}

/**
 * Parses a gzip'd tar within `maxBytes` (MAX_UNPACKED_BYTES unless a host with less memory passes a lower cap).
 * Throws ArchiveError for anything it will not read.
 */
export function readTarball(tgz: Uint8Array, maxBytes: number = MAX_UNPACKED_BYTES, meter?: Meter): TarEntry[] {
  return metered(meter, () => readTarMetered(gunzipCapped(tgz, Math.min(maxBytes, MAX_UNPACKED_BYTES))));
}

const DIGIT_0 = 0x30;
const SPACE = 0x20;
const EQUALS = 0x3d;
const NEWLINE = 0x0a;

/**
 * The `path` of a PAX extended header, or null when it sets none. A PAX header is a run of records, each
 * `<length> <key>=<value>\n` where `<length>` counts the whole record, digits and newline included. They are read with
 * one cursor that only moves forward, a record at a time, and a header that is not such a run is refused: a search
 * for `path=` anywhere in it (what this was before) tried every digit as a record's start, and a payload of repeated
 * digits made that quadratic. `at` is the header's offset, for the error.
 */
function paxPathOf(data: Uint8Array, at: number): string | null {
  chargeText("tar", data.length, 2);
  let path: string | null = null;
  let pos = 0;

  while (pos < data.length) {
    // a trailing NUL pad after the last record is allowed
    if (data[pos] === 0) break;
    let len = 0;
    let digits = 0;

    for (let c = data[pos + digits]; c !== undefined && c >= DIGIT_0 && c <= DIGIT_0 + 9; c = data[pos + digits]) {
      len = len * 10 + (c - DIGIT_0);
      digits++;

      if (digits > 12) throw invalid(`bad pax record length at byte ${at}`);
    }

    const end = pos + len;

    if (digits === 0 || data[pos + digits] !== SPACE || len <= digits + 3 || end > data.length || data[end - 1] !== NEWLINE) throw invalid(`malformed pax record at byte ${at}`);
    const record = data.subarray(pos + digits + 1, end - 1);
    const eq = record.indexOf(EQUALS);

    if (eq <= 0) throw invalid(`malformed pax record at byte ${at}`);

    if (eq === 4 && record[0] === 0x70 && record[1] === 0x61 && record[2] === 0x74 && record[3] === 0x68) path = new TextDecoder().decode(record.subarray(eq + 1));
    pos = end;
  }

  return path;
}

// ---------- reading a tarball as a stream ----------
//
// A tarball too large to hold (next 16.4.6 is 43.7 MB and unpacks to 192 MB; a Worker has 128 MB) is inflated and read a
// chunk at a time. Every file passes through; the caller's rule decides, from its path and size alone, which ones are
// kept whole, and which are gathered only to be looked at (the paths a file imports, say) and then let go. Of every file
// not kept only its first HEAD_BYTES are kept, which is all the checks of a file's first bytes read (score.ts's
// isBinaryData), or EXECUTABLE_HEAD_BYTES of one that starts like an executable, enough to check its structure
// (executable.ts). The headers are read exactly as readTar reads them: the same checksum,
// size, PAX, GNU long-name, type and path rules, the same limits and the same charges to the meter, so a held file is
// the bytes readTar would give for it (test/tarball-stream.test.ts holds the two to each other on random chunkings).

/** Bytes of a file kept when the read does not hold it: the most any check of a file's first bytes reads, and some. */
export const HEAD_BYTES = 16;

/** The most a PAX header or GNU long name may be in a streamed read, which must hold it whole to read it. */
export const MAX_STREAMED_NAME_BYTES = 1024 * 1024;

/**
 * The most file names a streamed read keeps, in characters, all paths together: it keeps every entry's path. next
 * 16.4.6's 8,711 take 0.6 million. A tarball past it is refused as too large.
 */
export const MAX_STREAMED_NAMES_BYTES = 8 * 1024 * 1024;

/** Bytes charged for each entry kept, beside its path (two bytes a character) and its kept bytes: the object and its array. */
export const ENTRY_BYTES = 192;

/** Bytes charged while an inflate runs, for the chunks the gunzip and the tar reader hold in flight. */
export const INFLATE_BYTES = 256 * 1024;

/**
 * Where a streamed read charges what it keeps before it keeps it, and gives back what it lets go: the registry passes
 * its memory lease (memory.ts), whose take and give are these. A charge it refuses stops the read (MemoryRefused).
 */
export type StreamMemory = { take(bytes: number): boolean; give(bytes: number): void };

const UNMETERED: StreamMemory = { take: () => true, give: () => undefined };

/** The memory refused a charge, so the read stopped before keeping it: the registry's limit, not the package's. */
export class MemoryRefused extends Error {
  override readonly name = "MemoryRefused";
}

/**
 * A read listed an entry other than the one the read it must match listed (a second pass against the first, verified
 * one), so these are not the bytes that read verified; it stopped before allocating the entry.
 */
export class TarballChanged extends Error {
  override readonly name = "TarballChanged";
}

/** An entry as a verified read listed it: what a read that must match it finds, in the same order. */
export type ListedEntry = { readonly path: string; readonly size: number; readonly mode: number };

/** What a streamed read is held to: the memory it charges, and the entries it must find (a second pass's). */
export type TarStreamOptions = { readonly memory?: StreamMemory; readonly expect?: readonly ListedEntry[] };

/**
 * A streamed read's files, in archive order, as readTar would give them, except that a file the read did not hold has
 * only its first HEAD_BYTES in `data` (its `size` is still its whole size). `notHeld` holds exactly those entries: as
 * in production (274d284), nothing of their text is read (round 11 review of ee69d23: reading the text of binaries the
 * read did not hold, as they passed, read files production never read, and three of them ended the isolate).
 */
export type StreamedTarball = { files: TarEntry[]; notHeld: ReadonlySet<TarEntry>; unpackedBytes: number; charged: number };

/**
 * What a streamed read does with a file, decided before any of its bytes arrive: "hold" keeps it whole; "look" gathers
 * it and keeps only its head once the read's `look` has seen it; "head" keeps only its head. `look` sees every held
 * and every gathered file once its last byte is in. A gathered file is let go before the next one starts, so a rule
 * bounds what the read holds by the sizes it allows.
 */
export type Keep = "hold" | "look" | "head";

export type HoldRule = (file: { path: string; size: number }) => Keep;

/** Called with each file the rule said to "hold" or to "look" at, and all of its bytes, which it must not keep. */
export type LookAt = (file: TarEntry, bytes: Uint8Array) => void;

type Pending =
  | { kind: "header" }
  // a file entry's bytes: all of them when held, else the first HEAD_BYTES
  // `name`: the header's own name field, which readTar's errors quote
  | { kind: "file"; entry: TarEntry; name: string; keep: Keep; gathered: Uint8Array | null; left: number; pad: number; probed: boolean }
  // a GNU long name or a PAX header, held whole to be read once its last byte is in
  | { kind: "meta"; type: "L" | "x"; name: string; buf: Uint8Array; at: number; left: number; pad: number }
  // bytes passed over: `required`, another entry type's data, which must all arrive; then `pad`, which may be cut short
  | { kind: "skip"; required: number; pad: number; name: string }
  // the end-of-archive block was read: the rest is ignored, as readTar ignores it
  | { kind: "ended" };

/**
 * readTar, a chunk at a time. `push` takes the next bytes of the uncompressed archive and `end` says there are no more;
 * either throws ArchiveError as readTar would for the same bytes (an entry that runs past the end, at `end`). Charges
 * the installed meter as readTar does, so the caller runs `push` and `end` under it.
 */
export class TarStream {
  private readonly header = new Uint8Array(512);
  private headerFill = 0;
  private pending: Pending = { kind: "header" };
  /** Bytes of the archive read so far: where the header being filled starts, as readTar's `off`. */
  private offset = 0;
  private headers = 0;
  private longName: string | null = null;
  private paxPath: string | null = null;
  private readonly entries: TarEntry[] = [];
  private readonly partial = new Set<TarEntry>();
  private namesBytes = 0;
  /** What this read has charged to its memory and still holds. */
  private charged = 0;
  private readonly memory: StreamMemory;
  private readonly expect: readonly ListedEntry[] | null;


  constructor(
    private readonly hold: HoldRule,
    private readonly look: LookAt = () => undefined,
    opts: TarStreamOptions = {},
  ) {
    this.memory = opts.memory ?? UNMETERED;
    this.expect = opts.expect ?? null;
  }

  /** Charges `n` before it is kept, or stops the read. */
  private take(n: number): void {
    if (!this.memory.take(n)) throw new MemoryRefused(`no memory for ${n} more bytes`);
    this.charged += n;
  }

  private give(n: number): void {
    this.memory.give(n);
    this.charged -= n;
  }

  push(chunk: Uint8Array): void {
    let at = 0;

    while (at < chunk.length) {
      const p = this.pending;

      switch (p.kind) {
        case "ended":
          return;
        case "header": {
          const n = Math.min(512 - this.headerFill, chunk.length - at);
          this.header.set(chunk.subarray(at, at + n), this.headerFill);
          this.headerFill += n;
          at += n;

          if (this.headerFill === 512) {
            this.headerFill = 0;
            this.readHeader();
          }

          break;
        }

        case "file": {
          const n = Math.min(p.left, chunk.length - at);
          const written = p.entry.size - p.left;

          if (p.gathered !== null) p.gathered.set(chunk.subarray(at, at + n), written);
          else if (written < p.entry.data.length) p.entry.data.set(chunk.subarray(at, at + Math.min(n, p.entry.data.length - written)), written);

          // an unheld file that starts like an executable keeps EXECUTABLE_HEAD_BYTES, so its structure can be checked
          // (executable.ts): a magic number alone does not make a file native code
          if (!p.probed && written + n >= Math.min(4, p.entry.size)) {
            p.probed = true;
            const head = p.gathered ?? p.entry.data;

            if (hasExecutableMagic(head)) this.keepHead(p, chunk.subarray(at, at + n), written);
          }

          p.left -= n;
          at += n;

          if (p.left === 0) {
            this.pending = p.pad > 0 ? { kind: "skip", required: 0, pad: p.pad, name: p.name } : { kind: "header" };

            if (p.gathered !== null) {
              if (p.keep === "look") p.entry.data.set(p.gathered.subarray(0, p.entry.data.length));
              this.look(p.entry, p.gathered);

              // a gathered file is let go once seen
              if (p.keep === "look") this.give(p.entry.size);
            }
          }

          break;
        }

        case "meta": {
          const n = Math.min(p.left, chunk.length - at);
          p.buf.set(chunk.subarray(at, at + n), p.buf.length - p.left);
          p.left -= n;
          at += n;

          if (p.left === 0) {
            this.readMeta(p);
            this.give(p.buf.length);
            this.pending = p.pad > 0 ? { kind: "skip", required: 0, pad: p.pad, name: p.name } : { kind: "header" };
          }

          break;
        }

        case "skip": {
          const n = Math.min(p.required + p.pad, chunk.length - at);
          const required = Math.min(n, p.required);
          p.required -= required;
          p.pad -= n - required;
          at += n;

          if (p.required === 0 && p.pad === 0) this.pending = { kind: "header" };

          break;
        }

        default: {
          const _exhaustive: never = p;

          return _exhaustive;
        }
      }
    }
  }

  /** The files read, once the archive's bytes have all been pushed. */
  end(): StreamedTarball {
    const p = this.pending;

    // a file's or a header's data cut short: readTar refuses it as running past the end (padding may be missing)
    if (p.kind === "file" && p.left > 0) throw invalid(`entry "${p.name}" runs past the end of the archive`);

    if (p.kind === "meta") throw invalid(`entry "${p.name}" runs past the end of the archive`);

    // another entry type's data cut short, a link's or a global PAX header's included: readTar refuses it too
    if (p.kind === "skip" && p.required > 0) throw invalid(`entry "${p.name}" runs past the end of the archive`);

    if (this.expect !== null && this.entries.length !== this.expect.length) throw new TarballChanged(`listed ${this.entries.length} files, not ${this.expect.length}`);

    return { files: this.entries, notHeld: this.partial, unpackedBytes: this.entries.reduce((n, e) => n + e.size, 0), charged: this.charged };
  }

  private readHeader(): void {
    const header = this.header;
    const off = this.offset;
    this.offset += 512;
    chargeText("tar", 512, 4);

    if (header.every((b) => b === 0)) {
      this.pending = { kind: "ended" };

      return;
    }

    this.headers++;

    if (this.headers > MAX_TAR_ENTRIES) throw new ArchiveError("too-large", `more than ${MAX_TAR_ENTRIES} entries`);
    const stored = readOctalField(header, 148, 8);

    if (stored === null || !checksumMatches(header, stored)) throw invalid(`bad header checksum at byte ${off}`);
    const size = readOctalField(header, 124, 12);

    if (size === null) throw invalid(`bad size field at byte ${off}`);
    const mode = readOctalField(header, 100, 8) ?? 0;
    const name = readString(header, 0, 100);
    const type = String.fromCharCode(header[156] ?? 48);
    const prefix = readString(header, 345, 155);
    const blocks = Math.ceil(size / 512) * 512;
    const pad = blocks - size;
    // readTar's offset once it has moved past this entry, which a PAX error names
    const after = off + 512 + blocks;
    this.offset += blocks;

    if (type === "L" || type === "x") {
      if (size > MAX_STREAMED_NAME_BYTES) throw new ArchiveError("too-large", `a ${type === "L" ? "long name" : "PAX header"} of more than ${MAX_STREAMED_NAME_BYTES / (1024 * 1024)} MB`);
      // held until its last byte is in, then let go (the name it gives is charged with the entry it names)
      this.take(size);
      const meta: Extract<Pending, { kind: "meta" }> = { kind: "meta", type, name, buf: new Uint8Array(size), at: after, left: size, pad };

      // an empty one has no data block to wait for
      if (size === 0) this.readMeta(meta);
      else this.pending = meta;

      return;
    }

    if (type === "g" || (type !== "0" && type !== "\0" && type !== "7")) {
      if (type !== "g") {
        this.longName = null;
        this.paxPath = null;
      }

      this.pending = blocks > 0 ? { kind: "skip", required: size, pad, name } : { kind: "header" };

      return;
    }

    let full = this.paxPath ?? this.longName ?? (prefix ? `${prefix}/${name}` : name);
    this.longName = null;
    this.paxPath = null;
    full = normalizeTarPath(full);
    this.namesBytes += full.length;

    if (this.namesBytes > MAX_STREAMED_NAMES_BYTES) throw new ArchiveError("too-large", `its file names take more than ${MAX_STREAMED_NAMES_BYTES / (1024 * 1024)} MB`);
    const listed = this.expect?.[this.entries.length];

    // a read held to a verified one: any other entry here means other bytes, refused before anything is allocated for it
    if (this.expect !== null && (listed === undefined || listed.path !== full || listed.size !== size || listed.mode !== mode)) throw new TarballChanged(`entry ${this.entries.length} is not the one the verified read listed`);
    const keep = this.hold({ path: full, size });
    const held = keep === "hold";
    // a held or gathered file's bytes are copied out of the archive, as readTar copies them; of the rest only the first few
    chargeText("tar", (keep === "head" ? Math.min(size, HEAD_BYTES) : size) + full.length);
    // the entry, its path and what it keeps of the file, and a gathered file's bytes until it has been seen
    this.take(ENTRY_BYTES + 2 * full.length + (held ? size : Math.min(size, HEAD_BYTES)) + (keep === "look" ? size : 0));
    const entry: TarEntry = { path: full, size, mode, data: new Uint8Array(held ? size : Math.min(size, HEAD_BYTES)) };
    this.entries.push(entry);

    if (!held) this.partial.add(entry);
    const gathered = held ? entry.data : keep === "look" ? new Uint8Array(size) : null;

    if (size === 0 && keep !== "head") this.look(entry, entry.data);
    // a file held whole is read by the analysis itself; one of HEAD_BYTES or less is held whole too (its head is all of it)
    this.pending = size > 0 ? { kind: "file", entry, name, keep, gathered, left: size, pad, probed: held } : { kind: "header" };
  }

  /**
   * Grows what an unheld file keeps from HEAD_BYTES to EXECUTABLE_HEAD_BYTES, charged first: `part` is the chunk's
   * bytes of the file from offset `written`. A gathered file is copied into it once it has all arrived.
   */
  private keepHead(p: Extract<Pending, { kind: "file" }>, part: Uint8Array, written: number): void {
    const old = p.entry.data;
    const grown = new Uint8Array(Math.min(p.entry.size, EXECUTABLE_HEAD_BYTES));

    if (grown.length <= old.length) return;
    chargeText("tar", grown.length - old.length);
    this.take(grown.length - old.length);
    grown.set(old);

    if (p.gathered === null) {
      // the chunk's bytes past what the first HEAD_BYTES already hold
      const from = Math.max(written, old.length);
      const to = Math.min(written + part.length, grown.length);

      if (to > from) grown.set(part.subarray(from - written, to - written), from);
    }

    p.entry.data = grown;
  }

  private readMeta(p: Extract<Pending, { kind: "meta" }>): void {
    if (p.type === "L") {
      chargeText("tar", p.buf.length);
      this.longName = readString(p.buf, 0, p.buf.length);
    } else this.paxPath = paxPathOf(p.buf, p.at);
  }
}

/**
 * What a streamed read of a tarball came to: its files, or why it stopped. "refused": an archive apm does not read.
 * "spent": the meter ran out. "memory": the memory refused a charge. "changed": it listed other entries than the read it
 * was held to.
 */
export type InflateResult =
  | { kind: "read"; tarball: StreamedTarball }
  | { kind: "refused"; error: ArchiveError }
  | { kind: "spent"; error: MeterExhausted }
  | { kind: "memory"; error: MemoryRefused }
  | { kind: "changed"; error: TarballChanged };

type ReadFailure = ArchiveError | MeterExhausted | MemoryRefused | TarballChanged;

/**
 * Inflates a gzip'd tarball pushed to it a chunk at a time and reads it with TarStream, holding the files `hold` picks.
 * The caller owns the source: it hashes every byte it pushes, and keeps pushing (or hashing alone) after `failed`
 * turns non-null, so it can tell bytes that failed their checksum from an archive that is not valid. Every inflated
 * chunk is charged to `meter` as gunzipCapped charges it, and the inflated stream may be at most `maxUnpackedBytes`.
 */
export class TarballInflater {
  private readonly tar: TarStream;
  private readonly gunzip = new DecompressionStream("gzip");
  private readonly writer = this.gunzip.writable.getWriter();
  private readonly drained: Promise<void>;
  private failure: ReadFailure | null = null;
  private inflated = 0;
  private readonly memory: StreamMemory;
  private inflating = 0;

  constructor(private readonly opts: { hold: HoldRule; look?: LookAt; maxUnpackedBytes: number; meter: Meter } & TarStreamOptions) {
    this.memory = opts.memory ?? UNMETERED;
    this.tar = new TarStream(opts.hold, opts.look, opts);

    // the chunks in flight, charged while the inflate runs
    if (this.memory.take(INFLATE_BYTES)) this.inflating = INFLATE_BYTES;
    else this.failure = new MemoryRefused(`no memory for the inflate's ${INFLATE_BYTES} bytes`);
    this.drained = this.drain();
    // a write the stream refuses once it has failed is recorded by the drain, never left unhandled
    this.writer.closed.catch(() => undefined);
  }

  /** Why the read stopped, once it has: the caller stops pushing (it may go on hashing). */
  get failed(): ReadFailure | null {
    return this.failure;
  }

  /** Pushes the next compressed bytes; resolves once the inflate has taken them. A push after a failure does nothing. */
  async push(chunk: Uint8Array<ArrayBuffer>): Promise<void> {
    if (this.failure !== null) return;

    try {
      await this.writer.write(chunk);
    } catch {
      // the inflate failed: the drain has recorded why
    }
  }

  /** Says the compressed bytes have all been pushed, and gives what they came to. */
  async end(): Promise<InflateResult> {
    if (this.failure === null) {
      try {
        await this.writer.close();
      } catch {
        // the drain records why
      }
    } else {
      // a read that failed before its drain saw the end (a refused charge at the start, say) is ended here, or the
      // drain would wait for bytes that never come
      await this.writer.abort().catch(() => undefined);
    }

    await this.drained;
    this.letGoOfInflate();
    const f = this.failure;

    if (f !== null) return resultOf(f);

    try {
      return { kind: "read", tarball: metered(this.opts.meter, () => this.tar.end()) };
    } catch (e) {
      return this.fail(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private letGoOfInflate(): void {
    this.memory.give(this.inflating);
    this.inflating = 0;
  }

  /** Stops reading: what is still queued is dropped. */
  async abandon(): Promise<void> {
    if (this.failure === null) this.failure = new ArchiveError("invalid", "the read was abandoned");
    await this.writer.abort().catch(() => undefined);
    await this.drained;
    this.letGoOfInflate();
  }

  /**
   * Records why the read stopped: a spent meter, a refused charge, an entry it was not held to, an archive apm refuses,
   * or the inflate's own error (not gzip).
   */
  private fail(e: Error): Exclude<InflateResult, { kind: "read" }> {
    const failure: ReadFailure = e instanceof MeterExhausted || e instanceof MemoryRefused || e instanceof TarballChanged || e instanceof ArchiveError ? e : new ArchiveError("invalid", `not valid gzip: ${e.message}`);
    this.failure = failure;

    return resultOf(failure);
  }

  private async drain(): Promise<void> {
    const reader = this.gunzip.readable.getReader();

    for (;;) {
      let next: Awaited<ReturnType<typeof reader.read>>;

      try {
        next = await reader.read();
      } catch (e) {
        if (this.failure === null) this.fail(e instanceof Error ? e : new Error(String(e)));

        return;
      }

      if (next.done) return;
      const chunk = next.value;
      this.inflated += chunk.length;

      try {
        if (this.inflated > this.opts.maxUnpackedBytes) throw new ArchiveError("too-large", `inflates to more than ${Math.floor(this.opts.maxUnpackedBytes / (1024 * 1024))} MB`);
        metered(this.opts.meter, () => {
          chargeText("gunzip", chunk.length, GUNZIP_PASSES);
          this.tar.push(chunk);
        });
      } catch (e) {
        this.fail(e instanceof Error ? e : new Error(String(e)));
        await reader.cancel().catch(() => undefined);
        await this.writer.abort().catch(() => undefined);

        return;
      }
    }
  }
}

function resultOf(f: ReadFailure): Exclude<InflateResult, { kind: "read" }> {
  if (f instanceof MeterExhausted) return { kind: "spent", error: f };

  if (f instanceof MemoryRefused) return { kind: "memory", error: f };

  if (f instanceof TarballChanged) return { kind: "changed", error: f };

  return { kind: "refused", error: f };
}

/** Paths that appear more than once, or that try to escape the package folder. */
export function ambiguousPaths(entries: readonly TarEntry[]): string[] {
  for (const e of entries) chargeText("tar", e.path.length, 4);
  const seen = new Set<string>();
  const bad = new Set<string>();

  for (const e of entries) {
    const norm = e.path.split("/").filter((s) => s !== "" && s !== ".").join("/");

    if (e.path.startsWith("/") || norm.split("/").includes("..")) bad.add(e.path);

    if (seen.has(norm)) bad.add(norm);
    seen.add(norm);
  }

  return [...bad];
}

export function entryText(e: TarEntry): string {
  return new TextDecoder().decode(e.data);
}
