// Read an npm package tarball (.tgz) into memory. Pure: bytes in, entries out.
// Every header is validated and every limit is enforced, so a hostile archive gets a typed
// error, never a hang or an unbounded allocation.
import { gunzipSync } from "node:zlib";
import { chargeText, metered, type Meter } from "./meter.ts";

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
    const slash = full.indexOf("/");
    full = slash >= 0 ? full.slice(slash + 1) : full;
    // the entry's bytes are copied out of the archive
    chargeText("tar", size + full.length);
    entries.push({ path: full, size, mode, data: new Uint8Array(data) });
  }

  return entries;
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
