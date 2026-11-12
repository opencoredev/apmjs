// Read an npm package tarball (.tgz) into memory. Pure: bytes in, entries out.
// Every header is validated and every limit is enforced, so a hostile archive gets a typed
// error, never a hang or an unbounded allocation.
import { gunzipSync } from "node:zlib";

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

/** Inflates gzip, refusing output larger than `maxBytes`. */
export function gunzipCapped(bytes: Uint8Array, maxBytes: number): Uint8Array {
  try {
    return new Uint8Array(gunzipSync(bytes, { maxOutputLength: maxBytes }));
  } catch (e) {
    if (e instanceof RangeError || (hasCode(e) && e.code === "ERR_BUFFER_TOO_LARGE")) {
      throw new ArchiveError("too-large", `inflates to more than ${Math.floor(maxBytes / (1024 * 1024))} MB`);
    }

    throw new ArchiveError("invalid", `not valid gzip: ${e instanceof Error ? e.message : String(e)}`);
  }
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
export function readTar(tar: Uint8Array): TarEntry[] {
  const entries: TarEntry[] = [];
  let off = 0;
  let headers = 0;
  let longName: string | null = null;
  let paxPath: string | null = null;

  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);

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
      longName = readString(data, 0, data.length);
      continue;
    }

    if (type === "x") {
      const text = new TextDecoder().decode(data);
      const m = /\d+ path=([^\n]*)\n/.exec(text);
      paxPath = m?.[1] ?? null;
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
    entries.push({ path: full, size, mode, data: new Uint8Array(data) });
  }

  return entries;
}

/**
 * Parses a gzip'd tar within `maxBytes` (MAX_UNPACKED_BYTES unless a host with less memory passes a lower cap).
 * Throws ArchiveError for anything it will not read.
 */
export function readTarball(tgz: Uint8Array, maxBytes: number = MAX_UNPACKED_BYTES): TarEntry[] {
  return readTar(gunzipCapped(tgz, Math.min(maxBytes, MAX_UNPACKED_BYTES)));
}

/** Paths that appear more than once, or that try to escape the package folder. */
export function ambiguousPaths(entries: readonly TarEntry[]): string[] {
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
