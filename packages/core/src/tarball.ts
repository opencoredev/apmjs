// Read an npm package tarball (.tgz) into memory. Pure: bytes in, entries out.
import { gunzipSync } from "node:zlib";

export type TarEntry = { path: string; size: number; mode: number; data: Uint8Array };

function readString(buf: Uint8Array, start: number, len: number): string {
  let end = start;
  while (end < start + len && buf[end] !== 0) end++;
  return new TextDecoder().decode(buf.subarray(start, end));
}

function readOctal(buf: Uint8Array, start: number, len: number): number {
  const s = readString(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}

/** Parses a gzip'd tar. Strips the leading "package/" (or any single top dir) from paths. */
export function readTarball(tgz: Uint8Array): TarEntry[] {
  const tar = new Uint8Array(gunzipSync(tgz));
  const entries: TarEntry[] = [];
  let off = 0;
  let longName: string | null = null;
  let paxPath: string | null = null;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const name = readString(header, 0, 100);
    const mode = readOctal(header, 100, 8);
    const size = readOctal(header, 124, 12);
    const type = String.fromCharCode(header[156] ?? 48);
    const prefix = readString(header, 345, 155);
    const dataStart = off + 512;
    const data = tar.subarray(dataStart, dataStart + size);
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
