// Whether a file is a native executable, by its structure, not its first bytes. A magic number alone proves nothing:
// `cf fa ed fe`, a newline and shell commands is a shell script that `sh lib/tool` runs line by line, and treating
// it as a Mach-O hid every command in it (review of 1978ee3, P1). A file is an executable here only when its header
// and every load command (Mach-O) or header table (ELF) parse and lie inside the file. Pure, bounded, no allocation of
// the file. A file a script, `bin` or a command runs through an interpreter is read as source whatever this says
// (score.ts), since an interpreter reads the bytes as text even when the structure is valid.

/**
 * How much of a file a streamed read keeps when its first four bytes are an executable's magic (tarball.ts), so the
 * structure can be checked on a file the read does not hold: a thin Mach-O's header and load commands (2,152 bytes in
 * @typescript/typescript-darwin-arm64's lib/tsc), a universal binary's table and its first slice's, an ELF header.
 */
export const EXECUTABLE_HEAD_BYTES = 64 * 1024;

const MAGICS: readonly (readonly [number, number, number, number])[] = [
  [0x7f, 0x45, 0x4c, 0x46],
  [0xcf, 0xfa, 0xed, 0xfe],
  [0xce, 0xfa, 0xed, 0xfe],
  [0xfe, 0xed, 0xfa, 0xcf],
  [0xfe, 0xed, 0xfa, 0xce],
  [0xca, 0xfe, 0xba, 0xbe],
  [0xca, 0xfe, 0xba, 0xbf],
];

/** Whether `d` starts with an ELF, Mach-O or universal Mach-O magic: worth checking, never proof on its own. */
export function hasExecutableMagic(d: Uint8Array): boolean {
  return MAGICS.some((m) => m.every((b, i) => d[i] === b));
}

/** Load commands, fat slices and ELF headers walked at most: more is not a real binary, and bounds the walk. */
const MAX_LOAD_COMMANDS = 4096;
const MAX_FAT_SLICES = 32;

/** CPU types a Mach-O names (mach/machine.h): x86, ARM, PowerPC, as 32-bit, 64-bit (ABI64) or arm64_32 (ABI64_32). */
function knownCpu(cputype: number): boolean {
  const base = cputype & 0x00ffffff;
  const abi = cputype & 0xff000000;

  return (base === 7 || base === 12 || base === 18) && (abi === 0 || abi === 0x01000000 || abi === 0x02000000);
}

const LC_SEGMENT = 0x1;
const LC_SEGMENT_64 = 0x19;

/**
 * A thin Mach-O at `at` in `data` (a prefix of the file), `size` bytes long: its header, its load commands (each at
 * least 8 bytes, aligned, together exactly `sizeofcmds`), and every segment's file range inside `size`, with at least
 * one segment. False when any of that is not in `data`.
 */
function isThinMachO(data: Uint8Array, at: number, size: number, expectCpu: number | null): boolean {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  if (at + 4 > data.length) return false;
  const m = [data[at], data[at + 1], data[at + 2], data[at + 3]];
  const wide = (m[0] === 0xcf && m[3] === 0xfe) || (m[0] === 0xfe && m[3] === 0xcf);
  const little = m[0] === 0xcf || m[0] === 0xce;

  if (!((m[0] === 0xcf || m[0] === 0xce) && m[1] === 0xfa && m[2] === 0xed && m[3] === 0xfe) && !(m[0] === 0xfe && m[1] === 0xed && m[2] === 0xfa && (m[3] === 0xcf || m[3] === 0xce))) return false;
  const headerSize = wide ? 32 : 28;

  if (at + headerSize > data.length || headerSize > size) return false;
  const u32 = (o: number): number => view.getUint32(at + o, little);
  const cputype = u32(4);
  const filetype = u32(12);
  const ncmds = u32(16);
  const sizeofcmds = u32(20);

  if (!knownCpu(cputype) || (expectCpu !== null && cputype !== expectCpu)) return false;

  if (filetype < 1 || filetype > 12 || ncmds < 1 || ncmds > MAX_LOAD_COMMANDS || sizeofcmds < ncmds * 8 || headerSize + sizeofcmds > size || at + headerSize + sizeofcmds > data.length) return false;
  const align = wide ? 8 : 4;
  const end = headerSize + sizeofcmds;
  let off = headerSize;
  let segments = 0;

  for (let i = 0; i < ncmds; i++) {
    if (off + 8 > end) return false;
    const cmd = u32(off);
    const cmdsize = u32(off + 4);

    if (cmdsize < 8 || cmdsize % align !== 0 || off + cmdsize > end) return false;

    if (cmd === LC_SEGMENT) {
      if (cmdsize < 56) return false;
      segments++;

      if (u32(off + 32) + u32(off + 36) > size) return false;
    } else if (cmd === LC_SEGMENT_64) {
      if (cmdsize < 72) return false;
      segments++;
      const fileoff = Number(view.getBigUint64(at + off + 40, little));
      const filesize = Number(view.getBigUint64(at + off + 48, little));

      if (fileoff + filesize > size) return false;
    }

    off += cmdsize;
  }

  return off === end && segments > 0;
}

/**
 * A universal (fat) Mach-O: a big-endian table of 1 to MAX_FAT_SLICES slices (a Java class file, which shares the magic,
 * has a version of 45 or more where the count is), each a known CPU, aligned, inside the file, not overlapping the
 * table or another slice, and every one a thin Mach-O of that CPU within `data`.
 */
function isFatMachO(data: Uint8Array, size: number): boolean {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  if (data.length < 8) return false;
  const wide = data[3] === 0xbf;
  const n = view.getUint32(4, false);
  const entry = wide ? 32 : 20;
  const table = 8 + n * entry;

  if (n < 1 || n > MAX_FAT_SLICES || table > data.length || table > size) return false;
  const slices: { cpu: number; offset: number; size: number }[] = [];

  for (let i = 0; i < n; i++) {
    const at = 8 + i * entry;
    const cpu = view.getUint32(at, false);
    const offset = wide ? Number(view.getBigUint64(at + 8, false)) : view.getUint32(at + 8, false);
    const length = wide ? Number(view.getBigUint64(at + 16, false)) : view.getUint32(at + 12, false);
    const align = view.getUint32(at + (wide ? 24 : 16), false);

    if (!knownCpu(cpu) || align > 20 || offset < table || offset % 2 ** align !== 0 || length < 28 || offset + length > size) return false;
    slices.push({ cpu, offset, size: length });
  }

  slices.sort((a, b) => a.offset - b.offset);

  for (let i = 1; i < slices.length; i++) {
    const prev = slices[i - 1];
    const next = slices[i];

    if (prev === undefined || next === undefined || prev.offset + prev.size > next.offset) return false;
  }

  // every slice is checked, whole: one the bytes at hand do not reach is not known to be a Mach-O (review of 4ac264b, P2:
  // a streamed read checked the first slice, skipped one past its head, and a shell script in that slice went unread)
  return slices.every((s) => isThinMachO(data.subarray(0, Math.min(data.length, s.offset + s.size)), s.offset, s.size, s.cpu));
}

/**
 * An ELF file: class, byte order and version in its identification, a known file type, the header size its class
 * has, and the program and section header tables (sized as their class has them) inside the file, with the program
 * header table in `data` and every program segment's file range inside the file.
 */
function isElf(data: Uint8Array, size: number): boolean {
  if (data.length < 52) return false;
  const cls = data[4];
  const order = data[5];

  if ((cls !== 1 && cls !== 2) || (order !== 1 && order !== 2) || data[6] !== 1) return false;
  const wide = cls === 2;
  const little = order === 1;

  if (wide && data.length < 64) return false;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const u16 = (o: number): number => view.getUint16(o, little);
  const u32 = (o: number): number => view.getUint32(o, little);
  const word = (o: number): number => (wide ? Number(view.getBigUint64(o, little)) : u32(o));
  const type = u16(16);
  const phoff = word(wide ? 32 : 28);
  const shoff = word(wide ? 40 : 32);
  const base = wide ? 52 : 40;
  const ehsize = u16(base);
  const phentsize = u16(base + 2);
  const phnum = u16(base + 4);
  const shentsize = u16(base + 6);
  const shnum = u16(base + 8);

  if (type < 1 || type > 4 || u32(20) !== 1 || ehsize !== (wide ? 64 : 52) || phnum > MAX_LOAD_COMMANDS) return false;

  if (phnum === 0 && type !== 1) return false;

  if (phnum > 0 && (phentsize !== (wide ? 56 : 32) || phoff < ehsize || phoff + phnum * phentsize > size)) return false;

  if (shnum > 0 && (shentsize !== (wide ? 64 : 40) || shoff + shnum * shentsize > size)) return false;

  // the program headers are checked, so they must be at hand: a table past the bytes kept proves nothing (review of
  // 4ac264b, P2)
  if (phnum > 0 && phoff + phnum * phentsize > data.length) return false;

  if (phnum > 0) {
    for (let i = 0; i < phnum; i++) {
      const at = phoff + i * phentsize;
      const offset = word(at + (wide ? 8 : 4));
      const filesz = word(at + (wide ? 32 : 16));

      if (offset + filesz > size) return false;
    }
  }

  return true;
}

/**
 * Whether a file is a native executable by its structure: an ELF file, a thin Mach-O or a universal Mach-O whose
 * headers parse and lie inside the file. `data` is the file, or its first bytes (a streamed read keeps
 * EXECUTABLE_HEAD_BYTES of a file that starts with a magic); `size` its whole size. What `data` does not show is not
 * taken on trust: a check that needs bytes past it is false, and the file is read, or reported unread, as any other.
 */
export function isExecutable(data: Uint8Array, size: number): boolean {
  if (data.length < 4 || size < data.length || !hasExecutableMagic(data)) return false;

  if (data[0] === 0x7f) return isElf(data, size);

  if (data[0] === 0xca) return isFatMachO(data, size);

  return isThinMachO(data, 0, size, null);
}

/** Names node and the platforms load as native code, whatever the bytes. */
export const NATIVE_NAME = /\.(?:node|exe|dll|so|dylib)$/;

/** Images, fonts, archives, PDFs and WebAssembly, by their first bytes: data, never code node or a shell reads as such. */
export function hasDataMagic(d: Uint8Array): boolean {
  if (d.length < 4) return false;
  const b = (i: number): number => d[i] ?? -1;
  const ascii = (s: string, at = 0): boolean => [...s].every((c, i) => b(at + i) === c.charCodeAt(0));

  return (
    (b(0) === 0x89 && ascii("PNG", 1)) ||
    (b(0) === 0xff && b(1) === 0xd8 && b(2) === 0xff) ||
    ascii("GIF8") ||
    (ascii("RIFF") && ascii("WEBP", 8)) ||
    ascii("wOFF") ||
    ascii("wOF2") ||
    ascii("OTTO") ||
    (b(0) === 0 && b(1) === 1 && b(2) === 0 && b(3) === 0) ||
    (b(0) === 0 && ascii("asm", 1)) ||
    (b(0) === 0x1f && b(1) === 0x8b) ||
    (ascii("PK") && b(2) === 3 && b(3) === 4) ||
    ascii("%PDF")
  );
}

/**
 * Whether a file may be one the analysis does not read as code, by its name or first bytes (a native name, an executable
 * or a data magic): the files whose shell-runnable text a streamed read scans as it passes (binary-text.ts), since it
 * holds only their first bytes.
 */
export function looksBinary(path: string, head: Uint8Array): boolean {
  return NATIVE_NAME.test(path) || hasExecutableMagic(head) || hasDataMagic(head);
}

/**
 * Whether production (274d284) read a file as text when nothing ran it as a script, by its name and first bytes: not a
 * native name, not an ELF file (its check matched ELF and no other executable), not data. A Mach-O or a universal
 * binary it read as text. Only these files' text is read when they are read as binary (binary-text.ts): exactly as
 * production decoded it. A file production never read is not read here either.
 */
export function readAsTextBefore(path: string, head: Uint8Array): boolean {
  return !nativeBefore(path, head) && !hasDataMagic(head);
}

/**
 * Production's (274d284) isBinary, exactly: a native name (`.node`, `.exe`, `.dll`, `.so`, `.dylib`) or ELF's magic.
 * It joined the four bytes with `<<` into a signed 32-bit number, so its Mach-O and universal magics never matched, and
 * its `MZ` check held only for a name ending `.exe`, which the name already matched. Production listed such a file as
 * `binary` and read none of it, whoever loaded or ran it.
 */
export function nativeBefore(path: string, head: Uint8Array): boolean {
  return NATIVE_NAME.test(path) || (head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46);
}
