// Minimal native executables whose structure parses (executable.ts), for tests: a thin Mach-O (32 or 64 bit, either
// byte order) with one segment that covers the file, a universal Mach-O of such slices, and an ELF file with one
// loadable segment. `tail` is what follows the headers: filler, or a shell script (a polyglot an interpreter runs).

const CPU_ARM64 = 0x0100000c;
const CPU_X86_64 = 0x01000007;
const CPU_X86 = 7;

/** A thin Mach-O of `size` bytes (at least the headers), `tail` written after its load commands. */
export function machO(opts: { size: number; wide?: boolean; little?: boolean; cpu?: number; tail?: Uint8Array }): Uint8Array {
  const wide = opts.wide ?? true;
  const little = opts.little ?? true;
  const header = wide ? 32 : 28;
  const segment = wide ? 72 : 56;
  const out = new Uint8Array(Math.max(opts.size, header + segment + (opts.tail?.length ?? 0)));
  const view = new DataView(out.buffer);
  const magic = wide ? 0xfeedfacf : 0xfeedface;

  view.setUint32(0, magic, little);
  view.setUint32(4, opts.cpu ?? (wide ? CPU_ARM64 : CPU_X86), little);
  view.setUint32(8, 0, little);
  view.setUint32(12, 2, little); // MH_EXECUTE
  view.setUint32(16, 1, little); // one load command
  view.setUint32(20, segment, little);
  view.setUint32(24, 0x200085, little);

  if (wide) {
    view.setUint32(header, 0x19, little); // LC_SEGMENT_64
    view.setUint32(header + 4, segment, little);
    out.set(new TextEncoder().encode("__TEXT"), header + 8);
    view.setBigUint64(header + 40, 0n, little);
    view.setBigUint64(header + 48, BigInt(out.length), little);
  } else {
    view.setUint32(header, 0x1, little); // LC_SEGMENT
    view.setUint32(header + 4, segment, little);
    out.set(new TextEncoder().encode("__TEXT"), header + 8);
    view.setUint32(header + 32, 0, little);
    view.setUint32(header + 36, out.length, little);
  }

  if (opts.tail) out.set(opts.tail, header + segment);

  return out;
}

/** A universal Mach-O: a big-endian table, then each slice at a 4096-byte boundary. */
export function fatMachO(opts: { slices: Uint8Array[]; cpus?: number[]; wide?: boolean }): Uint8Array {
  const wide = opts.wide ?? false;
  const entry = wide ? 32 : 20;
  const align = 12;
  let at = Math.ceil((8 + opts.slices.length * entry) / 4096) * 4096;
  const offsets: number[] = [];

  for (const s of opts.slices) {
    offsets.push(at);
    at = Math.ceil((at + s.length) / 4096) * 4096;
  }

  const out = new Uint8Array(at);
  const view = new DataView(out.buffer);
  view.setUint32(0, wide ? 0xcafebabf : 0xcafebabe, false);
  view.setUint32(4, opts.slices.length, false);

  opts.slices.forEach((s, i) => {
    const e = 8 + i * entry;
    const offset = offsets[i] ?? 0;
    view.setUint32(e, opts.cpus?.[i] ?? CPU_ARM64, false);

    if (wide) {
      view.setBigUint64(e + 8, BigInt(offset), false);
      view.setBigUint64(e + 16, BigInt(s.length), false);
      view.setUint32(e + 24, align, false);
    } else {
      view.setUint32(e + 8, offset, false);
      view.setUint32(e + 12, s.length, false);
      view.setUint32(e + 16, align, false);
    }

    out.set(s, offset);
  });

  return out;
}

/** A 64-bit little-endian ELF executable of `size` bytes with one PT_LOAD segment covering it. */
export function elf(opts: { size: number; tail?: Uint8Array }): Uint8Array {
  const out = new Uint8Array(Math.max(opts.size, 120 + (opts.tail?.length ?? 0)));
  const view = new DataView(out.buffer);
  out.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  view.setUint16(16, 2, true); // ET_EXEC
  view.setUint16(18, 0x3e, true);
  view.setUint32(20, 1, true);
  view.setBigUint64(32, 64n, true); // e_phoff
  view.setBigUint64(40, 0n, true);
  view.setUint16(52, 64, true);
  view.setUint16(54, 56, true);
  view.setUint16(56, 1, true);
  view.setUint32(64, 1, true); // PT_LOAD
  view.setBigUint64(64 + 8, 0n, true);
  view.setBigUint64(64 + 32, BigInt(out.length), true);

  if (opts.tail) out.set(opts.tail, 120);

  return out;
}

export { CPU_ARM64, CPU_X86, CPU_X86_64 };
