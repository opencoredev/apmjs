// The review of ee221e2, core half: what a streamed read keeps is bounded before it is kept, and it refuses what readTar
// refuses. Each test failed on ee221e2.
import { describe, expect, test } from "bun:test";
import { ArchiveError, firstPass, Meter, readTar, TarballInflater, TarStream, type StreamMemory, type TarEntry } from "../src/index.ts";

const enc = new TextEncoder();

function header(name: string, size: number, type: string): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string, at: number): void => h.set(enc.encode(s), at);
  put(name.slice(0, 99), 0);
  put("0000644\0", 100);
  put("0000000\0", 108);
  put("0000000\0", 116);
  put(`${size.toString(8).padStart(11, "0")}\0`, 124);
  put("00000000000\0", 136);
  put("        ", 148);
  put(type, 156);
  put("ustar\0", 257);
  put("00", 263);
  put(`${h.reduce((n, b) => n + b, 0).toString(8).padStart(6, "0")}\0 `, 148);

  return h;
}

const concat = (parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;

  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }

  return out;
};

const pad = (n: number): Uint8Array => new Uint8Array((512 - (n % 512)) % 512);

function errorOf(fn: () => void): string {
  try {
    fn();

    return "ok";
  } catch (e) {
    return e instanceof ArchiveError ? `${e.kind}: ${e.message}` : `other: ${e instanceof Error ? e.name : String(e)}`;
  }
}

function streamed(bytes: Uint8Array): string {
  return errorOf(() => {
    const t = new TarStream(() => "hold");

    t.push(bytes);
    t.end();
  });
}

describe("TarStream refuses a body cut short whatever the entry's type, as readTar does", () => {
  // a symlink (2), a directory with a payload (5), a global PAX header (g) and an unknown type (Z), each declaring 10
  // payload bytes and sending none
  for (const type of ["2", "5", "g", "Z"]) {
    test(`type ${type}`, () => {
      const bytes = concat([header("package/link", 10, type)]);

      const whole = errorOf(() => {
        readTar(bytes);
      });

      // a directory with a payload is refused for having one before its end is looked for, by both readers alike
      const refusal = type === "5" ? "a directory with a 10-byte body at byte 0, which npm and Bun read as more entries" : 'entry "package/link" runs past the end of the archive';

      expect(whole).toBe(`invalid: ${refusal}`);
      // on ee221e2 the stream accepted it: "ok", no files
      expect(streamed(bytes)).toBe(whole);
    });
  }

  test("an ignored entry's payload that arrives whole, padding missing, is accepted by both", () => {
    const bytes = concat([header("package/link", 10, "2"), new Uint8Array(10)]);

    expect(streamed(bytes)).toBe("ok");
    expect(errorOf(() => void readTar(bytes))).toBe("ok");
  });
});

/** A memory that records each charge and refuses past `limit`. */
function meterMemory(limit: number): StreamMemory & { peak: number; largest: number; now: number } {
  const m = {
    now: 0,
    peak: 0,
    largest: 0,
    take(n: number): boolean {
      if (m.now + n > limit) return false;
      m.now += n;
      m.peak = Math.max(m.peak, m.now);
      m.largest = Math.max(m.largest, n);

      return true;
    },
    give(n: number): void {
      m.now -= n;
    },
  };

  return m;
}

async function inflate(tgz: Uint8Array<ArrayBuffer>, opts: ConstructorParameters<typeof TarballInflater>[0]): Promise<Awaited<ReturnType<TarballInflater["end"]>>> {
  const inf = new TarballInflater(opts);

  for (let at = 0; at < tgz.length; at += 4096) await inf.push(tgz.slice(at, at + 4096));

  return inf.end();
}

describe("what a streamed read keeps is charged before it is kept", () => {
  test("file names past MAX_STREAMED_NAMES_BYTES in all are refused as too large", async () => {
    // 12 GNU long names of 1 MiB each: each under the 1 MiB a single name may be, 12 MiB of names together
    const parts: Uint8Array[] = [];

    for (let i = 0; i < 12; i++) {
      const name = enc.encode(`package/${String(i).padStart(2, "0")}${"n".repeat(1024 * 1024 - 20)}\0`);
      parts.push(header("././@LongLink", name.length, "L"), name, pad(name.length), header("x", 1, "0"), new Uint8Array(512));
    }

    parts.push(new Uint8Array(1024));
    const got = await inflate(Bun.gzipSync(concat(parts)), { hold: () => "head", maxUnpackedBytes: 1 << 30, meter: new Meter(1e12) });

    // on ee221e2: read, 12 MiB of names kept
    expect(got.kind).toBe("refused");
    expect(got.kind === "refused" && got.error.kind).toBe("too-large");
  });

  test("a memory that has no room stops the read before the bytes are kept", async () => {
    const big = new Uint8Array(300_000).fill(65);
    const tar = concat([header("package/a.js", big.length, "0"), big, pad(big.length), new Uint8Array(1024)]);
    // room for the inflate's own buffers (INFLATE_BYTES) and not for the file
    const memory = meterMemory(400_000);
    const got = await inflate(Bun.gzipSync(tar), { hold: () => "hold", maxUnpackedBytes: 1 << 30, meter: new Meter(1e12), memory });

    // on ee221e2 there was no memory to charge: read, 300 KB held
    expect(got.kind).toBe("memory");
    expect(memory.peak).toBeLessThanOrEqual(400_000);
    // and what it did charge is given back once the read has ended
    expect(memory.now).toBeLessThanOrEqual(400_000 - 262_144);
  });

  test("a memory with no room even for the inflate ends the read at once", async () => {
    const got = await inflate(Bun.gzipSync(new Uint8Array(1024)), { hold: () => "hold", maxUnpackedBytes: 1 << 30, meter: new Meter(1e12), memory: meterMemory(1000) });

    expect(got.kind).toBe("memory");
  });

  test("a second pass refuses an entry that is not the one the verified first pass listed, before it allocates it", async () => {
    const small = enc.encode("module.exports = 1;\n");
    const first = concat([header("package/a.js", small.length, "0"), small, pad(small.length), new Uint8Array(1024)]);
    const listed = readTar(first).map((f) => ({ path: f.path, size: f.size, mode: f.mode }));
    // the same path, now declaring 512 MiB
    const changed = concat([header("package/a.js", 512 * 1024 * 1024, "0"), new Uint8Array(4096)]);
    const memory = meterMemory(1 << 30);
    const got = await inflate(Bun.gzipSync(changed), { hold: () => "hold", maxUnpackedBytes: 1 << 30, meter: new Meter(1e12), memory, expect: listed });

    expect(got.kind).toBe("changed");
    expect(memory.largest).toBeLessThan(1024 * 1024);
  });
});

describe("the first pass's import graph is bounded", () => {
  test("it stops collecting at its allowance and says so", () => {
    const fp = firstPass({ holdBytes: 1 << 20, lookFileBytes: 1 << 30, lookTotalBytes: 1 << 30, importBytes: 64 * 1024, importEdges: 1000 });
    // 200 files of 100 imports with 100-character paths: 2 MB of import paths, 20,000 edges
    const text = Array.from({ length: 100 }, (_, i) => `require("./${"p".repeat(96)}${String(i).padStart(2, "0")}");`).join("\n");

    for (let i = 0; i < 200; i++) {
      const f: TarEntry = { path: `lib/f${i}.js`, size: text.length, mode: 0o644, data: enc.encode(text) };

      if (fp.hold({ path: f.path, size: f.size }) !== "head") fp.look(f, f.data);
    }

    const chars = [...fp.imports.values()].reduce((n, l) => n + l.reduce((m, p) => m + p.length, 0), 0);
    const edges = [...fp.imports.values()].reduce((n, l) => n + l.length, 0);

    // on ee221e2: 2 MB of paths and 20,000 edges kept, with nothing to say they were cut
    expect(chars).toBeLessThanOrEqual(64 * 1024);
    expect(edges).toBeLessThanOrEqual(1000);
    expect(fp.importsCut).toBe(true);
  });
});
