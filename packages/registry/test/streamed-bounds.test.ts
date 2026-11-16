// The review of ee221e2, registry half: the streamed run trusts nothing a pass sent until its bytes match, bounds what
// it keeps by a memory lease, and meters its planning. Each test failed on ee221e2.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { analyzeStreamedTarball, READ, type ReadLimits, type StreamedAnalysis } from "../src/streamed-analysis.ts";
import type { VersionRecord } from "../src/db.ts";
import type { Digest } from "../src/digest.ts";
import { MemoryPool } from "../src/memory.ts";
import type { OpenedTarball, UpstreamPackage } from "../src/upstream.ts";

const enc = new TextEncoder();

function tar(files: readonly (readonly [string, Uint8Array | string, number?])[]): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [];

  for (const [name, content, declared] of files) {
    const data = content instanceof Uint8Array ? content : enc.encode(content);
    const size = declared ?? data.length;
    const h = new Uint8Array(512);
    const put = (s: string, at: number): void => h.set(enc.encode(s), at);
    put(`package/${name}`, 0);
    put("0000644\0", 100);
    put("0000000\0", 108);
    put("0000000\0", 116);
    put(`${size.toString(8).padStart(11, "0")}\0`, 124);
    put("00000000000\0", 136);
    put("        ", 148);
    put("0", 156);
    put("ustar\0", 257);
    put("00", 263);
    put(`${h.reduce((n, b) => n + b, 0).toString(8).padStart(6, "0")}\0 `, 148);
    parts.push(h, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }

  parts.push(new Uint8Array(1024));

  return Buffer.concat(parts);
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

function body(bytes: Uint8Array): ReadableStream<Uint8Array> {
  let at = 0;

  return new ReadableStream<Uint8Array>({
    pull(c) {
      if (at >= bytes.length) {
        c.close();

        return;
      }

      c.enqueue(bytes.slice(at, at + 65536));
      at += 65536;
    },
  });
}

/** Opens answer `answers[i]` on the i-th open (the last one after that), each claiming `digest` and `length`. */
function opener(answers: readonly Uint8Array[], digest: Digest, length?: number) {
  let opens = 0;

  return {
    opens: () => opens,
    open: async (): Promise<OpenedTarball> => {
      const bytes = answers[Math.min(opens, answers.length - 1)] ?? new Uint8Array();
      opens++;

      return { kind: "stream", body: body(bytes), length: length ?? bytes.length, digest };
    },
  };
}

async function run(args: { answers: readonly Uint8Array[]; digest?: Digest; length?: number; limits?: Partial<ReadLimits>; memoryLimit?: number }): Promise<{ result: StreamedAnalysis; opens: number; peak: number }> {
  const src = opener(args.answers, args.digest ?? sha512(args.answers[0] ?? new Uint8Array()), args.length);
  const pool = new MemoryPool(1 << 30);
  const lease = pool.request(args.memoryLimit ?? 64 * 1024 * 1024);

  try {
    const result = await analyzeStreamedTarball({ pkg, v, digest: args.digest ?? sha512(args.answers[0] ?? new Uint8Array()), open: src.open, plan: { maxWork: 320_000_000 }, limits: { ...READ, ...args.limits }, memory: lease });

    return { result, opens: src.opens(), peak: lease.peakTaken };
  } finally {
    lease.release();
  }
}

const MANIFEST = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "index.js" });

describe("the second pass is held to the first, verified one", () => {
  test("an entry the second answer declares otherwise is refused before it is allocated, and nothing is used", async () => {
    // extra files first fill what the first pass may hold, so the entry's code needs a second pass
    const files: [string, string][] = [];

    for (let i = 0; i < 10; i++) files.push([`extra/x${i}.js`, `module.exports = '${"x".repeat(20_000)}';\n`]);
    files.push(["package.json", MANIFEST], ["index.js", "module.exports = require('./a.js');\n"], ["a.js", `module.exports = '${"a".repeat(30_000)}';\n`]);
    const first = Bun.gzipSync(tar(files));
    // the second answer: a.js now declares 512 MiB
    const second = Bun.gzipSync(tar(files.map(([n, c]) => (n === "a.js" ? ([n, c, 512 * 1024 * 1024] as const) : ([n, c] as const)))));
    const { result, opens, peak } = await run({ answers: [first, second], limits: { holdBytes: 80_000 } });

    expect(opens).toBe(2);
    // on ee221e2: "failed its integrity check", after allocating 536,870,912 bytes for a.js
    expect(result).toEqual({ kind: "fetch-failed", reason: "the tarball's second read listed other files than the first", retryable: true });
    expect(peak).toBeLessThan(8 * 1024 * 1024);
  });
});

describe("a size verdict is stored only once verified bytes show it", () => {
  test("an answer that declares more than apm reads, with bytes that do not match, is a fetch failure to retry", async () => {
    const bytes = Bun.gzipSync(tar([["package.json", MANIFEST], ["index.js", "1"]]));
    const other = sha512(enc.encode("other"));
    const { result } = await run({ answers: [bytes], digest: other, limits: { maxTarballBytes: 64 } });

    // on ee221e2: unscorable, too-large, from the declared length alone
    expect(result).toMatchObject({ kind: "fetch-failed", retryable: true });
  });

  test("the same, with bytes that do match their sha512, is recorded too large", async () => {
    const bytes = Bun.gzipSync(tar([["package.json", MANIFEST], ["index.js", "1"]]));
    const { result } = await run({ answers: [bytes], limits: { maxTarballBytes: 64 } });

    expect(result).toMatchObject({ kind: "unscorable", unscorable: { reason: "too-large" } });
  });
});

describe("what the run keeps comes out of its memory lease", () => {
  test("a lease with no room for the files it would hold is a fetch failure to retry, not a score", async () => {
    const files: [string, string][] = [["package.json", MANIFEST], ["index.js", `module.exports = '${"a".repeat(400_000)}';\n`]];
    const { result, peak } = await run({ answers: [Bun.gzipSync(tar(files))], memoryLimit: 256 * 1024 });

    // on ee221e2 no lease was charged: scored
    expect(result).toMatchObject({ kind: "fetch-failed", retryable: true });
    expect(peak).toBeLessThanOrEqual(256 * 1024);
  });
});

describe("planning runs under the stream's meter", () => {
  test("thousands of export patterns against thousands of files run the meter out, and that is an incomplete analysis", async () => {
    const exports: Record<string, string> = {};

    for (let i = 0; i < 3000; i++) exports[`./e${i}/*`] = `./lib/d${i}/*.js`;
    const files: [string, string][] = [["package.json", JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", exports })]];

    for (let i = 0; i < 3000; i++) files.push([`lib/d${i}/a.js`, "1"]);
    const { result } = await run({ answers: [Bun.gzipSync(tar(files))], limits: { streamWork: 2_000_000 } });

    // on ee221e2 the plan's 9 million comparisons charged nothing: scored, not spent
    expect(result.kind).toBe("scored");

    if (result.kind !== "scored") return;
    expect(result.spent).toBe(true);
    expect(result.analysis.signals.find((s) => s.id === "incomplete")?.evidence[0]).toContain("analysis work limit");
  });
});

describe("the analysis reads the tarball's own package.json, or says it did not", () => {
  // the registry's copy of the manifest, which the run falls back on: here it says nothing, so a fallback shows
  const SWC = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "index.js", os: ["linux"] });
  const addon = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, ...Array.from({ length: 70_000 }, () => 3)]);

  test("a budget of one byte still reads the tarball's package.json, never the registry's copy in its place", async () => {
    const { result } = await run({ answers: [Bun.gzipSync(tar([["package.json", SWC], ["README.md", "# pkg\n"], ["pkg.linux-x64-gnu.node", addon]]))], limits: { holdBytes: 1 } });

    expect(result.kind).toBe("scored");

    if (result.kind !== "scored") return;
    // on e8616ca: license null (the empty fallback manifest), coverage complete, so a read of nothing looked whole
    expect(result.analysis.facts.license).toBe("MIT");
    expect(result.analysis.coverage).toEqual({ kind: "complete" });
  });

  test("a package.json past what apm reads is counted as not read, and the coverage says the registry's copy was used", async () => {
    const huge = JSON.stringify({ name: "pkg", version: "1.0.0", license: "MIT", main: "index.js", description: "d".repeat(4_300_000) });
    const { result } = await run({ answers: [Bun.gzipSync(tar([["package.json", huge], ["index.js", "module.exports = 1;\n"]]))], limits: { holdBytes: 1024 * 1024 } });

    expect(result.kind).toBe("scored");

    if (result.kind !== "scored") return;
    // on e8616ca: coverage complete, the fallback manifest unmentioned
    expect(result.analysis.coverage).toMatchObject({ kind: "partial", omittedFiles: 1, reasons: ["too-large"] });
    expect(result.analysis.coverage?.kind === "partial" ? result.analysis.coverage.notes : []).toContain("the tarball's own package.json was not read, so the registry's copy of its manifest was used in its place");
    expect(result.analysis.skipped.map((s) => s.path)).toEqual(["package.json"]);
  });
});
