// The streamed run (streamed-analysis.ts) on tarballs made here and served from memory: nothing it read is used until
// every byte matched the version's sha512 and the declared length, a source that fails or stalls is a fetch failure to
// retry, the limits refuse what they say, and a package whose code is over the budget is scored incomplete, never
// clean. streamed-analysis.workerd.test.ts measures the same run inside workerd on real tarballs.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { analyzeStreamedTarball, READ, type ReadLimits, type StreamedAnalysis } from "../src/streamed-analysis.ts";
import type { VersionRecord } from "../src/db.ts";
import type { Digest } from "../src/digest.ts";
import type { OpenedTarball, UpstreamPackage } from "../src/upstream.ts";
import { MemoryPool } from "../src/memory.ts";

/** A lease with room for anything these tarballs keep, as a queue job's is. */
const lease = () => new MemoryPool(1 << 30).request(256 * 1024 * 1024);

const enc = new TextEncoder();

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
