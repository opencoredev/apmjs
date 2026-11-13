// The streaming packument reader (src/packument-read.ts): it accepts exactly what JSON.parse accepts, discarded regions
// included, keeps what JSON.parse gives minus the fields it drops however the bytes are split, resolves duplicate keys
// as JSON.parse does, and refuses a packument past any of its bounds (read, kept bytes, kept nodes, depth, a shared
// budget) instead of holding it.
import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import {
  DEV_DEPENDENCIES,
  DROPPED_VERSION_FIELDS,
  MAX_KEPT_PACKUMENT_NODES,
  MAX_PACKUMENT_DEPTH,
  MAX_PACKUMENT_WEIGHT,
  READ_OVERHEAD_WEIGHT,
  readPackument as readUnder,
  SLAB_BYTES,
  type JsonValue,
  type KeptPackument,
  type PackumentLimits,
  type PackumentRead,
  type ReadOptions,
} from "../src/packument-read.ts";
import { MemoryPool, type Lease } from "../src/memory.ts";

/** A lease with no limit, in a pool of its own: for a read that tests the reader's own bounds. */
const unlimited = (): Lease => new MemoryPool(Number.POSITIVE_INFINITY).request(Number.POSITIVE_INFINITY);

/** readPackument under `options.lease`, or an unlimited one. */
const readPackument = (body: ReadableStream<Uint8Array>, options: Partial<ReadOptions> = {}): Promise<PackumentRead> => readUnder(body, { ...options, lease: options.lease ?? unlimited() });

/** A request lease of `limit` for what reads keep, beside what each of `reads` holds while it runs, in a pool that has room. */
const leaseOf = (limit: number, reads = 1): Lease => new MemoryPool(Number.POSITIVE_INFINITY).request(limit + reads * READ_OVERHEAD_WEIGHT);

const LIMITS: PackumentLimits = { maxBytes: 10_000_000, maxKeptBytes: 1_000_000, maxKeptNodes: 100_000, maxWeight: 100_000_000, maxDepth: 1_000 };

function streamOf(text: string | Uint8Array, chunk: number): ReadableStream<Uint8Array> {
  const bytes = text instanceof Uint8Array ? text : new TextEncoder().encode(text);
  let at = 0;

  return new ReadableStream({
    pull(c) {
      if (at >= bytes.length) {
        c.close();

        return;
      }

      c.enqueue(bytes.slice(at, at + chunk));
      at += chunk;
    },
  });
}

const TOP = ["name", "dist-tags", "versions", "time", "description", "readme", "maintainers"];

type JsonObject = { readonly [key: string]: JsonValue };

/** A JSON value that is an object, not an array: JSON.parse's objects are instances of Object, its strings are not. */
const isJsonObject = (v: JsonValue): v is JsonObject => v instanceof Object && !Array.isArray(v);

/**
 * What the reader should keep: JSON.parse of the packument, its top-level fields and versions minus the dropped
 * fields. Built from JSON.parse's own value with Object.entries and Object.fromEntries (never a schema, which would
 * rebuild objects and drop a `__proto__` key), so duplicate keys resolve exactly as JSON.parse resolves them.
 */
function expected(packument: JsonValue): KeptPackument {
  if (!isJsonObject(packument)) throw new Error("not an object");
  const out: { [field: string]: JsonValue } = Object.fromEntries(Object.entries(packument).filter(([k]) => TOP.includes(k)));
  const versions = out.versions;

  if (versions !== undefined && isJsonObject(versions)) {
    out.versions = Object.fromEntries(
      Object.entries(versions).map(([v, d]) => [v, isJsonObject(d) ? Object.fromEntries(Object.entries(d).filter(([f]) => !DROPPED_VERSION_FIELDS.has(f))) : d]),
    );
  }

  return out;
}

/**
 * What the DEV_DEPENDENCIES profile should keep: JSON.parse's `versions` as it is when it is not an object, else each
 * version that is an object with only its devDependencies, and no version that is not one.
 */
function expectedDev(packument: JsonValue): KeptPackument {
  if (!isJsonObject(packument)) throw new Error("not an object");
  const versions = packument.versions;

  if (versions === undefined) return {};

  if (!isJsonObject(versions)) return { versions };

  return {
    versions: Object.fromEntries(
      Object.entries(versions)
        .filter(([, d]) => isJsonObject(d))
        .map(([v, d]) => [v, isJsonObject(d) ? Object.fromEntries(Object.entries(d).filter(([f]) => f === "devDependencies")) : d]),
    ),
  };
}

/** What res.text() and JSON.parse made of these bytes before the reader: the value, or not ok when JSON.parse throws. */
function oracle(bytes: Uint8Array): { ok: true; value: JsonValue } | { ok: false } {
  try {
    // JSON.parse of text only ever gives a JSON value
    const value: JsonValue = JSON.parse(new TextDecoder().decode(bytes));

    return { ok: true, value };
  } catch {
    return { ok: false };
  }
}

const PACKUMENT = {
  _id: "pkg",
  _rev: "12-abc",
  name: "pkg",
  "dist-tags": { latest: "1.1.0", next: "2.0.0-beta.1" },
  description: 'a package with "quotes", a \\ backslash, a   separator and é',
  readme: "# pkg\n\n```js\nconst a = { b: [1, 2] };\n```\n",
  maintainers: [{ name: "a", email: "a@example.invalid" }],
  users: { someone: true },
  time: { created: "2020-01-01T00:00:00.000Z", "1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2021-01-01T00:00:00.000Z" },
  versions: {
    "1.0.0": {
      name: "pkg",
      version: "1.0.0",
      dist: { tarball: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", shasum: "00", integrity: "sha512-AA==" },
      dependencies: { dep: "^1.0.0" },
      devDependencies: { tap: "^16.0.0" },
      licenseText: "MIT License {[\"x\"]}\n".repeat(50),
      readme: "old readme with } and ] and \\\" in it",
      scripts: { postinstall: "node install.js" },
      _npmUser: { name: "a" },
      deprecated: false,
      n: -1.5e3,
      t: true,
      z: null,
    },
    "1.1.0": { name: "pkg", version: "1.1.0", dist: { tarball: "https://registry.npmjs.org/pkg/-/pkg-1.1.0.tgz" }, bin: { pkg: "cli.js" }, readmeFilename: "README.md", "": "", __proto__x: 1 },
    "2.0.0-beta.1": { name: "pkg", version: "2.0.0-beta.1", dist: { tarball: "x" }, nested: { deep: [[[{ a: "}" }]]] }, devDependencies: {} },
  },
};

describe("readPackument", () => {
  for (const chunk of [1, 3, 64, 1 << 20]) {
    test(`keeps exactly the fields it reads, in chunks of ${chunk} bytes`, async () => {
      const text = JSON.stringify(PACKUMENT, null, chunk % 2 === 0 ? 2 : undefined);
      const r = await readPackument(streamOf(text, chunk), { limits: LIMITS });

      expect(r.kind).toBe("ok");

      if (r.kind !== "ok") return;
      expect(r.body).toEqual(expected(PACKUMENT));
      expect(r.bytes).toBe(new TextEncoder().encode(text).length);
      // the license text was read past, never kept
      expect(r.keptBytes).toBeLessThan(text.length - 50 * 20);
    });
  }

  test("the devDependencies profile keeps each version's devDependencies and nothing else", async () => {
    const r = await readPackument(streamOf(JSON.stringify(PACKUMENT), 7), { limits: LIMITS, profile: DEV_DEPENDENCIES });

    expect(r).toMatchObject({ kind: "ok", body: { versions: { "1.0.0": { devDependencies: { tap: "^16.0.0" } }, "1.1.0": {}, "2.0.0-beta.1": { devDependencies: {} } } } });
    expect(Object.keys(r.kind === "ok" ? r.body : {})).toEqual(["versions"]);
  });

  test("a key named __proto__ is an own property, not the prototype", async () => {
    const text = '{"name":"p","versions":{"1.0.0":{"name":"p","version":"1.0.0","__proto__":{"polluted":true},"dist":{"tarball":"t"}}}}';
    const r = await readPackument(streamOf(text, 5), { limits: LIMITS });

    expect(r.kind).toBe("ok");

    if (r.kind !== "ok") return;
    // read without a schema: zod rebuilds objects and drops a __proto__ key itself
    const v = Object.values(r.body.versions ?? {})[0];

    expect(Object.getPrototypeOf(v)).toBe(Object.prototype);
    expect(Object.keys(v ?? {})).toContain("__proto__");
    expect("polluted" in {}).toBe(false);
  });

  test("past the read cap it stops reading and says how far it got", async () => {
    const text = JSON.stringify({ name: "big", versions: {}, filler: "x".repeat(5_000) });
    const r = await readPackument(streamOf(text, 1000), { limits: { ...LIMITS, maxBytes: 2_000 } });

    expect(r).toMatchObject({ kind: "too-large", over: "read", limit: 2_000 });
    // it stopped at the first chunk past the cap, not at the end
    expect(r.kind === "too-large" ? r.bytes : 0).toBe(3_000);
  });

  test("a packument that would keep more than the kept cap is refused, though dropped fields do not count", async () => {
    const versions = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`1.0.${i}`, { name: "big", version: `1.0.${i}`, dist: { tarball: "t" }, licenseText: "L".repeat(10_000) }]));
    const text = JSON.stringify({ name: "big", versions });
    const small = { ...LIMITS, maxBytes: 1_000_000, maxKeptBytes: 10_000 };

    // 200 KB of license text, all dropped: well under a 10 KB kept cap
    expect((await readPackument(streamOf(text, 4096), { limits: small })).kind).toBe("ok");

    const kept = JSON.stringify({ name: "big", description: "D".repeat(20_000), versions });

    expect(await readPackument(streamOf(kept, 4096), { limits: small })).toMatchObject({ kind: "too-large", over: "kept", limit: 10_000 });
  });

  // Review of 89441a9, finding 1: every container got a frame, discarded ones included, with no bound, so 1,000
  // nested discarded arrays passed a 64-byte kept limit (and a 160 MB run of `[` would have taken a frame per byte)
  test("nesting past the depth cap is refused, in a discarded field too, before it is held", async () => {
    const nested = (n: number): string => `{"name":"p","versions":{},"users":${"[".repeat(n)}${"]".repeat(n)}}`;
    const tight = { ...LIMITS, maxKeptBytes: 64, maxDepth: 500 };

    expect(await readPackument(streamOf(nested(1_000), 97), { limits: tight })).toMatchObject({ kind: "too-large", over: "depth", limit: 500 });
    // under the cap it is read, and nothing of the discarded field is kept
    expect(await readPackument(streamOf(nested(400), 97), { limits: tight })).toMatchObject({ kind: "ok", body: { name: "p", versions: {} } });
    // the default cap: a run of brackets deeper than any real packument stops at MAX_PACKUMENT_DEPTH
    const deep = await readPackument(streamOf(nested(MAX_PACKUMENT_DEPTH + 10), 65_536));

    expect(deep).toMatchObject({ kind: "too-large", over: "depth", limit: MAX_PACKUMENT_DEPTH });
  });

  test("a kept field cheap as text and dear as objects is refused at the node cap", async () => {
    const arrays = `{"name":"p","versions":{"1.0.0":{"name":"p","version":"1.0.0","dist":{"tarball":"t"},"x":[${Array.from({ length: 5_000 }, () => "[]").join(",")}]}}}`;

    // 15 KB of text: under the kept bytes cap, past 1,000 nodes
    expect(await readPackument(streamOf(arrays, 512), { limits: { ...LIMITS, maxKeptNodes: 1_000 } })).toMatchObject({ kind: "too-large", over: "nodes", limit: 1_000 });
    // the same arrays in a dropped field are only read past
    const dropped = arrays.replace('"x":', '"readme":');

    expect((await readPackument(streamOf(dropped, 512), { limits: { ...LIMITS, maxKeptNodes: 1_000 } })).kind).toBe("ok");
  });

  // Review of f0e533a, finding 3: a version a profile does not keep (not an object, under DEV_DEPENDENCIES) left an
  // earlier one of the same key in place, where JSON.parse gives the later
  test("a later version of the same key replaces an earlier one, whatever its type, under both profiles", async () => {
    for (const text of [
      '{"versions":{"1.0.0":{"devDependencies":{"old":"1"}},"1.0.0":null}}',
      '{"versions":{"1.0.0":{"devDependencies":{"old":"1"}},"2.0.0":{},"1.0.0":"x","1.0.0":[1]}}',
      '{"versions":{"1.0.0":{"devDependencies":{"old":"1"}},"1.0.0":null,"1.0.0":{"devDependencies":{"new":"2"}}}}',
    ]) {
      const want = JSON.parse(text);

      expect(await readPackument(streamOf(text, 3), { limits: LIMITS, profile: DEV_DEPENDENCIES })).toMatchObject({ kind: "ok", body: expectedDev(want) });
      expect(await readPackument(streamOf(text, 3), { limits: LIMITS })).toMatchObject({ kind: "ok", body: expected(want) });
    }

    const dev = await readPackument(streamOf('{"versions":{"1.0.0":{"devDependencies":{"old":"1"}},"1.0.0":null}}', 5), { limits: LIMITS, profile: DEV_DEPENDENCIES });

    expect(dev.kind === "ok" ? dev.body : null).toEqual({ versions: {} });
  });

  // Review of f0e533a, finding 2: each fragment of a kept part was kept as its own Uint8Array, so a string sent a
  // byte at a time cost a typed array a byte (the heap is measured in packument-heap.workerd.test.ts)
  test("kept parts longer than a slab, sent a byte at a time and in odd pieces, are read whole", async () => {
    const long = "é€😀x".repeat(Math.ceil((2.5 * SLAB_BYTES) / 10));
    const versions = { "1.0.0": { name: "p", version: "1.0.0", dist: { tarball: "t" }, list: Array.from({ length: 30_000 }, (_, i) => ({ [`k${i % 7}`]: i })) } };
    const text = JSON.stringify({ name: "p", description: long, versions });

    for (const chunk of [1, 7, SLAB_BYTES - 1, SLAB_BYTES + 1]) {
      expect(await readPackument(streamOf(text, chunk), { limits: { ...LIMITS, maxBytes: 2e7, maxKeptBytes: 1e7 } })).toMatchObject({ kind: "ok", body: expected(JSON.parse(text)) });
    }
  });

  // Review of f0e533a, finding 1: kept bytes alone were charged, so a packument cheap as text and dear as objects
  // (1.49 million empty arrays: 4.5 MB of text, 30 MB of heap) was read and held
  test("a packument whose parsed weight passes MAX_PACKUMENT_WEIGHT is refused, under the node cap", async () => {
    const count = 1_490_000;
    const text = `{"name":"p","versions":{"1.0.0":{"name":"p","version":"1.0.0","dist":{"tarball":"t"},"x":[${"[],".repeat(count - 1)}[]]}}}`;
    const r = await readPackument(streamOf(text, 65_536));

    expect(count).toBeLessThan(MAX_KEPT_PACKUMENT_NODES);
    expect(r).toMatchObject({ kind: "too-large", over: "weight", limit: MAX_PACKUMENT_WEIGHT });
  });

  test("reads in flight together share a budget, and a refused one gives back what it took", async () => {
    const one = (n: number): string => JSON.stringify({ name: `p${n}`, description: "D".repeat(30_000), versions: {} });
    // alone, one read holds its 30 KB description as text and as the string it is parsed into, and twice more while it
    // is parsed: 120 KB at that moment, and what it holds after, 30 KB, is all it keeps taken
    const alone = leaseOf(125_000);

    expect((await readPackument(streamOf(one(0), 1_024), { limits: LIMITS, lease: alone })).kind).toBe("ok");
    expect(alone.taken).toBeLessThan(31_000);
    expect((await readPackument(streamOf(one(0), 1_024), { limits: LIMITS, lease: leaseOf(115_000) })).kind).toBe("too-large");
    // three in step hold one another's text: the first to parse finds no room. A refused read keeps its charge until
    // its stream's cancel has settled (review of 747a032, finding 2), so in step the others may find none either
    const budget = leaseOf(160_000, 3);
    const reads = await Promise.all([1, 2, 3].map((n) => readPackument(streamOf(one(n), 1_024), { limits: LIMITS, lease: budget })));

    expect(reads.filter((r) => r.kind === "too-large").length).toBeGreaterThanOrEqual(1);
    expect(reads.find((r) => r.kind === "too-large")).toMatchObject({ over: "budget", limit: 160_000 + 3 * READ_OVERHEAD_WEIGHT });
    // the ones that were kept stay taken, at what they weigh now; the refused ones' partial takes were given back
    const kept = reads.reduce((n, r) => n + (r.kind === "ok" ? r.weight : 0), 0);

    expect(budget.taken).toBe(kept);
    expect(kept).toBeLessThan(2 * 31_000);
    // one after another, two fit where three in step did not
    const after = leaseOf(160_000, 2);

    for (const n of [4, 5]) expect((await readPackument(streamOf(one(n), 1_024), { limits: LIMITS, lease: after })).kind).toBe("ok");
  });

  test("a refused read keeps its charge until its stream's cancel has settled, then gives all of it back", async () => {
    // review of 747a032, finding 2: the charge was given back before the cancel was awaited, while the scanner still
    // referred to what it had read
    const lease = leaseOf(1_000_000);
    let cancelStarted = (): void => undefined;
    let finishCancel = (): void => undefined;
    const started = new Promise<void>((r) => (cancelStarted = r));
    const stalled = new Promise<void>((r) => (finishCancel = r));
    let step = 0;

    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        if (step++ === 0) c.enqueue(new TextEncoder().encode(`{"name":"p","readme":"${"x".repeat(100_000)}","versions":{}}!`));
      },
      cancel() {
        cancelStarted();

        return stalled;
      },
    });

    const pending = readPackument(body, { limits: LIMITS, lease });

    await started;
    // what the read took is still charged while the cancel runs
    expect(lease.taken).toBeGreaterThan(100_000 + READ_OVERHEAD_WEIGHT);
    finishCancel();

    expect((await pending).kind).toBe("invalid");
    expect(lease.taken).toBe(0);
  });

  test("an aborted read cancels its stream, waits for that, and gives every charge back before it rejects", async () => {
    const lease = leaseOf(1_000_000);
    const abort = new AbortController();
    let cancelled = false;
    let reached = (): void => undefined;
    const parked = new Promise<void>((r) => (reached = r));
    let step = 0;

    const body = new ReadableStream<Uint8Array>({
      async pull(c) {
        if (step++ === 0) {
          c.enqueue(new TextEncoder().encode(`{"name":"p","versions":{},"readme":"${"x".repeat(100_000)}`));

          return;
        }

        reached();
        await new Promise(() => undefined);
      },
      async cancel() {
        await Bun.sleep(5);
        cancelled = true;
      },
    });

    const pending = readPackument(body, { limits: LIMITS, lease, signal: abort.signal });

    await parked;
    expect(lease.taken).toBeGreaterThan(100_000);
    abort.abort(new Error("stopped"));

    await expect(pending).rejects.toThrow("stopped");
    expect([cancelled, lease.taken]).toEqual([true, 0]);
  });

  for (const [what, text] of [
    ["an array", "[1,2]"],
    ["a truncated object", '{"name":"p","versions":{"1.0.0":{"name"'],
    ["two objects", '{"name":"p"}{"name":"q"}'],
    ["unbalanced brackets", '{"name":"p","versions":{"1.0.0":{]}}'],
    ["nothing", ""],
    ["only whitespace", "  \n"],
  ] as const) {
    test(`${what} is invalid`, async () => {
      expect((await readPackument(streamOf(text, 2), { limits: LIMITS })).kind).toBe("invalid");
    });
  }

  // Review of 89441a9, finding 2: the scanner only balanced brackets and quotes, so JSON.parse's errors inside a
  // discarded field were accepted. Each of these is placed in a discarded field, a dropped version field and a kept one.
  const BAD_VALUES = [
    "[1,2,]",
    '{"a":1,}',
    '"\\x"',
    '"\\u12g4"',
    "undefined",
    "NaN",
    "Infinity",
    "-Infinity",
    "01",
    "1.",
    ".5",
    "-",
    "+1",
    "1e",
    "1e+",
    "'single'",
    '"a\u0001b"',
    '"tab\there"',
    "[1 2]",
    '{"a" 1}',
    '{"a":1 "b":2}',
    "{a:1}",
    "tru",
    "nul",
    "falsey",
    "[,1]",
    "{,}",
    "/* comment */ 1",
    '{"a":1}}',
    "[1]]",
    '"unterminated',
  ];

  for (const bad of BAD_VALUES) {
    test(`invalid JSON is refused wherever it sits: ${bad}`, async () => {
      for (const text of [
        `{"name":"p","users":${bad},"versions":{}}`,
        `{"name":"p","versions":{"1.0.0":{"name":"p","licenseText":${bad}}}}`,
        `{"name":"p","versions":{"1.0.0":{"name":"p","dependencies":${bad}}}}`,
      ]) {
        expect(oracle(new TextEncoder().encode(text)).ok).toBe(false);
        expect({ text, kind: (await readPackument(streamOf(text, 3), { limits: LIMITS })).kind }).toEqual({ text, kind: "invalid" });
      }
    });
  }

  test("duplicate keys resolve as JSON.parse resolves them: the last one wins, `versions` included", async () => {
    const text = [
      '{"name":"first","versions":{"1.0.0":{"name":"p","version":"1.0.0","dist":{"tarball":"a"}}},',
      '"name":"p","versions":{"2.0.0":{"name":"p","version":"2.0.0","dist":{"tarball":"b"},"dependencies":{"x":"1"},"dependencies":{"y":"2"}},"2.0.0":{"name":"p","version":"2.0.0","dist":{"tarball":"c"}}}}',
    ].join("");

    const r = await readPackument(streamOf(text, 11), { limits: LIMITS });
    const want = expected(JSON.parse(text));

    expect(r).toMatchObject({ kind: "ok", body: want });
    // on 89441a9 the two `versions` objects were merged: 1.0.0 was still listed
    expect(r.kind === "ok" ? Object.keys(z.record(z.string(), z.unknown()).parse(r.body.versions)) : []).toEqual(["2.0.0"]);
    expect(want.versions).toEqual({ "2.0.0": { name: "p", version: "2.0.0", dist: { tarball: "c" } } });
  });

  test("a later `versions` that is not an object replaces an earlier object, and the other way round", async () => {
    for (const text of ['{"name":"p","versions":{"1.0.0":{"name":"p"}},"versions":"none"}', '{"name":"p","versions":"none","versions":{"1.0.0":{"name":"p"}}}']) {
      expect(await readPackument(streamOf(text, 4), { limits: LIMITS })).toMatchObject({ kind: "ok", body: expected(JSON.parse(text)) });
    }
  });

  test("a leading byte order mark is skipped, as res.text() skips it; one anywhere else is refused", async () => {
    const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"name":"p","versions":{}}')]);

    expect(await readPackument(streamOf(bom, 1), { limits: LIMITS })).toMatchObject({ kind: "ok", body: { name: "p", versions: {} } });
    const late = new Uint8Array([...new TextEncoder().encode(" "), ...bom]);

    expect(oracle(late).ok).toBe(false);
    expect((await readPackument(streamOf(late, 1), { limits: LIMITS })).kind).toBe("invalid");
  });

  test("vite's shape: every version repeating a long licenseText keeps under a tenth of the bytes", async () => {
    const versions = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`5.${i}.0`, { name: "vite", version: `5.${i}.0`, dist: { tarball: "t", integrity: "sha512-AA==" }, dependencies: { esbuild: "^0.21.3" }, licenseText: "# Vite core license\n".repeat(2_300) }]));
    const text = JSON.stringify({ name: "vite", "dist-tags": { latest: "5.199.0" }, versions });
    const r = await readPackument(streamOf(text, 65_536), { limits: { ...LIMITS, maxBytes: 20_000_000 } });

    expect(r.kind).toBe("ok");

    if (r.kind !== "ok") return;
    expect(r.keptBytes / r.bytes).toBeLessThan(0.1);
    expect(r.body).toEqual(expected(JSON.parse(text)));
  });
});

// ---------- fuzz: the reader against JSON.parse ----------

/** A small deterministic generator (mulberry32), so a failure names a seed that reproduces it. */
function rng(seed: number): () => number {
  let a = seed >>> 0;

  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);

    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

const KEYS = ["name", "versions", "time", "readme", "users", "dependencies", "devDependencies", "licenseText", "dist", "a", "", "__proto__", "1.0.0", "2.0.0", "é", "\\u0041"];
const STRINGS = ["", "x", 'q\\"q', "\\\\", "\\/", "\\b\\f\\n\\r\\t", "\\u00e9\\uD83D\\uDE00", "\\uD800", "é€😀", "}]{[,:", " "];
const NUMBERS = ["0", "-0", "1", "-12", "3.25", "1e3", "1E-3", "-0.5e+10", "123456789012345678901234567890"];

/** Random JSON text, as JSON.stringify would not write it: odd spacing, escapes, duplicate keys. */
function generate(next: () => number, depth: number): string {
  const ws = (): string => [" ", "", "", "\n", "\t", "\r\n  "][Math.floor(next() * 6)] ?? "";
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)] ?? xs[0]!;
  const r = next();

  if (depth > 4 || r < 0.35) {
    const s = next();

    if (s < 0.4) return `"${pick(STRINGS)}"`;

    if (s < 0.75) return pick(NUMBERS);

    return pick(["true", "false", "null"]);
  }

  if (r < 0.55) return `[${ws()}${Array.from({ length: Math.floor(next() * 4) }, () => `${ws()}${generate(next, depth + 1)}${ws()}`).join(",")}]`;

  return `{${ws()}${Array.from({ length: Math.floor(next() * 5) }, () => `${ws()}"${pick(KEYS)}"${ws()}:${ws()}${generate(next, depth + 1)}${ws()}`).join(",")}}`;
}

/** A packument-shaped document with random JSON in kept, dropped and discarded places. */
function packumentLike(next: () => number): string {
  // one version document: kept, dropped and unknown fields, each random
  const version = (v: string): string => `"${v}":{"name":"p","version":"${v}","dependencies":${generate(next, 2)},"licenseText":${generate(next, 2)},"devDependencies":${generate(next, 2)},"${KEYS[Math.floor(next() * KEYS.length)]}":${generate(next, 2)}}`;
  const versions = Array.from({ length: 1 + Math.floor(next() * 3) }, (_, i) => version(next() < 0.2 ? "1.0.0" : `1.0.${i}`)).join(",");
  const extra = next() < 0.3 ? `,"versions":${next() < 0.5 ? generate(next, 1) : `{${version("9.9.9")}}`}` : "";

  return `{"name":"p","users":${generate(next, 1)},"readme":${generate(next, 1)},"versions":{${versions}}${extra},"${KEYS[Math.floor(next() * KEYS.length)]}":${generate(next, 1)}}`;
}

/**
 * The longest member streamedJson writes for a kept packument at once, in characters: a top-level field with its key,
 * or one entry of `versions` with its key when it is an object. What maxPieceChars must be at least.
 */
function longestPiece(body: KeptPackument): number {
  let most = 0;

  for (const [k, v] of Object.entries(body)) {
    if (k === "versions" && isJsonObject(v)) {
      for (const [version, doc] of Object.entries(v)) most = Math.max(most, JSON.stringify(version).length + 1 + JSON.stringify(doc).length);
    } else most = Math.max(most, JSON.stringify(k).length + 1 + JSON.stringify(v).length);
  }

  return most;
}

/** One mutation of valid text: a byte removed, inserted or replaced with one that matters to the grammar. */
function mutate(next: () => number, text: string): string {
  const at = Math.floor(next() * text.length);
  const glyph = [",", ":", "{", "}", "[", "]", '"', "\\", " ", "0", "-", ".", "e", "+", "t", "n", "u", "x", "\u0001", "'"][Math.floor(next() * 20)] ?? "";
  const r = next();

  if (r < 0.33) return text.slice(0, at) + text.slice(at + 1);

  if (r < 0.66) return text.slice(0, at) + glyph + text.slice(at);

  return text.slice(0, at) + glyph + text.slice(at + 1);
}

describe("the longest member a stream writes (maxPieceChars)", () => {
  test("is at least what JSON.stringify writes, for numbers that grow, escapes that shrink and keys of every length", async () => {
    const docs = [
      `{"name":"p","versions":{"1.0.0":{"n":[1e20,1E20,-1e-7,0.1e1,5e-324,1.7976931348623157e308,${"1e20,".repeat(500)}1]}}}`,
      `{"name":"p","readme":"\\u0041\\/\\n\\u0001\\ud800\\u20ac\\"","versions":{"\\u0031.0.0":{"\\u006eame":"p","x":"\\t"}}}`,
      `{"name":"p","versions":{"1.0.0":{"${"k".repeat(5000)}":1}},"time":{"1.0.0":"2020-01-01"}}`,
      `{"name":"p","versions":{"1.0.0":"not an object","2.0.0":{"dependencies":{"a":"1"}}}}`,
      `{"name":"p","versions":[1e20,2e20]}`,
      `{"name":"€","description":"${"€".repeat(1000)}","versions":{}}`,
    ];

    for (const text of docs) {
      const r = await readPackument(streamOf(text, 7), { limits: LIMITS });

      if (r.kind !== "ok") throw new Error(`not read: ${text.slice(0, 80)}`);
      expect({ text: text.slice(0, 60), ok: r.maxPieceChars >= longestPiece(r.body) }).toEqual({ text: text.slice(0, 60), ok: true });
    }
  });
});

describe("readPackument against JSON.parse, on a fuzz corpus", () => {
  test("6,000 valid and invalid documents: the same verdict, and when valid the same value minus what it drops", async () => {
    const next = rng(0x5eed_2026);
    let valid = 0;
    let invalid = 0;

    for (let i = 0; i < 6_000; i++) {
      const base = packumentLike(next);
      const text = i % 3 === 0 ? base : mutate(next, i % 3 === 1 ? base : mutate(next, base));
      const bytes = new TextEncoder().encode(text);
      const want = oracle(bytes);
      const got = await readPackument(streamOf(bytes, 1 + Math.floor(next() * 40)), { limits: LIMITS });
      const isPackument = want.ok && isJsonObject(want.value);

      if (isPackument) {
        valid++;
        expect({ i, text, kind: got.kind }).toEqual({ i, text, kind: "ok" });

        if (got.kind === "ok") {
          expect({ i, body: got.body }).toEqual({ i, body: expected(want.value) });
          expect({ i, longest: longestPiece(got.body) <= got.maxPieceChars }).toEqual({ i, longest: true });
        }
      } else {
        invalid++;
        expect({ i, text, kind: got.kind }).toEqual({ i, text, kind: "invalid" });
      }
    }

    // both halves of the corpus are well represented
    expect(valid).toBeGreaterThan(2_000);
    expect(invalid).toBeGreaterThan(1_500);
  });

  test("3,000 documents under DEV_DEPENDENCIES: the same verdict, and when valid each version's devDependencies", async () => {
    const next = rng(0xdec0_2026);
    let valid = 0;

    for (let i = 0; i < 3_000; i++) {
      const base = packumentLike(next);
      const text = i % 3 === 0 ? base : mutate(next, base);
      const bytes = new TextEncoder().encode(text);
      const want = oracle(bytes);
      const got = await readPackument(streamOf(bytes, 1 + Math.floor(next() * 40)), { limits: LIMITS, profile: DEV_DEPENDENCIES });

      if (want.ok && isJsonObject(want.value)) {
        valid++;
        expect({ i, text, kind: got.kind }).toEqual({ i, text, kind: "ok" });

        if (got.kind === "ok") {
          expect({ i, body: got.body }).toEqual({ i, body: expectedDev(want.value) });
          expect({ i, longest: longestPiece(got.body) <= got.maxPieceChars }).toEqual({ i, longest: true });
        }
      } else expect({ i, text, kind: got.kind }).toEqual({ i, text, kind: "invalid" });
    }

    expect(valid).toBeGreaterThan(1_000);
  });
});

// The real packuments the reader is checked against, saved from registry.npmjs.org (not in the repository: 118 MB).
const REAL = process.env.APM_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments");

describe.skipIf(!existsSync(REAL))("readPackument against JSON.parse, on real packuments", () => {
  for (const name of ["_types_node", "aws-sdk", "esbuild", "lodash", "next", "react", "typescript", "vite"]) {
    test(`${name}: what JSON.parse gives, under both profiles, within the default limits`, async () => {
      const file = Bun.file(join(REAL, `${name}.json`));
      const want = oracle(new Uint8Array(await file.arrayBuffer()));

      if (!want.ok) throw new Error(`${name} is not JSON`);
      const trimmed = await readPackument(file.stream());
      const dev = await readPackument(file.stream(), { profile: DEV_DEPENDENCIES });

      expect(trimmed).toMatchObject({ kind: "ok", body: expected(want.value) });
      expect(dev).toMatchObject({ kind: "ok", body: expectedDev(want.value) });

      // what serializing it a member at a time holds is charged from this bound (http.ts, streamWeight)
      for (const r of [trimmed, dev]) if (r.kind === "ok") expect(r.maxPieceChars).toBeGreaterThanOrEqual(longestPiece(r.body));
    }, 120_000);
  }
});
