// The streaming packument reader (src/packument-read.ts): it accepts exactly what JSON.parse accepts, discarded regions
// included, keeps what JSON.parse gives minus the fields it drops however the bytes are split, resolves duplicate keys
// as JSON.parse does, and refuses a packument past any of its bounds (read, kept bytes, kept nodes, depth, a shared
// budget) instead of holding it.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import {
  DEV_DEPENDENCIES,
  DROPPED_VERSION_FIELDS,
  KeptBudget,
  MAX_PACKUMENT_DEPTH,
  readPackument,
  type JsonValue,
  type KeptPackument,
  type PackumentLimits,
} from "../src/packument-read.ts";

const LIMITS: PackumentLimits = { maxBytes: 10_000_000, maxKeptBytes: 1_000_000, maxKeptNodes: 100_000, maxDepth: 1_000 };

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

  test("reads in flight together share a budget, and a refused one gives back what it took", async () => {
    const one = (n: number): string => JSON.stringify({ name: `p${n}`, description: "D".repeat(30_000), versions: {} });
    const budget = new KeptBudget(70_000);
    const reads = await Promise.all([1, 2, 3].map((n) => readPackument(streamOf(one(n), 1_024), { limits: LIMITS, budget })));

    // each fits its own cap; two fit the budget, the third would pass it
    expect(reads.map((r) => r.kind).toSorted()).toEqual(["ok", "ok", "too-large"]);
    expect(reads.find((r) => r.kind === "too-large")).toMatchObject({ over: "budget", limit: 70_000 });
    // the two that were kept stay taken; the refused one's partial take was given back
    const kept = reads.reduce((n, r) => n + (r.kind === "ok" ? r.keptBytes : 0), 0);

    expect(budget.taken).toBe(kept);
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

/** One mutation of valid text: a byte removed, inserted or replaced with one that matters to the grammar. */
function mutate(next: () => number, text: string): string {
  const at = Math.floor(next() * text.length);
  const glyph = [",", ":", "{", "}", "[", "]", '"', "\\", " ", "0", "-", ".", "e", "+", "t", "n", "u", "x", "\u0001", "'"][Math.floor(next() * 20)] ?? "";
  const r = next();

  if (r < 0.33) return text.slice(0, at) + text.slice(at + 1);

  if (r < 0.66) return text.slice(0, at) + glyph + text.slice(at);

  return text.slice(0, at) + glyph + text.slice(at + 1);
}

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

        if (got.kind === "ok") expect({ i, body: got.body }).toEqual({ i, body: expected(want.value) });
      } else {
        invalid++;
        expect({ i, text, kind: got.kind }).toEqual({ i, text, kind: "invalid" });
      }
    }

    // both halves of the corpus are well represented
    expect(valid).toBeGreaterThan(2_000);
    expect(invalid).toBeGreaterThan(1_500);
  });
});
