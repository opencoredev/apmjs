// The packument reader's memory, measured where it runs: inside workerd, after a full GC, the JS heap and ArrayBuffer
// bytes together (workerd-heap.ts). The weight it charges (packument-read.ts, WEIGHTS) must be at least the memory V8
// holds a read in, for the shapes that
// cost V8 most for their text, so the budgets built on it (MAX_PACKUMENT_WEIGHT, REQUEST_METADATA_WEIGHT,
// PROBE_CACHE_WEIGHT) bound memory and not only bytes.
//
// Review of f0e533a: finding 1, four accepted packuments of 1.49 million empty arrays each were charged 17.9 MB of a
// walk's budget and held 156 MB of heap; finding 2, an 800,000-byte string delivered a byte at a time took 175 MB of
// heap before its end, one Uint8Array a byte.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { REQUEST_METADATA_WEIGHT } from "../src/apm.ts";
import { MEASURE, startWorkerdHeap, type WorkerdHeap } from "./workerd-heap.ts";

const SRC = join(import.meta.dir, "..", "src");
const MB = 1024 * 1024;

/** The heap a request may reach: half a Worker's 128 MB. */
const HEAP_CEILING = 64 * MB;

/** What two measurements of the same heap differ by: the request's own objects, code the run compiled. */
const NOISE = 256 * 1024;

const ENTRY = `
import { DEV_DEPENDENCIES, KeptBudget, readPackument, TRIMMED } from ${JSON.stringify(join(SRC, "packument-read.ts"))};
import { cachedPackage, packageMoment, packageWeight, scoredPackage } from ${JSON.stringify(join(SRC, "upstream.ts"))};
${MEASURE}
const encoder = new TextEncoder();

/** A packument whose version 1.0.0 keeps a field "x": an array of \`count\` copies of \`item\`, streamed about \`chunk\` bytes at a time. */
function repeated({ name, item, count, chunk }) {
  const per = Math.max(1, Math.floor(chunk / (item.length + 1)));
  const full = encoder.encode((item + ",").repeat(per));
  const parts = [encoder.encode('{"name":"' + name + '","versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"t"},"x":[')];
  let left = count - 1;
  return new ReadableStream({
    pull(c) {
      if (parts.length > 0) { c.enqueue(parts.shift()); return; }
      if (left >= per) { left -= per; c.enqueue(full.slice()); return; }
      if (left >= 0) { c.enqueue(encoder.encode((item + ",").repeat(left) + item + "]}}}")); left = -1; return; }
      c.close();
    },
  });
}

/** Text from a generator of strings, as a stream of \`chunk\`-byte pieces. */
function generated(make, chunk) {
  const it = make();
  let buf = new Uint8Array(0);
  return new ReadableStream({
    pull(c) {
      while (buf.length < chunk) {
        const n = it.next();
        if (n.done) break;
        const b = encoder.encode(n.value);
        const m = new Uint8Array(buf.length + b.length);
        m.set(buf); m.set(b, buf.length); buf = m;
      }
      if (buf.length === 0) { c.close(); return; }
      c.enqueue(buf.slice(0, chunk)); buf = buf.slice(chunk);
    },
  });
}

const FIXTURES = {
  emptyArrays: (n) => function* () { yield '{"name":"p","versions":{"1.0.0":{"x":['; for (let i = 0; i < n; i++) yield i ? ",[]" : "[]"; yield "]}}}"; },
  emptyObjects: (n) => function* () { yield '{"name":"p","versions":{"1.0.0":{"x":['; for (let i = 0; i < n; i++) yield i ? ",{}" : "{}"; yield "]}}}"; },
  nestedArrays: (n) => function* () { yield '{"name":"p","versions":{"1.0.0":{"x":['; for (let i = 0; i < n; i++) yield i ? ",[[[]]]" : "[[[]]]"; yield "]}}}"; },
  distinctKeyObjects: (n) => function* () { yield '{"name":"p","versions":{"1.0.0":{"x":['; for (let i = 0; i < n; i++) yield (i ? "," : "") + '{"k' + i + '":0}'; yield "]}}}"; },
  shortStrings: (n) => function* () { yield '{"name":"p","versions":{"1.0.0":{"x":['; for (let i = 0; i < n; i++) yield (i ? "," : "") + '"' + i + '"'; yield "]}}}"; },
  boxedNumbers: (n) => function* () { yield '{"name":"p","versions":{"1.0.0":{"x":[{}'; for (let i = 0; i < n; i++) yield ",1.5"; yield "]}}}"; },
  dictionaryObjects: (n) => function* () { const o = "{" + Array.from({ length: 2000 }, (_, j) => '"k' + j + '":{}').join(",") + "}"; yield '{"name":"p","versions":{"1.0.0":{"x":['; for (let i = 0; i < n / 2000; i++) yield (i ? "," : "") + o; yield "]}}}"; },
  versionsOwnFields: (n) => function* () { yield '{"name":"p","versions":{'; for (let i = 0; i < n; i++) yield (i ? "," : "") + '"' + i + '":{"f' + i + '":0}'; yield "}}"; },
  wideString: (n) => function* () { yield '{"name":"p","description":"\\u20ac'; for (let i = 0; i < n / 1000; i++) yield "a".repeat(1000); yield '"}'; },
  wideKeys: (n) => function* () { yield '{"name":"p","versions":{"1.0.0":{"x":{'; for (let i = 0; i < n; i++) yield (i ? "," : "") + '"€' + i + '":0'; yield "}}}}"; },
};

const ok = (r) => r.kind === "ok" ? { kind: "ok", weight: r.weight, keptNodes: r.keptNodes, keptBytes: r.keptBytes } : { kind: r.kind, over: r.over, reason: r.reason };

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const q = (k) => url.searchParams.get(k);
    const before = await measure(env);

    if (url.pathname === "/arrays") {
      // the walk's shape: four packuments read at once under one budget, held until it answers
      const budget = new KeptBudget(Number(q("budget")));
      let peak = 0;
      const sample = async () => { peak = Math.max(peak, await measure(env)); };
      const reads = await Promise.all([0, 1, 2, 3].map((i) => {
        const body = repeated({ name: "a" + i, item: "[]", count: Number(q("count")), chunk: 65536 });
        // the first stream stops every 16 chunks to have the heap measured while all four are in flight
        if (i !== 0) return readPackument(body, { budget });
        const reader = body.getReader();
        let n = 0;
        const sampled = new ReadableStream({ async pull(c) { if (++n % 16 === 0) await sample(); const r = await reader.read(); if (r.done) c.close(); else c.enqueue(r.value); } });
        return readPackument(sampled, { budget });
      }));
      const held = await measure(env);
      peak = Math.max(peak, held);
      globalThis.keep = reads; globalThis.keep = null;
      return Response.json({ reads: reads.map(ok), taken: budget.taken, held: held - before, peak: peak - before, base: before });
    }

    if (url.pathname === "/bytes") {
      // one kept string a byte at a time; the heap is measured with one byte of it still to come
      const size = Number(q("size"));
      const text = encoder.encode('{"name":"p","description":"' + "x".repeat(size) + '"}');
      let at = 0;
      let before_end = 0;
      const body = new ReadableStream({
        async pull(c) {
          if (at === text.length - 3) before_end = await measure(env);
          if (at >= text.length) { c.close(); return; }
          c.enqueue(text.slice(at, at + 1));
          at++;
        },
      });
      const r = await readPackument(body);
      return Response.json({ read: ok(r), length: r.kind === "ok" ? r.body.description.length : -1, beforeEnd: before_end - before, base: before });
    }

    if (url.pathname === "/fixture") {
      const r = await readPackument(generated(FIXTURES[q("fixture")](Number(q("n"))), 65536), { limits: { maxBytes: 1e9, maxKeptBytes: 1e9, maxKeptNodes: 1e9, maxWeight: 1e10, maxDepth: 1000 } });
      const held = await measure(env);
      globalThis.keep = r; globalThis.keep = null;
      return Response.json({ read: ok(r), held: held - before });
    }

    if (url.pathname === "/package") {
      // many small versions: what cachedPackage and scoredPackage add to the packument they are read from
      const count = Number(q("count"));
      let r = await readPackument(generated(function* () {
        yield '{"name":"p","versions":{';
        for (let i = 0; i < count; i++) yield (i ? "," : "") + '"1.0.' + i + '":{"name":"p","version":"1.0.' + i + '","dist":{"tarball":"https://registry.npmjs.org/p/-/p-1.0.' + i + '.tgz","integrity":"sha512-' + "A".repeat(86) + '=="},"f' + (i % 50) + '":' + i + "}";
        yield '},"time":{' + Array.from({ length: count }, (_, i) => '"1.0.' + i + '":"2020-01-01T00:00:00.000Z"').join(",") + "}}";
      }, 65536));
      const body = await measure(env);
      let pkg = cachedPackage("p", r.body);
      const both = await measure(env);
      const read = { weight: r.weight, versionCount: r.versionCount, versionDocs: r.versionDocs };
      r = null;
      const cached = await measure(env);
      const scored = scoredPackage(pkg, { scores: new Map(), unscorable: new Map() });
      const withScored = await measure(env);
      globalThis.keep = [pkg, scored]; globalThis.keep = null;
      return Response.json({ versions: pkg.versions.length, weight: read.weight, packageWeight: packageWeight(read), moment: packageMoment(read), body: body - before, both: both - before, cached: cached - before, scored: withScored - cached });
    }

    if (url.pathname === "/real") {
      const profile = q("profile") === "dev" ? DEV_DEPENDENCIES : TRIMMED;
      const r = await readPackument(req.body, { profile });
      const held = await measure(env);
      globalThis.keep = r; globalThis.keep = null;
      return Response.json({ read: ok(r), held: held - before });
    }

    return new Response("not found", { status: 404 });
  },
};
`;

const Read = z.union([
  z.object({ kind: z.literal("ok"), weight: z.number(), keptNodes: z.number(), keptBytes: z.number() }),
  z.object({ kind: z.literal("too-large"), over: z.string() }),
  z.object({ kind: z.literal("invalid"), reason: z.string() }),
]);

let heap: WorkerdHeap;

beforeAll(async () => {
  heap = await startWorkerdHeap(ENTRY);
}, 60_000);

afterAll(async () => {
  await heap.dispose();
});

const mb = (n: number): string => `${(n / MB).toFixed(1)} MB`;

describe("the packument reader's heap in workerd", () => {
  test("finding 1: four packuments of 1.49 million empty arrays, read at once under a walk's budget, stay under 64 MB or are refused", async () => {
    const res = await heap.dispatch(`/arrays?count=1490000&budget=${REQUEST_METADATA_WEIGHT}`);
    const got = z.object({ reads: z.array(Read), taken: z.number(), held: z.number(), peak: z.number(), base: z.number() }).parse(await res.json());

    process.stdout.write(`[heap] 4 x 1.49M empty arrays: ${got.reads.map((r) => (r.kind === "too-large" ? `too-large (${r.over})` : r.kind)).join(", ")}; held ${mb(got.held)}, peak ${mb(got.peak)} over a base of ${mb(got.base)}\n`);
    // on f0e533a all four were accepted, 17.9 MB charged, 156 MB held

    for (const r of got.reads) expect(r.kind === "ok" || r.kind === "too-large").toBe(true);
    expect(got.base + got.peak).toBeLessThan(HEAP_CEILING);
    expect(got.base + got.held).toBeLessThan(HEAP_CEILING);
    // what the accepted ones hold is charged at least at its heap
    expect(got.taken).toBeGreaterThanOrEqual(got.held - NOISE);
  }, 300_000);

  test("finding 2: an 800,000-byte string delivered a byte at a time takes about its length in heap before its end", async () => {
    const res = await heap.dispatch("/bytes?size=800000");
    const got = z.object({ read: Read, length: z.number(), beforeEnd: z.number(), base: z.number() }).parse(await res.json());

    process.stdout.write(`[heap] 800,000 bytes in 1-byte chunks: ${mb(got.beforeEnd)} held one byte before the end, over a base of ${mb(got.base)}\n`);
    expect(got.read.kind).toBe("ok");
    expect(got.length).toBe(800_000);
    // on f0e533a: 175 MB, one Uint8Array a byte. Slabs of 64 KiB: the text, at most one slab more
    expect(got.base + got.beforeEnd).toBeLessThan(HEAP_CEILING);
    expect(got.beforeEnd).toBeLessThan(2 * MB);
  }, 300_000);

  // each fixture is one V8 holds dearly for its text; n is chosen so each holds 8 MB or more, well past measuring noise
  for (const [fixture, n] of [
    ["emptyArrays", 1_000_000],
    ["emptyObjects", 500_000],
    ["nestedArrays", 300_000],
    ["distinctKeyObjects", 200_000],
    ["shortStrings", 500_000],
    ["boxedNumbers", 1_000_000],
    ["dictionaryObjects", 400_000],
    ["versionsOwnFields", 100_000],
    ["wideString", 8_000_000],
    ["wideKeys", 300_000],
  ] as const) {
    test(`the weight of ${fixture} is at least the heap it is held in`, async () => {
      const got = z.object({ read: Read, held: z.number() }).parse(await (await heap.dispatch(`/fixture?fixture=${fixture}&n=${n}`)).json());

      if (got.read.kind !== "ok") throw new Error(`${fixture} was not read: ${JSON.stringify(got.read)}`);
      process.stdout.write(`[heap] ${fixture}: weight ${mb(got.read.weight)}, heap ${mb(got.held)} (${(got.read.weight / got.held).toFixed(2)}x)\n`);
      expect(got.held).toBeGreaterThan(8 * MB);
      expect(got.read.weight).toBeGreaterThanOrEqual(got.held - NOISE);
    }, 300_000);
  }

  test("a cached package and its scored copy weigh at least what they hold, and reading it at least its moment", async () => {
    const got = z
      .object({ versions: z.number(), weight: z.number(), packageWeight: z.number(), moment: z.number(), body: z.number(), both: z.number(), cached: z.number(), scored: z.number() })
      .parse(await (await heap.dispatch("/package?count=30000")).json());

    process.stdout.write(
      `[heap] 30,000 small versions: packument ${mb(got.body)} (weight ${mb(got.weight)}), cached ${mb(got.cached)} (weight ${mb(got.packageWeight)}), both at once ${mb(got.both)} (weight ${mb(got.weight + got.packageWeight - got.weight + got.moment)}), scored copy ${mb(got.scored)}\n`,
    );
    expect(got.versions).toBe(30_000);
    expect(got.weight).toBeGreaterThanOrEqual(got.body);
    expect(got.packageWeight).toBeGreaterThanOrEqual(got.cached);
    expect(got.packageWeight + got.moment).toBeGreaterThanOrEqual(got.both);
    // SCORED_WEIGHT a version
    expect(160 * got.versions).toBeGreaterThanOrEqual(got.scored);
  }, 300_000);
});

// The real packuments the reader is checked against, saved from registry.npmjs.org (not in the repository: 118 MB).
const REAL = process.env.APM_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments");
const REAL_NAMES = ["_types_node", "aws-sdk", "esbuild", "lodash", "next", "react", "typescript", "vite"];

describe.skipIf(!existsSync(REAL))("real packuments in workerd", () => {
  for (const name of REAL_NAMES) {
    for (const profile of ["trimmed", "dev"] as const) {
      test(`${name} (${profile}): read, and weighs at least its heap`, async () => {
        const res = await heap.dispatch(`/real?profile=${profile}`, { method: "POST", body: Bun.file(join(REAL, `${name}.json`)).stream(), duplex: "half" });
        const got = z.object({ read: Read, held: z.number() }).parse(await res.json());

        if (got.read.kind !== "ok") throw new Error(`${name} was not read: ${JSON.stringify(got.read)}`);
        process.stdout.write(`[heap] ${name} ${profile}: ${got.read.keptNodes} nodes, weight ${mb(got.read.weight)}, heap ${mb(got.held)}\n`);
        expect(got.read.weight).toBeGreaterThanOrEqual(got.held - NOISE);
      }, 300_000);
    }
  }
});
