// The worker module memory-pool.workerd.test.ts runs inside workerd: the packument reader, the Upstream layer with a
// stand-in npm and data center cache, and the operations a mix runs at once. Kept apart so a probe can run it too.
import { join } from "node:path";
import { MEASURE } from "./workerd-heap.ts";

const SRC = join(import.meta.dir, "..", "src");
const EFFECT = join(import.meta.dir, "..", "node_modules", "effect", "dist", "index.js");

export const ENTRY = `
import { Effect, Layer } from ${JSON.stringify(EFFECT)};
import { DEV_DEPENDENCIES, READ_OVERHEAD_WEIGHT, readPackument, TRIMMED } from ${JSON.stringify(join(SRC, "packument-read.ts"))};
import { MemoryPool } from ${JSON.stringify(join(SRC, "memory.ts"))};
import { LazyMembers, streamedJson, streamWeight } from ${JSON.stringify(join(SRC, "http.ts"))};
import { Upstream } from ${JSON.stringify(join(SRC, "upstream.ts"))};
import { Store } from ${JSON.stringify(join(SRC, "db.ts"))};
import { Blobs } from ${JSON.stringify(join(SRC, "blobs.ts"))};
import { ReleaseHooks } from ${JSON.stringify(join(SRC, "hooks.ts"))};
${MEASURE}
const encoder = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- a gate every step of every operation waits at, so a sample is taken with all of them parked ----
let open = true;
let parked = [];
const gate = () => (open ? Promise.resolve() : new Promise((r) => parked.push(r)));
const closeGate = () => { open = false; };
const openGate = () => { open = true; const p = parked; parked = []; for (const r of p) r(); };

/**
 * A stream of the strings (or bytes) \`make\` yields, in pieces of about 64 KiB, each one after the gate. A cancel
 * takes a moment, as the network's does, and waits at the gate too.
 */
function streamOf(make) {
  const it = make();
  let buf = "";
  return new ReadableStream({
    async cancel() { await gate(); await sleep(1); },
    async pull(c) {
      await gate();
      for (;;) {
        const n = it.next();
        if (n.done) { if (buf) c.enqueue(encoder.encode(buf)); buf = ""; c.close(); return; }
        if (typeof n.value !== "string") { if (buf) { c.enqueue(encoder.encode(buf)); buf = ""; } c.enqueue(n.value); return; }
        buf += n.value;
        if (buf.length >= 65536) { c.enqueue(encoder.encode(buf)); buf = ""; return; }
      }
    },
  });
}

// ---- the packuments npm, standing in, sends: shapes that cost the reader, the cache and the stream most ----
const SHAPES = {
  // many small versions: records, hidden classes, the scored copy
  versions: (name, n) => function* () {
    yield '{"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{';
    for (let i = 0; i < n; i++) yield (i ? "," : "") + '"1.0.' + i + '":{"name":"' + name + '","version":"1.0.' + i + '","dist":{"tarball":"https://npm.invalid/' + name + '/-/x-1.0.' + i + '.tgz","integrity":"sha512-' + "A".repeat(86) + '=="},"notes":"' + "z".repeat(300) + '"}';
    yield '},"time":{"1.0.0":"2020-01-01T00:00:00.000Z"}}';
  },
  // one long readme: the longest member a stream writes at once
  readme: (name, n) => function* () {
    yield '{"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}},"readme":"';
    for (let i = 0; i < n; i += 65536) yield "r".repeat(Math.min(65536, n - i));
    yield '"}';
  },
  // two bytes a character, held as text and as strings
  wide: (name, n) => function* () {
    yield '{"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}},"description":"';
    for (let i = 0; i < n; i += 65535) yield "€" + "w".repeat(Math.min(65534, n - i));
    yield '"}';
  },
  // bytes that are not UTF-8: each decodes to U+FFFD
  badUtf8: (name, n) => function* () {
    yield '{"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}},"description":"';
    for (let i = 0; i < n; i += 65536) yield new Uint8Array(Math.min(65536, n - i)).fill(0x80);
    yield '"}';
  },
  // a readme, then a byte that is not JSON: refused as invalid once it has all been read, and its stream canceled
  malformed: (name, n) => function* () {
    yield '{"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}},"readme":"';
    for (let i = 0; i < n; i += 65536) yield "m".repeat(Math.min(65536, n - i));
    yield '"}!';
  },
  // a long top-level key the reader discards, then a small packument
  ignoredKey: (name, n) => function* () {
    yield '{"';
    for (let i = 0; i < n; i += 65536) yield "k".repeat(Math.min(65536, n - i));
    yield '":null,"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}}}';
  },
};

const CATALOG = [
  ["v-small", "versions", 1500], ["v-mid", "versions", 4000], ["v-big", "versions", 9000],
  ["r-small", "readme", 500000], ["r-big", "readme", 3000000],
  ["w-mid", "wide", 1500000], ["b-mid", "badUtf8", 2000000], ["k-long", "ignoredKey", 3000000],
  ["v-mid2", "versions", 5000], ["r-mid", "readme", 1500000], ["w-small", "wide", 400000], ["b-small", "badUtf8", 600000],
  ["m-mid", "malformed", 2000000], ["m-big", "malformed", 4000000],
];
const BY_NAME = new Map(CATALOG.map(([name, shape, n]) => [name, SHAPES[shape](name, n)]));

// "parked-…": a packument whose readme stops after its first 64 KiB until \`unpark\` is called
let unparkAll = [];
const unpark = () => { const u = unparkAll; unparkAll = []; for (const r of u) r(); };

function parkedStream(name) {
  let step = 0;
  return new ReadableStream({
    async pull(c) {
      if (step === 0) { step++; c.enqueue(encoder.encode('{"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}},"readme":"' + "p".repeat(65536))); return; }
      if (step === 1) { step++; await new Promise((r) => unparkAll.push(r)); c.enqueue(encoder.encode('"}')); return; }
      c.close();
    },
  });
}

// "i-<MiB>-…": a packument whose readme is sent, \`MiB\` of it, and then nothing more until the reader cancels it
function interruptedStream(name) {
  const n = Number(name.split("-")[1]) * 1024 * 1024;
  let at = -1, cancelled;
  const canceling = new Promise((r) => (cancelled = r));
  return new ReadableStream({
    async pull(c) {
      await gate();
      if (at < 0) { at = 0; c.enqueue(encoder.encode('{"name":"' + name + '","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"' + name + '","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}},"readme":"')); return; }
      if (at < n) { at += 65536; c.enqueue(encoder.encode("i".repeat(65536))); return; }
      await canceling;
    },
    async cancel() { await gate(); await sleep(1); cancelled(); },
  });
}

globalThis.fetch = async (input) => {
  const name = decodeURIComponent(new URL(typeof input === "string" ? input : input.url).pathname.slice(1));
  if (name.startsWith("parked-")) return new Response(parkedStream(name), { status: 200 });
  if (name.startsWith("i-")) return new Response(interruptedStream(name), { status: 200 });
  const make = BY_NAME.get(name);
  if (!make) return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
  return new Response(streamOf(make), { status: 200, headers: { "content-type": "application/json" } });
};

// ---- the data center's cache, standing in: each write reads the copy at its own pace, or stalls, or gives up ----
let writeMode = "read";
let release = [];
const shared = new Map();
const cache = {
  match: async () => undefined,
  put: async (key, res) => {
    const reader = res.body.getReader();
    if (writeMode === "stall") { await new Promise((r) => release.push(r)); await reader.cancel(); return; }
    const giveUp = Math.random() < 0.2;
    let n = 0;
    for (;;) {
      await gate();
      if (Math.random() < 0.3) await sleep(1);
      if (giveUp && ++n > 3) { await reader.cancel(); return; }
      const { done } = await reader.read();
      if (done) break;
    }
    shared.set(key.url, true);
  },
};
Object.defineProperty(globalThis, "caches", { value: { default: cache }, configurable: true });

const works = new Set();
const background = (work) => { const p = work.finally(() => works.delete(p)); works.add(p); };
const store = { upstreamAnalyses: () => Effect.succeed({ scores: new Map(), unscorable: new Map() }), upstreamAnalysesOf: () => Effect.succeed(new Map()) };
const deps = Layer.mergeAll(Layer.succeed(Store, store), Layer.succeed(Blobs, {}));
const upstreamLayer = Layer.provide(Upstream.layer("https://npm.invalid/", 60000, background), deps);
const run = (use) => Effect.runPromise(Effect.flatMap(Upstream, use).pipe(Effect.provide(upstreamLayer), Effect.scoped));

// ---- the review's look at each package npm sent, after the response: as a mix picks, it ends soon, stops when its
// lease's deadline signal aborts, or ignores that signal until the mix ends (and so keeps its charge) ----
let lookMode = () => "quick";
const looks = new Set();
const lookWorks = new Set();
let endLooks = [];
const hooks = Layer.succeed(ReleaseHooks, {
  afterCommit: () => Effect.void,
  upstreamFetched: (pkg, held) => Effect.sync(() => {
    const mode = lookMode();
    let looking = pkg;
    looks.add(held);
    const ended = new Promise((r) => endLooks.push(r));
    const stopped = new Promise((r) => (held.signal.aborted ? r() : held.signal.addEventListener("abort", r, { once: true })));
    const until = mode === "quick" ? sleep(1 + Math.floor(Math.random() * 4)) : mode === "stops" ? Promise.race([ended, stopped]) : ended;
    const work = until.then(() => { globalThis.keep = looking.readme; globalThis.keep = null; looking = null; looks.delete(held); held.release(); });
    lookWorks.add(work);
    work.finally(() => lookWorks.delete(work));
  }),
});
const mixLayer = Layer.provideMerge(Upstream.layer("https://npm.invalid/", 60000, background), Layer.mergeAll(deps, hooks));
const runMix = (use, signal) => Effect.runPromiseExit(Effect.flatMap(Upstream, use).pipe(Effect.provide(mixLayer), Effect.scoped), signal ? { signal } : undefined);

/** A seeded generator, so a failing mix can be run again. */
function rng(seed) {
  let s = seed >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const q = (k) => url.searchParams.get(k);

    if (url.pathname === "/ignored-key") {
      // a key the reader discards, at the root (TRIMMED) or in a version document (DEV_DEPENDENCIES keeps only some
      // fields there), measured while the reader is skipping its value
      const n = Number(q("n"));
      const atRoot = q("at") === "root";
      const pool = new MemoryPool(Infinity);
      const lease = pool.request(Infinity);
      const before = await measure(env);
      let step = 0, left = n, held = 0, taken = 0;
      const chunk = encoder.encode("k".repeat(65536));
      const body = new ReadableStream({
        async pull(c) {
          if (step === 0) { step++; c.enqueue(encoder.encode(atRoot ? '{"' : '{"name":"p","versions":{"1.0.0":{"')); return; }
          if (step === 1 && left > 0) { const m = Math.min(left, chunk.length); left -= m; c.enqueue(chunk.slice(0, m)); return; }
          if (step === 1) { step++; c.enqueue(encoder.encode('":[1,')); return; }
          // pulled once the reader has taken the chunk before: one more, and it has read that one when this is pulled
          if (step === 2) { step++; c.enqueue(encoder.encode("2,")); return; }
          if (step === 3) { step++; held = await measure(env); taken = lease.taken; c.enqueue(encoder.encode(atRoot ? '3]}' : '3]}}}')); return; }
          c.close();
        },
      });
      const r = await readPackument(body, { lease, profile: atRoot ? TRIMMED : DEV_DEPENDENCIES });
      return Response.json({ read: r.kind, weight: r.weight, held: held - before, taken });
    }

    if (url.pathname === "/kept-key") {
      // a version key the reader keeps: charged from when it is read
      const n = Number(q("n"));
      const lease = new MemoryPool(Infinity).request(Infinity);
      const before = await measure(env);
      let step = 0, left = n, held = 0, taken = 0;
      const chunk = encoder.encode("v".repeat(65536));
      const body = new ReadableStream({
        async pull(c) {
          if (step === 0) { step++; c.enqueue(encoder.encode('{"name":"p","versions":{"')); return; }
          if (step === 1 && left > 0) { const m = Math.min(left, chunk.length); left -= m; c.enqueue(chunk.slice(0, m)); return; }
          if (step === 1) { step++; c.enqueue(encoder.encode('":{"skipped":[1,')); return; }
          if (step === 2) { step++; c.enqueue(encoder.encode("2,")); return; }
          if (step === 3) { step++; held = await measure(env); taken = lease.taken; c.enqueue(encoder.encode('3]}}}')); return; }
          c.close();
        },
      });
      const r = await readPackument(body, { lease, profile: DEV_DEPENDENCIES });
      const after = await measure(env);
      globalThis.keep = r; globalThis.keep = null;
      return Response.json({ read: r.kind, weight: r.weight, held: held - before, taken, after: after - before });
    }

    if (url.pathname === "/bad-utf8") {
      const n = Number(q("n"));
      const lease = new MemoryPool(Infinity).request(Infinity);
      const before = await measure(env);
      const r = await readPackument(streamOf(SHAPES.badUtf8("p", n)), { lease });
      const held = await measure(env);
      const length = r.kind === "ok" ? r.body.description.length : -1;
      globalThis.keep = r; globalThis.keep = null;
      return Response.json({ read: r.kind, weight: r.weight, taken: lease.taken, held: held - before, length });
    }

    if (url.pathname === "/background") {
      // the real Upstream layer: a packument npm just sent is converted, and its copy's write stalls after the request
      // is done. A cache of one byte keeps nothing, so only the request and the write hold the package.
      writeMode = "stall";
      const pool = new MemoryPool();
      pool.cache(1);
      // room for the read itself, not for converting it into a package
      const alone = await readPackument(streamOf(BY_NAME.get("v-mid")), { lease: new MemoryPool(Infinity).request(Infinity) });
      const room = alone.weight + READ_OVERHEAD_WEIGHT + 256 * 1024;
      const before = await measure(env);
      const refusedLease = pool.request(room);
      const refused = await run((up) => up.probeWithin("v-mid", refusedLease));
      const writesAfterRefusal = release.length;
      refusedLease.release();
      const afterRefusal = await measure(env);

      const request = pool.request();
      let got = await run((up) => up.probeWithin("v-mid", request));
      const kind = got.kind;
      got = null;
      request.release();
      const stalled = await measure(env);
      const chargedStalled = pool.charged;
      for (const r of release.splice(0)) r();
      await Promise.all([...works]);
      const done = await measure(env);
      writeMode = "read";
      return Response.json({ refused: refused.kind, writesAfterRefusal, afterRefusal: afterRefusal - before, chargedAfterRefusal: 0, kind, stalled: stalled - before, chargedStalled, done: done - before, chargedDone: pool.charged });
    }

    if (url.pathname === "/in-flight") {
      // n reads through the Upstream layer, each stopped part way into a kept string: what they hold beyond their charge
      const n = Number(q("n"));
      const pool = new MemoryPool();
      { const l = pool.request(); await run((up) => up.probeWithin("v-small", l)); l.release(); }
      await Promise.all([...works]);
      const base = await measure(env);
      const charged0 = pool.charged;
      const leases = Array.from({ length: n }, () => pool.request());
      const reads = leases.map((l, i) => run((up) => up.probeWithin("parked-" + i + "-" + Math.random(), l)));
      while (unparkAll.length < n) await sleep(1);
      for (let i = 0; i < 3; i++) await sleep(1);
      const held = (await measure(env)) - base;
      const charged = pool.charged - charged0;
      unpark();
      await Promise.all(reads);
      for (const l of leases) l.release();
      await Promise.all([...works]);
      return Response.json({ n, held, charged, perRead: (held - charged) / n });
    }

    if (url.pathname === "/mix") {
      const random = rng(Number(q("seed")));
      const ops = Number(q("ops"));
      const pool = new MemoryPool();
      const names = CATALOG.map(([n]) => n);
      const pick = () => names[Math.floor(random() * names.length)];
      const hold = async () => { await sleep(Math.floor(random() * 4)); await gate(); };
      const counts = { read: 0, walk: 0, scan: 0, stream: 0, pressure: 0, interrupt: 0, deadline: 0, found: 0, overBudget: 0, refused: 0, cancelled: 0, interrupted: 0, stopped: 0, stalledLooks: 0 };
      lookMode = () => { const r = random(); if (r < 0.5) return "quick"; if (r < 0.8) return "stops"; counts.stalledLooks++; return "stalled"; };
      const mixed = async (use, signal) => { const exit = await runMix(use, signal); if (exit._tag === "Failure" && !signal?.aborted) throw new Error(String(exit.cause)); return exit._tag === "Success" ? exit.value : null; };
      const note = (p) => { if (p.kind === "found") counts.found++; if (p.kind === "over-budget") counts.overBudget++; if (p.kind === "unknown") counts.refused++; };

      // warm: the code every operation runs is compiled, and the layer built, before the base is measured
      { const l = pool.request(); note(await mixed((up) => up.probeWithin("v-small", l))); l.release(); }
      for (const r of release.splice(0)) r();
      for (const r of endLooks.splice(0)) r();
      await Promise.all([...works, ...lookWorks]);
      const base = await measure(env);
      pool.resetPeak();

      const operations = {
        async read() {
          const request = pool.request();
          try { note(await mixed((up) => up.probeWithin(pick(), request))); await hold(); } finally { request.release(); }
        },
        async walk() {
          const request = pool.request();
          try {
            const walk = request.child();
            const got = await mixed((up) => up.probeMany([pick(), pick(), pick(), pick()], walk));
            for (const p of got.values()) note(p);
            await hold();
          } finally { request.release(); }
        },
        async scan() {
          const request = pool.request();
          try {
            await Promise.all([pick(), pick(), pick()].map(async (name) => {
              const one = request.child();
              try { note(await mixed((up) => up.probeWithin(name, one))); await hold(); } finally { one.release(); }
            }));
          } finally { request.release(); }
        },
        async stream() {
          // the packument route: the answer is charged before it is made and keeps the request's lease until sent
          const request = pool.request();
          let res = null;
          try {
            const p = await mixed((up) => up.probeWithin(pick(), request));
            note(p);
            if (p.kind !== "found") return;
            const pkg = p.pkg;
            if (!request.take(pkg.serveCost.versionDocs + pkg.versions.length * 64 + streamWeight(pkg.serveCost.maxPieceChars + 16384))) return;
            const versions = new LazyMembers(function* () { for (const v of pkg.versions) yield [v.version, { ...v.manifest, dist: { tarball: "https://registry.test/x.tgz", integrity: v.integrity } }]; });
            res = streamedJson({ name: pkg.name, readme: pkg.readme, versions }, "versions", {}, { onDone: request.retain() });
          } finally { request.release(); }
          if (res === null) return;
          const reader = res.body.getReader();
          const cancelAfter = random() < 0.3 ? 1 + Math.floor(random() * 4) : Infinity;
          for (let n = 0; ; n++) {
            await gate();
            if (n >= cancelAfter) { counts.cancelled++; await reader.cancel(); return; }
            const { done } = await reader.read();
            if (done) return;
            if (random() < 0.3) await sleep(1);
          }
        },
        async interrupt() {
          // a read part way into a packument, interrupted (a sibling failed, the request ended): it cancels its stream
          // and lets go of what it read before its lease is released
          const request = pool.request();
          const stop = new AbortController();
          try {
            const reading = mixed((up) => up.probeWithin("i-" + (1 + Math.floor(random() * 6)) + "-" + Math.random(), request), stop.signal);
            await sleep(1 + Math.floor(random() * 8));
            await gate();
            stop.abort();
            if ((await reading) === null) counts.interrupted++;
          } finally { request.release(); }
        },
        async deadline() {
          // looks past their deadline are told to stop: the ones that honour it let go, the others keep their charge
          for (const l of looks) if (random() < 0.5) { l.stop(); counts.stopped++; }
          await hold();
        },
        async pressure() {
          // memory a holder takes for itself, and has: the pool takes back cache entries only the cache holds
          const request = pool.request();
          try {
            const size = (4 + Math.floor(random() * 28)) * 1024 * 1024;
            if (!request.take(size)) return;
            const bytes = new Uint8Array(size).fill(1);
            await hold();
            await hold();
            globalThis.keep = bytes; globalThis.keep = null;
          } finally { request.release(); }
        },
      };
      const kinds = q("kinds") ? q("kinds").split(",") : Object.keys(operations);
      const samples = [];
      let running = 0;
      let started = 0;
      let failed = null;
      let maxRunning = 0;
      const inFlight = new Set();

      const startOne = () => {
        const kind = kinds[Math.floor(random() * kinds.length)];
        counts[kind]++;
        started++;
        running++;
        const p = operations[kind]().catch((e) => { failed = failed ?? String(e && e.stack || e); }).finally(() => { running--; inFlight.delete(p); });
        inFlight.add(p);
      };

      while (started < ops || running > 0) {
        while (started < ops && running < 10) startOne();
        await sleep(1 + Math.floor(random() * 6));
        // a sample: every operation parked at the gate, then a full GC and the isolate's memory beside the pool's charge
        closeGate();
        for (let i = 0; i < 5; i++) await sleep(0);
        const charged = pool.charged;
        const held = (await measure(env)) - base;
        samples.push({ held, charged, running });
        openGate();
        if (failed) break;
        maxRunning = Math.max(maxRunning, samples.at(-1).running);
      }

      for (const r of release.splice(0)) r();
      await Promise.all([...inFlight]);
      for (const r of endLooks.splice(0)) r();
      await Promise.all([...works, ...lookWorks]);
      for (let i = 0; i < 3; i++) await sleep(5);
      const end = (await measure(env)) - base;

      const worst = samples.reduce((m, s) => (s.held - s.charged > m.held - m.charged ? s : m), samples[0]);
      return Response.json({
        failed, counts, samples: samples.length, maxRunning,
        peakCharged: pool.peakCharged, peakHeld: Math.max(...samples.map((s) => s.held)),
        worstOver: worst.held - worst.charged, worst,
        end, endCharged: pool.charged, cacheHeld: pool.cache().taken,
      });
    }

    return new Response("not found", { status: 404 });
  },
};
`;
