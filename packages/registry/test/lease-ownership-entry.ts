// The worker module lease-ownership.workerd.test.ts runs inside workerd: one route per finding of the review of
// 747a032, each measuring what the isolate holds (workerd-heap.ts) beside what the memory pool is charged, at the
// moment the finding said the two came apart. Kept apart so a probe can run it too.
import { join } from "node:path";
import { MEASURE } from "./workerd-heap.ts";

const SRC = join(import.meta.dir, "..", "src");
const EFFECT = join(import.meta.dir, "..", "node_modules", "effect", "dist", "index.js");
const src = (file: string): string => JSON.stringify(join(SRC, file));

export const ENTRY = `
import { Effect, Layer } from ${JSON.stringify(EFFECT)};
import { MemoryPool, RequestMemory } from ${src("memory.ts")};
import { readPackument } from ${src("packument-read.ts")};
import { Upstream } from ${src("upstream.ts")};
import { Store } from ${src("db.ts")};
import { Blobs } from ${src("blobs.ts")};
import { Clock } from ${src("clock.ts")};
import { Analysis } from ${src("analysis.ts")};
import { RegistryConfig } from ${src("config.ts")};
import { ReleaseHooks } from ${src("hooks.ts")};
import { apmRoute } from ${src("apm.ts")};
${MEASURE}
const MiB = 1024 * 1024;
const encoder = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const empty = () => ({ scores: new Map(), unscorable: new Map() });
const store = { confirmedReviews: () => Effect.succeed([]), getPackage: () => Effect.succeed(null), upstreamAnalyses: () => Effect.succeed(empty()), upstreamAnalysesOf: () => Effect.succeed(new Map()) };
const deps = Layer.mergeAll(Layer.succeed(Store, store), Layer.succeed(Blobs, {}));
const HEAD = '{"name":"p","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"p","version":"1.0.0","dist":{"tarball":"https://npm.invalid/t"}}},"time":{"1.0.0":"2020-01-01T00:00:00.000Z"},"readme":"';

/** A packument with a readme of \`n\` characters, in 64 KiB chunks, then \`tail\`. */
function readmeStream(n, tail = '"}') {
  let at = -1;
  return new ReadableStream({
    pull(c) {
      if (at < 0) { at = 0; c.enqueue(encoder.encode(HEAD)); return; }
      if (at < n) { const m = Math.min(65536, n - at); at += m; c.enqueue(encoder.encode("x".repeat(m))); return; }
      c.enqueue(encoder.encode(tail)); c.close();
    },
  });
}

const layerWith = (hooks) => Layer.provideMerge(Upstream.layer("https://npm.invalid/", 60000, null), hooks ? Layer.mergeAll(deps, hooks) : deps);

export default {
  async fetch(req, env) {
    const path = new URL(req.url).pathname;

    if (path === "/interrupt") {
      // finding 1: a read 8 MiB into a packument, parked on npm's next chunk, interrupted because a sibling lookup failed
      const pool = new MemoryPool();
      const lease = pool.request();
      let reached, cancelled = false;
      const parked = new Promise((r) => (reached = r));
      let at = -1;
      globalThis.fetch = async () => new Response(new ReadableStream({
        async pull(c) {
          if (at < 0) { at = 0; c.enqueue(encoder.encode(HEAD)); return; }
          if (at < 8 * MiB) { at += 65536; c.enqueue(encoder.encode("x".repeat(65536))); return; }
          reached();
          await new Promise(() => undefined);
        },
        // the network takes a moment to let go of the connection
        async cancel() { await sleep(20); cancelled = true; },
      }));
      const base = await measure(env);
      const sibling = Effect.promise(() => parked).pipe(Effect.andThen(Effect.fail("a sibling lookup failed")));
      const both = Effect.all([Effect.flatMap(Upstream, (u) => u.listing("p", lease)), sibling], { concurrency: "unbounded" });
      const pending = Effect.runPromiseExit(both.pipe(Effect.provide(layerWith(null)), Effect.scoped, Effect.ensuring(Effect.sync(() => lease.release()))));
      await parked;
      const during = { held: (await measure(env)) - base, charged: pool.charged };
      const exit = await pending;
      // the moment the lease is released: what the isolate holds now is what the interrupted read left behind
      const after = { held: (await measure(env)) - base, charged: pool.charged, open: lease.open, cancelled };
      return Response.json({ exit: exit._tag, during, after });
    }

    if (path === "/malformed") {
      // finding 2: a 10 MiB readme and then a byte that is not JSON: the read is refused and its stream's cancel stalls
      const pool = new MemoryPool();
      const lease = pool.request();
      let cancelStarted, finishCancel;
      const cancelling = new Promise((r) => (cancelStarted = r));
      const stalled = new Promise((r) => (finishCancel = r));
      let at = -1;
      const body = new ReadableStream({
        pull(c) {
          if (at < 0) { at = 0; c.enqueue(encoder.encode('{"name":"p","readme":"')); return; }
          if (at < 10 * MiB) { at += 65536; c.enqueue(encoder.encode("x".repeat(65536))); return; }
          if (at === 10 * MiB) { at++; c.enqueue(encoder.encode('","versions":{}}!')); }
        },
        cancel() { cancelStarted(); return stalled; },
      });
      const base = await measure(env);
      const pending = readPackument(body, { lease });
      await cancelling;
      const during = { held: (await measure(env)) - base, charged: pool.charged };
      finishCancel();
      const read = await pending;
      const after = { held: (await measure(env)) - base, charged: pool.charged };
      lease.release();
      return Response.json({ read: read.kind, during, after });
    }

    if (path === "/deadline") {
      // finding 3: the review's look at a fetched package, past its deadline. \`mode\` "stalled" ignores the lease's
      // signal; "stops" stops when it aborts, as worker.ts's listener does, and only then releases the lease
      const mode = new URL(req.url).searchParams.get("mode");
      let now = 0;
      const pool = new MemoryPool(80 * MiB, () => now);
      const lease = pool.request();
      globalThis.fetch = async () => new Response(readmeStream(8 * MiB));
      let held = null, done = null, finish;
      const stalled = new Promise((r) => (finish = r));
      const hooks = Layer.succeed(ReleaseHooks, {
        afterCommit: () => Effect.void,
        upstreamFetched: (pkg, lease) => Effect.sync(() => {
          held = lease;
          const look = Effect.promise(() => stalled).pipe(Effect.andThen(Effect.sync(() => pkg.readme.length)));
          done = mode === "stalled"
            ? (async () => { await stalled; const n = pkg.readme.length; lease.release(); return n; })()
            : Effect.runPromiseExit(look, { signal: lease.signal }).finally(() => lease.release());
        }),
      });
      const base = await measure(env);
      let got = await Effect.runPromise(Effect.flatMap(Upstream, (u) => u.listing("p", lease)).pipe(Effect.provide(layerWith(hooks)), Effect.scoped));
      const kind = got.kind;
      got = null;
      lease.release();
      const before = { held: (await measure(env)) - base, charged: pool.charged, open: held.open };
      // past the deadline, a request needs the whole pool
      now = 61_000;
      const pressure = pool.request(80 * MiB);
      const fits = pressure.take(80 * MiB);
      pressure.release();
      await sleep(5);
      const after = { held: (await measure(env)) - base, charged: pool.charged, open: held.open, stopped: held.signal?.aborted ?? false };
      finish();
      await done;
      const settled = { held: (await measure(env)) - base, charged: pool.charged, open: held.open };
      return Response.json({ kind, before, fits, after, settled });
    }

    if (path === "/package-answer") {
      // finding 4: the package page's answer for an upstream package with an 8 MiB readme, through the real apmRoute
      const pool = new MemoryPool();
      const lease = pool.request();
      globalThis.fetch = async () => new Response(readmeStream(8 * MiB));
      const services = Layer.mergeAll(deps, Clock.fixed({ now: Date.parse("2026-11-13"), wallNow: 0 }), Analysis.none, Layer.succeed(RegistryConfig, { baseUrl: "https://registry.test/", webUrl: "https://web.test/" }));
      const layersFor = (l) => Layer.provideMerge(Upstream.layer("https://npm.invalid/", 60000, null), Layer.mergeAll(services, Layer.succeed(RequestMemory, l)));
      const layers = layersFor(lease);
      const request = new Request("https://registry.test/-/apm/v1/packages/p");
      const base = await measure(env);
      let res = await Effect.runPromise(apmRoute(request, new URL(request.url), { kind: "anonymous" }).pipe(Effect.provide(layers), Effect.scoped));
      const status = res.status;
      lease.release();
      // a request that needs the whole pool: the isolate cache's entries are evicted, and nothing else should give way
      const pressure = pool.request(80 * MiB);
      const fits = pressure.take(80 * MiB);
      pressure.release();
      const unread = { held: (await measure(env)) - base, charged: pool.charged, open: lease.open };
      // the client reads the answer: once the last byte is sent the lease is released
      const reader = res.body.getReader();
      let bytes = 0, chunks = 0, text = "";
      const decoder = new TextDecoder();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.length;
        chunks++;
        if (bytes < 4096) text += decoder.decode(value.subarray(0, 4096));
      }
      res = null;
      const sent = { held: (await measure(env)) - base, charged: pool.charged, open: lease.open };
      // the same route, cancelled by the client after its first chunk
      const second = pool.request();
      let res2 = await Effect.runPromise(apmRoute(request, new URL(request.url), { kind: "anonymous" }).pipe(Effect.provide(layersFor(second)), Effect.scoped));
      second.release();
      const r2 = res2.body.getReader();
      await r2.read();
      const beforeCancel = { charged: pool.charged, open: second.open };
      await r2.cancel();
      res2 = null;
      const afterCancel = { charged: pool.charged, open: second.open, cache: pool.cache().taken };
      return Response.json({ status, fits, unread, bytes, chunks, head: text.slice(0, 40), sent, beforeCancel, afterCancel, cache: pool.cache().taken });
    }

    return new Response("not found", { status: 404 });
  },
};
`;
