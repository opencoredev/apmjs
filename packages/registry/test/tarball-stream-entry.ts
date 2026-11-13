// The worker module tarball-stream.workerd.test.ts runs inside workerd: the Upstream layer with a stand-in npm whose
// one version's tarball is 40 MB, made a chunk at a time as it is read, so nothing but the registry's own path holds it.
import { join } from "node:path";
import { MEASURE } from "./workerd-heap.ts";

const SRC = join(import.meta.dir, "..", "src");
const EFFECT = join(import.meta.dir, "..", "node_modules", "effect", "dist", "index.js");

/** The stand-in tarball's size: over MAX_UPSTREAM_TARBALL_BYTES, the analysis cap. */
export const TARBALL_BYTES = 40 * 1000 * 1000;

export const ENTRY = `
import { Effect, Layer, Option } from ${JSON.stringify(EFFECT)};
import { MemoryPool } from ${JSON.stringify(join(SRC, "memory.ts"))};
import { Upstream } from ${JSON.stringify(join(SRC, "upstream.ts"))};
import { Store } from ${JSON.stringify(join(SRC, "db.ts"))};
import { Blobs } from ${JSON.stringify(join(SRC, "blobs.ts"))};
import { createHash } from "node:crypto";
${MEASURE}
const SIZE = ${TARBALL_BYTES};
const CHUNK = 64 * 1024;

/** Chunk \`i\` of the tarball: fresh bytes each time, from a generator seeded by \`i\`. */
function chunkAt(i) {
  const n = Math.min(CHUNK, SIZE - i * CHUNK);
  const out = new Uint8Array(n);
  let s = (i + 1) * 2654435761 >>> 0;
  for (let k = 0; k < n; k++) { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; out[k] = s & 255; }
  return out;
}

function tarballStream() {
  let i = 0;
  return new ReadableStream({
    pull(c) {
      if (i * CHUNK >= SIZE) { c.close(); return; }
      c.enqueue(chunkAt(i++));
    },
  }, { highWaterMark: 0 });
}

let expected = null;
function expectedHex() {
  if (expected) return expected;
  const h = createHash("sha512");
  for (let i = 0; i * CHUNK < SIZE; i++) h.update(chunkAt(i));
  expected = h.digest("hex");
  return expected;
}

globalThis.fetch = async (input) => {
  // the tarball is fetched by URL object, the packument by string
  const path = new URL(input instanceof Request ? input.url : String(input)).pathname;
  if (path === "/huge/-/huge-1.0.0.tgz") return new Response(tarballStream(), { status: 200, headers: { "content-type": "application/octet-stream", "content-length": String(SIZE) } });
  if (path === "/huge") {
    const integrity = "sha512-" + Buffer.from(expectedHex(), "hex").toString("base64");
    return Response.json({ name: "huge", "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name: "huge", version: "1.0.0", dist: { tarball: "https://npm.invalid/huge/-/huge-1.0.0.tgz", integrity } } }, time: { "1.0.0": "2026-01-01T00:00:00.000Z" } });
  }
  return Response.json({ error: "Not found" }, { status: 404 });
};
Object.defineProperty(globalThis, "caches", { value: { default: { match: async () => undefined, put: async () => {} } }, configurable: true });

const puts = [];
const store = { upstreamAnalyses: () => Effect.succeed({ scores: new Map(), unscorable: new Map() }), upstreamAnalysesOf: () => Effect.succeed(new Map()) };
const blobs = { bytes: () => Effect.succeed(Option.none()), put: (key) => Effect.sync(() => { puts.push(key); }), remove: () => Effect.void };
const layer = Layer.provide(Upstream.layer("https://npm.invalid/", 60000, null), Layer.mergeAll(Layer.succeed(Store, store), Layer.succeed(Blobs, blobs)));
const pool = new MemoryPool();

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname === "/measure") return new Response(String(await measure(env)));

    if (url.pathname === "/expected") return new Response(expectedHex());

    if (url.pathname === "/serve") {
      const lease = pool.request();
      const got = await Effect.runPromise(Effect.gen(function* () {
        const u = yield* Upstream;
        const p = yield* u.probe("huge", lease);
        if (p.kind !== "found") return { kind: p.kind };
        return yield* u.serve(p.pkg, "1.0.0");
      }).pipe(Effect.provide(layer), Effect.scoped));
      lease.release();
      if (got.kind !== "stream") return Response.json(got, { status: 500 });
      // as the tarball route answers it (apm.ts, upstreamRoute)
      return new Response(got.body, { headers: { "content-type": "application/octet-stream", "content-length": String(got.length), "x-pool-charged": String(pool.charged), "x-blob-puts": String(puts.length) } });
    }

    return new Response("not found", { status: 404 });
  },
};
`;
