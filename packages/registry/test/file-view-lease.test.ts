// The file view reads a tarball too large to hold as one verified stream (files.ts, readOneFile). What that read keeps,
// and the index and file body built from it, stay charged to the request's lease until the answer is built (review of
// e8616ca, finding 3: the read's child lease was released as soon as it ended, so a 625 KB index was built and cached
// with nothing charged for it). npm is a local stand-in on 127.0.0.1.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { Store } from "../src/db.ts";
import { fileRoute } from "../src/files.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { MAX_UPSTREAM_TARBALL_BYTES, Upstream } from "../src/upstream.ts";

const enc = new TextEncoder();
const NOW = Date.parse("2026-11-16T00:00:00Z");

function tgz(files: readonly (readonly [string, Uint8Array])[]): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const [name, data] of files) {
    const h = new Uint8Array(512);
    const put = (s: string, at: number): void => h.set(enc.encode(s), at);
    put(`package/${name}`.slice(0, 99), 0);
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

/** 33 MiB of a native binary, which no gzip shrinks: each package is too large to hold, so the file view streams it. */
const ADDON = new Uint8Array(randomBytes(33 * 1024 * 1024));

/** A package of `files` beside the addon. */
const files = (name: string, rest: readonly [string, Uint8Array][]): [string, Uint8Array][] => [
  ["package.json", enc.encode(JSON.stringify({ name, version: "1.0.0", main: "index.js" }))],
  ["index.js", enc.encode("module.exports = 1;\n")],
  ...rest,
  ["prebuilt/addon.node", ADDON],
];

/** 5,000 small files whose paths repeat `char` 80 times: an index of about 600 KB, or 2.5 MB when JSON escapes `char`. */
const many = (char: string): [string, Uint8Array][] => Array.from({ length: 5_000 }, (_, i): [string, Uint8Array] => [`l/${char.repeat(80)}/${String(i).padStart(5, "0")}.js`, enc.encode(`module.exports = ${i};\n`)]);

/** The packages served, each with the file the view is asked for. */
const PACKAGES = {
  wide: { files: files("wide", many("a")), path: "index.js" },
  // inert: U+0001 in every path, which JSON writes as \u0001, six characters for one (review of 8249989)
  escaped: { files: files("escaped", many("\u0001")), path: "index.js" },
  // inert: a 1 MiB text file of U+0001, six times as long as JSON
  control: { files: files("control", [["notes.txt", new Uint8Array(1024 * 1024).fill(1)]]), path: "notes.txt" },
} satisfies Record<string, { files: [string, Uint8Array][]; path: string }>;

const BYTES = new Map<string, Uint8Array>();
let db: Awaited<ReturnType<typeof freshDatabase>>;
let npm: ReturnType<typeof Bun.serve>;

beforeAll(async () => {
  for (const [name, p] of Object.entries(PACKAGES)) BYTES.set(name, tgz(p.files));
  db = await freshDatabase();
  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;
      const tar = /^\/([^/]+)\/-\/[^/]+\.tgz$/.exec(path);
      const name = tar?.[1] ?? path.slice(1);
      const bytes = BYTES.get(name);

      if (!bytes) return Response.json({ error: "Not found" }, { status: 404 });

      if (tar) return new Response(bytes, { headers: { "content-length": String(bytes.length) } });
      const dist = { tarball: `${npm.url.href}${name}/-/${name}-1.0.0.tgz`, integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}` };

      return Response.json({ name, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name, version: "1.0.0", dist } }, time: { "1.0.0": "2026-10-01T00:00:00Z" } });
    },
  });
}, 60_000);

afterAll(async () => {
  await npm.stop(true);
  await db.drop();
});

/** Asks the file view for `name`'s file, with the cached writes it made and what the request's lease held at each. */
async function view(name: keyof typeof PACKAGES, limit = 512 * 1024 * 1024) {
  const bytes = BYTES.get(name) ?? new Uint8Array();

  expect(bytes.length).toBeGreaterThan(MAX_UPSTREAM_TARBALL_BYTES);
  const lease = new MemoryPool(1 << 30).request(limit);
    // each cached write, with what the request's lease holds as it is written
    const puts: { key: string; bytes: number; taken: number; open: boolean }[] = [];

    const blobs = Layer.succeed(
      Blobs,
      Blobs.of({
        put: (key, bytes) => Effect.sync(() => void puts.push({ key, bytes: bytes.length, taken: lease.taken, open: lease.open })),
        stream: () => Effect.succeed(Option.none()),
        bytes: () => Effect.succeed(Option.none()),
        exists: () => Effect.succeed(false),
        remove: () => Effect.void,
      }),
    );

    const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), blobs, Layer.succeed(RequestMemory, lease));
    const layers = Layer.provideMerge(Upstream.layer(npm.url.href, 1, null), base);
    const req = new Request(`http://registry.test/-/apm/v1/file/${name}/1.0.0?path=${encodeURIComponent(PACKAGES[name].path)}`);

  try {
    const res = await Effect.runPromise(Effect.flatMap(fileRoute(req, new URL(req.url)), (r) => Effect.promise(async () => (r ? { status: r.status, text: await r.text() } : null))).pipe(Effect.provide(layers), Effect.scoped));

    return { res, index: puts.find((p) => p.key.endsWith("index.json")), body: puts.find((p) => !p.key.endsWith("index.json")), peak: lease.peakTaken };
  } finally {
    lease.release();
  }
}

/**
 * What writing `bytes` of cached JSON holds at once at least: the JSON text (one byte a character when it is all
 * ASCII, as these are) and its UTF-8 copy.
 */
const serialized = (bytes: number): number => 2 * bytes;

describe("the file view's streamed read", () => {
  test("keeps what it read, and the index and body built from it, charged to the request until the answer is built", async () => {
    const { res, index, body } = await view("wide");

    expect(res?.status, res?.text.slice(0, 200)).toBe(200);
    expect(index?.bytes ?? 0).toBeGreaterThan(500_000);
    // on e8616ca: the read's child lease was closed by now and the request held 2,680 bytes as the index went out

    for (const p of [index, body]) {
      expect(p?.open).toBe(true);
      expect(p?.taken ?? 0).toBeGreaterThan(serialized(index?.bytes ?? 0));
    }
  }, 120_000);
});

describe("what serializing the index and a file body charges, before either is built", () => {
  test("paths JSON escapes: the index's text and its encoded copy are charged", async () => {
    const { res, index } = await view("escaped");

    expect(res?.status, res?.text.slice(0, 200)).toBe(200);
    process.stdout.write(`[file-view] escaped paths: ${index?.bytes} bytes of index JSON, ${index?.taken} bytes charged as it was written\n`);
    expect(index?.bytes ?? 0).toBeGreaterThan(2_500_000);
    // on 8249989: a 2,565,124-byte index with 4,253,840 bytes charged, under the 5,130,248 its text and copy hold
    expect(index?.taken ?? 0).toBeGreaterThan(serialized(index?.bytes ?? 0));
  }, 120_000);

  test("a text file JSON escapes: its decoded text, its JSON and that JSON's encoded copy are charged", async () => {
    const { res, body } = await view("control");

    expect(res?.status, res?.text.slice(0, 200)).toBe(200);
    process.stdout.write(`[file-view] control text: ${body?.bytes} bytes of body JSON, ${body?.taken} bytes charged as it was written\n`);
    expect(body?.bytes ?? 0).toBeGreaterThan(6_000_000);
    // on 8249989: 6,291,481 bytes of JSON with 9,496,700 bytes charged, under the 12,582,962 its text and copy hold,
    // and the decoded text besides
    expect(body?.taken ?? 0).toBeGreaterThan(serialized(body?.bytes ?? 0) + 1024 * 1024);
  }, 120_000);

  test("and a request with no room for them is answered 503, not built outside the lease", async () => {
    // room for the streamed read and the index of two paths, not for 6 MB of JSON and its copy
    const { res, body } = await view("control", 10 * 1024 * 1024);

    expect(res?.status, res?.text.slice(0, 200)).toBe(503);
    expect(body).toBeUndefined();
  }, 120_000);
});
