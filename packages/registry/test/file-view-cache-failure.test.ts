// The file and readme views cache an index and file bodies in R2 (files.ts). That cache is rebuilt from the verified
// tarball, so R2 failing to answer one of its reads or writes costs a rebuild, never the answer: before, a cache read
// past R2_GET_MS (HEAD of a file, 2026-11-24) and R2's 10001 errors (a readme, 2026-11-22) each made the view a 500.
// npm is a local stand-in on 127.0.0.1.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { Store } from "../src/db.ts";
import { DeadlinePassed } from "../src/deadline.ts";
import { BlobError } from "../src/errors.ts";
import { fileRoute } from "../src/files.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { Upstream } from "../src/upstream.ts";

const enc = new TextEncoder();
const NOW = Date.parse("2026-11-24T16:00:00Z");
const NAME = "cache-down";

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

const TARBALL = tgz([
  ["package.json", enc.encode(JSON.stringify({ name: NAME, version: "1.0.0", main: "index.js" }))],
  ["index.js", enc.encode("module.exports = 1;\n")],
  ["README.md", enc.encode("# cache-down\n")],
]);

let db: Awaited<ReturnType<typeof freshDatabase>>;
let npm: ReturnType<typeof Bun.serve>;

beforeAll(async () => {
  db = await freshDatabase();
  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;

      if (path === `/${NAME}/-/${NAME}-1.0.0.tgz`) return new Response(TARBALL, { headers: { "content-length": String(TARBALL.length) } });

      if (path !== `/${NAME}`) return Response.json({ error: "Not found" }, { status: 404 });
      const dist = { tarball: `${npm.url.href}${NAME}/-/${NAME}-1.0.0.tgz`, integrity: `sha512-${createHash("sha512").update(TARBALL).digest("base64")}` };

      return Response.json({ name: NAME, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name: NAME, version: "1.0.0", dist } }, time: { "1.0.0": "2026-10-01T00:00:00Z" } });
    },
  });
}, 60_000);

afterAll(async () => {
  await npm.stop(true);
  await db.drop();
});

/** A blob store whose every read and write fails with `cause`, the way R2 did. */
const failingBlobs = (cause: () => Error) =>
  Layer.succeed(
    Blobs,
    Blobs.of({
      put: (key) => Effect.fail(new BlobError({ operation: "put", key, cause: cause() })),
      stream: (key) => Effect.fail(new BlobError({ operation: "get", key, cause: cause() })),
      bytes: (key) => Effect.fail(new BlobError({ operation: "get", key, cause: cause() })),
      exists: (key) => Effect.fail(new BlobError({ operation: "head", key, cause: cause() })),
      remove: (key) => Effect.fail(new BlobError({ operation: "delete", key, cause: cause() })),
    }),
  );

const CAUSES = {
  "a read past its deadline": () => new DeadlinePassed("r2-get", 5_000),
  "an R2 error (10001)": () => new Error("get: We encountered an internal error. Please try again. (10001)"),
} satisfies Record<string, () => Error>;

async function ask(input: { method: "GET" | "HEAD"; path: string; cause: () => Error }) {
  const lease = new MemoryPool(1 << 30).request(64 * 1024 * 1024);
  const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), failingBlobs(input.cause), Layer.succeed(RequestMemory, lease));
  const layers = Layer.provideMerge(Upstream.layer(npm.url.href, 1, null), base);
  const req = new Request(`http://registry.test${input.path}`, { method: input.method });

  try {
    return await Effect.runPromise(Effect.flatMap(fileRoute(req, new URL(req.url)), (r) => Effect.promise(async () => (r ? { status: r.status, text: await r.text() } : null))).pipe(Effect.provide(layers), Effect.scoped));
  } finally {
    lease.release();
  }
}

const PATHS = {
  file: `/-/apm/v1/file/${NAME}/1.0.0?path=index.js`,
  excerpt: `/-/apm/v1/file/${NAME}/1.0.0?path=index.js&line=1&context=0`,
  readme: `/-/apm/v1/readme/${NAME}/1.0.0`,
} as const;

describe("the file view answers when its R2 cache cannot be read or written", () => {
  for (const [label, cause] of Object.entries(CAUSES)) {
    test(`${label}: GET of a file, an excerpt and a readme`, async () => {
      const file = await ask({ method: "GET", path: PATHS.file, cause });

      expect(file?.status, file?.text.slice(0, 200)).toBe(200);
      expect(JSON.parse(file?.text ?? "{}")).toMatchObject({ kind: "text", path: "index.js", text: "module.exports = 1;\n" });

      const excerpt = await ask({ method: "GET", path: PATHS.excerpt, cause });

      expect(excerpt?.status, excerpt?.text.slice(0, 200)).toBe(200);
      expect(JSON.parse(excerpt?.text ?? "{}")).toMatchObject({ kind: "excerpt", totalLines: 1 });

      const readme = await ask({ method: "GET", path: PATHS.readme, cause });

      expect(readme?.status, readme?.text.slice(0, 200)).toBe(200);
      expect(JSON.parse(readme?.text ?? "{}")).toMatchObject({ kind: "text", path: "README.md" });
    }, 60_000);

    test(`${label}: HEAD of a file is 200 with no body`, async () => {
      const res = await ask({ method: "HEAD", path: PATHS.file, cause });

      expect(res?.status).toBe(200);
      expect(res?.text).toBe("");
    }, 60_000);
  }

  test("a file the tarball lacks is still a 404", async () => {
    const res = await ask({ method: "HEAD", path: `/-/apm/v1/file/${NAME}/1.0.0?path=nope.js`, cause: CAUSES["a read past its deadline"] });

    expect(res?.status).toBe(404);
  }, 60_000);
});
