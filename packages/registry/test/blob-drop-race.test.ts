// A delete that outlives its caller's wait must never erase a replacement upload (review of 11cbf13, finding 1), on a
// real Postgres. dropBlobIfUnused holds the blob's lock exclusively while it checks for references and deletes the
// object; an upload holds it shared from its put until its version row is in. On 11cbf13 the blob store gave up on a
// delete after 5 s: the transaction rolled back and released the lock while R2's delete was still in flight, a publish
// of the same bytes took the shared lock, wrote and committed, and then the late delete removed the object its new
// version points at. Here R2's delete is held past that bound (the stand-in's bound is 50 ms) while a publish of the
// same bytes starts: the publish must wait for the delete, and the object must be there at the end.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Exit, Layer } from "effect";
import { Client } from "pg";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Blobs, type BlobBucket } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { Store } from "../src/db.ts";
import { commitVersion, dropBlobIfUnused } from "../src/server.ts";

const NOW = Date.parse("2026-11-18T00:00:00Z");
const BYTES = new TextEncoder().encode("the same tarball bytes");
const KEY = `sha512/${createHash("sha512").update(BYTES).digest("hex")}`;

/** The stand-in's R2 bounds: far below the time the test holds the delete. */
const LIMITS = { getMs: 50, readMs: 50, idleMs: 50 };

/** How long the test holds R2's delete before it lets it land. */
const DELETE_HELD_MS = 600;

let db: Awaited<ReturnType<typeof freshDatabase>>;

beforeAll(async () => {
  db = await freshDatabase();
  const c = new Client({ connectionString: db.url });

  await c.connect();

  try {
    await c.query("INSERT INTO users (name, password_hash, email, created_at) VALUES ('alice', 'x', 'alice@example.test', 0)");
  } finally {
    await c.end();
  }
}, 60_000);

afterAll(async () => {
  await db.drop();
});

/** An R2 bucket in memory whose deletes land only when the test releases them; `deleting` resolves once one is asked. */
function heldDeletes() {
  const objects = new Map<string, Uint8Array>();
  const gate = Promise.withResolvers<void>();
  const asked = Promise.withResolvers<void>();

  const bucket: BlobBucket = {
    get: async (key) => {
      const bytes = objects.get(key);

      return bytes === undefined ? null : { body: new Blob([bytes]).stream(), size: bytes.length };
    },
    put: async (key, value) => {
      objects.set(key, value);

      return {};
    },
    head: async (key) => (objects.has(key) ? {} : null),
    delete: async (key) => {
      asked.resolve();
      await gate.promise;
      objects.delete(key);
    },
  };

  return { objects, bucket, release: () => gate.resolve(), deleting: asked.promise };
}

describe("dropBlobIfUnused and a replacement upload of the same bytes", () => {
  test("a delete held past the blob store's bounds keeps the lock: the upload waits, and its object survives", async () => {
    const r2 = heldDeletes();
    const layers = Layer.mergeAll(Store.postgres(db.url), Blobs.r2(r2.bucket, LIMITS), Clock.fixed({ now: NOW, wallNow: NOW }));
    const run = <A, E>(effect: Effect.Effect<A, E, Store | Blobs | Clock>) => Effect.runPromiseExit(effect.pipe(Effect.provide(layers)));

    // an object nothing points at (a rejected staged upload, say), which cleanup deletes
    r2.objects.set(KEY, BYTES);
    const drop = run(dropBlobIfUnused(KEY));

    await r2.deleting;
    // past the blob store's bounds: on 11cbf13 the drop had given up by now and released the lock
    await Bun.sleep(LIMITS.getMs * 4);
    let published = false;

    const publish = run(
      commitVersion({
        name: "same-bytes",
        version: "1.0.0",
        manifest: { name: "same-bytes", version: "1.0.0" },
        tarballKey: KEY,
        size: BYTES.length,
        shasum: createHash("sha1").update(BYTES).digest("hex"),
        integrity: `sha512-${createHash("sha512").update(BYTES).digest("base64")}`,
        tag: "latest",
        readme: null,
        score: null,
        publisher: "alice",
        detail: {},
        upload: BYTES,
        fence: { kind: "fenced", name: "same-bytes" },
      }),
    ).then((exit) => {
      published = true;

      return exit;
    });

    await Bun.sleep(DELETE_HELD_MS);
    // the publish is still waiting for the blob's lock: the drop holds it until R2's delete settles
    expect(published).toBe(false);
    r2.release();
    const [dropped, committed] = await Promise.all([drop, publish]);

    expect(Exit.isSuccess(dropped)).toBe(true);
    expect(Exit.isSuccess(committed), String(committed)).toBe(true);
    // the late delete landed before the upload's put, so the object the new version points at is there
    expect(r2.objects.get(KEY)).toEqual(BYTES);
    const c = new Client({ connectionString: db.url });

    await c.connect();

    try {
      const rows = await c.query("SELECT tarball_key FROM versions WHERE package = 'same-bytes' AND version = '1.0.0'");

      expect(rows.rows).toEqual([{ tarball_key: KEY }]);
    } finally {
      await c.end();
    }
  }, 30_000);

  test("an upstream cache's delete (\"cache\") is still given up on at its bound", async () => {
    const r2 = heldDeletes();
    const blobs = Blobs.r2(r2.bucket, LIMITS);
    const started = performance.now();
    const exit = await Effect.runPromiseExit(Effect.flatMap(Blobs, (b) => b.remove(KEY, "cache")).pipe(Effect.provide(blobs)));

    expect(Exit.isFailure(exit)).toBe(true);
    expect(performance.now() - started).toBeLessThan(1_000);
    r2.release();
  });
});
