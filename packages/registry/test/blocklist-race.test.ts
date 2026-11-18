// Races on the install block list (blocklist.ts), on workerd's own R2 (Miniflare): a write whose transaction is about to
// commit is never lost to a concurrent sync, whether the object already exists or both writers find it missing, and a
// confirmation repeated after the cron read an older state keeps its entry through the next sync.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { Miniflare } from "miniflare";
import { BLOCKLIST_KEY, readFrom, reconciled, rewrite, SYNC_GRACE_MS, withBlocks, type BlocklistBody, type BlocklistBucket } from "../src/blocklist.ts";

let mf: Miniflare;
let bucket: BlocklistBucket;

beforeAll(async () => {
  mf = new Miniflare({ modules: true, script: "export default { fetch() { return new Response(null); } }", r2Buckets: ["BLOBS"] });
  const raw = await mf.getR2Bucket("BLOBS");

  bucket = {
    // workerd's object, its bytes handed on as a stream of this runtime's (the list reads only `body` and `etag`)
    get: async (key) => {
      const obj = await raw.get(key);

      return obj === null ? null : { body: new Blob([new Uint8Array(await obj.arrayBuffer())]).stream(), etag: obj.etag };
    },
    put: async (key, value, options) => raw.put(key, value, options),
  };
});

afterAll(async () => {
  await mf.dispose();
});

beforeEach(async () => {
  await (await mf.getR2Bucket("BLOBS")).delete(BLOCKLIST_KEY);
});

/** The bucket as one writer sees it: after its first read, `meanwhile` runs to completion before it goes on. */
function interleaved(meanwhile: () => Promise<BlocklistBody>): BlocklistBucket {
  let first = true;

  return {
    get: async (key) => {
      const got = await bucket.get(key);

      if (first) {
        first = false;
        await meanwhile();
      }

      return got;
    },
    put: (key, value, options) => bucket.put(key, value, options),
  };
}

/** The list as R2 holds it, read the way the degraded routes read it. */
async function stored(): Promise<BlocklistBody | null> {
  const read = await readFrom(bucket);

  return read.kind === "ok" ? read.list : null;
}

const T = Date.now();
const NOTHING = { local: [], confirmed: [] };

describe("creating the list", () => {
  test("R2's create-only put refuses a key that exists and leaves it as it was", async () => {
    const createOnly = { httpMetadata: { contentType: "text/plain" }, customMetadata: {}, onlyIf: { etagDoesNotMatch: "*" } } as const;

    expect(await bucket.put(BLOCKLIST_KEY, "first", createOnly)).not.toBeNull();
    expect(await bucket.put(BLOCKLIST_KEY, "second", createOnly)).toBeNull();
    const kept = await bucket.get(BLOCKLIST_KEY);

    expect(kept === null ? null : await new Response(kept.body).text()).toBe("first");
  });

  test("a sync that found the object missing does not overwrite a first publish's block written in between", async () => {
    // the cron read the database before the publish; both writers find no object
    await rewrite(
      interleaved(() => rewrite(bucket, (list) => withBlocks(list, { local: ["@a/first"] }, T))),
      (list) => reconciled(list, NOTHING, T + 1),
    );
    const list = await stored();

    expect(list?.syncedAt).toBe(T + 1);
    expect(list?.local.map((e) => e.name)).toEqual(["@a/first"]);
  });
});

describe("an existing list", () => {
  test("a sync never drops a block written between its read and its put", async () => {
    await rewrite(bucket, (list) => reconciled(list, NOTHING, T));
    await rewrite(
      interleaved(() => rewrite(bucket, (list) => withBlocks(list, { confirmed: [{ name: "ms", version: "2.1.2", digest: "sha512-aa" }] }, T + 1))),
      (list) => reconciled(list, NOTHING, T + 2),
    );

    expect((await stored())?.confirmed.map((c) => c.version)).toEqual(["2.1.2"]);
  });

  test("confirming again renews an entry that was about to age out, and the next sync keeps it", async () => {
    const old = { name: "ms", version: "2.1.2", digest: "sha512-aa" };
    // confirmed long ago, then dismissed: the database no longer holds it, and its grace has passed
    await rewrite(bucket, (list) => withBlocks(list, { confirmed: [old] }, T - SYNC_GRACE_MS * 3));
    // confirmed again, while the cron reads the dismissed state
    await rewrite(bucket, (list) => withBlocks(list, { confirmed: [old] }, T));
    await rewrite(bucket, (list) => reconciled(list, NOTHING, T + 1_000));

    expect((await stored())?.confirmed).toEqual([{ ...old, addedAt: T }]);
  });
});
