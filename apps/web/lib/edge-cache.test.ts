// The edge cache through fetchCachedJson, against a real local server that counts its reads, so "from the cache" means
// the registry was not asked. Only source-free answers may be cached; the paths here are a package's public log.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { lookup, store } from "./edge-cache";
import { fetchCachedJson, fetchJson } from "./registry-fetch";

const Doc = z.object({ name: z.string(), n: z.number() });

let server: ReturnType<typeof Bun.serve>;
let base = "";
const reads = new Map<string, number>();
const status = new Map<string, number>();

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;
      const n = (reads.get(path) ?? 0) + 1;
      reads.set(path, n);
      const s = status.get(path) ?? 200;

      return s === 200 ? Response.json({ name: path, n }) : Response.json({ error: "no" }, { status: s });
    },
  });
  base = `http://127.0.0.1:${server.port}`;
});

afterAll(() => {
  void server.stop(true);
});

const FAST = { freshMs: 60_000, staleMs: 60_000 };

/** A source-free path (a package's public log) the cache may keep, named after the test. */
const ev = (id: string): string => `/-/apm/v1/packages/${id}/events`;

describe("fetchCachedJson", () => {
  test("a second read within the fresh window does not reach the registry", async () => {
    const url = `${base}${ev("fresh")}`;
    const a = await fetchCachedJson({ url, schema: Doc, cache: FAST });
    const b = await fetchCachedJson({ url, schema: Doc, cache: FAST });

    expect(a).toEqual({ kind: "ok", value: { name: ev("fresh"), n: 1 } });
    expect(b).toEqual(a);
    expect(reads.get(ev("fresh"))).toBe(1);
  });

  test("a stale entry is served at once and refreshed in the background", async () => {
    const url = `${base}${ev("stale")}`;
    const policy = { freshMs: 1, staleMs: 60_000 };
    await fetchCachedJson({ url, schema: Doc, cache: policy });
    await Bun.sleep(5);
    const served = await fetchCachedJson({ url, schema: Doc, cache: policy });

    expect(served).toEqual({ kind: "ok", value: { name: ev("stale"), n: 1 } });

    // the refresh runs on its own; wait for the server to see it and the cache to hold its answer
    for (let i = 0; i < 50 && (reads.get(ev("stale")) ?? 0) < 2; i++) await Bun.sleep(10);
    await Bun.sleep(10);
    expect(reads.get(ev("stale"))).toBe(2);
    expect((await lookup(url, { freshMs: 60_000, staleMs: 0 }))?.text).toContain('"n":2');
  });

  test("past fresh and stale, the registry is asked before answering", async () => {
    const url = `${base}${ev("expired")}`;
    await fetchCachedJson({ url, schema: Doc, cache: { freshMs: 1, staleMs: 1 } });
    await Bun.sleep(5);
    const again = await fetchCachedJson({ url, schema: Doc, cache: { freshMs: 1, staleMs: 1 } });

    expect(again).toEqual({ kind: "ok", value: { name: ev("expired"), n: 2 } });
  });

  test("an outage keeps what was cached; a 404 or 410 drops it", async () => {
    const url = `${base}${ev("gone")}`;
    // always stale: every read serves the entry and refreshes it in the background
    const stale = { freshMs: 0, staleMs: 60_000 };
    const settle = () => Bun.sleep(30);
    await fetchCachedJson({ url, schema: Doc, cache: FAST });

    status.set(ev("gone"), 503);
    expect((await fetchCachedJson({ url, schema: Doc, cache: stale })).kind).toBe("ok");
    await settle();
    expect(await lookup(url, FAST)).not.toBeNull();

    status.set(ev("gone"), 410);
    expect((await fetchCachedJson({ url, schema: Doc, cache: stale })).kind).toBe("ok");
    await settle();
    expect(await lookup(url, FAST)).toBeNull();

    store(url, JSON.stringify({ name: ev("gone"), n: 9 }), FAST);
    status.set(ev("gone"), 404);
    await fetchCachedJson({ url, schema: Doc, cache: stale });
    await settle();
    expect(await lookup(url, FAST)).toBeNull();
    expect((await fetchCachedJson({ url, schema: Doc, cache: FAST })).kind).toBe("missing");
  });

  test("a path that can carry a version's source is refused, and fetchJson reads it every time", async () => {
    for (const path of ["/-/apm/v1/packages/x", "/-/apm/v1/file/x/1.0.0", "/-/apm/v1/readme/x/1.0.0", "/-/apm/v1/review/x/1.0.0", "/-/apm/v1/score/x/1.0.0", "/x"]) {
      await expect(fetchCachedJson({ url: `${base}${path}?path=a`, schema: Doc, cache: FAST })).rejects.toThrow("can carry a version's source");
    }

    const url = `${base}/-/apm/v1/packages/private`;
    await fetchJson({ url, schema: Doc });
    await fetchJson({ url, schema: Doc });
    expect(reads.get("/-/apm/v1/packages/private")).toBe(2);
    expect(await lookup(url, FAST)).toBeNull();
  });

  test("an answer that fails its schema is not cached", async () => {
    const url = `${base}${ev("shape")}`;
    const Wrong = z.object({ other: z.string() });
    expect((await fetchCachedJson({ url, schema: Wrong, cache: FAST })).kind).toBe("unavailable");
    expect(await lookup(url, FAST)).toBeNull();
  });
});
