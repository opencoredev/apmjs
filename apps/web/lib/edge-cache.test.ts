// The edge cache through fetchJson, against a real local server that counts its reads, so "from the cache" means
// the registry was not asked.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { lookup, store } from "./edge-cache";
import { fetchJson } from "./registry-fetch";

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

describe("fetchJson with a cache policy", () => {
  test("a second read within the fresh window does not reach the registry", async () => {
    const url = `${base}/fresh`;
    const a = await fetchJson({ url, schema: Doc, cache: FAST });
    const b = await fetchJson({ url, schema: Doc, cache: FAST });

    expect(a).toEqual({ kind: "ok", value: { name: "/fresh", n: 1 } });
    expect(b).toEqual(a);
    expect(reads.get("/fresh")).toBe(1);
  });

  test("a stale entry is served at once and refreshed in the background", async () => {
    const url = `${base}/stale`;
    const policy = { freshMs: 1, staleMs: 60_000 };
    await fetchJson({ url, schema: Doc, cache: policy });
    await Bun.sleep(5);
    const served = await fetchJson({ url, schema: Doc, cache: policy });

    expect(served).toEqual({ kind: "ok", value: { name: "/stale", n: 1 } });

    // the refresh runs on its own; wait for the server to see it and the cache to hold its answer
    for (let i = 0; i < 50 && (reads.get("/stale") ?? 0) < 2; i++) await Bun.sleep(10);
    await Bun.sleep(10);
    expect(reads.get("/stale")).toBe(2);
    expect((await lookup(url, { freshMs: 60_000, staleMs: 0 }))?.text).toContain('"n":2');
  });

  test("past fresh and stale, the registry is asked before answering", async () => {
    const url = `${base}/expired`;
    await fetchJson({ url, schema: Doc, cache: { freshMs: 1, staleMs: 1 } });
    await Bun.sleep(5);
    const again = await fetchJson({ url, schema: Doc, cache: { freshMs: 1, staleMs: 1 } });

    expect(again).toEqual({ kind: "ok", value: { name: "/expired", n: 2 } });
  });

  test("an outage keeps what was cached; a 404 or 410 drops it", async () => {
    const url = `${base}/gone`;
    // always stale: every read serves the entry and refreshes it in the background
    const stale = { freshMs: 0, staleMs: 60_000 };
    const settle = () => Bun.sleep(30);
    await fetchJson({ url, schema: Doc, cache: FAST });

    status.set("/gone", 503);
    expect((await fetchJson({ url, schema: Doc, cache: stale })).kind).toBe("ok");
    await settle();
    expect(await lookup(url, FAST)).not.toBeNull();

    status.set("/gone", 410);
    expect((await fetchJson({ url, schema: Doc, cache: stale })).kind).toBe("ok");
    await settle();
    expect(await lookup(url, FAST)).toBeNull();

    store(url, JSON.stringify({ name: "/gone", n: 9 }), FAST);
    status.set("/gone", 404);
    await fetchJson({ url, schema: Doc, cache: stale });
    await settle();
    expect(await lookup(url, FAST)).toBeNull();
    expect((await fetchJson({ url, schema: Doc, cache: FAST })).kind).toBe("missing");
  });

  test("a read that sends headers (a visitor's cookie) is never cached", async () => {
    const url = `${base}/private`;
    await fetchJson({ url, schema: Doc, cache: FAST, headers: { cookie: "a=b" } });
    await fetchJson({ url, schema: Doc, cache: FAST, headers: { cookie: "a=b" } });

    expect(reads.get("/private")).toBe(2);
    expect(await lookup(url, FAST)).toBeNull();
  });

  test("an answer that fails its schema is not cached", async () => {
    const url = `${base}/shape`;
    const Wrong = z.object({ other: z.string() });
    expect((await fetchJson({ url, schema: Wrong, cache: FAST })).kind).toBe("unavailable");
    expect(await lookup(url, FAST)).toBeNull();
  });
});
