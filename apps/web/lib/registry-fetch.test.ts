// Runs fetchJson against a real local server, so timeouts, caps and statuses are the real thing.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { classifyStatus, fetchJson, readCappedText, type Fetched } from "./registry-fetch";

const Doc = z.object({ name: z.string() });

let server: ReturnType<typeof Bun.serve>;
let base = "";

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const path = new URL(req.url).pathname;

      switch (path) {
        case "/ok":
          return Response.json({ name: "left-pad" });
        case "/missing":
          return Response.json({ error: "Not found" }, { status: 404 });
        case "/broken":
          return Response.json({ error: "boom" }, { status: 500 });
        case "/unavailable":
          return new Response("down", { status: 503 });
        case "/wrong-shape":
          return Response.json({ ok: true });
        case "/not-json":
          return new Response("<html>", { headers: { "content-type": "text/html" } });
        case "/big":
          return Response.json({ name: "x".repeat(2048) });
        case "/big-chunked":
          // No Content-Length: the cap has to hold while streaming.
          return new Response(
            new ReadableStream({
              start(controller) {
                for (let i = 0; i < 64; i++) controller.enqueue(new TextEncoder().encode("x".repeat(1024)));
                controller.close();
              },
            }),
          );
        case "/slow":
          await Bun.sleep(2_000);

          return Response.json({ name: "late" });
        default:
          return new Response("no route", { status: 404 });
      }
    },
  });
  base = `http://127.0.0.1:${server.port}`;
});

afterAll(() => {
  server.stop(true);
});

function reasonOf<T>(r: Fetched<T>): string {
  return r.kind === "unavailable" ? r.reason.kind : r.kind;
}

describe("fetchJson error mapping", () => {
  test("a parsed 200 is ok", async () => {
    expect(await fetchJson({ url: `${base}/ok`, schema: Doc })).toEqual({ kind: "ok", value: { name: "left-pad" } });
  });

  test("only a registry 404 is missing", async () => {
    expect(await fetchJson({ url: `${base}/missing`, schema: Doc })).toEqual({ kind: "missing" });
  });

  test("5xx is unavailable with the status", async () => {
    expect(await fetchJson({ url: `${base}/broken`, schema: Doc })).toEqual({ kind: "unavailable", reason: { kind: "status", status: 500 } });
    expect(await fetchJson({ url: `${base}/unavailable`, schema: Doc })).toEqual({ kind: "unavailable", reason: { kind: "status", status: 503 } });
  });

  test("a schema mismatch is unavailable, not missing", async () => {
    expect(reasonOf(await fetchJson({ url: `${base}/wrong-shape`, schema: Doc }))).toBe("invalid");
    expect(reasonOf(await fetchJson({ url: `${base}/not-json`, schema: Doc }))).toBe("invalid");
  });

  test("a refused connection is unavailable", async () => {
    const closed = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("") });
    const url = `http://127.0.0.1:${closed.port}/ok`;

    await closed.stop(true);
    expect(reasonOf(await fetchJson({ url, schema: Doc }))).toBe("network");
  });

  test("a stalled registry times out", async () => {
    const started = performance.now();
    const r = await fetchJson({ url: `${base}/slow`, schema: Doc, timeoutMs: 150 });

    expect(reasonOf(r)).toBe("timeout");
    expect(performance.now() - started).toBeLessThan(1_500);
  });

  test("a body over the cap is unavailable, with or without Content-Length", async () => {
    expect(await fetchJson({ url: `${base}/big`, schema: Doc, maxBytes: 1024 })).toEqual({ kind: "unavailable", reason: { kind: "too-large", limit: 1024 } });
    expect(await fetchJson({ url: `${base}/big-chunked`, schema: Doc, maxBytes: 4096 })).toEqual({ kind: "unavailable", reason: { kind: "too-large", limit: 4096 } });
  });

  test("the caller's abort stops the request", async () => {
    const controller = new AbortController();
    const pending = fetchJson({ url: `${base}/slow`, schema: Doc, signal: controller.signal });

    controller.abort();
    expect((await pending).kind).toBe("unavailable");
  });
});

describe("classifyStatus", () => {
  test.each<[number, ReturnType<typeof classifyStatus>]>([
    [200, "ok"],
    [204, "ok"],
    [404, "missing"],
    [301, "unavailable"],
    [400, "unavailable"],
    [401, "unavailable"],
    [410, "unavailable"],
    [429, "unavailable"],
    [500, "unavailable"],
    [502, "unavailable"],
    [503, "unavailable"],
  ])("%i is %s", (status, kind) => {
    expect(classifyStatus(status)).toBe(kind);
  });
});

describe("readCappedText", () => {
  test("reads a body under the cap, including multi-byte text split across chunks", async () => {
    const bytes = new TextEncoder().encode("añb€c");

    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const b of bytes) controller.enqueue(new Uint8Array([b]));
        controller.close();
      },
    });

    expect(await readCappedText(new Response(body), 100)).toEqual({ kind: "ok", text: "añb€c" });
  });

  test("stops at the cap even when Content-Length understates the body", async () => {
    const res = new Response("x".repeat(5000), { headers: { "content-length": "10" } });

    expect(await readCappedText(res, 1000)).toEqual({ kind: "too-large", limit: 1000 });
  });

  test("rejects up front when Content-Length is over the cap", async () => {
    const res = new Response("x".repeat(10), { headers: { "content-length": "999999" } });

    expect(await readCappedText(res, 1000)).toEqual({ kind: "too-large", limit: 1000 });
  });
});
