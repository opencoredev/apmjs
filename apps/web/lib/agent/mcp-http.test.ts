// Re-review finding 5: POST /mcp called request.text() and then compared the string's length with the limit, so a
// body of any size was buffered whole first, the limit counted UTF-16 units instead of bytes, and a body that failed
// mid-read threw. The body is now read through a byte-counting reader that stops at 64 KiB.
import { describe, expect, test } from "bun:test";
import { MAX_BODY_BYTES, mcpPost } from "./mcp-http";
import { fakeSource } from "./testing";

const allow = () => ({ ok: true as const });
const URL_ = "https://apmjs.dev/mcp";

/** A request body and how many bytes of it the reader has pulled so far. */
type CountedBody = { stream: ReadableStream<Uint8Array>; pulled: () => number };

/** A body stream of `chunks` chunks of `size` bytes each, counting how many bytes the reader pulled. */
function counted(input: { size: number; chunks: number; failAt?: number }): CountedBody {
  let sent = 0;
  let pulled = 0;
  const chunk = new Uint8Array(input.size).fill(0x20);

  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (input.failAt !== undefined && sent === input.failAt) {
        controller.error(new Error("connection reset"));

        return;
      }

      if (sent === input.chunks) {
        controller.close();

        return;
      }

      sent++;
      pulled += chunk.byteLength;
      controller.enqueue(chunk);
    },
    // no read ahead: a chunk is pulled only when the reader asks for it
  }, { highWaterMark: 0 });

  return { stream, pulled: () => pulled };
}

const post = (body: BodyInit, headers: Record<string, string> = {}) => new Request(URL_, { method: "POST", body, headers: { "content-type": "application/json", ...headers } });

describe("the MCP body limit", () => {
  test("a declared Content-Length over the limit is refused before any of the body is read", async () => {
    const body = counted({ size: 16 * 1024, chunks: 64 });
    const res = await mcpPost(post(body.stream, { "content-length": String(1024 * 1024) }), { source: fakeSource(), take: allow });

    expect(res.status).toBe(413);
    expect(body.pulled()).toBe(0);
  });

  test("a streamed body with no length stops being read once it passes 64 KiB", async () => {
    // 10 MB on offer, 16 KiB at a time
    const body = counted({ size: 16 * 1024, chunks: 640 });
    const res = await mcpPost(post(body.stream), { source: fakeSource(), take: allow });

    expect(res.status).toBe(413);
    expect(body.pulled()).toBeLessThanOrEqual(MAX_BODY_BYTES + 2 * 16 * 1024);
  });

  test("the limit counts bytes: 40,000 two-byte characters (80,000 bytes) are too large", async () => {
    const message = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", params: { pad: "é".repeat(40_000) } });

    expect(message.length).toBeLessThan(MAX_BODY_BYTES);
    expect(new TextEncoder().encode(message).byteLength).toBeGreaterThan(MAX_BODY_BYTES);
    expect((await mcpPost(post(message), { source: fakeSource(), take: allow })).status).toBe(413);
  });

  test("a body that fails mid-read is a 400, not a crash", async () => {
    const body = counted({ size: 1024, chunks: 10, failAt: 2 });
    const res = await mcpPost(post(body.stream), { source: fakeSource(), take: allow });

    expect(res.status).toBe(400);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  test("a message under the limit, streamed in pieces, is answered", async () => {
    const bytes = new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" }));

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes.slice(0, 5));
        controller.enqueue(bytes.slice(5));
        controller.close();
      },
    });

    const res = await mcpPost(post(stream), { source: fakeSource(), take: allow });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jsonrpc: "2.0", id: 7, result: {} });
  });
});
