// Review item 3: a request body is read only up to the limit. A streamed body (no Content-Length, or a false
// one) is cancelled as soon as it passes the limit, by both parsers, instead of being buffered whole first.
import { describe, expect, test } from "bun:test";
import { Cause, Effect, Exit } from "effect";
import { z } from "zod";
import { MAX_JSON_BODY_BYTES, parseBody, parseOptionalBody } from "../src/http.ts";

const CHUNK = 1024 * 1024;

/** A streamed request, how many chunks the reader pulled from it, and whether the reader cancelled it. */
type Streamed = { readonly req: Request; readonly pulled: () => number; readonly cancelled: () => boolean };

/** A streamed POST of `chunks` one-MiB chunks with no Content-Length; counts how many chunks were pulled. */
function streamed(chunks: number, fill = 0x20): Streamed {
  let pulled = 0;
  let cancelled = false;

  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (pulled >= chunks) {
        controller.close();

        return;
      }

      pulled++;
      controller.enqueue(new Uint8Array(CHUNK).fill(fill));
    },
    cancel() {
      cancelled = true;
    },
  });

  return { req: new Request("http://registry.test/-/apm/v1/scan", { method: "POST", body, duplex: "half" }), pulled: () => pulled, cancelled: () => cancelled };
}

function statusOf<A, E extends { status: number }>(exit: Exit.Exit<A, E>): number | "ok" {
  if (Exit.isSuccess(exit)) return "ok";
  const failure = exit.cause.reasons.find(Cause.isFailReason);

  return failure ? failure.error.status : -1;
}

const Anything = z.unknown();

describe("request bodies are bounded while they are read", () => {
  test("parseBody stops reading a streamed body at the limit and answers 413", async () => {
    const s = streamed(64);
    const exit = await Effect.runPromiseExit(parseBody(s.req, Anything, 5 * CHUNK));

    expect(statusOf(exit)).toBe(413);
    // at most the limit plus the chunk that crossed it
    expect(s.pulled()).toBeLessThanOrEqual(6);
    expect(s.cancelled()).toBe(true);
  });

  test("parseOptionalBody refuses a streamed body over the limit and stops reading it", async () => {
    const s = streamed(64);
    const exit = await Effect.runPromiseExit(parseOptionalBody(s.req, Anything));

    expect(statusOf(exit)).toBe(413);
    expect(s.pulled()).toBeLessThanOrEqual(MAX_JSON_BODY_BYTES / CHUNK + 1);
  });

  test("parseOptionalBody refuses a body just over the limit that sent no Content-Length", async () => {
    const text = `${" ".repeat(MAX_JSON_BODY_BYTES)}{}`;
    const req = new Request("http://registry.test/-/apm/v1/account", { method: "POST", body: new Blob([text]).stream(), duplex: "half" });
    const exit = await Effect.runPromiseExit(parseOptionalBody(req, Anything));

    expect(statusOf(exit)).toBe(413);
  });

  test("bodies within the limit still parse, and an empty optional body is {}", async () => {
    const ok = await Effect.runPromise(parseBody(new Request("http://registry.test/", { method: "POST", body: '{"a":1}' }), z.object({ a: z.number() })));
    expect(ok).toEqual({ a: 1 });
    const empty = await Effect.runPromise(parseOptionalBody(new Request("http://registry.test/", { method: "POST" }), z.object({}).loose()));
    expect(empty).toEqual({});
  });
});
