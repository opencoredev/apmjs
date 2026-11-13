// Review item 3: a request body is read only up to the limit. A streamed body (no Content-Length, or a false
// one) is cancelled as soon as it passes the limit, by both parsers, instead of being buffered whole first.
import { describe, expect, test } from "bun:test";
import { Cause, Effect, Exit } from "effect";
import { z } from "zod";
import { jsonChars, LazyMembers, longestPiece, MAX_JSON_BODY_BYTES, parseBody, parseOptionalBody, STREAM_OVERHEAD_WEIGHT, streamedJson, streamWeight } from "../src/http.ts";

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

// streamedJson writes a packument a member at a time; LazyMembers are made only as they are written
describe("streamedJson", () => {
  test("writes what JSON.stringify writes, a spread object's and LazyMembers' members one at a time", async () => {
    let made = 0;

    function* docs(): Generator<readonly [string, unknown]> {
      for (let i = 0; i < 3_000; i++) {
        made++;
        yield [`1.0.${i}`, { name: "p", version: `1.0.${i}`, skip: undefined, text: "x".repeat(100) }];
      }
    }

    const body = { name: "p", gone: undefined, versions: new LazyMembers(docs), time: { "1.0.0": "t" }, empty: new LazyMembers(() => []) };
    const res = streamedJson(body, "time");

    // nothing is made before the body is read
    expect(made).toBe(0);
    const want = { name: "p", versions: Object.fromEntries([...docs()].map(([k, v]) => [k, v])), time: { "1.0.0": "t" }, empty: {} };

    expect(JSON.parse(await res.text())).toEqual(JSON.parse(JSON.stringify(want)));
  });

  test("a member that fails to serialize after the first chunk errors the stream, never ends it as if complete", async () => {
    const deep: unknown[] = [];
    let at: unknown[] = deep;

    // deeper than JSON.stringify's recursion can go
    for (let i = 0; i < 1_000_000; i++) {
      const next: unknown[] = [];
      at.push(next);
      at = next;
    }

    function* docs(): Generator<readonly [string, unknown]> {
      for (let i = 0; i < 2_000; i++) yield [`1.0.${i}`, "y".repeat(100)];
      yield ["9.9.9", deep];
    }

    const errors: unknown[] = [];
    const log = console.error;
    console.error = (...args: unknown[]) => errors.push(args);

    try {
      const res = streamedJson({ name: "p", versions: new LazyMembers(docs) }, "versions");

      // the status was sent with the first chunk; the body then fails, so no client reads it as complete
      expect(res.status).toBe(200);
      await expect(res.text()).rejects.toThrow();
    } finally {
      console.error = log;
    }

    expect(JSON.stringify(errors)).toContain("streamed-json");
  });
});

describe("the size of an answer is counted before it is serialized", () => {
  // escapes of every kind, a pair split by nothing, lone surrogates, numbers JSON writes as null, members JSON leaves out
  const SAMPLES: readonly unknown[] = [
    "",
    'quote " backslash \\ tab \t newline \n bell \u0007 nul \u0000 del \u007f',
    "pair 😀 lone high \ud800 x lone low \udc00 y end high \ud83d",
    "é€ wide",
    0,
    -1.5e-7,
    1e21,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    true,
    false,
    null,
    [],
    [1, undefined, () => 0, "a", null, [[]]],
    {},
    { a: 1, skipped: undefined, fn: () => 0, "k\"ey\n": "v", nested: { deep: [{ x: "y" }] } },
    { at: new Date(0), boxed: [Object("s"), Object(2), Object(false)] },
  ];

  test("jsonChars is the length of JSON.stringify, for every kind of value route code answers with", () => {
    for (const value of SAMPLES) expect(jsonChars(value)).toBe(JSON.stringify(value)?.length);
    expect(jsonChars(undefined)).toBeUndefined();
  });

  test("a long string member is streamed in pieces and the text is what JSON.stringify writes", async () => {
    // a pair across a piece boundary, control characters, lone surrogates and two-byte characters
    const readme = `${"r".repeat(65_535)}😀${"\u0001\"\\".repeat(30_000)}\ud800${"€".repeat(70_000)}\udc00`;
    const body = { name: "p", readme, description: "short", list: [1, 2, 3] };
    const text = await streamedJson(body, null).text();

    expect(text).toBe(JSON.stringify(body));
    expect(JSON.parse(text)).toEqual(body);
  });

  test("the longest piece of an answer with a megabytes-long readme is bounded by a chunk, not by the readme", () => {
    const readme = "x".repeat(8 * 1024 * 1024);
    const longest = longestPiece({ name: "p", readme, versions: [{ version: "1.0.0", deprecated: "d".repeat(200_000) }] });

    // the versions member is one piece of its own; the readme is written 64 KiB at a time
    expect(longest).toBeLessThan(500_000);
    expect(longest).toBeGreaterThan(200_000);
    expect(streamWeight(longest)).toBeLessThan(STREAM_OVERHEAD_WEIGHT + 2 * 1024 * 1024);
    // without a long string, the longest piece is its member's JSON exactly: `,"key":` and the text
    expect(longestPiece({ a: 1, list: ["x".repeat(1000)] })).toBe(`,"list":`.length + JSON.stringify(["x".repeat(1000)]).length);
  });
});
