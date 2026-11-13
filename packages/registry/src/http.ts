// Response helpers and request-body parsing shared by every route.
import { Effect } from "effect";
import type { z } from "zod";
import { ArchiveError, gunzipCapped, httpStatusOf } from "@apm/core";
import { refuse, type ErrorExtra, type HttpFailure } from "./errors.ts";

/** JSON bodies of the apm and audit APIs, before and after gzip. Thousands of packages fit in a fraction of it. */
export const MAX_JSON_BODY_BYTES = 5 * 1024 * 1024;

/**
 * A publish body: the manifest plus the base64 tarball. A Worker holds the body, its text and the decoded
 * tarball at once in 128 MB, so this is lower than npm's own limit.
 */
export const MAX_PUBLISH_BODY_BYTES = 32 * 1024 * 1024;

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- the response boundary: route code builds the body from parsed records and JSON.stringify serializes it
export function json(body: unknown, status = 200, headers: Readonly<Record<string, string>> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

/** Bytes a streamed answer gathers before it sends them: big enough to keep the stream's overhead small. */
const STREAM_CHUNK_CHARS = 64 * 1024;

/**
 * The members of an object in a streamed answer, made only as they are written (streamedJson): a packument's
 * `versions`, say, so each version's document exists only while it is sent.
 */
export class LazyMembers {
  readonly entries: () => Iterable<readonly [string, unknown]>;

  constructor(entries: () => Iterable<readonly [string, unknown]>) {
    this.entries = entries;
  }
}

/** The members a streamed answer writes one at a time: a LazyMembers, or a plain object named in `spread`. */
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- the response boundary: a member of the body jsonPieces is writing, whatever JSON.stringify accepts
function membersOf(value: unknown, spread: boolean): Iterable<readonly [string, unknown]> | null {
  if (value instanceof LazyMembers) return value.entries();

  // an object (not an array, not null): JSON.stringify would write it as members too
  if (spread && value instanceof Object && !Array.isArray(value)) return Object.entries(value);

  return null;
}

/** The JSON text of `body`, an object, in pieces: each member on its own, and the members of `spread` one at a time. */
function* jsonPieces<T extends object>(body: T, spread: keyof T & string): Generator<string> {
  let first = true;

  for (const [key, value] of Object.entries(body)) {
    const head = `${first ? "{" : ","}${JSON.stringify(key)}:`;
    const members = membersOf(value, key === spread);

    if (members) {
      let inner = true;

      for (const [k, v] of members) {
        const text = JSON.stringify(v);

        // as JSON.stringify does: a member whose value has no JSON form is left out
        if (text === undefined) continue;
        yield `${inner ? `${head}{` : ","}${JSON.stringify(k)}:${text}`;
        inner = false;
      }

      yield inner ? `${head}{}` : "}";
      first = false;
      continue;
    }

    const text = JSON.stringify(value);

    if (text === undefined) continue;
    yield `${head}${text}`;
    first = false;
  }

  yield first ? "{}" : "}";
}

/**
 * What a streamed answer (streamedJson) holds at once beside the member it is writing, in bytes: the chunk being put
 * together and its encoded copy (STREAM_CHUNK_CHARS characters, two bytes each, and three bytes each encoded), and two
 * chunks the reader of the stream may not have let go yet.
 */
export const STREAM_OVERHEAD_WEIGHT = 1024 * 1024;

/**
 * The memory a streamed answer may hold while it is written, as weight (packument-read.ts, WEIGHTS), for an answer
 * whose longest member is `maxPieceChars` characters of JSON: that member's text as JSON.stringify builds and returns
 * it (two bytes a character, twice), and STREAM_OVERHEAD_WEIGHT. Charged to a lease before the stream is made.
 */
export const streamWeight = (maxPieceChars: number): number => 4 * maxPieceChars + STREAM_OVERHEAD_WEIGHT;

/** When a streamed answer ends: `onDone` once it is sent, failed or canceled, or `signal` aborted it. */
export type StreamOptions = { readonly signal?: AbortSignal; readonly onDone?: () => void };

const isHighSurrogate = (unit: number): boolean => unit >= 0xd800 && unit <= 0xdbff;

/**
 * Like json, for an object with large members (`spread`, a packument's `versions`, and any LazyMembers): the text is
 * written as it is sent, one member of each at a time, so the answer is never held whole as a string and again as
 * bytes. next's full packument is 30 MB of JSON. A member longer than a chunk is sent in chunks of it, so what is
 * encoded at once stays STREAM_CHUNK_CHARS (streamWeight).
 *
 * The status is sent before the body, so a piece that fails to serialize after the first cannot become an error
 * answer: the stream is errored instead, which ends the response without its last chunk, and a client reads that as
 * a failed download, never as a complete packument. Callers make what can fail before they call this (apm.ts,
 * upstreamPackument); this stays the backstop, and logs.
 */
export function streamedJson<T extends object>(body: T, spread: keyof T & string, headers: Readonly<Record<string, string>> = {}, options: StreamOptions = {}): Response {
  // dropped when the stream ends: what still refers to the stream (a timer's abort listener, a reader that never lets
  // go of it) then holds none of `body`
  let pieces: Generator<string> | null = jsonPieces(body, spread);
  const encoder = new TextEncoder();
  // the member being written, and how much of it is sent
  let piece = "";
  let at = 0;
  let onAbort: (() => void) | null = null;

  const end = (): void => {
    if (pieces === null) return;
    pieces = null;
    piece = "";

    if (onAbort) options.signal?.removeEventListener("abort", onAbort);
    onAbort = null;
    options.onDone?.();
  };

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const signal = options.signal;

      if (!signal) return;

      onAbort = () => {
        if (pieces === null) return;
        controller.error(signal.reason ?? new Error("the streamed answer was aborted"));
        end();
      };

      signal.addEventListener("abort", onAbort, { once: true });
    },
    pull(controller) {
      let text = "";

      try {
        while (text.length < STREAM_CHUNK_CHARS) {
          if (pieces === null) return;

          if (at >= piece.length) {
            piece = "";
            const next = pieces.next();

            if (next.done) {
              if (text !== "") controller.enqueue(encoder.encode(text));
              controller.close();
              end();

              return;
            }

            piece = next.value;
            at = 0;
          }

          let to = Math.min(piece.length, at + STREAM_CHUNK_CHARS - text.length);

          // each chunk is encoded on its own, so a surrogate pair is never split between two
          if (to < piece.length && isHighSurrogate(piece.charCodeAt(to - 1))) to++;
          text += at === 0 && to === piece.length ? piece : piece.slice(at, to);
          at = to;
        }
      } catch (e) {
        console.error(JSON.stringify({ level: "error", event: "streamed-json", error: e instanceof Error ? e.message : String(e) }));
        controller.error(e);
        end();

        return;
      }

      controller.enqueue(encoder.encode(text));
    },
    cancel() {
      end();
    },
  });

  return new Response(stream, { status: 200, headers: { "content-type": "application/json", ...headers } });
}

export function fail(status: number, error: string, extra: ErrorExtra = {}): Response {
  return json({ error, ...extra }, status);
}

/** Package reads under /~safe/ see only versions that pass apm's policy; the rest of the path routes as usual. */
export const SAFE_PREFIX = "/~safe";

/** The path the router dispatches on, and whether the request came through the /~safe alias. */
export type RoutedPath = { readonly path: string; readonly viaSafe: boolean };

/** A /~safe alias is the same route as the path after it. */
export function routePath(pathname: string): RoutedPath {
  if (pathname !== SAFE_PREFIX && !pathname.startsWith(`${SAFE_PREFIX}/`)) return { path: pathname, viaSafe: false };

  return { path: pathname.slice(SAFE_PREFIX.length) || "/", viaSafe: true };
}

// Answers that belong to whoever asked: the account, sessions, staged versions, tokens, step-ups and login.
const PER_USER_PATHS = ["/api/auth/", "/-/whoami", "/-/user/", "/-/npm/v1/", "/-/apm/v1/account", "/-/apm/v1/staged", "/-/apm/v1/verify", "/-/apm/v1/login/", "/-/apm/v1/review", "/-/apm/v1/evidence-admin"];

// Answers that can carry a version's source (file text, excerpts, readmes, score evidence, review quotes, and the
// score reports resolve embeds). Whether a version may be shown is decided on every request from the database, so no
// cache downstream may keep the answer.
const SOURCE_PATHS = ["/-/apm/v1/file/", "/-/apm/v1/readme/", "/-/apm/v1/score/", "/-/apm/v1/packages/", "/-/apm/v1/resolve"];

/**
 * Marks per-user answers `Cache-Control: private, no-store` and `Vary: Authorization, Cookie`, so no shared
 * cache keeps one: every answer on a per-user path, and any other /-/ answer to a request that carried
 * credentials, and every answer that can carry a version's source (SOURCE_PATHS). Packuments and tarballs are the
 * same for everyone and keep their own caching. The path is
 * classified as the router dispatches it, so /~safe/-/whoami is as private as /-/whoami.
 */
export function withPrivacyHeaders(req: Request, res: Response): Response {
  const { path } = routePath(new URL(req.url).pathname);
  const credentialed = req.headers.has("authorization") || req.headers.has("cookie");

  const sourceBearing = SOURCE_PATHS.some((p) => path.startsWith(p));

  if (!sourceBearing && !PER_USER_PATHS.some((p) => path.startsWith(p)) && !(credentialed && path.startsWith("/-/"))) return res;
  // some answers (redirects, fetched responses) have immutable headers, so the answer is rebuilt around a copy
  const headers = new Headers(res.headers);

  const vary = new Set(
    (headers.get("vary") ?? "")
      .split(",")
      .map((v) => v.trim())
      .filter((v) => v !== ""),
  );

  vary.add("Authorization");
  vary.add("Cookie");
  headers.set("cache-control", "private, no-store");
  headers.set("vary", [...vary].join(", "));

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

// The read answers the website's package page makes; each says where its time went (timing.ts).
const TIMED_PATHS = ["/-/apm/v1/packages/", "/-/apm/v1/score/", "/-/apm/v1/review/", "/-/apm/v1/readme/", "/-/apm/v1/file/"];

/** Adds `Server-Timing` to a GET or HEAD of a TIMED_PATHS answer; any other answer, or a null value, is returned as it is. */
export function withServerTiming(req: Request, res: Response, value: string | null): Response {
  const { path } = routePath(new URL(req.url).pathname);

  if (value === null || (req.method !== "GET" && req.method !== "HEAD") || !TIMED_PATHS.some((p) => path.startsWith(p))) return res;
  const headers = new Headers(res.headers);
  headers.set("server-timing", value);

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

export function failureResponse(f: HttpFailure): Response {
  return fail(f.status, f.error, f.extra ?? {});
}

/**
 * Reads a body (a request's or a response's) up to `max` bytes. The stream is cancelled as soon as it passes the
 * limit, so a client that sends no Content-Length, or a false one, cannot make the Worker buffer more than
 * `max` plus one chunk. Null when the body is over the limit.
 */
export async function readCapped(source: { readonly body: ReadableStream<Uint8Array> | null }, max: number): Promise<Uint8Array | null> {
  if (!source.body) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = source.body.getReader();

  for (;;) {
    const { done, value } = await reader.read();

    if (done) break;
    total += value.length;

    if (total > max) {
      await reader.cancel();

      return null;
    }

    chunks.push(value);
  }

  return Buffer.concat(chunks);
}

/**
 * Parses a JSON body within `maxBytes` with a schema, gunzipping it first when the client sent it compressed
 * (npm and bun do for audits). The body is read through readCapped, so its size is checked while it arrives;
 * the inflated size has the same cap. Any failure is a 400, or a 413 when the body is too large.
 */
export const parseBody = <S extends z.ZodType>(req: Request, schema: S, maxBytes: number = MAX_JSON_BODY_BYTES): Effect.Effect<z.output<S>, HttpFailure> =>
  Effect.tryPromise({
    try: async () => {
      const tooLarge = (): ArchiveError => new ArchiveError("too-large", `request body over ${maxBytes / (1024 * 1024)} MB`);

      if (Number(req.headers.get("content-length") ?? 0) > maxBytes) throw tooLarge();
      const enc = req.headers.get("content-encoding") ?? "";
      const buf = await readCapped(req, maxBytes);

      if (buf === null) throw tooLarge();
      const raw = enc.includes("gzip") || (buf[0] === 0x1f && buf[1] === 0x8b) ? gunzipCapped(buf, maxBytes) : buf;

      return schema.safeParse(JSON.parse(new TextDecoder().decode(raw)));
    },
    catch: (e) =>
      e instanceof ArchiveError ? refuse(httpStatusOf(e), `Request body refused: ${e.message}`) : refuse(400, `Invalid request body: ${e instanceof Error ? e.message : String(e)}`),
  }).pipe(Effect.flatMap((parsed) => (parsed.success ? Effect.succeed(parsed.data) : Effect.fail(refuse(400, `Invalid request body: ${parsed.error.message}`)))));

/** Like parseBody, but an empty body counts as `{}` (the account routes accept bodiless POSTs). Read within the same 5 MB, while it arrives. */
export const parseOptionalBody = <S extends z.ZodType>(req: Request, schema: S): Effect.Effect<z.output<S>, HttpFailure> =>
  Effect.gen(function* () {
    if (Number(req.headers.get("content-length") ?? 0) > MAX_JSON_BODY_BYTES) return yield* Effect.fail(refuse(413, "Request body refused: too large"));
    const bytes = yield* Effect.tryPromise({ try: () => readCapped(req, MAX_JSON_BODY_BYTES), catch: () => refuse(400, "The request body could not be read.") });

    if (bytes === null) return yield* Effect.fail(refuse(413, "Request body refused: too large"));
    const text = new TextDecoder().decode(bytes);
    const parsed = yield* Effect.try({ try: () => schema.safeParse(text.trim() === "" ? {} : JSON.parse(text)), catch: () => refuse(400, "Body must be JSON.") });

    if (!parsed.success) return yield* Effect.fail(refuse(400, `Invalid request body: ${parsed.error.message}`));

    return parsed.data;
  });

export function withSlash(u: string): string {
  return u.endsWith("/") ? u : `${u}/`;
}
