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

// Answers that can carry a version's source (file text, excerpts, readmes, score evidence, review quotes). Whether a
// version may be shown is decided on every request from the database, so no cache downstream may keep the answer.
const SOURCE_PATHS = ["/-/apm/v1/file/", "/-/apm/v1/readme/", "/-/apm/v1/score/", "/-/apm/v1/packages/"];

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
