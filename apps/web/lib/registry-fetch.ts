// Reads one JSON document from the registry with a time budget and a size cap, and says why it failed.
// No "server-only" here so the unit tests can import it; lib/registry.ts is the server entry point.
import type { z } from "zod";
import { evict, inBackground, lookup, store, type CachePolicy } from "./edge-cache";
import { registryFetch } from "./registry-transport";

/** Every registry call gives up after this long, so a stalled registry can't pin a render. */
export const REGISTRY_TIMEOUT_MS = 8_000;

/** Largest registry response the site will buffer and parse. */
export const MAX_REGISTRY_BODY_BYTES = 5 * 1024 * 1024;

export type Unavailable =
  | { kind: "status"; status: number }
  | { kind: "timeout" }
  | { kind: "network"; message: string }
  | { kind: "too-large"; limit: number }
  | { kind: "invalid"; message: string };

/** A registry answer: the parsed value, a registry 404, or a reason the registry could not be read. */
export type Fetched<T> = { kind: "ok"; value: T } | { kind: "missing" } | { kind: "unavailable"; reason: Unavailable };

export type CappedText = { kind: "ok"; text: string } | { kind: "too-large"; limit: number };

/** Reads a body as UTF-8 text, giving up as soon as it passes `maxBytes`, whatever Content-Length claims. */
export async function readCappedText(res: Response, maxBytes: number): Promise<CappedText> {
  const declared = Number(res.headers.get("content-length"));

  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel();

    return { kind: "too-large", limit: maxBytes };
  }

  if (!res.body) return { kind: "ok", text: "" };
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";

  for (;;) {
    const chunk = await reader.read();

    if (chunk.done) break;
    total += chunk.value.byteLength;

    if (total > maxBytes) {
      await reader.cancel();

      return { kind: "too-large", limit: maxBytes };
    }

    text += decoder.decode(chunk.value, { stream: true });
  }

  return { kind: "ok", text: text + decoder.decode() };
}

/** One signal that fires on the caller's abort or after `timeoutMs`, whichever comes first. */
export function withTimeout(timeoutMs: number, signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);

  return signal ? AbortSignal.any([timeout, signal]) : timeout;
}

/** Maps an HTTP status to the result kind: only a registry 404 means "this does not exist". */
export function classifyStatus(status: number): "ok" | "missing" | "unavailable" {
  if (status === 404) return "missing";

  return status >= 200 && status < 300 ? "ok" : "unavailable";
}

export type FetchJsonOptions<T> = {
  url: string;
  schema: z.ZodType<T>;
  signal?: AbortSignal;
  timeoutMs?: number;
  maxBytes?: number;
  headers?: HeadersInit;
  /**
   * Keep a 2xx answer in the edge cache (lib/edge-cache.ts) for this long, keyed by the URL. Only for answers that are
   * the same for everyone: a cached read never sends `headers`.
   */
  cache?: CachePolicy;
};

/** One read of the registry: the parsed value, or why there is none, and the body to cache when it was a 2xx. */
type Loaded<T> = { result: Fetched<T>; body: string | null };

/** Parses a registry body with `schema`. */
function parseBody<T>(text: string, schema: z.ZodType<T>): Fetched<T> {
  let json: unknown;

  try {
    json = JSON.parse(text);
  } catch {
    return { kind: "unavailable", reason: { kind: "invalid", message: "the body is not JSON" } };
  }

  const parsed = schema.safeParse(json);

  if (!parsed.success) return { kind: "unavailable", reason: { kind: "invalid", message: parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") } };

  return { kind: "ok", value: parsed.data };
}

/** GET `url`, read at most `maxBytes`, and parse the body with `schema`. Never throws. */
async function load<T>(opts: FetchJsonOptions<T>): Promise<Loaded<T>> {
  const timeoutMs = opts.timeoutMs ?? REGISTRY_TIMEOUT_MS;
  const signal = withTimeout(timeoutMs, opts.signal);

  try {
    const res = await registryFetch(opts.url, { cache: "no-store", headers: { accept: "application/json", ...opts.headers }, signal });
    const kind = classifyStatus(res.status);

    if (kind !== "ok") {
      await res.body?.cancel();

      return { result: kind === "missing" ? { kind: "missing" } : { kind: "unavailable", reason: { kind: "status", status: res.status } }, body: null };
    }

    const body = await readCappedText(res, opts.maxBytes ?? MAX_REGISTRY_BODY_BYTES);

    if (body.kind === "too-large") return { result: { kind: "unavailable", reason: body }, body: null };
    const result = parseBody(body.text, opts.schema);

    return { result, body: result.kind === "ok" ? body.text : null };
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") return { result: { kind: "unavailable", reason: { kind: "timeout" } }, body: null };

    return { result: { kind: "unavailable", reason: { kind: "network", message: error instanceof Error ? error.message : "fetch failed" } }, body: null };
  }
}

/** Reads the registry and keeps what it should: a 2xx is stored, a 404 or 410 drops what was stored, an outage keeps it. */
async function loadAndKeep<T>(opts: FetchJsonOptions<T>, policy: CachePolicy): Promise<Fetched<T>> {
  const { result, body } = await load(opts);

  if (body !== null) store(opts.url, body, policy);
  else if (result.kind === "missing" || (result.kind === "unavailable" && result.reason.kind === "status" && result.reason.status === 410)) evict(opts.url);

  return result;
}

/** GET `url`, read at most `maxBytes`, and parse the body with `schema`; from the edge cache when `cache` is set. Never throws. */
export async function fetchJson<T>(opts: FetchJsonOptions<T>): Promise<Fetched<T>> {
  const policy = opts.cache;

  if (!policy || opts.headers !== undefined) return (await load(opts)).result;
  const hit = await lookup(opts.url, policy);

  if (hit) {
    const cached = parseBody(hit.text, opts.schema);

    if (cached.kind === "ok") {
      // the background refresh must outlive this request's abort signal
      if (hit.stale) inBackground(loadAndKeep({ ...opts, signal: undefined }, policy));

      return cached;
    }
  }

  return loadAndKeep(opts, policy);
}

/** One line for the server log. */
export function describeUnavailable(reason: Unavailable): string {
  switch (reason.kind) {
    case "status":
      return `answered ${reason.status}`;
    case "timeout":
      return "timed out";
    case "network":
      return `could not be reached (${reason.message})`;
    case "too-large":
      return `sent more than ${reason.limit} bytes`;
    case "invalid":
      return `sent an unexpected answer (${reason.message})`;
    default: {
      const _exhaustive: never = reason;

      return _exhaustive;
    }
  }
}

/** One structured line on stderr for each registry read that failed for a reason other than a 404. */
export function logUnavailable(path: string, reason: Unavailable): void {
  console.error(JSON.stringify({ event: "registry_unavailable", path, reason, detail: describeUnavailable(reason) }));
}
