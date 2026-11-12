// Reads one JSON document from the registry with a time budget and a size cap, and says why it failed.
// No "server-only" here so the unit tests can import it; lib/registry.ts is the server entry point.
import type { z } from "zod";
import { evict, inBackground, lookup, store, type CachePolicy } from "./edge-cache";
import { registryFetch } from "./registry-transport";

/** Every registry call gives up after this long, so a stalled registry can't pin a render. */
export const REGISTRY_TIMEOUT_MS = 8_000;

/** A file view's budget: the first read of a big upstream tarball takes a while. */
export const FILE_TIMEOUT_MS = 20_000;

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
};

/**
 * Registry answers the site may keep: search results and a package's public log. Neither carries a version's source
 * (file text, excerpts, readmes, review quotes, score evidence), so a revoke has nothing to take back from them.
 * Search keeps only answers made of npm's packages (lib/registry.ts): a local package's description changes when one
 * of its versions is revoked. Everything else is read from the registry on every view, and the registry decides then
 * whether it may be shown.
 */
const SOURCE_FREE: readonly RegExp[] = [/\/-\/v1\/search$/, /\/-\/apm\/v1\/packages\/[^/]+\/events$/];

/** Whether `url` names a registry answer that carries no source, so the edge cache may keep it. */
export function isSourceFree(url: string): boolean {
  const { pathname } = new URL(url);

  return SOURCE_FREE.some((p) => p.test(pathname));
}

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

/** Why a fetch that threw got no answer: its timeout, or the network (null when what it threw was not an Error). */
const unreachable = (error: Error | null): Fetched<never> => {
  if (error instanceof DOMException && error.name === "TimeoutError") return { kind: "unavailable", reason: { kind: "timeout" } };

  return { kind: "unavailable", reason: { kind: "network", message: error?.message ?? "fetch failed" } };
};

/** GET `url`, read at most `maxBytes`, and parse the body with `schema`. Never throws. */
async function load<T>(opts: FetchJsonOptions<T>): Promise<Loaded<T>> {
  const signal = withTimeout(opts.timeoutMs ?? REGISTRY_TIMEOUT_MS, opts.signal);

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
    return { result: unreachable(error instanceof Error ? error : null), body: null };
  }
}

/** A 404, or a 410: what was cached under that URL is no longer the answer. */
function isGone(result: Fetched<unknown>): boolean {
  return result.kind === "missing" || (result.kind === "unavailable" && result.reason.kind === "status" && result.reason.status === 410);
}

/** Which answers of one URL the cache may keep; an answer it refuses is read from the registry every time. */
type Keep<T> = (value: T) => boolean;

/**
 * Reads the registry and keeps what it should: a 2xx that `keep` accepts is stored; one it refuses, a 404 or a 410
 * drops what was stored; an outage keeps it.
 */
async function loadAndKeep<T>(opts: FetchJsonOptions<T>, policy: CachePolicy, keep: Keep<T>): Promise<Fetched<T>> {
  const start = Date.now();
  const loaded = await load(opts);

  if (loaded.body !== null && loaded.result.kind === "ok" && keep(loaded.result.value)) store(opts.url, loaded.body, policy, start);
  else if (loaded.body !== null || isGone(loaded.result)) evict(opts.url);

  return loaded.result;
}

/** How the registry answers a HEAD of `url` right now, never from a cache. Never throws. */
export async function headStatus(input: { url: string; signal?: AbortSignal; timeoutMs?: number }): Promise<Fetched<null>> {
  try {
    const res = await registryFetch(input.url, { method: "HEAD", cache: "no-store", signal: withTimeout(input.timeoutMs ?? REGISTRY_TIMEOUT_MS, input.signal) });

    await res.body?.cancel();
    const kind = classifyStatus(res.status);

    if (kind === "ok") return { kind: "ok", value: null };

    return kind === "missing" ? { kind: "missing" } : { kind: "unavailable", reason: { kind: "status", status: res.status } };
  } catch (error) {
    return unreachable(error instanceof Error ? error : null);
  }
}

/** GET `url`, read at most `maxBytes`, and parse the body with `schema`, from the registry every time. Never throws. */
export async function fetchJson<T>(opts: FetchJsonOptions<T>): Promise<Fetched<T>> {
  return (await load(opts)).result;
}

/**
 * fetchJson through the edge cache (lib/edge-cache.ts), for an answer that is the same for everyone and carries no
 * source (isSourceFree): a fresh copy is served as is, a stale one is served while one background read replaces it.
 * `keep` narrows that to the answers the cache may hold; one it refuses is neither stored nor served from the cache.
 * Throws for any other URL, so a source-bearing answer can't be cached by mistake.
 */
export async function fetchCachedJson<T>(opts: Omit<FetchJsonOptions<T>, "headers"> & { cache: CachePolicy; keep?: Keep<T> }): Promise<Fetched<T>> {
  if (!isSourceFree(opts.url)) throw new Error(`refusing to cache ${new URL(opts.url).pathname}: it can carry a version's source`);
  const { cache, keep = () => true, ...read } = opts;
  const hit = await lookup(read.url, cache);
  const cached = hit ? parseBody(hit.text, read.schema) : null;

  if (hit && cached?.kind === "ok" && keep(cached.value)) {
    // the background refresh must outlive this request's abort signal
    if (hit.stale) inBackground(loadAndKeep({ ...read, signal: undefined }, cache, keep));

    return cached;
  }

  return loadAndKeep(read, cache, keep);
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
