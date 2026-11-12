// Reads one JSON document from the registry with a time budget and a size cap, and says why it failed.
// No "server-only" here so the unit tests can import it; lib/registry.ts is the server entry point.
import type { z } from "zod";
import { evict, inBackground, lookup, lookupShared, peek, POLICIES, store, type CacheHit, type CachePolicy } from "./edge-cache";
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

/** A parsed JSON document, before any schema has read it. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/**
 * For an answer that can quote a version's source (a review's excerpts, a score's evidence lines). A cached copy that
 * quotes it is shown only while the registry said within POLICIES.servable that the version may be shown; past that the
 * answer is read again, and the registry's new answer (redacted when the version was revoked) is what is shown.
 */
export type SourceGate<T> = {
  /**
   * From the raw answer: the version's servableKey (lib/registry-url.ts) and whether the registry redacted the answer
   * (undefined from a registry too old to say). Null when the answer quotes no source and is not redacted. Reads raw JSON, so any read of the
   * URL, whatever schema it parses with, records what the registry said.
   */
  quotes: (json: JsonValue) => { key: string; redacted: boolean | undefined } | null;
  /** The answer with what it quotes taken out: shown when a cached copy can't be confirmed because the registry is down. */
  withoutSource: (value: T) => T;
};

export type FetchJsonOptions<T> = {
  url: string;
  schema: z.ZodType<T>;
  signal?: AbortSignal;
  /** At most MAX_REGISTRY_TIMEOUT_MS. */
  timeoutMs?: number;
  maxBytes?: number;
  headers?: HeadersInit;
  /**
   * Keep a 2xx answer in the edge cache (lib/edge-cache.ts) for this long, keyed by the URL. Only for answers that are
   * the same for everyone: a cached read never sends `headers`.
   */
  cache?: CachePolicy;
  /**
   * For a version's files, excerpts and readme: the version's servableKey (lib/registry-url.ts). The bytes are kept
   * under `cache`, but a cached copy is shown only while the registry said within POLICIES.servable that the version
   * may be shown; past that, a HEAD asks again, and a 410 or 404 drops the copy before anything is served.
   */
  servable?: string;
  /** For a review or a score: see SourceGate. */
  gate?: SourceGate<T>;
};

/**
 * The longest any registry request may run. The registry's no is kept longer than this (POLICIES.servableRecord), so
 * every yes still in flight when the no arrives is compared with it, never with an empty slot.
 */
export const MAX_REGISTRY_TIMEOUT_MS = 20_000;

const timeoutOf = (timeoutMs: number | undefined): number => Math.min(timeoutMs ?? REGISTRY_TIMEOUT_MS, MAX_REGISTRY_TIMEOUT_MS);

/** One read of the registry: the parsed value, or why there is none, and the body to cache and its JSON when it was a 2xx. */
type Loaded<T> = { result: Fetched<T>; body: string | null; json: JsonValue };

/** A body read with a schema, and its JSON for a SourceGate (null when it was not JSON). */
type Parsed<T> = { result: Fetched<T>; json: JsonValue };

/** Parses a registry body with `schema`, keeping the JSON for a SourceGate. */
function parseBody<T>(text: string, schema: z.ZodType<T>): Parsed<T> {
  let json: JsonValue;

  try {
    json = JSON.parse(text);
  } catch {
    return { result: { kind: "unavailable", reason: { kind: "invalid", message: "the body is not JSON" } }, json: null };
  }

  const parsed = schema.safeParse(json);

  if (!parsed.success) return { result: { kind: "unavailable", reason: { kind: "invalid", message: parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") } }, json };

  return { result: { kind: "ok", value: parsed.data }, json };
}

/** GET `url`, read at most `maxBytes`, and parse the body with `schema`. Never throws. */
async function load<T>(opts: FetchJsonOptions<T>): Promise<Loaded<T>> {
  const signal = withTimeout(timeoutOf(opts.timeoutMs), opts.signal);

  try {
    const res = await registryFetch(opts.url, { cache: "no-store", headers: { accept: "application/json", ...opts.headers }, signal });
    const kind = classifyStatus(res.status);

    if (kind !== "ok") {
      await res.body?.cancel();

      return { result: kind === "missing" ? { kind: "missing" } : { kind: "unavailable", reason: { kind: "status", status: res.status } }, body: null, json: null };
    }

    const body = await readCappedText(res, opts.maxBytes ?? MAX_REGISTRY_BODY_BYTES);

    if (body.kind === "too-large") return { result: { kind: "unavailable", reason: body }, body: null, json: null };
    const { result, json } = parseBody(body.text, opts.schema);

    return { result, body: result.kind === "ok" ? body.text : null, json };
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") return { result: { kind: "unavailable", reason: { kind: "timeout" } }, body: null, json: null };

    return { result: { kind: "unavailable", reason: { kind: "network", message: error instanceof Error ? error.message : "fetch failed" } }, body: null, json: null };
  }
}

/** A 404, or a 410 (a revoked version): what was cached under that URL is no longer the answer. */
function isGone(result: Fetched<unknown>): boolean {
  return result.kind === "missing" || (result.kind === "unavailable" && result.reason.kind === "status" && result.reason.status === 410);
}

// ---------- the registry's last word on a version ----------
/** What the registry said about showing a version's source, and when the request that asked it started. */
type Permission = { kind: "allow" | "deny"; start: number };

const PERMISSION = /^(allow|deny) (\d+)$/;

function parsePermission(hit: CacheHit | null): Permission | null {
  const m = hit ? PERMISSION.exec(hit.text) : null;

  if (!m?.[1] || !m[2]) return null;

  return { kind: m[1] === "allow" ? "allow" : "deny", start: Number(m[2]) };
}

/** `a` stands over `b`: asked later, or asked at the same moment and a no. */
const outranks = (a: Permission, b: Permission): boolean => a.start > b.start || (a.start === b.start && a.kind === "deny" && b.kind === "allow");

/**
 * Writes what a request that started at `next.start` heard, unless either cache layer holds a word from a request that
 * started later: a no (410, 404) is a tombstone no older yes can replace. False when it was not written.
 */
async function recordPermission(key: string, next: Permission): Promise<boolean> {
  const shared = parsePermission(await lookupShared(key, POLICIES.servableRecord));
  // read after the await, so a word this isolate wrote meanwhile is seen; nothing runs between this check and the write
  const local = parsePermission(peek(key, POLICIES.servableRecord));

  if ((shared && outranks(shared, next)) || (local && outranks(local, next))) return false;
  store(key, `${next.kind} ${next.start}`, POLICIES.servableRecord, next.start);

  return true;
}

/** A yes from a request that started less than POLICIES.servable ago. */
const isFreshYes = (p: Permission | null, now: number): boolean => p?.kind === "allow" && now >= p.start && now - p.start < POLICIES.servable.freshMs;

/** Whether the registry said yes for `key` within POLICIES.servable, counted from when the asking request started. */
async function permitted(key: string, now = Date.now()): Promise<boolean> {
  if (isFreshYes(parsePermission(peek(key, POLICIES.servableRecord, now)), now)) return true;

  return isFreshYes(parsePermission(await lookupShared(key, POLICIES.servableRecord, now)), now);
}

/** What one registry answer says about a version: a 2xx is a yes for `servable`, a 404 or 410 a no; a gate reads the body. */
function verdictOf<T>(input: { opts: FetchJsonOptions<T>; loaded: Loaded<T> }): { key: string; kind: Permission["kind"] } | null {
  const { opts, loaded } = input;

  if (opts.servable !== undefined) {
    if (loaded.result.kind === "ok") return { key: opts.servable, kind: "allow" };

    if (isGone(loaded.result)) return { key: opts.servable, kind: "deny" };
  }

  const quoted = opts.gate && loaded.result.kind === "ok" ? opts.gate.quotes(loaded.json) : null;

  if (!quoted || quoted.redacted === undefined) return null;

  return { key: quoted.key, kind: quoted.redacted ? "deny" : "allow" };
}

/**
 * Reads the registry and keeps what it should: a 2xx is stored, a 404 or 410 drops what was stored, an outage keeps it.
 * What the answer says about the version is recorded as of when this request started, so an answer that took a while
 * can't undo a revoke heard in the meantime, and its yes runs out POLICIES.servable after it was asked.
 */
async function loadAndKeep<T>(opts: FetchJsonOptions<T>, policy: CachePolicy): Promise<Fetched<T>> {
  const start = Date.now();
  const loaded = await load(opts);
  const verdict = verdictOf({ opts, loaded });
  const written = verdict ? await recordPermission(verdict.key, { kind: verdict.kind, start }) : true;

  // a yes that a later no outranks keeps its bytes out of the cache too
  if (loaded.body !== null && (written || verdict?.kind !== "allow")) store(opts.url, loaded.body, policy, start);
  else if (isGone(loaded.result)) evict(opts.url);

  return loaded.result;
}

/** How the registry answers a HEAD of `url` right now, never from a cache. Never throws. */
export async function headStatus(input: { url: string; signal?: AbortSignal; timeoutMs?: number }): Promise<Fetched<null>> {
  try {
    const res = await registryFetch(input.url, { method: "HEAD", cache: "no-store", signal: withTimeout(timeoutOf(input.timeoutMs), input.signal) });

    await res.body?.cancel();
    const kind = classifyStatus(res.status);

    if (kind === "ok") return { kind: "ok", value: null };

    return kind === "missing" ? { kind: "missing" } : { kind: "unavailable", reason: { kind: "status", status: res.status } };
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") return { kind: "unavailable", reason: { kind: "timeout" } };

    return { kind: "unavailable", reason: { kind: "network", message: error instanceof Error ? error.message : "fetch failed" } };
  }
}

type ServableCheck = { url: string; servable: string; signal?: AbortSignal; timeoutMs?: number };

/** A HEAD in flight and when it started. */
type Flight = { start: number; result: Promise<Fetched<null>> };

declare global {
  /** HEADs in flight per URL, on globalThis so proxy.ts and the pages (bundled apart) share them. Only this file uses it. */
  var apmServableFlights: Map<string, Flight> | undefined;
}

/** `result`, or an abort's answer as soon as `signal` fires: a caller that gives up does not wait on a shared HEAD. */
function until<T>(result: Promise<Fetched<T>>, signal: AbortSignal | undefined): Promise<Fetched<T>> {
  if (!signal) return result;
  const aborted = (): Fetched<T> => ({ kind: "unavailable", reason: { kind: "network", message: "aborted" } });

  if (signal.aborted) return Promise.resolve(aborted());

  return Promise.race([result, new Promise<Fetched<T>>((resolve) => signal.addEventListener("abort", () => resolve(aborted()), { once: true }))]);
}

/**
 * A HEAD of `url` and what it says about the version's permission and the bytes cached under `url`. Callers that ask
 * about the same URL while a HEAD started less than POLICIES.servable ago is in flight share it, so a burst of views
 * sends one HEAD.
 */
export function askServable(input: ServableCheck): Promise<Fetched<null>> {
  const flights = (globalThis.apmServableFlights ??= new Map());
  const start = Date.now();
  const current = flights.get(input.url);

  if (current && start >= current.start && start - current.start < POLICIES.servable.freshMs) return until(current.result, input.signal);

  const result = (async (): Promise<Fetched<null>> => {
    // shared, so not cut short by the first caller's signal; its own timeout still ends it
    const answer = await headStatus({ url: input.url, timeoutMs: input.timeoutMs });

    if (answer.kind === "ok") await recordPermission(input.servable, { kind: "allow", start });
    else if (isGone(answer)) {
      evict(input.url);
      await recordPermission(input.servable, { kind: "deny", start });
    }

    return answer;
  })();

  const flight: Flight = { start, result };

  flights.set(input.url, flight);
  // the runtime keeps the request that started it alive until it settles, for the callers that joined it
  inBackground(result.finally(() => flights.get(input.url) === flight && flights.delete(input.url)));

  return until(result, input.signal);
}

/**
 * Whether a version's file may be shown now: from a yes the registry gave to a request that started within the last
 * few seconds, else a HEAD of `url`. Anything but a 2xx (a revoke's 410, a 404, an outage) means the cached copy is not shown.
 */
export async function confirmServable(input: ServableCheck): Promise<Fetched<null>> {
  return (await permitted(input.servable)) ? { kind: "ok", value: null } : askServable(input);
}

/** GET `url`, read at most `maxBytes`, and parse the body with `schema`; from the edge cache when `cache` is set. Never throws. */
export async function fetchJson<T>(opts: FetchJsonOptions<T>): Promise<Fetched<T>> {
  const policy = opts.cache;

  if (!policy || opts.headers !== undefined) return (await load(opts)).result;
  const hit = await lookup(opts.url, policy);
  const cached = hit ? parseBody(hit.text, opts.schema) : null;

  if (hit && cached?.result.kind === "ok") {
    if (opts.servable !== undefined) {
      const allowed = await confirmServable({ url: opts.url, servable: opts.servable, signal: opts.signal, timeoutMs: opts.timeoutMs });

      if (allowed.kind !== "ok") return allowed;
    }

    const quoted = opts.gate?.quotes(cached.json);

    if (opts.gate && quoted && quoted.redacted !== true && !(await permitted(quoted.key))) {
      // a copy that quotes source the registry may have stopped showing: what the registry says now is the answer
      const fresh = await loadAndKeep(opts, policy);

      return fresh.kind === "unavailable" && !isGone(fresh) ? { kind: "ok", value: opts.gate.withoutSource(cached.result.value) } : fresh;
    }

    // the background refresh must outlive this request's abort signal
    if (hit.stale) inBackground(loadAndKeep({ ...opts, signal: undefined }, policy));

    return cached.result;
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
