// A per-address limit on GET /-/apm/v1/resolve, the most expensive read anyone can make without signing in: one ask
// walks a dependency tree (up to 400 npm lookups), queues an analysis for every unscored version in it, and waits up
// to 20 s polling the database. The website's explain route has its own limit (apps/web/lib/agent/agent-limit.ts);
// this one covers callers that reach the registry directly, the CLI's `apm add` included, which asks once and then
// about every 10 s while versions are pending.
//
// Counted by the Workers rate limiting binding (RESOLVE_RATE_LIMIT, packages/infra/registry-env.ts): per Cloudflare
// location and eventually, so a burst can pass slightly over. Keyed on CF-Connecting-IP, which Cloudflare sets on every
// request from the internet and overwrites when a client sends one. A request without it came through the website's
// service binding (the website's own reads send none; its /-/apm/v1/* proxy passes the visitor's on, lib/client-ip.ts)
// or from a local run, and is not counted here. A binding that is missing or fails lets the request through.
//
// A caller apm verified is not counted: a live token (server.ts callerOf) or a website session that names an apm
// account (apm.ts sessionUser), the same check that lifts the anonymous queue cap. CI behind one NAT signs in. So a
// request with no Authorization and no Cookie header is counted before the router builds anything (worker.ts). For one
// that carries either, the router records what its credentials came to (ResolveCaller) as soon as it has checked them,
// before any handler answers (apm.ts noteResolveCaller), and the request is counted by the resolve handler before its
// answer or, when something else answered it (a HEAD's 405, a database outage, an error), after (worker.ts, countsLate).
// Only a caller the router positively verified goes uncounted.
import { Context } from "effect";
import { json } from "./http.ts";
import { getRouteOf } from "./routes.ts";

/** Resolves per address per minute: the website's explain limit, and far above what one `apm add` asks. */
export const RESOLVE_LIMIT_PER_MINUTE = 60;

/** The binding's surface apm uses (Cloudflare's RateLimit); worker.ts checks the binding has it. */
export type RateLimiter = { limit: (options: { key: string }) => Promise<{ success: boolean }> };

/**
 * What the router found a credentialed resolve's credentials name: "verified", a live token or a website session naming
 * an apm account; "unverified", it checked and they name nobody; "unknown", it never finished checking (a database
 * outage, an error or a defect first).
 */
export type ResolveCaller = "unknown" | "verified" | "unverified";

/** One credentialed resolve's standing: what its credentials came to, and whether it was counted yet. */
export type ResolveCount = { caller: ResolveCaller; counted: boolean };

/**
 * Whether a credentialed resolve that reached its answer uncounted is counted after it (review of 0126b2b, findings 2
 * and 3). A verified caller never is. An unverified one is, unless the answer was a server-side failure (5xx): apm's own
 * fault is not charged to someone it already checked. One whose credentials were never checked is counted whatever the
 * answer: forged credentials in a database outage would otherwise never count.
 */
export function countsLate(input: { req: Request; request: ResolveCount; status: number }): boolean {
  if (!carriesCredentials(input.req) || input.request.counted) return false;

  switch (input.request.caller) {
    case "verified":
      return false;
    case "unverified":
      return input.status < 500;
    case "unknown":
      return true;
    default: {
      const _exhaustive: never = input.request.caller;

      return _exhaustive;
    }
  }
}

/**
 * The rate limiter the router counts unverified credentialed resolves with (null: nothing is counted), and the
 * request's ResolveCount, which worker.ts reads after the answer.
 */
export class ResolveLimit extends Context.Service<ResolveLimit, { readonly limiter: RateLimiter | null; readonly request: ResolveCount }>()("@apm/registry/ResolveLimit") {}

/** Whether the request names a caller apm could verify: a bearer token or a cookie. */
export function carriesCredentials(req: Request): boolean {
  return req.headers.has("authorization") || req.headers.has("cookie");
}

/** Normalizes an IPv6 address to its /64 prefix, while unwrapping IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to its IPv4 address. */
export function normalizeRateLimitAddress(ip: string): string {
  const clean = ip.split("%")[0]?.trim().toLowerCase() ?? "";

  if (!clean.includes(":")) return clean;

  const halves = clean.split("::");

  const expandSide = (part: string): string[] => {
    const groups: string[] = [];

    for (const seg of part.split(":").filter((s) => s !== "")) {
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(seg);

      if (m) {
        const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];

        if (octets.every((n) => n >= 0 && n <= 255)) {
          groups.push((((octets[0] ?? 0) << 8) | (octets[1] ?? 0)).toString(16), (((octets[2] ?? 0) << 8) | (octets[3] ?? 0)).toString(16));
          continue;
        }
      }

      groups.push(seg);
    }

    return groups;
  };

  const left = halves[0] ? expandSide(halves[0]) : [];
  const right = halves.length > 1 && halves[1] ? expandSide(halves[1]) : [];
  const missing = halves.length > 1 ? Math.max(0, 8 - left.length - right.length) : 0;
  const full = [...left, ...Array<string>(missing).fill("0"), ...right].slice(0, 8).map((g) => g.padStart(4, "0"));

  if (full.length < 4) return clean;

  // IPv4-mapped IPv6 (::ffff:a.b.c.d or ::ffff:aabb:ccdd): keep the IPv4 address so distinct IPv4 clients never share 0000::/64
  if (full.length === 8 && full.slice(0, 5).every((g) => g === "0000") && full[5] === "ffff") {
    const hi = parseInt(full[6] ?? "0", 16);
    const lo = parseInt(full[7] ?? "0", 16);

    if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
      return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    }
  }

  return `${full.slice(0, 4).join(":")}::/64`;
}

/** The address Cloudflare reported for the request, or null when there is none (a service binding, a local run). */
function clientAddress(headers: Headers): string | null {
  const first = headers.get("cf-connecting-ip")?.split(",")[0]?.trim();

  return first ? normalizeRateLimitAddress(first) : null;
}

/** What a refused resolve answers: when to ask again, and never kept by a cache. */
export function tooManyResolves(): Response {
  return json(
    { error: `Too many resolves from this address: at most ${RESOLVE_LIMIT_PER_MINUTE} a minute. Wait a minute and try again.` },
    429,
    { "retry-after": "60", "cache-control": "no-store" },
  );
}

/** A 429 when this request is a resolve over its address's limit; null to let it through. */
export async function admitResolve(input: { req: Request; limiter: RateLimiter | null }): Promise<Response | null> {
  const { req, limiter } = input;

  if (limiter === null || (req.method !== "GET" && req.method !== "HEAD")) return null;

  if (getRouteOf(new URL(req.url).pathname) !== "resolve") return null;
  const key = clientAddress(req.headers);

  if (key === null) return null;

  try {
    const { success } = await limiter.limit({ key });

    if (success) return null;
  } catch (e) {
    console.error(JSON.stringify({ level: "error", event: "resolve-limit", error: String(e) }));

    return null;
  }

  // no address in the line: the route and the fact are enough to see a flood in Workers Logs
  console.warn(JSON.stringify({ level: "warn", event: "rate-limited", route: "GET resolve" }));

  return tooManyResolves();
}
