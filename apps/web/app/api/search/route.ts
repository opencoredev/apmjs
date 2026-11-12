// Same-origin search for the home page: the browser calls this on every keystroke.
import type { NextRequest } from "next/server";
import { search } from "@/lib/registry";
import { clientIp } from "@/lib/client-ip";
import { createSharedCache, createTokenBucket } from "@/lib/rate-limit";
import type { SearchAnswer } from "@/lib/search-schema";

// Each search can make the registry ask npm, from one egress address. Per visitor: a burst of 20, then
// 5 a second, which typing with the 30 ms debounce stays under. In memory, one process; Cloudflare
// rate limiting and its cache replace both after the port.
const perClient = createTokenBucket({ capacity: 20, refillPerSecond: 5, maxKeys: 10_000 });
const answers = createSharedCache<SearchAnswer>({ ttlMs: 30_000, maxEntries: 2_000 });

export async function GET(request: NextRequest): Promise<Response> {
  const q = (request.nextUrl.searchParams.get("q") ?? "").trim().toLowerCase().slice(0, 214);

  if (q === "") return Response.json({ error: "q is required" }, { status: 400 });
  const allowed = perClient.take(clientIp(request.headers));

  if (!allowed.ok) {
    return Response.json({ error: "Too many searches. Wait a moment and try again." }, { status: 429, headers: { "retry-after": String(allowed.retryAfterSeconds), "cache-control": "no-store" } });
  }

  // No request signal: other visitors may be waiting on the same load. The registry call has its own timeout.
  const answer = await answers.get(q, () => search(q));

  if (!answer) return Response.json({ error: "The registry did not answer." }, { status: 502 });

  // A short private cache lets back and forward reuse answers; the registry caches npm for 60s itself.
  return Response.json(answer, { headers: { "cache-control": "private, max-age=30" } });
}
