// Runs before routing (Next.js 16 "proxy", formerly middleware). Three jobs:
//  1. Forwarding headers: drop every client-supplied one, so neither the registry nor the search rate
//     limit trusts an address the client made up.
//  2. Registry routes: /api/auth/* and /-/apm/v1/* are forwarded to the registry from here, with the
//     security headers and a private, no-store cache policy on every answer.
//  3. Package pages: with Cache Components the page shell is sent before the page can look the package
//     up, so the response status is decided here: a rewrite to an unmatched path for a registry 404
//     (Next.js renders its not-found page with a 404), and a standalone 503 page when it can't be read.
import { NextResponse, type NextRequest } from "next/server";
import { CLIENT_FORWARDING_HEADERS, edgeClientIp } from "@/lib/client-ip";
import { packageStatus } from "@/lib/package-status";
import { forwardToRegistry, isRegistryPath } from "@/lib/registry-proxy";
import { REGISTRY } from "@/lib/registry-url";
import { securityHeaders } from "@/lib/security-headers";
import { unavailablePage } from "@/lib/unavailable-page";

function forwardedHeaders(request: NextRequest): Headers {
  const headers = new Headers(request.headers);
  const edge = edgeClientIp(request.headers);

  for (const name of CLIENT_FORWARDING_HEADERS) headers.delete(name);

  // With no X-Forwarded-For, Next.js fills it from the TCP peer for app routes. Requests forwarded to
  // the registry don't get that, so they only carry an address when the edge reported one.
  if (edge) headers.set("x-forwarded-for", edge);

  return headers;
}

function packageName(pathname: string): string | null {
  const rest = pathname.slice("/package/".length);

  if (!rest) return null;

  try {
    return rest.split("/").map(decodeURIComponent).join("/");
  } catch {
    return null;
  }
}

export async function proxy(request: NextRequest): Promise<Response> {
  const headers = forwardedHeaders(request);
  const { pathname } = request.nextUrl;

  if (isRegistryPath(pathname)) return forwardToRegistry(request, { registry: REGISTRY, headers, dev: process.env.NODE_ENV === "development" });
  const prefetch = request.headers.has("next-router-prefetch") || request.headers.get("purpose") === "prefetch";
  const name = pathname.startsWith("/package/") && (request.method === "GET" || request.method === "HEAD") && !prefetch ? packageName(pathname) : null;

  if (name) {
    const status = await packageStatus(name, request.signal);

    if (status.kind === "missing") return NextResponse.rewrite(new URL("/package-missing", request.url), { status: 404, request: { headers } });

    if (status.kind === "unavailable") {
      const html = unavailablePage({ name, retryPath: `${pathname}${request.nextUrl.search}` });

      return new Response(html, {
        status: 503,
        headers: [
          ["content-type", "text/html; charset=utf-8"],
          ["cache-control", "no-store"],
          ["retry-after", "30"],
          ...securityHeaders(process.env.NODE_ENV === "development").map((h): [string, string] => [h.key, h.value]),
        ],
      });
    }
  }

  return NextResponse.next({ request: { headers } });
}

export const config = {
  matcher: [
    // Everything but build assets and icons.
    "/((?!_next/static|_next/image|favicon.ico|icon.svg|apple-icon.png).*)",
  ],
};
