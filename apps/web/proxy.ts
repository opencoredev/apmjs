// Runs before routing (Next.js 16 "proxy", formerly middleware). Three jobs:
//  1. Forwarding headers: drop every client-supplied one, so neither the registry nor the search rate
//     limit trusts an address the client made up.
//  2. Registry routes: /api/auth/* and /-/apm/v1/* are forwarded to the registry from here, with the
//     security headers and a private, no-store cache policy on every answer.
//  3. Package pages and file views: with Cache Components the page shell is sent before the page can look
//     the package up, so the response status is decided here: a rewrite to an unmatched path for a registry
//     404 (Next.js renders its not-found page with a 404), and a standalone 503 page when it can't be read.
//     A package or file known to exist is answered from the edge cache (lib/package-status.ts), and a package
//     looked up here stays cached for the page, so a view reads the package from the registry at most once.
import { NextResponse, type NextRequest } from "next/server";
import { CLIENT_FORWARDING_HEADERS, edgeClientIp } from "@/lib/client-ip";
import { fileStatus, packageStatus } from "@/lib/package-status";
import { parsePackageRoute, type PackageRoute } from "@/lib/package-route";
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

/** The package route a /package/... path names; null when it names none. */
function packageRoute(pathname: string): PackageRoute | null {
  const segs = pathname.slice("/package/".length).split("/");

  // "/package/zod/" is the same page as "/package/zod"
  if (segs.length > 1 && segs.at(-1) === "") segs.pop();

  return parsePackageRoute(segs);
}

export async function proxy(request: NextRequest): Promise<Response> {
  const headers = forwardedHeaders(request);
  const { pathname } = request.nextUrl;

  if (isRegistryPath(pathname)) return forwardToRegistry(request, { registry: REGISTRY, headers, dev: process.env.NODE_ENV === "development" });
  const prefetch = request.headers.has("next-router-prefetch") || request.headers.get("purpose") === "prefetch";
  const checked = pathname.startsWith("/package/") && (request.method === "GET" || request.method === "HEAD") && !prefetch;
  const route = checked ? packageRoute(pathname) : undefined;
  const missing = () => NextResponse.rewrite(new URL("/package-missing", request.url), { status: 404, request: { headers } });

  if (route === null) return missing();

  if (route) {
    const name = route.name;
    // a file view asks for the file alone: the registry answers 404 when the package, the version or the file is
    // missing. Both checks are answered from the edge cache once the answer is known to be yes.
    const status = route.kind === "file" ? await fileStatus(route, request.signal) : await packageStatus(name, request.signal);

    if (status === "missing") return missing();

    if (status === "unavailable") {
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
