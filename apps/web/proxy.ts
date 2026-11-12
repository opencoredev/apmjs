// Runs before routing (Next.js 16 "proxy", formerly middleware). Three jobs, and a rewrite of
// /package/<name>.md to the Markdown view for agents:
//  1. Forwarding headers: drop every client-supplied one, so neither the registry nor the search rate
//     limit trusts an address the client made up.
//  2. Registry routes: /api/auth/* and /-/apm/v1/* are forwarded to the registry from here, with the
//     security headers and a private, no-store cache policy on every answer.
//  3. Package pages and file views: with Cache Components the page shell is sent before the page can look
//     the package up, so the response status is decided here: a rewrite to an unmatched path for a registry
//     404 (Next.js renders its not-found page with a 404), and a standalone 503 page when it can't be read. A file
//     the registry refuses on purpose (a revoked version's 410, a 422) goes on to the page, which says why.
//     Both checks are HEAD requests the registry answers without building the package answer or reading the
//     file, and a package or file known to exist is answered from the edge cache (lib/package-status.ts).
import { NextResponse, type NextRequest } from "next/server";
import { markdownApiPath, markdownRoute } from "@/lib/agent/md-route";
import { forwardingHeaders } from "@/lib/client-ip";
import { fileStatus, packageStatus } from "@/lib/package-status";
import { parsePackageRoute, type PackageRoute } from "@/lib/package-route";
import { forwardToRegistry, isRegistryPath } from "@/lib/registry-proxy";
import { REGISTRY } from "@/lib/registry-url";
import { securityHeaders } from "@/lib/security-headers";
import { unavailablePage } from "@/lib/unavailable-page";

function forwardedHeaders(request: NextRequest): Headers {
  return forwardingHeaders(request.headers);
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
  // /package/<name>.md and ?format=md: the Markdown view for agents, rendered by app/api/package-md
  const md = request.method === "GET" || request.method === "HEAD" ? markdownRoute(request.nextUrl) : null;

  if (md) return NextResponse.rewrite(new URL(markdownApiPath(md), request.url), { request: { headers } });
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
