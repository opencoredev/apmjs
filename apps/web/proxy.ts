// Runs before routing (Next.js 16 "proxy", formerly middleware). Three jobs, and a rewrite of
// /package/<name>.md to the Markdown view for agents:
//  1. Forwarding headers: drop every client-supplied one, so neither the registry nor the search rate
//     limit trusts an address the client made up.
//  2. Registry routes: /api/auth/* and /-/apm/v1/* are forwarded to the registry from here, with the
//     security headers and a private, no-store cache policy on every answer. The sign-in options, the same for
//     everyone, come from the edge cache (lib/auth-config.ts).
//  3. Package pages and file views: with Cache Components the page shell is sent before the page can look
//     the package up, so the response status is decided here: a rewrite to an unmatched path for a registry
//     404 (Next.js renders its not-found page with a 404), and a standalone 503 page when it can't be read. A file
//     the registry refuses on purpose (a revoked version's 410, a 422) goes on to the page, which says why.
//     Both checks are HEAD requests the registry answers without building the package answer or reading the
//     file, and a package or file known to exist is answered from the edge cache (lib/package-status.ts).
// And the apm CLI's downloads: /install and /cli/*, streamed from the CLI bucket (lib/cli-download.ts).
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { markdownApiPath, markdownRoute } from "@/lib/agent/md-route";
import { cachedAuthConfig } from "@/lib/auth-config";
import { cliDownload, isCliRoute, type CliBucket } from "@/lib/cli-download";
import { forwardingHeaders } from "@/lib/client-ip";
import { fileStatus, packageStatus } from "@/lib/package-status";
import { canonicalPackagePath } from "@/lib/agent/site";
import { parsePackageRoute, parseVersionRoute } from "@/lib/package-route";
import { forwardToRegistry, isRegistryPath } from "@/lib/registry-proxy";
import { REGISTRY } from "@/lib/registry-url";
import { securityHeaders } from "@/lib/security-headers";
import { unavailablePage } from "@/lib/unavailable-page";

function forwardedHeaders(request: NextRequest): Headers {
  return forwardingHeaders(request.headers);
}

/** The path segments after /package/, still percent-encoded. */
function packageSegments(pathname: string): string[] {
  const segs = pathname.slice("/package/".length).split("/");

  // "/package/zod/" is the same page as "/package/zod"
  if (segs.length > 1 && segs.at(-1) === "") segs.pop();

  return segs;
}

/** /package/<name>/v/<version> to the version's page, /package/<name>?v=<version>, keeping the rest of the query. */
function versionRedirect(request: NextRequest): Response | null {
  const { pathname } = request.nextUrl;
  const version = pathname.startsWith("/package/") ? parseVersionRoute(packageSegments(pathname)) : null;

  if (!version) return null;
  const target = new URL(canonicalPackagePath(version.name), request.url);
  target.search = request.nextUrl.search;
  target.searchParams.set("v", version.version);

  return NextResponse.redirect(target, 308);
}

const BucketBinding = z.object({ get: z.instanceof(Function), head: z.instanceof(Function) });

/** The CLI bucket when this runs inside the website Worker and the deploy bound it, else null. */
function cliBucket(): CliBucket | null {
  let bucket: CliBucket | undefined;

  try {
    bucket = getCloudflareContext().env.CLI;
  } catch {
    // not on Cloudflare: no bindings
    return null;
  }

  return bucket !== undefined && BucketBinding.safeParse(bucket).success ? bucket : null;
}

export async function proxy(request: NextRequest): Promise<Response> {
  const headers = forwardedHeaders(request);
  const { pathname } = request.nextUrl;

  if (isCliRoute(pathname)) return cliDownload({ pathname, method: request.method, bucket: cliBucket() });

  if (isRegistryPath(pathname)) {
    const dev = process.env.NODE_ENV === "development";

    return (await cachedAuthConfig(request, { registry: REGISTRY, dev })) ?? forwardToRegistry(request, { registry: REGISTRY, headers, dev });
  }

  const moved = versionRedirect(request);

  if (moved) return moved;

  // /package/<name>.md and ?format=md: the Markdown view for agents, rendered by app/api/package-md
  const md = request.method === "GET" || request.method === "HEAD" ? markdownRoute(request.nextUrl) : null;

  if (md) return NextResponse.rewrite(new URL(markdownApiPath(md), request.url), { request: { headers } });
  const prefetch = request.headers.has("next-router-prefetch") || request.headers.get("purpose") === "prefetch";
  const checked = pathname.startsWith("/package/") && (request.method === "GET" || request.method === "HEAD") && !prefetch;
  const route = checked ? parsePackageRoute(packageSegments(pathname)) : undefined;
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
