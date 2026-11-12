// The package page as Markdown. proxy.ts sends /package/<name>.md and /package/<name>?format=md here.
import type { NextRequest } from "next/server";
import { packageMarkdown } from "@/lib/agent/package-md";
import { loadPackageView } from "@/lib/agent/package-view";
import { registrySource } from "@/lib/agent/registry-source";
import { packagePath, parsePackageRoute } from "@/lib/package-route";
import { REGISTRY } from "@/lib/registry-url";
import { siteUrl } from "@/lib/agent/site";

const TEXT = { "content-type": "text/markdown; charset=utf-8", "access-control-allow-origin": "*" };

export async function GET(request: NextRequest, ctx: RouteContext<"/api/package-md/[...name]">): Promise<Response> {
  const route = parsePackageRoute((await ctx.params).name);

  if (route?.kind !== "package") return new Response("Not a package name.\n", { status: 404, headers: TEXT });
  const loaded = await loadPackageView({ name: route.name, version: request.nextUrl.searchParams.get("v"), registry: REGISTRY, source: registrySource });

  if (loaded.kind === "missing") return new Response(`${loaded.reason}\n`, { status: 404, headers: { ...TEXT, "cache-control": "public, max-age=60" } });

  if (loaded.kind === "unavailable") return new Response("The registry did not answer. Nothing was checked; try again.\n", { status: 503, headers: { ...TEXT, "cache-control": "no-store", "retry-after": "30" } });

  return new Response(packageMarkdown(loaded.view), {
    headers: { ...TEXT, "cache-control": "public, max-age=300", link: `<${siteUrl(packagePath(route.name))}>; rel="canonical"` },
  });
}
