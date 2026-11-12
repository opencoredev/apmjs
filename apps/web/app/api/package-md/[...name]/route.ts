// The package page as Markdown. proxy.ts sends /package/<name>.md and /package/<name>?format=md here.
import type { NextRequest } from "next/server";
import { markdownResponse } from "@/lib/agent/agent-http";
import { registrySource } from "@/lib/agent/registry-source";
import { parsePackageRoute } from "@/lib/package-route";
import { REGISTRY } from "@/lib/registry-url";

export async function GET(request: NextRequest, ctx: RouteContext<"/api/package-md/[...name]">): Promise<Response> {
  const route = parsePackageRoute((await ctx.params).name);

  if (route?.kind !== "package") return new Response("Not a package name.\n", { status: 404, headers: { "content-type": "text/markdown; charset=utf-8" } });

  return markdownResponse({ name: route.name, version: request.nextUrl.searchParams.get("v"), registry: REGISTRY, source: registrySource });
}
