// Open Graph images: /og for the site, /og/<name> for a package (components/og-card.tsx). 1200×630 PNG.
import { ImageResponse } from "next/og";
import type { NextRequest } from "next/server";
import { OG_SIZE, packageCard, packageCardInput, siteCard } from "@/components/og-card";
import { AGENT_CACHE } from "@/lib/agent/agent-http";
import { parsePackageRoute } from "@/lib/package-route";
import { getPackage } from "@/lib/registry";

export async function GET(_request: NextRequest, ctx: RouteContext<"/og/[[...name]]">): Promise<Response> {
  const segs = (await ctx.params).name ?? [];

  // the site card never changes between deploys
  if (segs.length === 0) return new ImageResponse(siteCard(), { ...OG_SIZE, headers: { "cache-control": "public, max-age=3600, s-maxage=3600" } });
  const route = parsePackageRoute(segs);

  if (route?.kind !== "package") return new Response("Not found", { status: 404 });
  // a package card shows a score that a yank, a revoke or a dismissal changes: stored for seconds, not an hour
  const headers = { "cache-control": AGENT_CACHE.image };
  const found = await getPackage(route.name);

  if (found.kind === "missing") return new Response("Not found", { status: 404, headers });
  // registry down: the card still names the package, unscored
  const card = packageCard(packageCardInput({ name: route.name, pkg: found.kind === "ok" ? found.value : null }));

  return new ImageResponse(card, { ...OG_SIZE, headers });
}
