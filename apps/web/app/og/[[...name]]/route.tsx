// Open Graph images: /og for the site, /og/<name> for a package (components/og-card.tsx). 1200×630 PNG.
import type { NextRequest } from "next/server";
import { OG_SIZE, packageCard, packageCardInput, siteCard } from "@/components/og-card";
import { AGENT_CACHE } from "@/lib/agent/agent-http";
import { parsePackageRoute } from "@/lib/package-route";
import { getPackage } from "@/lib/registry";

// The renderer is imported once, when this module loads, and not through next/og. next/og's ImageResponse imports it
// inside every render, and with Cache Components Next tracks each import() on one signal shared by the isolate, which
// keeps a timer from the request that made it. On Workers the next request to touch that timer throws ("Cannot
// perform I/O on behalf of a different request"), the image stream never ends, and the Worker answers 500 after 8 s:
// only the first card an isolate drew ever worked. OpenNext points this path at the edge build (resvg as WebAssembly).
const og = import("next/dist/compiled/@vercel/og/index.node.js");

export async function GET(_request: NextRequest, ctx: RouteContext<"/og/[[...name]]">): Promise<Response> {
  const segs = (await ctx.params).name ?? [];
  const { ImageResponse } = await og;

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
