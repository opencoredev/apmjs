// The full readme of a package as plain text, for readmes longer than the package page shows.
import type { NextRequest } from "next/server";
import { getPackage } from "@/lib/registry";

export async function GET(request: NextRequest): Promise<Response> {
  const name = request.nextUrl.searchParams.get("name")?.trim() ?? "";

  if (name === "" || name.length > 214) return Response.json({ error: "name is required" }, { status: 400 });
  const found = await getPackage(name);

  if (found.kind === "missing") return Response.json({ error: "No such package." }, { status: 404 });

  if (found.kind === "unavailable") return Response.json({ error: "The registry did not answer." }, { status: 503, headers: { "retry-after": "30" } });

  // Publisher-written text: plain text with nosniff, and next.config.ts sandboxes this route's CSP.
  return new Response(found.value.readme, { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=60" } });
}
