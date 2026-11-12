// One part of the name check per request, so each slot on the search page fills on its own.
import type { NextRequest } from "next/server";
import { checkNamePart } from "@/lib/registry";
import { isNamePart, looksLikePackageName } from "@/lib/search-schema";

export async function GET(request: NextRequest): Promise<Response> {
  const params = request.nextUrl.searchParams;
  const q = (params.get("q") ?? "").trim().toLowerCase();
  const part = params.get("part");

  if (!isNamePart(part)) return Response.json({ error: "part must be exact, lookalike or alternatives" }, { status: 400 });

  if (!looksLikePackageName(q)) return Response.json({ error: "not a package name" }, { status: 400 });
  const answer = await checkNamePart(q, part, request.signal);

  if (!answer) return Response.json({ error: "The registry did not answer." }, { status: 502 });

  return Response.json(answer, { headers: { "cache-control": "private, max-age=30" } });
}
