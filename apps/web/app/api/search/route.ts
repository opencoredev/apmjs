// Same-origin search for the home page: the browser calls this on every keystroke.
import type { NextRequest } from "next/server";
import { search } from "@/lib/registry";

export async function GET(request: NextRequest): Promise<Response> {
  const q = (request.nextUrl.searchParams.get("q") ?? "").trim().toLowerCase().slice(0, 214);
  if (q === "") return Response.json({ error: "q is required" }, { status: 400 });
  const answer = await search(q, request.signal);
  if (!answer) return Response.json({ error: "The registry did not answer." }, { status: 502 });
  // A short private cache lets back and forward reuse answers; the registry caches npm for 60s itself.
  return Response.json(answer, { headers: { "cache-control": "private, max-age=30" } });
}
