// The full readme of a package as plain text, for readmes longer than the package page shows. Read from the registry on
// every request and never kept by a cache: a revoke of the version that wrote it hides it at once.
import { getPackage } from "@/lib/registry";

const NO_STORE = { "cache-control": "private, no-store" };

export async function GET(request: Request): Promise<Response> {
  const name = new URL(request.url).searchParams.get("name")?.trim() ?? "";

  if (name === "" || name.length > 214) return Response.json({ error: "name is required" }, { status: 400, headers: NO_STORE });
  const found = await getPackage(name);

  if (found.kind === "missing") return Response.json({ error: "No such package." }, { status: 404, headers: NO_STORE });

  if (found.kind === "unavailable") return Response.json({ error: "The registry did not answer." }, { status: 503, headers: { ...NO_STORE, "retry-after": "30" } });

  // Publisher-written text: plain text with nosniff, and next.config.ts sandboxes this route's CSP.
  return new Response(found.value.readme, { headers: { "content-type": "text/plain; charset=utf-8", ...NO_STORE } });
}
