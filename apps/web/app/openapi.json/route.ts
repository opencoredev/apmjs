// /openapi.json: the registry's public JSON API and the website's agent routes. Static: prerendered at build.
import { openApiDocument } from "@/lib/agent/openapi";

export function GET(): Response {
  return Response.json(openApiDocument(), { headers: { "cache-control": "public, max-age=3600", "access-control-allow-origin": "*" } });
}
