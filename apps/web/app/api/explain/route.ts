// GET /api/explain?package=<name>[@range]: the install verdict as JSON, for agents without MCP.
import type { NextRequest } from "next/server";
import { explainFor, parsePackageSpec } from "@/lib/agent/explain";
import { registrySource } from "@/lib/agent/registry-source";
import { clientIp } from "@/lib/client-ip";
import { createTokenBucket } from "@/lib/rate-limit";

// resolve walks the dependency tree and may score tarballs: a smaller burst than search.
const perClient = createTokenBucket({ capacity: 10, refillPerSecond: 0.5, maxKeys: 10_000 });

export async function GET(request: NextRequest): Promise<Response> {
  const spec = parsePackageSpec(request.nextUrl.searchParams.get("package") ?? "");

  if (!spec) return Response.json({ error: "Name a package: ?package=<name> or ?package=<name>@<range>." }, { status: 400 });
  const allowed = perClient.take(clientIp(request.headers));

  if (!allowed.ok) return Response.json({ error: "Too many requests. Wait a moment and try again." }, { status: 429, headers: { "retry-after": String(allowed.retryAfterSeconds) } });
  const verdict = await explainFor({ ...spec, source: registrySource });

  return Response.json(verdict, { headers: { "cache-control": "public, max-age=60", "access-control-allow-origin": "*" } });
}
