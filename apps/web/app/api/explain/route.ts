// GET /api/explain?package=<name>[@range]: the install verdict as JSON, for agents without MCP. Never cached: see
// lib/agent/agent-http.ts.
import type { NextRequest } from "next/server";
import { explainResponse } from "@/lib/agent/agent-http";
import { sharedLimitBinding, takeAgentRequest } from "@/lib/agent/agent-limit";
import { registrySource } from "@/lib/agent/registry-source";
import { agentClientKey } from "@/lib/client-ip";
import { createTokenBucket } from "@/lib/rate-limit";

// resolve walks the dependency tree and may score tarballs: a smaller burst than search. Keyed on CF-Connecting-IP
// only, and shared across isolates like the MCP endpoint's (lib/agent/agent-limit.ts).
const perClient = createTokenBucket({ capacity: 10, refillPerSecond: 0.5, maxKeys: 10_000 });

export async function GET(request: NextRequest): Promise<Response> {
  return explainResponse(request.nextUrl, { source: registrySource, take: () => takeAgentRequest({ key: agentClientKey(request.headers), local: perClient, shared: sharedLimitBinding() }) });
}
