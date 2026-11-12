// The remote MCP server: POST one JSON-RPC message, get one JSON answer. Read-only, no auth, rate-limited per client.
import type { NextRequest } from "next/server";
import { connection } from "next/server";
import { sharedLimitBinding, takeAgentRequest } from "@/lib/agent/agent-limit";
import { mcpGet, mcpOptions, mcpPost } from "@/lib/agent/mcp-http";
import { registrySource } from "@/lib/agent/registry-source";
import { agentClientKey } from "@/lib/client-ip";
import { createTokenBucket } from "@/lib/rate-limit";

// A tool call can make the registry read npm or a tarball. Per client address (CF-Connecting-IP only): a burst of 30,
// then one a second, in this isolate; and 60 a minute across isolates (lib/agent/agent-limit.ts).
const perClient = createTokenBucket({ capacity: 30, refillPerSecond: 1, maxKeys: 10_000 });

export async function POST(request: NextRequest): Promise<Response> {
  return mcpPost(request, { source: registrySource, take: () => takeAgentRequest({ key: agentClientKey(request.headers), local: perClient, shared: sharedLimitBinding() }) });
}

export async function GET(): Promise<Response> {
  // request time only: a prerendered 405 would be served from the static cache
  await connection();

  return mcpGet();
}

export async function OPTIONS(): Promise<Response> {
  return mcpOptions();
}
