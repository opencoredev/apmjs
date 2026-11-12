// The remote MCP server: POST one JSON-RPC message, get one JSON answer. Read-only, no auth, rate-limited per client.
import type { NextRequest } from "next/server";
import { connection } from "next/server";
import { mcpGet, mcpOptions, mcpPost } from "@/lib/agent/mcp-http";
import { registrySource } from "@/lib/agent/registry-source";
import { clientIp } from "@/lib/client-ip";
import { createTokenBucket } from "@/lib/rate-limit";

// A tool call can make the registry read npm or a tarball. Per client: a burst of 30, then one a second.
// In memory per isolate, like the search route's limit.
const perClient = createTokenBucket({ capacity: 30, refillPerSecond: 1, maxKeys: 10_000 });

export async function POST(request: NextRequest): Promise<Response> {
  return mcpPost(request, { source: registrySource, take: () => perClient.take(clientIp(request.headers)) });
}

export async function GET(): Promise<Response> {
  // request time only: a prerendered 405 would be served from the static cache
  await connection();

  return mcpGet();
}

export async function OPTIONS(): Promise<Response> {
  return mcpOptions();
}
