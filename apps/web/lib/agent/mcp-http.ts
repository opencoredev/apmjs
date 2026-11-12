// The HTTP side of the MCP endpoint: one JSON-RPC message per POST, a JSON answer (or 202 for a notification),
// 405 for GET and DELETE since there is no stream or session, and a rate limit per client. Pure over its inputs,
// so the unit tests drive it with real Request objects.
import type { Take } from "../rate-limit";
import { parseJson } from "./json";
import { handleMessage, isKnownProtocolVersion, Message, RPC, rpcError, type JsonRpcResponse } from "./mcp";
import { siteUrl } from "./site";
import type { AgentSource } from "./source";

/** Read-only and unauthenticated, so any origin may call it: a browser-based MCP client included. */
export const MCP_CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, GET, OPTIONS",
  "access-control-allow-headers": "content-type, accept, mcp-protocol-version, mcp-session-id, last-event-id",
  "access-control-expose-headers": "mcp-protocol-version",
  "access-control-max-age": "86400",
} satisfies Record<string, string>;

const MAX_BODY_BYTES = 64 * 1024;

function json_(body: JsonRpcResponse | { error: string; docs: string }, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...MCP_CORS, ...extra } });
}

export type McpDeps = { source: AgentSource; take: () => Take };

export async function mcpPost(request: Request, deps: McpDeps): Promise<Response> {
  const version = request.headers.get("mcp-protocol-version");

  if (version !== null && !isKnownProtocolVersion(version)) return json_(rpcError(null, RPC.invalidRequest, `Unsupported MCP-Protocol-Version: ${version}`), 400);
  const allowed = deps.take();

  if (!allowed.ok) return json_(rpcError(null, RPC.internal, "Too many requests. Wait a moment and try again."), 429, { "retry-after": String(allowed.retryAfterSeconds) });
  const raw = await request.text();

  if (raw.length > MAX_BODY_BYTES) return json_(rpcError(null, RPC.invalidRequest, "Message too large."), 413);
  const json = parseJson(raw);

  if (!json) return json_(rpcError(null, RPC.parse, "Parse error: the body is not JSON."), 400);

  // JSON-RPC batches were dropped from MCP in 2025-06-18
  if (Array.isArray(json.value)) return json_(rpcError(null, RPC.invalidRequest, "Send one JSON-RPC message per request."), 400);
  const message = Message.safeParse(json.value);

  if (!message.success) return json_(rpcError(null, RPC.invalidRequest, "Not a JSON-RPC 2.0 message."), 400);
  const answer = await handleMessage(message.data, deps.source);

  if (answer === null) return new Response(null, { status: 202, headers: MCP_CORS });

  return json_(answer);
}

/** GET: no server-to-client stream on a stateless server. A short JSON note says how to use it instead. */
export function mcpGet(): Response {
  return json_(
    { error: "This MCP server is stateless and has no event stream. POST one JSON-RPC message per request (streamable HTTP).", docs: siteUrl("/docs#agents") },
    405,
    { allow: "POST, OPTIONS" },
  );
}

export function mcpOptions(): Response {
  return new Response(null, { status: 204, headers: MCP_CORS });
}
