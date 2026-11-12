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

/** The largest JSON-RPC message accepted, in bytes. */
export const MAX_BODY_BYTES = 64 * 1024;

export type BodyRead = { kind: "ok"; text: string } | { kind: "too-large" } | { kind: "failed" };

/**
 * The request body as text, read at most `maxBytes` bytes in: a declared Content-Length over the limit is refused
 * before anything is read, and a stream that runs past it is cancelled at that point, so an oversized body is never
 * buffered whole. A body that fails mid-read is "failed", never a partial message.
 */
export async function readCappedBody(request: Request, maxBytes: number): Promise<BodyRead> {
  const declared = request.headers.get("content-length");

  if (declared !== null && /^\d+$/.test(declared.trim()) && Number(declared) > maxBytes) {
    await request.body?.cancel().catch(() => undefined);

    return { kind: "too-large" };
  }

  if (request.body === null) return { kind: "ok", text: "" };
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";

  try {
    for (;;) {
      const chunk = await reader.read();

      if (chunk.done) break;
      total += chunk.value.byteLength;

      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);

        return { kind: "too-large" };
      }

      text += decoder.decode(chunk.value, { stream: true });
    }
  } catch {
    await reader.cancel().catch(() => undefined);

    return { kind: "failed" };
  }

  return { kind: "ok", text: text + decoder.decode() };
}

function json_(body: JsonRpcResponse | { error: string; docs: string }, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...MCP_CORS, ...extra } });
}

export type McpDeps = { source: AgentSource; take: () => Take | Promise<Take> };

export async function mcpPost(request: Request, deps: McpDeps): Promise<Response> {
  const version = request.headers.get("mcp-protocol-version");

  if (version !== null && !isKnownProtocolVersion(version)) return json_(rpcError(null, RPC.invalidRequest, `Unsupported MCP-Protocol-Version: ${version}`), 400);
  const allowed = await deps.take();

  if (!allowed.ok) return json_(rpcError(null, RPC.internal, "Too many requests. Wait a moment and try again."), 429, { "retry-after": String(allowed.retryAfterSeconds) });
  const body = await readCappedBody(request, MAX_BODY_BYTES);

  if (body.kind === "too-large") return json_(rpcError(null, RPC.invalidRequest, `Message too large: the limit is ${MAX_BODY_BYTES} bytes.`), 413);

  if (body.kind === "failed") return json_(rpcError(null, RPC.parse, "Could not read the request body."), 400);
  const json = parseJson(body.text);

  if (!json) return json_(rpcError(null, RPC.parse, "Parse error: the body is not JSON."), 400);

  // JSON-RPC batches were dropped from MCP in 2025-06-18
  if (Array.isArray(json.value)) return json_(rpcError(null, RPC.invalidRequest, "Send one JSON-RPC message per request."), 400);
  const message = Message.safeParse(json.value);

  if (!message.success) return json_(rpcError(null, RPC.invalidRequest, "Not a JSON-RPC 2.0 message."), 400);
  const answer = await handleMessage(message.data, deps.source);

  if (answer === null) return new Response(null, { status: 202, headers: { ...MCP_CORS, "cache-control": "no-store" } });

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
  return new Response(null, { status: 204, headers: { ...MCP_CORS, "cache-control": "no-store" } });
}
