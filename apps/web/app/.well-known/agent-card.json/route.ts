// /.well-known/agent-card.json: how an agent finds apm's MCP server, API and docs. Static: prerendered at build.
import { agentCard } from "@/lib/agent/agent-card";

export function GET(): Response {
  return Response.json(agentCard(), { headers: { "cache-control": "public, max-age=3600", "access-control-allow-origin": "*" } });
}
