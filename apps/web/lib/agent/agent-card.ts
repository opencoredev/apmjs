// /.well-known/agent-card.json: who apm is and how an agent talks to it, shaped like an A2A agent card. apm
// speaks MCP, not A2A, so the card names the MCP endpoint, the OpenAPI document and llms.txt under `endpoints`
// and leaves the A2A transport fields out. Pure.
import { TOOLS } from "./mcp";
import { MCP_URL, PUBLIC_REGISTRY_URL, siteUrl } from "./site";

export function agentCard() {
  return {
    name: "apm",
    description:
      "A package registry in front of npm. Scores every version out of 100 with file:line evidence, holds new versions for 24 hours, and lets maintainers yank or revoke a bad version. Ask it before installing a package.",
    url: siteUrl("/"),
    version: "1.0.0",
    provider: { organization: "apm", url: siteUrl("/") },
    documentationUrl: siteUrl("/docs#agents"),
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["text/markdown", "application/json"],
    endpoints: {
      mcp: { url: MCP_URL, transport: "streamable-http", auth: "none", readOnly: true },
      openapi: siteUrl("/openapi.json"),
      llms: siteUrl("/llms.txt"),
      llmsFull: siteUrl("/llms-full.txt"),
      explain: siteUrl("/api/explain?package={name}"),
      packageMarkdown: siteUrl("/package/{name}.md"),
      registry: PUBLIC_REGISTRY_URL,
    },
    skills: TOOLS.map((t) => ({ id: t.name, name: t.title, description: t.description, tags: ["npm", "security", "packages"] })),
  };
}
