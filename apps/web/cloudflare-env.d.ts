// Bindings the website Worker gets from packages/infra/alchemy.run.ts, read through getCloudflareContext().
interface CloudflareEnv {
  /** The registry Worker, as a service binding. */
  REGISTRY?: { fetch: (request: Request) => Promise<Response> };
  /** The registry's public URL. */
  APM_REGISTRY?: string;
  /** The Workers rate limiting binding the agent routes (/mcp, /api/explain) share; see lib/agent/agent-limit.ts. */
  AGENT_RATE_LIMIT?: { limit: (options: { key: string }) => Promise<{ success: boolean }> };
}
