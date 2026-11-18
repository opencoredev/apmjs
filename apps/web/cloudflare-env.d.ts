// Bindings the website Worker gets from packages/infra/alchemy.run.ts, read through getCloudflareContext().
interface CloudflareEnv {
  /** The registry Worker, as a service binding. */
  REGISTRY?: { fetch: (request: Request) => Promise<Response> };
  /** The apm CLI's install script and binaries (R2); lib/cli-download.ts serves them at /install and /cli/*. */
  CLI?: import("./lib/cli-download").CliBucket;
  /** The registry's public URL. */
  APM_REGISTRY?: string;
  /** The Workers rate limiting binding the agent routes (/mcp, /api/explain) share; see lib/agent/agent-limit.ts. */
  AGENT_RATE_LIMIT?: { limit: (options: { key: string }) => Promise<{ success: boolean }> };
  /** The deploy run that uploaded this version (packages/infra/deploy.ts); GET /api/build reports it. */
  APM_BUILD?: string;
  /** Databuddy's public client id; unhandled server errors are reported to it (lib/server-errors.ts). Production only. */
  APM_DATABUDDY_CLIENT_ID?: string;
}
