// The HTTP side of GET /api/explain and the package Markdown view, and the cache policy of every agent-facing answer.
// Pure over its inputs (the registry port, the rate limit), so the unit tests drive it with real Request objects.
//
// What an agent acts on must not outlive a change of state: a yank, a revoke or a confirmed AI review shows at once.
// The verdict and the MCP answers are never stored. The Markdown view quotes source (evidence lines, the AI review's
// excerpts), and the registry alone decides, on every request, whether a version's source may be shown: so the view is
// never stored either, by the site, the edge or a shared cache. Only the OG image, which carries no source and no text
// the publisher wrote (components/og-card.tsx), is kept for a few seconds.
import type { Take } from "../rate-limit";
import { packagePath } from "../package-route";
import { explainFor, parsePackageSpec } from "./explain";
import { packageMarkdown } from "./package-md";
import { loadPackageView } from "./package-view";
import { siteUrl } from "./site";
import type { AgentSource } from "./source";

export const AGENT_CACHE = {
  /** An install verdict, an MCP answer: never stored anywhere. */
  decision: "no-store",
  /** The package Markdown view: it can quote a version's source, so nothing may keep it. */
  source: "private, no-store",
  /** The OG image: the name, latest version, score and grade, no source and no publisher text; a few seconds, so a status change shows almost at once. */
  image: "public, max-age=5",
} as const;

export async function explainResponse(url: URL, deps: { source: AgentSource; take: () => Take | Promise<Take> }): Promise<Response> {
  const headers = { "cache-control": AGENT_CACHE.decision, "access-control-allow-origin": "*" };
  const spec = parsePackageSpec(url.searchParams.get("package") ?? "");

  if (!spec) return Response.json({ error: "Name a package: ?package=<name> or ?package=<name>@<range>." }, { status: 400, headers });
  const allowed = await deps.take();

  if (!allowed.ok) return Response.json({ error: "Too many requests. Wait a moment and try again." }, { status: 429, headers: { ...headers, "retry-after": String(allowed.retryAfterSeconds) } });

  return Response.json(await explainFor({ ...spec, source: deps.source }), { headers });
}

const TEXT = { "content-type": "text/markdown; charset=utf-8", "access-control-allow-origin": "*" };

export async function markdownResponse(input: { name: string; version: string | null; registry: string; source: AgentSource }): Promise<Response> {
  const loaded = await loadPackageView(input);

  switch (loaded.kind) {
    case "missing":
      return new Response(`${loaded.reason}\n`, { status: 404, headers: { ...TEXT, "cache-control": AGENT_CACHE.source } });
    case "unavailable":
      return new Response("The registry did not answer. Nothing was checked; try again.\n", { status: 503, headers: { ...TEXT, "cache-control": AGENT_CACHE.source, "retry-after": "30" } });
    case "ok":
      return new Response(packageMarkdown(loaded.view), { headers: { ...TEXT, "cache-control": AGENT_CACHE.source, link: `<${siteUrl(packagePath(input.name))}>; rel="canonical"` } });
    default: {
      const _exhaustive: never = loaded;

      return _exhaustive;
    }
  }
}
