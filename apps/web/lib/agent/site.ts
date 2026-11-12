// The public addresses agents and search engines are given, and the packages the home page and the
// sitemap name as popular. Pure, so the text views, the MCP server and the tests share one copy.

/** The website's public origin, with no trailing slash. Canonical URLs, the sitemap and llms.txt use it. */
export const SITE_URL = (process.env.APM_SITE_URL ?? "https://apmjs.dev").replace(/\/+$/, "");

/** The registry's public URL, ending in "/". The registry Worker serves the JSON API on it. */
export const PUBLIC_REGISTRY_URL = (process.env.APM_PUBLIC_REGISTRY ?? "https://registry.apmjs.dev/").replace(/\/?$/, "/");

/** An absolute URL on the website for a path that starts with "/". */
export function siteUrl(path: string): string {
  return `${SITE_URL}${path}`;
}

/** A package page's public path with the scope's "@" kept readable (/package/@scope/name), for canonical URLs and the sitemap. */
export function canonicalPackagePath(name: string): string {
  return `/package/${name
    .split("/")
    .map((part) => encodeURIComponent(part).replace(/^%40/, "@"))
    .join("/")}`;
}

/** A popular npm package the home page shows with its score, and the sitemap lists. */
export type PopularPackage = { name: string; blurb: string };

/** Hand-picked and short on purpose: each one costs one score lookup on a cold home page. */
export const POPULAR_PACKAGES: readonly PopularPackage[] = [
  { name: "react", blurb: "UI library" },
  { name: "next", blurb: "React framework" },
  { name: "typescript", blurb: "Typed JavaScript compiler" },
  { name: "vite", blurb: "Dev server and bundler" },
  { name: "zod", blurb: "Schema validation" },
  { name: "hono", blurb: "Web framework" },
  { name: "express", blurb: "Node.js web framework" },
  { name: "lodash", blurb: "Utility functions" },
  { name: "tailwindcss", blurb: "Utility-first CSS" },
  { name: "axios", blurb: "HTTP client" },
  { name: "prettier", blurb: "Code formatter" },
  { name: "eslint", blurb: "JavaScript linter" },
];

/** The MCP endpoint, for docs, llms.txt and the agent card. */
export const MCP_URL = siteUrl("/mcp");
