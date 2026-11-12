import type { NextConfig } from "next";
import { securityHeaders } from "./lib/security-headers";

const dev = process.env.NODE_ENV === "development";

const NOINDEX = ["/account", "/account/:path*", "/approve/:path*", "/admin/:path*", "/device", "/device/:path*", "/signin", "/publish"];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // Sign-in and the account routes (/api/auth/*, /-/apm/v1/*) are served by the registry. proxy.ts
  // forwards them, so the session cookie stays on this origin and every answer gets a no-store policy.
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders(dev) },
      // Publisher-written readme text: no scripts, no subresources, even if a browser tried to render it.
      { source: "/api/readme", headers: [{ key: "Content-Security-Policy", value: "sandbox; default-src 'none'; frame-ancestors 'none'" }] },
      // Signed-in and one-time pages: crawlable (robots.txt allows all) but never indexed.
      ...NOINDEX.map((source) => ({ source, headers: [{ key: "X-Robots-Tag", value: "noindex, nofollow" }] })),
    ];
  },
  /* config options here */
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
      // Markdown is imported as a string: app/llms-full.txt bundles the repo's docs at build time
      "*.md": { type: "text" },
    },
  },
};

export default nextConfig;
