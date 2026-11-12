import type { NextConfig } from "next";
import { securityHeaders } from "./lib/security-headers";

const dev = process.env.NODE_ENV === "development";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // Sign-in and the account routes (/api/auth/*, /-/apm/v1/*) are served by the registry. proxy.ts
  // forwards them, so the session cookie stays on this origin and every answer gets a no-store policy.
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders(dev) },
      // Publisher-written readme text: no scripts, no subresources, even if a browser tried to render it.
      { source: "/api/readme", headers: [{ key: "Content-Security-Policy", value: "sandbox; default-src 'none'; frame-ancestors 'none'" }] },
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
    },
  },
};

export default nextConfig;
