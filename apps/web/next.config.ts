import type { NextConfig } from "next";

const REGISTRY = (process.env.APM_REGISTRY ?? "http://127.0.0.1:4873/").replace(/\/?$/, "/");

const nextConfig: NextConfig = {
  // Sign-in and the account routes are served by the registry; proxying them keeps the session cookie on this origin.
  async rewrites() {
    return [
      { source: "/api/auth/:path*", destination: `${REGISTRY}api/auth/:path*` },
      { source: "/-/apm/v1/:path*", destination: `${REGISTRY}-/apm/v1/:path*` },
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
