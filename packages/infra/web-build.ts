// How the website Worker is built and served: alchemy.run.ts deploys with these options, and build-web.ts and the
// site bench (scripts/perf/site-bench.ts) build and serve it the same way.
type WebBuild = { readonly buildCommand: string; readonly minify?: boolean };

// Minified, a cold isolate has about half the JavaScript to load. OpenNext keeps every function's name either way
// (patches/@opennextjs%2Fcloudflare@1.20.13.patch), which React needs to resume a prerendered page.
export const WEB_BUILD: WebBuild = { buildCommand: "bun run build", minify: true };

/** Which requests run the Worker before the static assets are looked at: `true` for all, or path patterns. */
type WebAssets = { readonly runWorkerFirst: true | readonly string[] };

// Everything runs the Worker first (OpenNext routes it all), except the build's hashed files: the asset layer serves
// those itself, without waking the Worker, with the year-long immutable Cache-Control in apps/web/public/_headers.
export const WEB_ASSETS: WebAssets = { runWorkerFirst: ["/*", "!/_next/static/*"] };
