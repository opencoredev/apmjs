// Which deploy run uploaded the website version that answers: its build id (APM_BUILD, stamped by packages/infra/
// deploy.ts) in x-apm-build, never cached. The deploy's smoke check reads it (packages/infra/smoke-identity.ts), from
// GET /api/build (app/api/build/route.ts).

export const BUILD_HEADER = "x-apm-build";

/** The answer for `env` (the Worker's bindings; null outside Cloudflare): 204, with the build id when there is one. */
export function buildIdentity(env: { APM_BUILD?: string } | null): Response {
  const build = env?.APM_BUILD?.trim() ?? "";
  const headers = new Headers({ "cache-control": "no-store" });

  if (build !== "") headers.set(BUILD_HEADER, build);

  return new Response(null, { status: 204, headers });
}
