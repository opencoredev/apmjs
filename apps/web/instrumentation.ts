// Next.js calls onRequestError for every server error it catches while rendering a page, running a route handler or a
// server action, or in proxy.ts (node_modules/next/dist/docs/01-app/03-api-reference/03-file-conventions/
// instrumentation.md). Each is reported to Databuddy after the answer as a fixed code and a route label
// (lib/server-errors.ts); nothing here waits on it.
import type { Instrumentation } from "next";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { reportRequestError } from "@/lib/server-errors";

export const onRequestError: Instrumentation.onRequestError = (error, request, context) => {
  try {
    const { env, ctx } = getCloudflareContext();

    reportRequestError(
      { error, method: request.method, headers: request.headers, routePath: context.routePath, routeType: context.routeType },
      { clientId: env.APM_DATABUDDY_CLIENT_ID?.trim() ?? "", build: env.APM_BUILD?.trim() ?? "", waitUntil: (work) => ctx.waitUntil(work) },
    );
  } catch {
    // not on Cloudflare (next dev, the build): there is no client id, so there is nothing to report
  }
};
