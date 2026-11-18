// Databuddy (https://www.databuddy.cc): label-only page views on apmjs.dev and docs.apmjs.dev (apps/web/lib/analytics.ts,
// apps/docs/analytics.ts), and the Workers' unhandled 500s as fixed codes (packages/core/src/error-report.ts). Production alone is given the client id, so
// staging and local builds send nothing: deploy.ts passes it to the builds, alchemy.run.ts binds it to the Workers.
// The id is the public one Databuddy's script tag carries, not a secret.

export const DATABUDDY_CLIENT_ID = "f01a8a38-a972-4554-92c9-71cadebf5640";

/** The stage's client id, or "" for every stage but production. */
export function databuddyClientId(stage: string): string {
  return stage === "production" ? DATABUDDY_CLIENT_ID : "";
}

/**
 * What the website and docs builds read: apps/web/lib/analytics.ts sends page views only when it is set (Next.js
 * inlines NEXT_PUBLIC_ values at build time), and apps/docs/blume.config.ts adds its page-view script only then.
 */
export function databuddyBuildEnv(stage: string) {
  return { NEXT_PUBLIC_DATABUDDY_CLIENT_ID: databuddyClientId(stage) };
}

/** Plain-text Worker vars, by name. */
export type WorkerVars = Readonly<Record<string, string>>;

/** The Workers' binding for server error reports; absent outside production, which turns the reports off. */
export function databuddyWorkerEnv(stage: string): WorkerVars {
  const id = databuddyClientId(stage);

  return id === "" ? {} : { APM_DATABUDDY_CLIENT_ID: id };
}
