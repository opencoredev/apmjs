// The registry's unhandled 500s, sent to Databuddy (packages/core/src/error-report.ts) after the answer, from inside
// ExecutionContext.waitUntil; with no execution context nothing is reported. On only when the Worker has
// APM_DATABUDDY_CLIENT_ID, which packages/infra binds on production alone. worker.ts calls reportFailure where it
// answers "Internal error" or "misconfigured"; a handled answer (a 4xx, a degraded install read, a 503 for a database
// it cannot reach) is not reported.
//
// A report carries a fixed code chosen by the failure's class (errorCode), the route's label from the route tables
// (routes.ts routeLabel), the status, the build id and the colo. The error's text, the path and everything else the
// request carried stay in Workers Logs (logFailure in worker.ts).
import { errorReporter, type ErrorCode, type ErrorReporter, type WaitUntil } from "@apm/core/error-report";
import { Cause } from "effect";
import { z } from "zod";
import { DatabaseUnavailable, isDatabaseUnavailable, StalledConnection, StatementTimeout, TransactionTimeout } from "./db-health.ts";
import { AuthError, BlobError, QueueError, StoreError, type InfraError } from "./errors.ts";
import { routeLabel } from "./routes.ts";

/** What went wrong, as worker.ts saw it: its env did not parse, a typed infrastructure error, or a defect. */
export type Failure = { readonly kind: "misconfigured" } | { readonly kind: "infra"; readonly error: InfraError } | { readonly kind: "defect"; readonly cause: Cause.Cause<unknown> };

/** The code for an infrastructure error, by its class. */
function infraCode(e: InfraError): ErrorCode {
  if (e instanceof StoreError) return isDatabaseUnavailable(e) ? "db_unavailable" : "db_error";

  if (e instanceof BlobError) return "blob_error";

  if (e instanceof AuthError) return "auth_error";

  if (e instanceof QueueError) return "queue_error";

  return "unknown";
}

/** The code for a defect, by its class: the database classes db-health.ts throws, an infrastructure error, else internal. */
function defectCode(cause: Cause.Cause<unknown>): ErrorCode {
  const defect = Cause.squash(cause);

  if (defect instanceof DatabaseUnavailable || defect instanceof StalledConnection || defect instanceof StatementTimeout || defect instanceof TransactionTimeout) return "db_unavailable";

  if (defect instanceof StoreError || defect instanceof BlobError || defect instanceof AuthError || defect instanceof QueueError) return infraCode(defect);

  return defect instanceof Error ? "internal" : "unknown";
}

/** The fixed code a failure is reported with. Nothing of the error's name, message or cause text is read. */
export function errorCode(failure: Failure): ErrorCode {
  switch (failure.kind) {
    case "misconfigured":
      return "misconfigured";
    case "infra":
      return infraCode(failure.error);
    case "defect":
      return defectCode(failure.cause);
    default: {
      const _exhaustive: never = failure;

      return _exhaustive;
    }
  }
}

/** The Cloudflare location that answered, from request.cf (absent outside Cloudflare). */
const CfColo = z.object({ cf: z.object({ colo: z.string() }) });

/** One reporter for the isolate, made once: its limit counts every request, whatever hostname or client id it had. */
let reporter: ErrorReporter = errorReporter({ fetch: (input, init) => fetch(input, init) });

/** The Worker's vars a report reads; worker.ts passes its unparsed env, so a misconfigured Worker still reports. */
export type ReportEnv = { readonly APM_DATABUDDY_CLIENT_ID?: string | undefined; readonly APM_BUILD?: string | undefined };

export type FailureReport = {
  readonly req: Request;
  readonly env: ReportEnv;
  /** ExecutionContext.waitUntil, or null outside a request: then nothing is reported, since nothing would hold the send. */
  readonly waitUntil: WaitUntil | null;
  readonly failure: Failure;
};

/**
 * Reports one failed request. Never throws. Only the client id is read here; the failure is classified, labelled and
 * serialized in the waitUntil task, after the answer.
 */
export function reportFailure(r: FailureReport): void {
  try {
    const waitUntil = r.waitUntil;

    if (waitUntil === null) return;
    const { req, env, failure } = r;

    reporter.report({
      clientId: env.APM_DATABUDDY_CLIENT_ID?.trim() ?? "",
      waitUntil,
      error: () => ({
        worker: "registry",
        code: errorCode(failure),
        route: routeLabel(req.method, new URL(req.url).pathname),
        status: 500,
        build: env.APM_BUILD?.trim() ?? "",
        colo: CfColo.safeParse(req).data?.cf.colo ?? "",
      }),
    });
  } catch {
    // reporting is best effort
  }
}

/** For tests: a fresh reporter (and limit) for the isolate, optionally with its own fetch and clock. */
export function resetReporter(options?: Parameters<typeof errorReporter>[0]): void {
  reporter = errorReporter(options ?? { fetch: (input, init) => fetch(input, init) });
}
