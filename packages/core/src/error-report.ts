// Server errors to Databuddy's error tracking: the registry Worker and the website Worker send each unhandled 500 to
// Databuddy's documented error collector (POST https://basket.databuddy.cc/errors?client_id=<id>, the endpoint its
// browser tracker posts to; https://www.databuddy.cc/docs/api/events). The client id is the public one a script tag
// would carry, so no secret is involved, and production alone is given one (packages/infra/analytics.ts).
//
// A report carries six things, each from a closed set or a value apm itself set: the worker, a fixed error code (the
// worker picks it from the error's class, never from its text), a static route label from the worker's method and
// route table ("unknown" for anything else), the status, the build id and the Cloudflare location. Never an error's
// message, name, digest or stack, a path or query as sent, headers, cookies or a body: those stay in Workers Logs.
//
// Reporting never throws and never changes the answer: report() only checks the client id and the limit and hands a
// task to waitUntil. The task starts only once waitUntil holds it, and classifies, builds and sends the report there,
// after the answer. At most `max` reports leave one isolate per window whichever hostname the requests came in on.

/** What went wrong, as the worker classified it. Only these values are ever sent. */
export const ERROR_CODES = ["misconfigured", "db_unavailable", "db_error", "blob_error", "auth_error", "queue_error", "internal", "unknown"] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export type Worker = "registry" | "web";

/** The origin each worker's reports name, whichever hostname a request came in on: production's, the one stage with a client id. */
export const REPORT_ORIGINS = { registry: "https://registry.apmjs.dev", web: "https://apmjs.dev" } as const satisfies Readonly<Record<Worker, string>>;

/** The label a report carries for a route outside the worker's table. */
export const UNKNOWN_ROUTE = "unknown";

export type ServerError = {
  readonly worker: Worker;
  readonly code: ErrorCode;
  /** A static label from the worker's route table, such as "GET packument" or "GET render package"; never a path. */
  readonly route: string;
  /** The status the worker answered with, or null when it reports before knowing it (the website's onRequestError). */
  readonly status: number | null;
  /** This version's build id (APM_BUILD), or "" when it has none. */
  readonly build: string;
  /** The Cloudflare location that answered (request.cf.colo, or the cf-ray suffix), or "" when unknown. */
  readonly colo: string;
};

/** One item of the error collector's array, in its documented fields only. */
export type ErrorPayload = {
  readonly timestamp: number;
  readonly path: string;
  readonly message: string;
  readonly errorType: string;
  readonly filename: string;
  readonly stack: string;
};

export const DATABUDDY_ERRORS_URL = "https://basket.databuddy.cc/errors";

/** The User-Agent every report carries. A fixed product name: never a version, a host or anything from the request. */
export const REPORT_USER_AGENT = "apmjs/1.0";

/** Reports one isolate sends per window. */
export const REPORT_LIMIT = { max: 10, windowMs: 60_000 } as const;

/** How long a send may take before it is dropped, so waitUntil never waits on a slow collector. */
const SEND_TIMEOUT_MS = 3_000;

/** A route label as the tables write them: a method, then lowercase words. */
const ROUTE_LABEL = /^[A-Z]{3,7}( [a-z][a-z0-9-]{0,40}){1,4}$/;

/** A build id as deploy.ts writes it. */
const BUILD_ID = /^[A-Za-z0-9._-]{1,64}$/;

/** An IATA code, as Cloudflare names its locations. */
const COLO = /^[A-Z]{3}$/;

/** A Databuddy client id: a UUID, or the dashboard's string id. */
const CLIENT_ID = /^[A-Za-z0-9-]{1,64}$/;

const CODES: ReadonlySet<string> = new Set(ERROR_CODES);

/**
 * The collector's fields for one error. Every field is checked against its closed form here as well, so a caller's
 * mistake sends "unknown" or "-" rather than whatever it passed. The collector has no field for the status, location
 * or build, so they go in `stack` as one `key=value` line.
 */
export function errorPayload(e: ServerError, now: number): ErrorPayload {
  const code = CODES.has(e.code) ? e.code : "unknown";
  const route = ROUTE_LABEL.test(e.route) ? e.route.replaceAll(" ", "_") : UNKNOWN_ROUTE;
  const status = e.status === null ? "-" : Number.isInteger(e.status) && e.status >= 500 && e.status <= 599 ? e.status : 500;
  const build = BUILD_ID.test(e.build) ? e.build : "-";
  const colo = COLO.test(e.colo) ? e.colo : "-";

  return {
    timestamp: now,
    path: `${REPORT_ORIGINS[e.worker]}/_server/${route}`,
    message: code,
    errorType: code,
    filename: `${e.worker}@${build}`,
    stack: `worker=${e.worker} code=${code} status=${status} route=${route} colo=${colo} build=${build}`,
  };
}

/** A fixed-window counter: true while fewer than `max` were taken in the current window. */
export function rateLimiter(limit: { max: number; windowMs: number }, now: () => number): () => boolean {
  let windowStart = Number.NEGATIVE_INFINITY;
  let used = 0;

  return () => {
    const t = now();

    if (t - windowStart >= limit.windowMs) {
      windowStart = t;
      used = 0;
    }

    if (used >= limit.max) return false;
    used += 1;

    return true;
  };
}

export type ReporterOptions = {
  readonly fetch: (input: string, init: RequestInit) => Promise<Response>;
  readonly now?: () => number;
  readonly limit?: { max: number; windowMs: number };
};

/** Hands a promise to the runtime to finish after the answer (ExecutionContext.waitUntil). */
export type WaitUntil = (work: Promise<unknown>) => void;

export type ReportRequest = {
  /** The Databuddy client id; "" turns reporting off. */
  readonly clientId: string;
  readonly waitUntil: WaitUntil;
  /** Builds the report. Called inside the waitUntil task, after the answer, so a throwing getter sends nothing and changes nothing. */
  readonly error: () => ServerError;
};

export type ErrorReporter = {
  /** Queues one report on `waitUntil`; false when it was not queued (reporting off, over the limit, or waitUntil threw). */
  readonly report: (request: ReportRequest) => boolean;
};

/**
 * One reporter per isolate: each worker module makes one at load, so its limit counts every request the isolate
 * answers, on any hostname and for any client id.
 */
export function errorReporter(options: ReporterOptions): ErrorReporter {
  const now = options.now ?? Date.now;
  const take = rateLimiter(options.limit ?? REPORT_LIMIT, now);

  const send = async (url: string, init: RequestInit): Promise<void> => {
    try {
      const res = await options.fetch(url, init);

      // the answer is not read: a refused report changes nothing for the request that failed
      await res.body?.cancel();
    } catch {
      // best effort
    }
  };

  /** Builds the report and sends it. Runs inside the waitUntil task, off the answer's path, and never rejects. */
  const deliver = async (clientId: string, build: () => ServerError): Promise<void> => {
    try {
      const e = build();
      const url = `${DATABUDDY_ERRORS_URL}?client_id=${encodeURIComponent(clientId)}`;

      await send(url, {
        method: "POST",
        // Workers send no User-Agent of their own, and Databuddy's edge refuses a report without one (missing_user_agent)
        headers: { "content-type": "application/json", origin: REPORT_ORIGINS[e.worker], "user-agent": REPORT_USER_AGENT },
        body: JSON.stringify([errorPayload(e, now())]),
        // the collector's answer is never followed anywhere else
        redirect: "manual",
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
      });
    } catch {
      // a builder that throws sends nothing
    }
  };

  return {
    report: (request) => {
      try {
        const clientId = request.clientId;

        if (!CLIENT_ID.test(clientId) || !take()) return false;
        const build = request.error;

        // the report is built and sent on a later microtask, and only if waitUntil took the promise without throwing
        let held = false;
        const work = Promise.resolve().then(() => (held ? deliver(clientId, build) : undefined));

        request.waitUntil(work);
        held = true;

        return true;
      } catch {
        return false;
      }
    },
  };
}
