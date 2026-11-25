// Sign-ups and sign-ins, counted in Databuddy (https://www.databuddy.cc/docs/api/events) as two server-side custom
// events: account_created when a sign-in makes a new account, sign_in when an existing account signs in again. Each
// carries one property, how the person signed in (a fixed value), and the account's analytics id: a SHA-256 of the
// account's random internal id, never its email, name or GitHub login. The website gives the same id to Databuddy's
// identify() on public pages (apps/web/lib/databuddy-client.ts), so Databuddy can tie a visitor's earlier page views to
// the account they made. A request that carries Global Privacy Control or Do Not Track is still counted, without the id.
//
// Sending never touches the sign-in: send() only hands a task to the request's waitUntil, and the task posts after the
// answer, gives up after SEND_TIMEOUT_MS and swallows every failure. On only when the Worker has APM_DATABUDDY_CLIENT_ID
// (production alone, packages/infra/analytics.ts).
import { createHash } from "node:crypto";
import { REPORT_ORIGINS, REPORT_USER_AGENT } from "@apm/core/error-report";
import { z } from "zod";

export const DATABUDDY_TRACK_URL = "https://basket.databuddy.cc/track";

export const ACCOUNT_EVENT_NAMES = ["account_created", "sign_in"] as const;

export type AccountEventName = (typeof ACCOUNT_EVENT_NAMES)[number];

/** How someone signed in, from the Better Auth route that made the session or the account. */
export const SIGN_IN_METHODS = ["github", "vercel", "passkey", "cli"] as const;

export type SignInMethod = (typeof SIGN_IN_METHODS)[number];

/** What an event names as the method: a sign-in route, or "other" for an account made anywhere else. */
export type EventMethod = SignInMethod | "other";

/** The Better Auth routes (as ctx.path names them) that sign someone in without a provider. */
const METHOD_BY_PATH: ReadonlyMap<string, SignInMethod> = new Map([
  ["/passkey/verify-authentication", "passkey"],
  ["/device/token", "cli"],
]);

/** The OAuth callback routes, whose provider is the route's parameter. */
const CALLBACK_PATHS: ReadonlySet<string> = new Set(["/callback/:id", "/oauth2/callback/:providerId"]);

const Provider = z.enum(["github", "vercel"]);

/** A callback route's parameters: Better Auth's own callback names the provider `id`, the generic OAuth one `providerId`. */
const CallbackParams = z.union([z.object({ id: Provider }), z.object({ providerId: Provider })]);

/** The sign-in method of a Better Auth route and its parameters, or null for a route that is not a sign-in. */
export function signInMethod(route: { readonly path?: string | undefined; readonly params?: unknown } | null | undefined): SignInMethod | null {
  const path = route?.path;

  if (path === undefined) return null;

  if (!CALLBACK_PATHS.has(path)) return METHOD_BY_PATH.get(path) ?? null;
  const params = CallbackParams.safeParse(route?.params);

  if (!params.success) return null;

  return "id" in params.data ? params.data.id : params.data.providerId;
}

/** The id Databuddy knows an account by: opaque, stable, and the same on the server and the website. */
export function analyticsId(authUserId: string): string {
  return createHash("sha256").update(`apm-analytics:${authUserId}`).digest("hex").slice(0, 32);
}

/** Whether a request asks not to be tracked: Global Privacy Control, or Do Not Track. */
export function optedOut(headers: Headers | undefined): boolean {
  if (headers === undefined) return false;

  return headers.get("sec-gpc")?.trim() === "1" || headers.get("dnt")?.trim() === "1";
}

export type AccountEvent = {
  readonly name: AccountEventName;
  readonly method: EventMethod;
  readonly authUserId: string;
  /** The request asked not to be tracked: the event is counted without the account's id. */
  readonly optedOut: boolean;
};

/** The body Databuddy's /track takes for one event, in its documented fields only. No profileId on an opt-out. */
export type TrackPayload = { name: AccountEventName; properties: { method: EventMethod }; source: "registry"; profileId?: string };

export function trackPayload(e: AccountEvent): TrackPayload {
  const payload: TrackPayload = { name: e.name, properties: { method: e.method }, source: "registry" };

  if (!e.optedOut) payload.profileId = analyticsId(e.authUserId);

  return payload;
}

/** How long a send may take before it is dropped, so waitUntil never waits on a slow collector. */
const SEND_TIMEOUT_MS = 3_000;

/** A Databuddy client id: a UUID, or the dashboard's string id. */
const CLIENT_ID = /^[A-Za-z0-9-]{1,64}$/;

export type AccountEvents = {
  /** Queues one event to send after the answer. Never throws and never waits. */
  readonly send: (event: AccountEvent) => void;
};

/**
 * Account events for one request: `clientId` is the Databuddy client id ("" or a malformed one turns them off),
 * `background` the request's waitUntil. Null when they are off, so the caller wires nothing.
 */
export function accountEvents(input: {
  readonly clientId: string;
  readonly background: (work: Promise<void>) => void;
  readonly url?: string | undefined;
  readonly fetch?: (url: string, init: RequestInit) => Promise<Response>;
}): AccountEvents | null {
  const clientId = input.clientId.trim();

  if (!CLIENT_ID.test(clientId)) return null;
  const doFetch = input.fetch ?? ((url, init) => fetch(url, init));
  const url = `${input.url ?? DATABUDDY_TRACK_URL}?website_id=${encodeURIComponent(clientId)}`;

  const deliver = async (event: AccountEvent): Promise<void> => {
    try {
      const res = await doFetch(url, {
        method: "POST",
        // Workers send no User-Agent of their own, and Databuddy's edge refuses a request without one
        headers: { "content-type": "application/json", origin: REPORT_ORIGINS.web, "user-agent": REPORT_USER_AGENT },
        body: JSON.stringify(trackPayload(event)),
        redirect: "manual",
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
      });

      await res.body?.cancel();
    } catch {
      // best effort: a lost count never reaches the person signing in
    }
  };

  return {
    send: (event) => {
      try {
        input.background(Promise.resolve().then(() => deliver(event)));
      } catch {
        // waitUntil refused the task: nothing is sent
      }
    },
  };
}
