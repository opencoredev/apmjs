// The custom events and the one feature flag apmjs.dev reads from Databuddy, on top of the tracker lib/analytics.ts
// loads. This is the only file that talks to window.databuddy (lib/analytics.test.ts checks that), and it only ever
// asks the tracker that is already on the page: where the loader declined (another origin, an opt-out, a private
// route) there is no window.databuddy, every track() does nothing and every flag read returns its default.
//
// Event properties carry no search text, no URL and nothing about the visitor: only the fixed values TrackedEvent
// lists, counts, and a package name where the event is about one package. databuddy.js adds its usual envelope (the
// page path without ?q, its random visitor and session ids), the same as a page view.
import { z } from "zod";
import "./zod-csp";
import { DATABUDDY_FLAGS_ORIGIN } from "./databuddy-origin";
import { InstallClient } from "./install-note";

/** An npm package name, scoped or not; nothing longer or looser can ride along as a "package". */
const PackageName = z.string().regex(/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i).max(214);

const Count = z.number().int().nonnegative().max(10_000);

/**
 * Each custom event and exactly what its properties may hold: fixed values, counts and package names, never free
 * text. Goals and funnels in Databuddy match these names.
 */
const TrackedEvent = z.discriminatedUnion("name", [
  z.object({ name: z.literal("install_command_copied"), props: z.strictObject({ client: InstallClient, package: PackageName }) }),
  z.object({ name: z.literal("registry_setup_copied"), props: z.strictObject({ client: InstallClient }) }),
  z.object({ name: z.literal("cli_install_copied"), props: z.strictObject({ method: z.enum(["curl", "brew"]), source: z.literal("docs") }) }),
  z.object({ name: z.literal("agent_prompt_copied"), props: z.strictObject({ package: PackageName }) }),
  z.object({ name: z.literal("agent_setup_copied"), props: z.strictObject({ kind: z.enum(["prompt", "instructions"]) }) }),
  z.object({ name: z.literal("mcp_setup_copied"), props: z.strictObject({ agent: z.enum(["claude", "codex", "cursor"]), source: z.enum(["home", "docs"]) }) }),
  z.object({ name: z.literal("docs_cta_clicked"), props: z.strictObject({ location: z.enum(["nav", "docs_overview", "install_note", "agent_setup", "not_found"]) }) }),
  z.object({ name: z.literal("package_searched"), props: z.strictObject({ results: Count }) }),
  z.object({ name: z.literal("search_result_opened"), props: z.strictObject({ package: PackageName, position: Count }) }),
  z.object({ name: z.literal("evidence_opened"), props: z.strictObject({ package: PackageName, signal: z.string().regex(/^[a-z0-9-]{1,64}$/) }) }),
  z.object({ name: z.literal("sign_in_clicked"), props: z.strictObject({ location: z.literal("header") }) }),
  z.object({ name: z.literal("$flag_evaluated"), props: z.strictObject({ flag: z.literal("install-default-client"), variant: InstallClient, value: InstallClient }) }),
]);

/** One event with its properties, as a value a component can hold and pass on. */
export type TrackedEvent = z.infer<typeof TrackedEvent>;

/** Every event and the property names it may carry, for the tests and for anyone wiring a goal. */
export const EVENT_PROPS: ReadonlyMap<TrackedEvent["name"], readonly string[]> = new Map(TrackedEvent.options.map((o) => [o.shape.name.value, Object.keys(o.shape.props.shape)]));

/** The part of databuddy.js's window.databuddy this file uses. */
const Tracker = z.object({
  track: z.custom<(name: string, props: Readonly<Record<string, string | number>>) => void>((v) => v instanceof Function),
  flush: z.custom<() => void>((v) => v instanceof Function),
  getTrackingIds: z.custom<() => { anonId: string | null }>((v) => v instanceof Function),
});

type Tracker = z.infer<typeof Tracker>;

declare global {
  interface Window {
    /** Set by databuddy.js once it loads; absent wherever the loader (lib/analytics.ts) declined. */
    databuddy?: unknown;
  }
}

function tracker(): Tracker | null {
  const parsed = Tracker.safeParse(globalThis.window?.databuddy);

  return parsed.success ? parsed.data : null;
}

/**
 * Sends one event now, when the tracker is on the page. It is flushed at once because several of these clicks leave
 * the page (the evidence file view, sign-in, the docs site) before databuddy.js's own batch would go.
 */
export function track(event: TrackedEvent): void {
  try {
    const t = tracker();
    const parsed = TrackedEvent.safeParse(event);

    if (!t || !parsed.success) return;
    t.track(parsed.data.name, parsed.data.props);
    t.flush();
  } catch {
    // analytics never breaks the page
  }
}

/** The data- attributes that make a server-rendered element send `event` when clicked (components/analytics-events.tsx). */
export function clickEvent(event: TrackedEvent) {
  return { "data-event": event.name, "data-event-props": JSON.stringify(event.props) };
}

/** The data- attributes that make text copied from inside an element send `event` (components/analytics-events.tsx). */
export function copyEvent(event: TrackedEvent) {
  return { "data-copy-event": event.name, "data-event-props": JSON.stringify(event.props) };
}

/** Reads back what clickEvent or copyEvent put on an element: the event when its schema accepts it, or null. */
export function eventFromAttributes({ name, props }: { name: string | undefined; props: string | undefined }): TrackedEvent | null {
  if (props === undefined) return null;

  try {
    const parsed = TrackedEvent.safeParse({ name, props: JSON.parse(props) });

    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

// ---------- feature flags ----------

/** Where databuddy.js's flags are evaluated (the SDK's own endpoint). The CSP allows this origin in connect-src. */
export const DATABUDDY_FLAGS_URL = `${DATABUDDY_FLAGS_ORIGIN}/public/v1/flags/bulk`;

/** Which client the package page's install box opens on. Variants are InstallClient values; "apm" is today's default. */
export const INSTALL_DEFAULT_CLIENT_FLAG = "install-default-client";

const FlagResult = z.object({ enabled: z.boolean(), value: z.unknown(), variant: z.string().optional() });

const FlagsResponse = z.object({ flags: z.record(z.string(), z.unknown()) });

/** How long a flag read waits for databuddy.js, which loads after the page, before it keeps the default. */
const TRACKER_WAIT_MS = 3000;

/** What `read` finds once databuddy.js has loaded, or null when it has not within TRACKER_WAIT_MS. */
async function loaded<T>(read: () => T | null): Promise<T | null> {
  const deadline = Date.now() + TRACKER_WAIT_MS;

  while (Date.now() < deadline) {
    const t = read();

    if (t) return t;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  return null;
}

async function loadedTracker(): Promise<Tracker | null> {
  return loaded(tracker);
}

/** Reports that the install box opened on `client` because of the flag, for Databuddy's experiment results. */
export function trackInstallDefaultShown(client: InstallClient): void {
  track({ name: "$flag_evaluated", props: { flag: INSTALL_DEFAULT_CLIENT_FLAG, variant: client, value: client } });
}

/**
 * The install box's starting client the flag serves this visitor, or null to keep the box's own default: a disabled
 * flag, a value that is not an InstallClient, any error. Only asked where the tracker loaded, keyed by its random
 * visitor id, so a visitor who opted out, or any copy of the site off apmjs.dev, never makes the request. `clientId`
 * is the build's Databuddy client id: "" off production, where nothing is asked.
 */
export async function installDefaultClient({ clientId }: { clientId: string }): Promise<InstallClient | null> {
  if (clientId === "") return null;

  try {
    const t = await loadedTracker();
    const anonId = z.string().min(1).safeParse(t?.getTrackingIds().anonId);

    if (!anonId.success) return null;

    const response = await fetch(DATABUDDY_FLAGS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientId, userId: anonId.data, keys: [INSTALL_DEFAULT_CLIENT_FLAG] }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return null;

    const body = FlagsResponse.safeParse(await response.json());
    const result = body.success ? FlagResult.safeParse(body.data.flags[INSTALL_DEFAULT_CLIENT_FLAG]) : null;

    if (!result?.success || !result.data.enabled) return null;
    const client = InstallClient.safeParse(result.data.value);

    return client.success ? client.data : null;
  } catch {
    return null;
  }
}

// ---------- linking a signed-in visitor to their account ----------

/** The part of window.databuddy that ties this browser to an account. */
const IdentityTracker = z.object({
  identify: z.custom<(profileId: string) => void>((v) => v instanceof Function),
  clearProfile: z.custom<() => void>((v) => v instanceof Function),
  getProfileId: z.custom<() => string | null>((v) => v instanceof Function),
});

type IdentityTracker = z.infer<typeof IdentityTracker>;

function identityTracker(): IdentityTracker | null {
  const parsed = IdentityTracker.safeParse(globalThis.window?.databuddy);

  return parsed.success ? parsed.data : null;
}

/** An account's analytics id as the registry makes it (packages/registry/src/account-events.ts): 32 hex characters. */
const AnalyticsId = z.string().regex(/^[0-9a-f]{32}$/);

/**
 * Ties this browser's visits to the signed-in account, or unties them once the visitor is signed out. `analyticsId`
 * is the account's opaque id from the registry (a hash of its internal id: never an email, name or login), or null
 * when the visitor is signed out. Only where the tracker loaded, so a visitor who opted out, or a private page, sends
 * nothing; anonymous visitors are never identified. Databuddy then counts the account's sign-up with the page views
 * that led to it. Never throws.
 */
export async function linkAccount(analyticsId: string | null): Promise<void> {
  try {
    const t = await loaded(identityTracker);

    if (!t) return;
    const current = t.getProfileId();

    if (analyticsId === null) {
      if (current !== null) t.clearProfile();

      return;
    }

    const id = AnalyticsId.safeParse(analyticsId);

    if (id.success && current !== id.data) t.identify(id.data);
  } catch {
    // analytics never breaks the page
  }
}
