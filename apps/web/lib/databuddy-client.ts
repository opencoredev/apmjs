// The custom events and the one feature flag apmjs.dev reads from Databuddy, on top of the tracker lib/analytics.ts
// loads. This is the only file that talks to window.databuddy (lib/analytics.test.ts checks that), and it only ever
// asks the tracker that is already on the page: where the loader declined (another origin, an opt-out, a private
// route) there is no window.databuddy, every track() does nothing and every flag read returns its default.
//
// Events carry no search text, no URL and nothing about the visitor: only the fixed values listed in EVENTS, and a
// package name where the event is about one package.
import { z } from "zod";
import "./zod-csp";
import { DATABUDDY_FLAGS_ORIGIN } from "./databuddy-origin";
import { InstallClient } from "./install-note";

/** Each custom event and the property names it carries. Goals and funnels in Databuddy match these names. */
export const EVENTS = {
  install_command_copied: ["client", "package"],
  registry_setup_copied: ["client"],
  cli_install_copied: ["method", "source"],
  agent_prompt_copied: ["package"],
  agent_setup_copied: ["kind"],
  mcp_setup_copied: ["agent", "source"],
  docs_cta_clicked: ["location"],
  package_searched: ["results"],
  search_result_opened: ["package", "position"],
  evidence_opened: ["package", "signal"],
  sign_in_clicked: ["location"],
  $flag_evaluated: ["flag", "variant", "value"],
} as const satisfies Readonly<Record<string, readonly string[]>>;

export type EventName = keyof typeof EVENTS;

export type EventProps<E extends EventName> = { readonly [K in (typeof EVENTS)[E][number]]: string | number };

/** One event with its properties, as a value a component can hold and pass on. */
export type TrackedEvent = { [E in EventName]: { readonly name: E; readonly props: EventProps<E> } }[EventName];

const EVENT_KEYS: ReadonlyMap<string, readonly string[]> = new Map(Object.entries(EVENTS));

const RawEvent = z.object({ name: z.string(), props: z.record(z.string(), z.union([z.string(), z.number()])) });

/** Whether a parsed event is one of EVENTS with exactly its property names. */
function hasEventKeys(e: z.infer<typeof RawEvent>): e is TrackedEvent {
  const keys = EVENT_KEYS.get(e.name);
  const got = Object.keys(e.props);

  return keys !== undefined && got.length === keys.length && keys.every((k) => got.includes(k));
}

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

    if (!t) return;
    t.track(event.name, event.props);
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

/**
 * Reads back what clickEvent or copyEvent put on an element: the event when its name is one of EVENTS and its
 * properties are exactly that event's, each a string or a number, or null.
 */
export function eventFromAttributes({ name, props }: { name: string | undefined; props: string | undefined }): TrackedEvent | null {
  if (props === undefined) return null;

  try {
    const parsed = RawEvent.safeParse({ name, props: JSON.parse(props) });

    return parsed.success && hasEventKeys(parsed.data) ? parsed.data : null;
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

async function loadedTracker(): Promise<Tracker | null> {
  const deadline = Date.now() + TRACKER_WAIT_MS;

  while (Date.now() < deadline) {
    const t = tracker();

    if (t) return t;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  return null;
}

/**
 * The install box's starting client for this visitor: the flag's variant when Databuddy serves one that is an
 * InstallClient, else `fallback`. Only asked where the tracker loaded, keyed by its random visitor id, so a visitor
 * who opted out, or any copy of the site off apmjs.dev, never makes the request and gets `fallback`. `clientId` is the
 * build's Databuddy client id: "" off production, where nothing is asked.
 */
export async function installDefaultClient({ clientId, fallback }: { clientId: string; fallback: InstallClient }): Promise<InstallClient> {
  if (clientId === "") return fallback;

  try {
    const t = await loadedTracker();
    const anonId = z.string().min(1).safeParse(t?.getTrackingIds().anonId);

    if (!anonId.success) return fallback;

    const response = await fetch(DATABUDDY_FLAGS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientId, userId: anonId.data, keys: [INSTALL_DEFAULT_CLIENT_FLAG] }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return fallback;

    const body = FlagsResponse.safeParse(await response.json());
    const result = body.success ? FlagResult.safeParse(body.data.flags[INSTALL_DEFAULT_CLIENT_FLAG]) : null;

    if (!result?.success || !result.data.enabled) return fallback;
    const client = InstallClient.safeParse(result.data.value);

    if (!client.success) return fallback;
    track({ name: "$flag_evaluated", props: { flag: INSTALL_DEFAULT_CLIENT_FLAG, variant: result.data.variant ?? client.data, value: client.data } });

    return client.data;
  } catch {
    return fallback;
  }
}
