// The custom events and the install-default-client flag read (lib/databuddy-client.ts): what an event may carry, the
// attributes server components declare, and that nothing is sent or asked without the tracker on the page. The
// tracker and Databuddy's flag endpoint are stand-ins here; scripts/analytics-browser.ts runs the real databuddy.js.
import { afterEach, describe, expect, test } from "bun:test";
import { DATABUDDY_FLAGS_URL, EVENTS, INSTALL_DEFAULT_CLIENT_FLAG, clickEvent, copyEvent, eventFromAttributes, installDefaultClient, track } from "./databuddy-client";

type Sent = { name: string; props: Readonly<Record<string, string | number>> };

/** What a stand-in tracker was sent, and how often it was flushed. */
type FakeTracker = { sent: Sent[]; flushes: () => number };

/** Puts a stand-in for databuddy.js's window.databuddy on globalThis.window and returns what it was sent. */
function fakeTracker(anonId: string | null = "anon_test"): FakeTracker {
  const sent: Sent[] = [];
  let flushes = 0;

  const databuddy = {
    track: (name: string, props: Readonly<Record<string, string | number>>) => sent.push({ name, props }),
    flush: () => {
      flushes += 1;
    },
    getTrackingIds: () => ({ anonId }),
  };

  Reflect.set(globalThis, "window", { databuddy });

  return { sent, flushes: () => flushes };
}

const realFetch = globalThis.fetch;

afterEach(() => {
  Reflect.deleteProperty(globalThis, "window");
  globalThis.fetch = realFetch;
});

describe("the events", () => {
  test("carry no free text: no search query, URL, path, email or user id", () => {
    const props = Object.values(EVENTS).flat();

    for (const word of ["q", "query", "text", "url", "path", "href", "email", "user", "userId", "referrer"]) expect(props, word).not.toContain(word);
  });

  test("a declared click or copy reads back as the same event", () => {
    const event = { name: "evidence_opened", props: { package: "zod", signal: "network-at-install" } } as const;
    const click = clickEvent(event);
    const copy = copyEvent(event);

    expect(eventFromAttributes({ name: click["data-event"], props: click["data-event-props"] })).toEqual(event);
    expect(eventFromAttributes({ name: copy["data-copy-event"], props: copy["data-event-props"] })).toEqual(event);
  });

  test("anything but one of EVENTS with exactly its properties is dropped", () => {
    expect(eventFromAttributes({ name: "page_hijack", props: '{"location":"nav"}' })).toBeNull();
    expect(eventFromAttributes({ name: "docs_cta_clicked", props: '{"location":"nav","q":"secret"}' })).toBeNull();
    expect(eventFromAttributes({ name: "docs_cta_clicked", props: "{}" })).toBeNull();
    expect(eventFromAttributes({ name: "docs_cta_clicked", props: '{"location":{"a":1}}' })).toBeNull();
    expect(eventFromAttributes({ name: "docs_cta_clicked", props: "not json" })).toBeNull();
    expect(eventFromAttributes({ name: "docs_cta_clicked", props: undefined })).toBeNull();
    expect(eventFromAttributes({ name: undefined, props: '{"location":"nav"}' })).toBeNull();
    expect(eventFromAttributes({ name: "package_searched", props: '{"results":3}' })).toEqual({ name: "package_searched", props: { results: 3 } });
  });
});

describe("track", () => {
  test("does nothing where the tracker did not load, on the server or on the page", () => {
    expect(() => track({ name: "docs_cta_clicked", props: { location: "nav" } })).not.toThrow();
    Reflect.set(globalThis, "window", {});
    expect(() => track({ name: "docs_cta_clicked", props: { location: "nav" } })).not.toThrow();
  });

  test("hands the event to the tracker and flushes it, since the click may leave the page", () => {
    const t = fakeTracker();

    track({ name: "install_command_copied", props: { client: "npm", package: "zod" } });
    expect(t.sent).toEqual([{ name: "install_command_copied", props: { client: "npm", package: "zod" } }]);
    expect(t.flushes()).toBe(1);
  });

  test("a tracker that throws never reaches the page", () => {
    Reflect.set(globalThis, "window", {
      databuddy: {
        track: () => {
          throw new Error("tracker broke");
        },
        flush: () => {},
        getTrackingIds: () => ({ anonId: null }),
      },
    });
    expect(() => track({ name: "sign_in_clicked", props: { location: "header" } })).not.toThrow();
  });
});

describe("the install-default-client flag", () => {
  /** One flag's result as Databuddy's endpoint returns it, or an error body. */
  type FlagReply = { enabled: boolean; value: string; variant?: string; reason: string; payload: null } | { error: string };

  /** A stand-in for Databuddy's flag endpoint that serves `result` and records each request body. */
  function serve(result: FlagReply, status = 200): unknown[] {
    const bodies: unknown[] = [];

    globalThis.fetch = Object.assign(
      async (url: string | URL | Request, init?: RequestInit) => {
        expect(String(url)).toBe(DATABUDDY_FLAGS_URL);
        bodies.push(JSON.parse(String(init?.body)));

        return new Response(JSON.stringify({ flags: { [INSTALL_DEFAULT_CLIENT_FLAG]: result } }), { status });
      },
      { preconnect: realFetch.preconnect },
    );

    return bodies;
  }

  test("off production (no client id) asks nothing and keeps the default", async () => {
    fakeTracker();
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });

    expect(await installDefaultClient({ clientId: "", fallback: "apm" })).toBe("apm");
    expect(bodies).toEqual([]);
  });

  test("serves the variant for this visitor's random id, and reports which one it saw", async () => {
    const t = fakeTracker("anon_abc");
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });

    expect(await installDefaultClient({ clientId: "client-1", fallback: "apm" })).toBe("npm");
    expect(bodies).toEqual([{ clientId: "client-1", userId: "anon_abc", keys: [INSTALL_DEFAULT_CLIENT_FLAG] }]);
    expect(t.sent).toEqual([{ name: "$flag_evaluated", props: { flag: INSTALL_DEFAULT_CLIENT_FLAG, variant: "npm", value: "npm" } }]);
  });

  test("keeps the default for a disabled flag, a value that is not a client, an error, or no visitor id", async () => {
    fakeTracker();
    serve({ enabled: false, value: "npm", reason: "DISABLED", payload: null });
    expect(await installDefaultClient({ clientId: "client-1", fallback: "apm" })).toBe("apm");

    serve({ enabled: true, value: "<script>", variant: "x", reason: "RULE_MATCH", payload: null });
    expect(await installDefaultClient({ clientId: "client-1", fallback: "apm" })).toBe("apm");

    serve({ error: "boom" }, 500);
    expect(await installDefaultClient({ clientId: "client-1", fallback: "apm" })).toBe("apm");

    fakeTracker(null);
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });
    expect(await installDefaultClient({ clientId: "client-1", fallback: "apm" })).toBe("apm");
    expect(bodies).toEqual([]);
  });

  test("without the tracker (an opt-out, another origin) it waits briefly, asks nothing and keeps the default", async () => {
    Reflect.set(globalThis, "window", {});
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });

    expect(await installDefaultClient({ clientId: "client-1", fallback: "apm" })).toBe("apm");
    expect(bodies).toEqual([]);
  }, 10_000);
});
