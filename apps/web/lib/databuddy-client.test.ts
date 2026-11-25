// The custom events and the install-default-client flag read (lib/databuddy-client.ts): what an event may carry, the
// attributes server components declare, and that nothing is sent or asked without the tracker on the page. The
// tracker and Databuddy's flag endpoint are stand-ins here; scripts/analytics-browser.ts runs the real databuddy.js.
import { afterEach, describe, expect, test } from "bun:test";
import { DATABUDDY_FLAGS_URL, EVENT_PROPS, INSTALL_DEFAULT_CLIENT_FLAG, clickEvent, copyEvent, eventFromAttributes, forgetAccount, installDefaultClient, LINKED_KEY, linkAccount, track, trackInstallDefaultShown } from "./databuddy-client";

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
    const props = [...EVENT_PROPS.values()].flat();

    for (const word of ["q", "query", "text", "url", "path", "href", "email", "user", "userId", "referrer"]) expect(props, word).not.toContain(word);
  });

  test("a declared click or copy reads back as the same event", () => {
    const event = { name: "evidence_opened", props: { package: "zod", signal: "network" } } as const;
    const click = clickEvent(event);
    const copy = copyEvent(event);

    expect(eventFromAttributes({ name: click["data-event"], props: click["data-event-props"] })).toEqual(event);
    expect(eventFromAttributes({ name: copy["data-copy-event"], props: copy["data-event-props"] })).toEqual(event);
  });

  test("a value outside an event's schema is dropped: a URL as a location, free text as a package, a fraction", () => {
    expect(eventFromAttributes({ name: "docs_cta_clicked", props: '{"location":"https://evil.test/?q=secret"}' })).toBeNull();
    expect(eventFromAttributes({ name: "evidence_opened", props: '{"package":"my secret query","signal":"network"}' })).toBeNull();
    expect(eventFromAttributes({ name: "package_searched", props: '{"results":2.5}' })).toBeNull();
    expect(eventFromAttributes({ name: "search_result_opened", props: '{"package":"JSONStream","position":1}' })).not.toBeNull();
    expect(eventFromAttributes({ name: "search_result_opened", props: '{"package":"@scope/pkg","position":2}' })).toEqual({ name: "search_result_opened", props: { package: "@scope/pkg", position: 2 } });
  });

  test("track drops an event its schema refuses, even when the tracker is there", () => {
    const t = fakeTracker();

    track(JSON.parse('{"name":"docs_cta_clicked","props":{"location":"https://evil.test/"}}'));
    expect(t.sent).toEqual([]);
  });

  test("anything but a known event with exactly its properties is dropped", () => {
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

  test("off production (no client id) asks nothing", async () => {
    fakeTracker();
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });

    expect(await installDefaultClient({ clientId: "" })).toBeNull();
    expect(bodies).toEqual([]);
  });

  test("serves the variant for this visitor's random id, and reports exposure only when the box shows it", async () => {
    const t = fakeTracker("anon_abc");
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });

    expect(await installDefaultClient({ clientId: "client-1" })).toBe("npm");
    expect(bodies).toEqual([{ clientId: "client-1", userId: "anon_abc", keys: [INSTALL_DEFAULT_CLIENT_FLAG] }]);
    expect(t.sent).toEqual([]);
    trackInstallDefaultShown("npm");
    expect(t.sent).toEqual([{ name: "$flag_evaluated", props: { flag: INSTALL_DEFAULT_CLIENT_FLAG, variant: "npm", value: "npm" } }]);
  });

  test("serves nothing for a disabled flag, a value that is not a client, an error, or no visitor id", async () => {
    fakeTracker();
    serve({ enabled: false, value: "npm", reason: "DISABLED", payload: null });
    expect(await installDefaultClient({ clientId: "client-1" })).toBeNull();

    serve({ enabled: true, value: "<script>", variant: "x", reason: "RULE_MATCH", payload: null });
    expect(await installDefaultClient({ clientId: "client-1" })).toBeNull();

    serve({ error: "boom" }, 500);
    expect(await installDefaultClient({ clientId: "client-1" })).toBeNull();

    fakeTracker(null);
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });

    expect(await installDefaultClient({ clientId: "client-1" })).toBeNull();
    expect(bodies).toEqual([]);
  });

  test("without the tracker (an opt-out, another origin) it waits briefly and asks nothing", async () => {
    Reflect.set(globalThis, "window", {});
    const bodies = serve({ enabled: true, value: "npm", variant: "npm", reason: "RULE_MATCH", payload: null });

    expect(await installDefaultClient({ clientId: "client-1" })).toBeNull();
    expect(bodies).toEqual([]);
  }, 10_000);
});

describe("linking a signed-in visitor to their account", () => {
  const ID = "0123456789abcdef0123456789abcdef";
  const OTHER = "fedcba9876543210fedcba9876543210";

  /** A stand-in for databuddy.js's identity calls and the page's local storage, with `stored` already in it. */
  function fakeIdentity(stored: Record<string, string> = {}, opts: { throws?: boolean; inMemory?: string } = {}) {
    const calls: string[] = [];
    const storage = new Map(Object.entries(stored));
    const session = new Map<string, string>([["did_session", "sess_1"]]);
    let profile = opts.inMemory ?? null;

    const store = (m: Map<string, string>) => ({
      getItem: (k: string) => m.get(k) ?? null,
      setItem: (k: string, v: string) => m.set(k, v),
      removeItem: (k: string) => m.delete(k),
    });

    Reflect.set(globalThis, "window", {
      databuddy: {
        identify: (id: string) => {
          if (opts.throws) throw new Error("tracker bug");
          calls.push(`identify ${id}`);
          profile = id;
          storage.set("did_profile", id);
        },
        clear: () => {
          calls.push("clear");
          profile = null;
          storage.delete("did_profile");
        },
        getProfileId: () => profile,
      },
      localStorage: store(storage),
      sessionStorage: store(session),
    });

    return { calls, storage, session };
  }

  test("a signed-in visitor is identified by the account's analytics id, and databuddy.js keeps no copy for the next page load", async () => {
    const { calls, storage } = fakeIdentity();

    await linkAccount(ID);
    expect(calls).toEqual([`identify ${ID}`]);
    expect(storage.get("did_profile")).toBeUndefined();
    expect(storage.get(LINKED_KEY)).toBe(ID);
  });

  test("each page load identifies again (databuddy.js sends one request per session)", async () => {
    const { calls } = fakeIdentity({ [LINKED_KEY]: ID });

    await linkAccount(ID);
    expect(calls).toEqual([`identify ${ID}`]);
  });

  test("anything but an analytics id (an email, a login, free text) is never sent", async () => {
    const { calls } = fakeIdentity();

    for (const bad of ["someone@example.com", "octocat", "0123456789ABCDEF0123456789ABCDEF", `${ID}0`, ""]) await linkAccount(bad);
    expect(calls).toEqual([]);
  });

  test("signing out starts new visitor ids once; an anonymous visitor is left alone", async () => {
    const linked = fakeIdentity({ [LINKED_KEY]: ID });

    await linkAccount(null);
    await linkAccount(null);
    expect(linked.calls).toEqual(["clear"]);
    expect(linked.storage.get(LINKED_KEY)).toBeUndefined();

    const anonymous = fakeIdentity();

    await linkAccount(null);
    expect(anonymous.calls).toEqual([]);
  });

  test("a tab still holding the profile in memory clears it on sign-out, even after another tab dropped the marker", async () => {
    const { calls } = fakeIdentity({}, { inMemory: ID });

    await linkAccount(null);
    expect(calls).toEqual(["clear"]);
  });

  test("the sign-out button drops databuddy.js's stored visitor, session and profile ids and the link marker", () => {
    const { storage, session } = fakeIdentity({ did: "anon_1", did_profile: ID, [LINKED_KEY]: ID, unrelated: "kept" });

    forgetAccount();
    expect([...storage.keys()]).toEqual(["unrelated"]);
    expect([...session.keys()]).toEqual([]);
  });

  test("a different account signing in starts new visitor ids before it is identified", async () => {
    const { calls, storage } = fakeIdentity({ [LINKED_KEY]: ID });

    await linkAccount(OTHER);
    expect(calls).toEqual(["clear", `identify ${OTHER}`]);
    expect(storage.get(LINKED_KEY)).toBe(OTHER);
  });

  test("a tracker that throws never reaches the page", async () => {
    fakeIdentity({}, { throws: true });

    await expect(linkAccount(ID)).resolves.toBeUndefined();
  });

  test("without the tracker (an opt-out, a private page) it waits briefly and sends nothing", async () => {
    Reflect.set(globalThis, "window", {});

    await expect(linkAccount(ID)).resolves.toBeUndefined();
  }, 10_000);
});
