// Sign-up and sign-in counts (src/account-events.ts): which routes count, what an event carries, and that sending can
// never reach the request. tests/acceptance/account-events.test.ts runs them through a real sign-in.
import { describe, expect, test } from "bun:test";
import { accountEvents, analyticsId, optedOut, signInMethod, trackPayload } from "../src/account-events.ts";

const CLIENT_ID = "f01a8a38-a972-4554-92c9-71cadebf5640";

describe("analyticsId", () => {
  test("is 32 hex characters, the same for the same account, different for another, and shows nothing of the id", () => {
    const id = analyticsId("AbC123internalUserId");

    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(analyticsId("AbC123internalUserId")).toBe(id);
    expect(analyticsId("AbC123internalUserId2")).not.toBe(id);
    expect(id).not.toContain("abc123");
  });
});

describe("signInMethod", () => {
  test("names the provider of an OAuth callback, a passkey sign-in and the CLI's device flow", () => {
    expect(signInMethod({ path: "/callback/:id", params: { id: "github" } })).toBe("github");
    expect(signInMethod({ path: "/callback/:id", params: { id: "vercel" } })).toBe("vercel");
    expect(signInMethod({ path: "/oauth2/callback/:providerId", params: { providerId: "github" } })).toBe("github");
    expect(signInMethod({ path: "/passkey/verify-authentication" })).toBe("passkey");
    expect(signInMethod({ path: "/device/token" })).toBe("cli");
  });

  test("anything else is not a sign-in: another route, an unknown provider, no route at all", () => {
    expect(signInMethod({ path: "/two-factor/enable" })).toBeNull();
    expect(signInMethod({ path: "/callback/:id", params: { id: "evil<script>" } })).toBeNull();
    expect(signInMethod({ path: "/callback/:id" })).toBeNull();
    expect(signInMethod({})).toBeNull();
    expect(signInMethod(null)).toBeNull();
  });
});

describe("optedOut", () => {
  test("Sec-GPC: 1 or DNT: 1 opts out; anything else, or no request, does not", () => {
    expect(optedOut(new Headers({ "sec-gpc": "1" }))).toBe(true);
    expect(optedOut(new Headers({ dnt: "1" }))).toBe(true);
    expect(optedOut(new Headers({ dnt: "0" }))).toBe(false);
    expect(optedOut(new Headers())).toBe(false);
    expect(optedOut(undefined)).toBe(false);
  });
});

describe("trackPayload", () => {
  test("carries the name, the method and the analytics id, and leaves the id out on an opt-out", () => {
    const e = { name: "sign_in", method: "github", authUserId: "user-1", optedOut: false } as const;

    expect(trackPayload(e)).toEqual({ name: "sign_in", properties: { method: "github" }, source: "registry", profileId: analyticsId("user-1") });
    expect(trackPayload({ ...e, optedOut: true })).toEqual({ name: "sign_in", properties: { method: "github" }, source: "registry" });
  });
});

describe("accountEvents", () => {
  const event = { name: "account_created", method: "github", authUserId: "user-1", optedOut: false } as const;

  test("are off without a well-formed client id", () => {
    expect(accountEvents({ clientId: "", background: () => {} })).toBeNull();
    expect(accountEvents({ clientId: "not a client id!", background: () => {} })).toBeNull();
  });

  test("send queues the post on waitUntil and posts nothing before it runs", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const held: Promise<void>[] = [];

    const events = accountEvents({
      clientId: CLIENT_ID,
      background: (work) => held.push(work),
      url: "https://collector.test/track",
      fetch: async (url, init) => {
        calls.push({ url, init });

        return new Response("ok");
      },
    });

    events?.send(event);
    expect(calls).toEqual([]);
    await Promise.all(held);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`https://collector.test/track?website_id=${CLIENT_ID}`);
    expect(new Headers(calls[0]?.init.headers).get("user-agent")).toBe("apmjs/1.0");
    expect(JSON.parse(String(calls[0]?.init.body))).toEqual(trackPayload(event));
  });

  test("a collector that throws, or a waitUntil that throws, never reaches the caller", async () => {
    const held: Promise<void>[] = [];
    const failing = accountEvents({ clientId: CLIENT_ID, background: (work) => held.push(work), fetch: () => Promise.reject(new Error("network down")) });

    expect(() => failing?.send(event)).not.toThrow();
    await expect(Promise.all(held)).resolves.toBeDefined();

    const refused = accountEvents({
      clientId: CLIENT_ID,
      background: () => {
        throw new Error("waitUntil refused");
      },
    });

    expect(() => refused?.send(event)).not.toThrow();
  });
});
