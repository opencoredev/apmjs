// Spec: sign-ups and sign-ins counted in Databuddy (packages/registry/src/account-events.ts).
// - A GitHub sign-in that makes a new account sends account_created; a later sign-in to it sends sign_in; `apm login`
//   is not counted (its token request carries no browser privacy signals). Each carries the account's opaque
//   analytics id, the same for every event of one account, and nothing else about the person.
// - Global Privacy Control or Do Not Track on the sign-in keeps the id out; the event is still counted.
// - Databuddy failing or hanging never fails or slows a sign-in: the response never waits on the send.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { deviceLogin, dig, signInWithGitHub, startFakeGitHub, startRegistry, type FakeGitHub, type Registry } from "./harness";

const CLIENT_ID = "00000000-0000-4000-8000-000000000001";

type Sent = { websiteId: string | null; userAgent: string | null; body: unknown };

let mode: "ok" | "fail" | "hang" = "ok";
const sent: Sent[] = [];
let databuddy: ReturnType<typeof Bun.serve>;
let gh: FakeGitHub;
let reg: Registry;

beforeAll(async () => {
  databuddy = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url);

      if (url.pathname !== "/track" || req.method !== "POST") return new Response("not found", { status: 404 });
      sent.push({ websiteId: url.searchParams.get("website_id"), userAgent: req.headers.get("user-agent"), body: await req.json() });

      if (mode === "fail") return new Response("down", { status: 500 });

      if (mode === "hang") return new Promise<Response>(() => {});

      return Response.json({ status: "success", type: "custom_event", count: 1 });
    },
  });
  gh = startFakeGitHub();
  reg = await startRegistry({
    legacyAuth: false,
    namePolicy: "scoped",
    github: gh,
    env: { APM_DATABUDDY_CLIENT_ID: CLIENT_ID, APM_DATABUDDY_TRACK_URL: `${databuddy.url.origin}/track` },
  });
});

afterAll(async () => {
  await reg?.stop();
  await gh?.stop();
  await databuddy?.stop(true);
});

/** The events Databuddy got from the index `from` on, once `count` of them arrived (they are sent after the answer). */
async function eventsFrom(from: number, count: number): Promise<Sent[]> {
  const deadline = Date.now() + 8_000;

  while (sent.length - from < count && Date.now() < deadline) await Bun.sleep(50);

  return sent.slice(from);
}

describe("account events", () => {
  test("a new account sends account_created with its analytics id; signing in again sends sign_in with the same id", async () => {
    const before = sent.length;
    await signInWithGitHub(reg, gh, "Signup-Sam");
    const [created, ...rest] = await eventsFrom(before, 1);
    const id = z.object({ profileId: z.string().regex(/^[0-9a-f]{32}$/) }).parse(created?.body).profileId;

    expect(created?.websiteId).toBe(CLIENT_ID);
    expect(created?.userAgent).toBe("apmjs/1.0");
    expect(created?.body).toEqual({ name: "account_created", properties: { method: "github" }, source: "registry", profileId: id });
    await Bun.sleep(300);
    // the account's first session is its sign-up, not a returning sign-in
    expect(rest).toEqual([]);
    expect(sent.length).toBe(before + 1);

    const again = sent.length;
    await signInWithGitHub(reg, gh, "Signup-Sam");
    const [signIn] = await eventsFrom(again, 1);

    expect(signIn?.body).toEqual({ name: "sign_in", properties: { method: "github" }, source: "registry", profileId: id });
  });

  test("the events carry nothing about the person: no email, name, login or GitHub id", async () => {
    const before = sent.length;
    await signInWithGitHub(reg, gh, "Private-Pat");
    const [e] = await eventsFrom(before, 1);
    const text = JSON.stringify(e?.body).toLowerCase();

    expect(e).toBeDefined();

    for (const word of ["private-pat", "users.example.test", "@", "email", "avatar"]) expect(text, word).not.toContain(word);
    // each account has its own id
    expect(new Set(sent.filter((s) => dig(s.body, "name") === "account_created").map((s) => dig(s.body, "profileId"))).size).toBe(sent.filter((s) => dig(s.body, "name") === "account_created").length);
  });

  test("apm login (the device flow) sends nothing", async () => {
    const b = await signInWithGitHub(reg, gh, "Cli-Casey");

    await Bun.sleep(500);
    const before = sent.length;
    await deviceLogin(b);
    await Bun.sleep(1_000);

    expect(sent.slice(before)).toEqual([]);
  });

  test("Global Privacy Control or Do Not Track on the sign-in keeps the id out, and the sign-up is still counted", async () => {
    for (const [login, headers] of [
      ["Gpc-Gale", { "sec-gpc": "1" }],
      ["Dnt-Dana", { dnt: "1" }],
    ] as const) {
      const before = sent.length;
      await signInWithGitHub(reg, gh, login, headers);
      const [e] = await eventsFrom(before, 1);

      expect(e?.body, login).toEqual({ name: "account_created", properties: { method: "github" }, source: "registry" });
    }
  });

  test("Databuddy failing or never answering does not fail or slow a sign-in", async () => {
    try {
      for (const m of ["fail", "hang"] as const) {
        mode = m;
        const before = sent.length;
        const started = Date.now();
        const b = await signInWithGitHub(reg, gh, `Down-${m}`);
        const me = await b.json("-/apm/v1/account");

        expect(me.status, m).toBe(200);
        expect(dig(me.body, "scope"), m).toBe(`down-${m}`);
        // a sign-in here takes well under a second; the send's own 3 s timeout never comes into it
        expect(Date.now() - started, m).toBeLessThan(2_500);
        expect((await eventsFrom(before, 1)).length, m).toBe(1);
      }
    } finally {
      mode = "ok";
    }
  });
});
