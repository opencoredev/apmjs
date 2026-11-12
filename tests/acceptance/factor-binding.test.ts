// A second factor on the website confirms one action: the session that made it, the change, and every parameter of
// the change. A passkey check answers a challenge made for one named action, so a passkey sign-in confirms nothing.
// A code or a passkey check made for one action (or one evidence item, or one reason) is refused by every other, and
// a confirmation works once. Covers each caller: evidence dismiss and undo, review decisions, publish approvals, CLI
// confirmations and account changes. The same website-only routes refuse a request without the website's Origin,
// sent directly or through the website's proxy, while token routes take no Origin.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { z } from "zod";
import { forwardToRegistry } from "../../apps/web/lib/registry-proxy";
import type { LiveAction, SessionAction } from "../../packages/registry/src/actions";
import { approvalId, deviceLogin, dig, enableTotp, getJson, putPublish, signInWithGitHub, startFakeGitHub, startRegistry, totp, type Browser, type FakeGitHub, type Registry } from "./harness";
import { addSoftPasskey, type SoftPasskey } from "./passkey";

const DENY = "module.exports = { deny: ['.env', '.npmrc'] };\n";

// a second file with the same kind of list: a second credential item to dismiss
const FILES = { "index.js": DENY, "lib/b.js": "module.exports = { deny: ['.npmrc'] };\n" };

let reg: Registry;
let gh: FakeGitHub;
let alice: string;
let admin: Browser;
let adminSecret: string;
let adminToken: string;
let key: SoftPasskey;

type Item = { name: string; version: string; digest: string; scorer: string; signal: string; file: string; line: number };

const Signals = z.object({ digest: z.string(), scorer: z.string(), signals: z.array(z.object({ id: z.string(), evidence: z.array(z.string()) })) });

/** The credential items a version's score cites, by file and line. */
async function credentialItems(name: string, version: string): Promise<Item[]> {
  const s = Signals.parse((await getJson(`${reg.url}-/apm/v1/score/${encodeURIComponent(name)}/${version}`)).body);
  const cred = s.signals.find((x) => x.id === "credential-mention");

  return (cred?.evidence ?? []).flatMap((e) => {
    const m = /^([^:]+):(\d+):/.exec(e);

    return m?.[1] && m[2] ? [{ name, version, digest: s.digest, scorer: s.scorer, signal: "credential-mention", file: m[1], line: Number(m[2]) }] : [];
  });
}

const Score = z.object({ score: z.number() });

async function score(name: string, version: string): Promise<number> {
  return Score.parse((await getJson(`${reg.url}-/apm/v1/score/${encodeURIComponent(name)}/${version}`)).body).score;
}

/** A website change, as the registry names it (actions.ts). */
type Action = SessionAction;

/** What a test sends with an evidence item: the reason, and the proof (or what the website used to send). */
type Extra = { reason?: string; code?: string; confirmation?: string; passkey?: true };

const Confirmed = z.object({ confirmation: z.string() });

/** The registry's passkey ceremony for one action, answered by the software passkey: challenge, then confirm. */
async function passkeyConfirm(b: Browser, action: Action, answer: { forAction?: Action; origin?: string } = {}): Promise<{ status: number; body: unknown }> {
  const ch = await b.json("-/apm/v1/factor/passkey-challenge", { method: "POST", body: { action } });

  if (ch.status !== 200) return ch;
  const challenge = String(dig(ch.body, "options", "challenge"));
  const response = key.assert({ challenge, origin: answer.origin ?? new URL(reg.url).origin });

  return b.json("-/apm/v1/factor/confirm", { method: "POST", body: { action: answer.forAction ?? action, passkey: { challengeId: dig(ch.body, "challengeId"), response } } });
}

async function confirmationFor(b: Browser, action: Action, factor: "passkey" | "totp"): Promise<string> {
  const r = factor === "passkey" ? await passkeyConfirm(b, action) : await b.json("-/apm/v1/factor/confirm", { method: "POST", body: { action, code: totp(adminSecret) } });
  const parsed = Confirmed.safeParse(r.body);

  if (r.status !== 200 || !parsed.success) throw new Error(`confirmation failed: ${r.status} ${JSON.stringify(r.body)}`);

  return parsed.data.confirmation;
}

const REASON = "A deny list: the dev server refuses to serve .npmrc.";

const dismiss = (b: Browser, item: Item, extra: Extra) => b.json("-/apm/v1/evidence-admin/dismiss", { method: "POST", body: { ...item, reason: REASON, ...extra } });
const restore = (b: Browser, item: Item, extra: Extra) => b.json("-/apm/v1/evidence-admin/restore", { method: "POST", body: { ...item, ...extra } });

beforeAll(async () => {
  gh = startFakeGitHub();
  reg = await startRegistry({ github: gh, admins: ["octo-admin"], review: { serviceTokenHash: createHash("sha256").update("svc-token").digest("hex"), admins: ["octo-admin"] } });
  alice = await reg.mintToken({ user: "alice", scope: "publish" });
  admin = await signInWithGitHub(reg, gh, "octo-admin");
  adminSecret = await enableTotp(admin);
  adminToken = (await deviceLogin(admin)).token;
  key = await addSoftPasskey(reg, "octo-admin");
  expect((await putPublish(reg, alice, { name: "bound-a", version: "1.0.0", license: "MIT", main: "index.js" }, { files: FILES })).status).toBe(201);
}, 60_000);

afterAll(async () => {
  await reg?.stop();
  await gh?.stop();
});

describe("finding 1: a factor confirms one action", () => {
  test("a passkey sign-in proves nothing to a dismissal", async () => {
    const [item] = await credentialItems("bound-a", "1.0.0");

    if (!item) throw new Error("no credential evidence");
    // the reviewer signs in with the passkey, through Better Auth's own passkey sign-in
    const options = await admin.json("api/auth/passkey/generate-authenticate-options");

    expect(options.status).toBe(200);

    const signIn = await admin.json("api/auth/passkey/verify-authentication", {
      method: "POST",
      body: { response: key.assert({ challenge: String(dig(options.body, "challenge")), origin: new URL(reg.url).origin }) },
    });

    expect(signIn.status, JSON.stringify(signIn.body)).toBe(200);
    // what the website used to send after a passkey check
    expect((await dismiss(admin, item, { passkey: true })).status).toBe(401);
    expect((await admin.json("api/auth/two-factor/disable", { method: "POST", body: {}, headers: { "x-apm-second-factor": "passkey" } })).status).toBe(403);
    expect(await score("bound-a", "1.0.0")).toBe(97);
  });

  test("a passkey check made for one evidence item or reason cannot dismiss another, and works once", async () => {
    const [a, b] = await credentialItems("bound-a", "1.0.0");

    if (!a || !b) throw new Error("expected two credential items");
    const id = await confirmationFor(admin, { kind: "evidence-dismiss", ...a, reason: REASON }, "passkey");

    // another item, another reason, another kind of action: all refused, and none of them spends it
    expect((await dismiss(admin, b, { confirmation: id })).status).toBe(401);
    expect((await dismiss(admin, a, { confirmation: id, reason: "Another reason." })).status).toBe(401);
    expect((await admin.json("-/apm/v1/review-admin/decide", { method: "POST", body: { name: a.name, version: a.version, digest: a.digest, decision: "dismiss", confirmation: id } })).status).toBe(401);
    expect(await score("bound-a", "1.0.0")).toBe(97);
    // the item it was made for
    expect((await dismiss(admin, a, { confirmation: id })).status).toBe(200);
    // once: the same confirmation does not undo it
    expect((await restore(admin, a, { confirmation: id, reason: "Undo." })).status).toBe(401);
    expect((await restore(admin, a, { code: totp(adminSecret), reason: "Undo." })).status).toBe(200);
  });

  test("a passkey answer to one action's challenge cannot confirm another action, nor come from another origin", async () => {
    const [a, b] = await credentialItems("bound-a", "1.0.0");

    if (!a || !b) throw new Error("expected two credential items");
    expect((await passkeyConfirm(admin, { kind: "evidence-dismiss", ...a, reason: REASON }, { forAction: { kind: "evidence-dismiss", ...b, reason: REASON } })).status).toBe(401);
    expect((await passkeyConfirm(admin, { kind: "evidence-dismiss", ...a, reason: REASON }, { origin: "https://evil.example" })).status).toBe(401);
  });

  test("a TOTP confirmation is bound the same way, and works once", async () => {
    const [a, b] = await credentialItems("bound-a", "1.0.0");

    if (!a || !b) throw new Error("expected two credential items");
    const id = await confirmationFor(admin, { kind: "evidence-dismiss", ...b, reason: REASON }, "totp");

    expect((await dismiss(admin, a, { confirmation: id })).status).toBe(401);
    expect((await dismiss(admin, b, { confirmation: id, reason: "Another reason." })).status).toBe(401);
    expect((await dismiss(admin, b, { confirmation: id })).status).toBe(200);
    // a second CLI confirmation with one TOTP confirmation: the first spends it
    const command = { kind: "revoke", name: "bound-a", version: "1.0.0" } satisfies LiveAction;
    const cli = await confirmationFor(admin, { kind: "cli-confirm", command }, "totp");

    expect((await admin.json("-/apm/v1/verify", { method: "POST", body: { command: { ...command, version: "1.0.1" }, confirmation: cli } })).status).toBe(401);
    expect((await admin.json("-/apm/v1/verify", { method: "POST", body: { command, confirmation: cli } })).status).toBe(200);
    expect((await admin.json("-/apm/v1/verify", { method: "POST", body: { command, confirmation: cli } })).status).toBe(401);
  });

  test("approvals, review decisions and account changes take only a confirmation made for them", async () => {
    const staged = await putPublish(reg, adminToken, { name: "@octo-admin/bound", version: "1.0.0", license: "MIT", main: "index.js" });
    const id = approvalId(JSON.stringify(staged.body));

    if (!id) throw new Error(`no approval link: ${JSON.stringify(staged.body)}`);
    const forOther = await confirmationFor(admin, { kind: "approve", id: `${id}x` }, "passkey");

    expect((await admin.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: { confirmation: forOther } })).status).toBe(401);
    const forThis = await confirmationFor(admin, { kind: "approve", id }, "passkey");

    expect((await admin.json(`-/apm/v1/staged/${id}/approve`, { method: "POST", body: { confirmation: forThis } })).status).toBe(200);

    // a review decision checks the factor before it looks the review up: the right confirmation gets as far as 404
    const decision = { name: "bound-a", version: "1.0.0", digest: "sha512-none", decision: "dismiss", note: "" } as const;
    const wrongDecision = await confirmationFor(admin, { kind: "review-decision", ...decision, decision: "confirm" }, "passkey");
    const rightDecision = await confirmationFor(admin, { kind: "review-decision", ...decision }, "passkey");

    expect((await admin.json("-/apm/v1/review-admin/decide", { method: "POST", body: { ...decision, confirmation: wrongDecision } })).status).toBe(401);
    expect((await admin.json("-/apm/v1/review-admin/decide", { method: "POST", body: { ...decision, confirmation: rightDecision } })).status).toBe(404);

    // turning off 2FA needs a confirmation made for turning off 2FA
    const linkSocial = await confirmationFor(admin, { kind: "account", change: "link-social" }, "passkey");
    const off = await admin.json("api/auth/two-factor/disable", { method: "POST", body: {}, headers: { "x-apm-second-factor": `confirmation:${linkSocial}` } });

    expect(off.status).toBe(401);
    expect(dig(off.body, "code")).toBe("STALE_CONFIRMATION");
    expect(dig((await admin.json("-/apm/v1/account")).body, "security", "totp")).toBe(true);
  });
});

describe("finding 5: website-only routes need the website's Origin", () => {
  /** A signed-in browser's request headers: its cookie, and `origin` or none at all. */
  const browserHeaders = (b: Browser, origin: string | null): Headers => {
    const headers = new Headers({ cookie: b.cookie(), "content-type": "application/json" });

    if (origin !== null) headers.set("origin", origin);

    return headers;
  };

  /** `json` is the request body, already JSON. */
  const post = (b: Browser, path: string, json: string, origin: string | null) => getJson(`${reg.url}${path}`, { method: "POST", headers: browserHeaders(b, origin), body: json });

  test("direct requests with no Origin, or another site's, are refused before anything is checked; token routes are not", async () => {
    const [item] = await credentialItems("bound-a", "1.0.0");

    if (!item) throw new Error("no credential evidence");
    const staged = await putPublish(reg, adminToken, { name: "@octo-admin/origin", version: "1.0.0", license: "MIT", main: "index.js" });
    const id = approvalId(JSON.stringify(staged.body)) ?? "missing";
    const code = "123456";

    const routes: [string, object][] = [
      ["-/apm/v1/evidence-admin/dismiss", { ...item, reason: REASON, code }],
      ["-/apm/v1/evidence-admin/restore", { ...item, reason: REASON, code }],
      ["-/apm/v1/review-admin/decide", { name: item.name, version: item.version, digest: item.digest, decision: "dismiss", code }],
      ["-/apm/v1/factor/confirm", { action: { kind: "approve", id }, code }],
      ["-/apm/v1/factor/passkey-challenge", { action: { kind: "approve", id } }],
      ["-/apm/v1/verify", { command: { kind: "revoke", name: "bound-a", version: "1.0.0" }, code }],
      [`-/apm/v1/staged/${id}/approve`, { code }],
      [`-/apm/v1/staged/${id}/reject`, {}],
      ["-/apm/v1/account/tokens/revoke", { id: "0123456789abcdef" }],
      ["api/auth/two-factor/disable", {}],
    ];

    for (const [path, body] of routes) {
      expect((await post(admin, path, JSON.stringify(body), null)).status, `${path} without Origin`).toBe(403);
      expect((await post(admin, path, JSON.stringify(body), "https://evil.example")).status, `${path} from another site`).toBe(403);
    }

    // nothing changed: the upload still waits, the score stands, 2FA is on
    expect(dig((await admin.json(`-/apm/v1/staged/${id}`)).body, "status")).toBe("pending");
    expect(dig((await admin.json("-/apm/v1/account")).body, "security", "totp")).toBe(true);
    // a CLI token sends no Origin and needs none, on a route a signed-in browser also uses
    const request = await getJson(`${reg.url}-/apm/v1/review/bound-a/1.0.0/request`, { method: "POST", headers: { authorization: `Bearer ${adminToken}` } });

    expect(request.status, JSON.stringify(request.body)).toBe(200);
  });

  test("through the website's proxy, the browser's Origin decides the same way", async () => {
    const [item] = await credentialItems("bound-a", "1.0.0");

    if (!item) throw new Error("no credential evidence");

    const proxied = (origin: string | null) => {
      const req = new Request("https://website.example/-/apm/v1/evidence-admin/dismiss", {
        method: "POST",
        headers: browserHeaders(admin, origin),
        body: JSON.stringify({ ...item, reason: REASON }),
      });

      return forwardToRegistry(req, { registry: reg.url, headers: new Headers(req.headers), dev: false });
    };

    expect((await proxied(null)).status).toBe(403);
    expect((await proxied("https://evil.example")).status).toBe(403);
    // the website's own origin gets past the check, to the factor the dismissal still needs
    expect((await proxied(new URL(reg.url).origin)).status).toBe(401);
  });
});
