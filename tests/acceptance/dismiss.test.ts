// Score evidence an apm reviewer dismisses: only a reviewer signed in on the website, with a fresh code, can do it
// (tokens get 403); the score is recomputed without the item; nothing carries over to another version or digest;
// an undo, which needs its own reason, restores it; both go into the package's public log in the same transaction
// as the change, and a dismissed fallback item can be undone like any other. The website-only routes refuse a
// request without the website's Origin, sent directly or through the website's proxy. Every package is inert: one
// names `.npmrc` in a list it never reads, the way vite's dev-server deny list does.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { z } from "zod";
import { deviceLogin, dig, enableTotp, getJson, pkgTgz, putPublish, signInWithGitHub, startFakeGitHub, startRegistry, totp, type Browser, type FakeGitHub, type Registry } from "./harness";

const DENY = "module.exports = { deny: ['.env', '.env.*', '.npmrc'] };\n";

let reg: Registry;
let gh: FakeGitHub;
let npm: ReturnType<typeof Bun.serve>;
let alice: string;
let admin: Browser;
let adminSecret: string;
let adminToken: string;
let outsider: Browser;
let outsiderSecret: string;

type Item = { name: string; version: string; digest: string; scorer: string; signal: string; file: string; line: number };

async function score(name: string, version: string): Promise<{ status: number; body: unknown }> {
  // a token caller's request analyses an upstream version inline; an anonymous one only queues it
  return getJson(`${reg.url}-/apm/v1/score/${encodeURIComponent(name)}/${version}`, { headers: { authorization: `Bearer ${alice}` } });
}

/** The credential item a version's score cites, as the version page names it. */
async function credentialItem(name: string, version: string): Promise<Item> {
  const s = await score(name, version);
  const evidence = dig(s.body, "signals");
  const cred = Array.isArray(evidence) ? evidence.find((x) => dig(x, "id") === "credential-mention") : undefined;
  const first = String(dig(cred, "evidence", 0) ?? "");
  const m = /^([^:]+):(\d+):/.exec(first);

  if (!m?.[1] || !m[2]) throw new Error(`no credential evidence: ${JSON.stringify(s.body)}`);

  return { name, version, digest: String(dig(s.body, "digest")), scorer: String(dig(s.body, "scorer")), signal: "credential-mention", file: m[1], line: Number(m[2]) };
}

/** What a request adds to the item: the reviewer's reason, the code. */
type Extra = { reason?: string; code?: string };

const dismiss = (b: Browser, item: Item, extra: Extra = {}, headers: Record<string, string> = {}) =>
  b.json("-/apm/v1/evidence-admin/dismiss", { method: "POST", body: { ...item, reason: "A deny list: the dev server refuses to serve .npmrc.", ...extra }, headers });

const restore = (b: Browser, item: Item, extra: Extra = {}, headers: Record<string, string> = {}) => b.json("-/apm/v1/evidence-admin/restore", { method: "POST", body: { ...item, ...extra }, headers });

/** The signal ids a score answer lists. */
const ScoreSignals = z.object({ signals: z.array(z.object({ id: z.string() })) });

async function events(name: string): Promise<{ kind: string; actor: string; detail: unknown }[]> {
  const r = await getJson(`${reg.url}-/apm/v1/packages/${encodeURIComponent(name)}/events`);
  const list = dig(r.body, "events");

  return Array.isArray(list) ? list.map((e) => ({ kind: String(dig(e, "kind")), actor: String(dig(e, "actor")), detail: dig(e, "detail") })) : [];
}

beforeAll(async () => {
  // a fake npm with one package: the upstream case (vite's), scored from its tarball
  const upstreamTgz = pkgTgz({ name: "deny-list-upstream", version: "2.0.0", license: "MIT", main: "index.js" }, { "index.js": DENY });

  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const u = new URL(req.url);

      if (u.pathname === "/deny-list-upstream/-/deny-list-upstream-2.0.0.tgz") return new Response(upstreamTgz);

      if (u.pathname !== "/deny-list-upstream") return Response.json({ error: "Not found" }, { status: 404 });

      return Response.json({
        name: "deny-list-upstream",
        "dist-tags": { latest: "2.0.0" },
        versions: {
          "2.0.0": {
            name: "deny-list-upstream",
            version: "2.0.0",
            main: "index.js",
            license: "MIT",
            dist: {
              tarball: `${npm.url.toString()}deny-list-upstream/-/deny-list-upstream-2.0.0.tgz`,
              shasum: createHash("sha1").update(upstreamTgz).digest("hex"),
              integrity: `sha512-${createHash("sha512").update(upstreamTgz).digest("base64")}`,
            },
          },
        },
        time: { "2.0.0": "2026-11-01T00:00:00Z" },
      });
    },
  });
  gh = startFakeGitHub();
  reg = await startRegistry({ github: gh, upstream: npm.url.toString(), upstreamTtlMs: 1, admins: ["octo-admin"] });
  alice = await reg.mintToken({ user: "alice", scope: "publish" });
  admin = await signInWithGitHub(reg, gh, "octo-admin");
  adminSecret = await enableTotp(admin);
  adminToken = (await deviceLogin(admin)).token;
  outsider = await signInWithGitHub(reg, gh, "someone-else");
  outsiderSecret = await enableTotp(outsider);
}, 60_000);

afterAll(async () => {
  await reg?.stop();
  await gh?.stop();
  npm?.stop(true);
});

describe("dismissing score evidence", () => {
  test("only a reviewer's website session with a fresh code can dismiss; tokens get 403", async () => {
    expect((await putPublish(reg, alice, { name: "deny-list-a", version: "1.0.0", license: "MIT", main: "index.js" }, { files: { "index.js": DENY } })).status).toBe(201);
    const item = await credentialItem("deny-list-a", "1.0.0");

    expect(dig((await score("deny-list-a", "1.0.0")).body, "score")).toBe(97);
    expect((await getJson(`${reg.url}-/apm/v1/evidence-admin/me`)).body).toEqual({ admin: false });
    expect(dig((await admin.json("-/apm/v1/evidence-admin/me")).body, "admin")).toBe(true);
    expect(dig((await outsider.json("-/apm/v1/evidence-admin/me")).body, "admin")).toBe(false);

    const post = (token: string) =>
      getJson(`${reg.url}-/apm/v1/evidence-admin/dismiss`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ ...item, reason: "x", code: totp(adminSecret) }),
      });

    expect((await getJson(`${reg.url}-/apm/v1/evidence-admin/dismiss`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...item, reason: "x" }) })).status).toBe(401);
    // the reviewer's own CLI token, and a publisher's token, are refused
    expect((await post(adminToken)).status).toBe(403);
    expect((await post(alice)).status).toBe(403);
    // a signed-in person who is not a reviewer, even with their own fresh code
    expect((await dismiss(outsider, item, { code: totp(outsiderSecret) })).status).toBe(403);
    // the reviewer without a fresh factor, and with a wrong one
    expect((await dismiss(admin, item)).status).toBe(401);
    expect((await dismiss(admin, item, { code: "000000" })).status).toBe(401);
    // a reason is required
    expect((await dismiss(admin, item, { reason: " ", code: totp(adminSecret) })).status).toBe(400);
    expect(dig((await score("deny-list-a", "1.0.0")).body, "score")).toBe(97);
  });

  test("the score is recomputed without the item, which stays listed as dismissed", async () => {
    const item = await credentialItem("deny-list-a", "1.0.0");
    const done = await dismiss(admin, item, { code: totp(adminSecret) });

    expect(done.status).toBe(200);
    expect(dig(done.body, "score", "score")).toBe(100);
    const s = await score("deny-list-a", "1.0.0");

    expect(dig(s.body, "score")).toBe(100);
    expect(ScoreSignals.parse(s.body).signals.map((x) => x.id)).not.toContain("credential-mention");
    expect(dig(s.body, "dismissed", 0, "signal")).toBe("credential-mention");
    expect(dig(s.body, "dismissed", 0, "reason")).toBe("A deny list: the dev server refuses to serve .npmrc.");
    expect(String(dig(s.body, "dismissed", 0, "evidence", 0))).toContain(".npmrc");
    // the package page, the version list and the packument's score agree
    const pkg = await getJson(`${reg.url}-/apm/v1/packages/deny-list-a`);

    expect(dig(pkg.body, "score", "score")).toBe(100);
    expect(dig(pkg.body, "versions", 0, "score")).toBe(100);
    expect(dig((await getJson(`${reg.url}deny-list-a`)).body, "versions", "1.0.0", "_apmScore", "score")).toBe(100);
    // the same item cannot be dismissed twice
    expect((await dismiss(admin, item, { code: totp(adminSecret) })).status).toBe(409);
  });

  test("a new version, another digest or another scorer is not affected", async () => {
    expect((await putPublish(reg, alice, { name: "deny-list-a", version: "1.0.1", license: "MIT", main: "index.js" }, { files: { "index.js": DENY } })).status).toBe(201);
    expect(dig((await score("deny-list-a", "1.0.1")).body, "score")).toBe(97);
    expect(dig((await score("deny-list-a", "1.0.1")).body, "dismissed")).toEqual([]);
    const item = await credentialItem("deny-list-a", "1.0.1");
    const otherDigest = String(dig((await score("deny-list-a", "1.0.0")).body, "digest"));

    expect(otherDigest).not.toBe(item.digest);

    // naming 1.0.1 with 1.0.0's digest, or a scorer that did not score it, is refused
    expect((await dismiss(admin, { ...item, digest: otherDigest }, { code: totp(adminSecret) })).status).toBe(409);
    expect((await dismiss(admin, { ...item, scorer: "apm-score-v7" }, { code: totp(adminSecret) })).status).toBe(409);
    // an item the score does not cite
    expect((await dismiss(admin, { ...item, line: 99 }, { code: totp(adminSecret) })).status).toBe(404);
    expect(dig((await score("deny-list-a", "1.0.1")).body, "score")).toBe(97);
  });

  test("an undo restores the item and its points", async () => {
    const s = await score("deny-list-a", "1.0.0");
    const d = dig(s.body, "dismissed", 0);
    const item: Item = { name: "deny-list-a", version: "1.0.0", digest: String(dig(s.body, "digest")), scorer: String(dig(s.body, "scorer")), signal: String(dig(d, "signal")), file: String(dig(d, "file")), line: Number(dig(d, "line")) };

    expect((await restore(admin, item, { reason: "Reopened to check again." })).status).toBe(401);
    expect((await restore(admin, item, { code: totp(adminSecret), reason: "Reopened to check again." })).status).toBe(200);
    const after = await score("deny-list-a", "1.0.0");

    expect(dig(after.body, "score")).toBe(97);
    expect(dig(after.body, "dismissed")).toEqual([]);
    expect(ScoreSignals.parse(after.body).signals.map((x) => x.id)).toContain("credential-mention");
    expect((await restore(admin, item, { code: totp(adminSecret), reason: "Again." })).status).toBe(404);
  });

  test("dismissals and undos are in the package's public log, with who and why", async () => {
    const log = await events("deny-list-a");
    const dismissed = log.find((e) => e.kind === "evidence-dismissed");
    const restored = log.find((e) => e.kind === "evidence-restored");

    expect(dismissed?.actor).toBe("octo-admin");
    expect(dig(dismissed?.detail, "reason")).toBe("A deny list: the dev server refuses to serve .npmrc.");
    expect(dig(dismissed?.detail, "version")).toBe("1.0.0");
    expect(dig(dismissed?.detail, "signal")).toBe("credential-mention");
    expect(restored?.actor).toBe("octo-admin");
    // finding 4: the undo's own reason, and the reason it undid
    expect(dig(restored?.detail, "reason")).toBe("Reopened to check again.");
    expect(dig(restored?.detail, "dismissal", "reason")).toBe("A deny list: the dev server refuses to serve .npmrc.");
  });

  test("an upstream package's evidence can be dismissed, and its log is public", async () => {
    expect(dig((await score("deny-list-upstream", "2.0.0")).body, "score")).toBe(97);
    const item = await credentialItem("deny-list-upstream", "2.0.0");

    expect((await dismiss(admin, item, { code: totp(adminSecret) })).status).toBe(200);
    expect(dig((await score("deny-list-upstream", "2.0.0")).body, "score")).toBe(100);
    expect((await events("deny-list-upstream")).map((e) => e.kind)).toEqual(["evidence-dismissed"]);
  });
});

/** The live dismissal rows of a package, straight from the registry's database. */
async function liveRows(name: string): Promise<number> {
  const rows = await reg.query("SELECT count(*)::int AS n FROM evidence_dismissals WHERE package = $1 AND restored_at IS NULL", [name]);

  return z.array(z.object({ n: z.number() })).parse(rows)[0]?.n ?? -1;
}

describe("finding 2: a dismissal or an undo and its log entry are one write", () => {
  test("when the log entry cannot be written, the dismissal is not kept and the request fails", async () => {
    expect((await putPublish(reg, alice, { name: "deny-list-tx", version: "1.0.0", license: "MIT", main: "index.js" }, { files: { "index.js": DENY } })).status).toBe(201);
    const item = await credentialItem("deny-list-tx", "1.0.0");
    const r = await dismiss(admin, item, { code: totp(adminSecret) }, { "x-apm-test-fault": "event-insert" });

    expect(r.status).toBe(500);
    expect(dig((await score("deny-list-tx", "1.0.0")).body, "score")).toBe(97);
    expect(dig((await score("deny-list-tx", "1.0.0")).body, "dismissed")).toEqual([]);
    expect(await liveRows("deny-list-tx")).toBe(0);
    expect((await events("deny-list-tx")).filter((e) => e.kind.startsWith("evidence-"))).toEqual([]);
  });

  test("when the log entry cannot be written, the undo is not kept either", async () => {
    const item = await credentialItem("deny-list-tx", "1.0.0");

    expect((await dismiss(admin, item, { code: totp(adminSecret) })).status).toBe(200);
    expect(dig((await score("deny-list-tx", "1.0.0")).body, "score")).toBe(100);
    const r = await restore(admin, item, { code: totp(adminSecret), reason: "Checking the fault." }, { "x-apm-test-fault": "event-insert" });

    expect(r.status).toBe(500);
    expect(dig((await score("deny-list-tx", "1.0.0")).body, "score")).toBe(100);
    expect(await liveRows("deny-list-tx")).toBe(1);
    expect((await events("deny-list-tx")).map((e) => e.kind).filter((k) => k.startsWith("evidence-"))).toEqual(["evidence-dismissed"]);
    // with the log working, the same undo goes through
    expect((await restore(admin, item, { code: totp(adminSecret), reason: "Checking the fault." })).status).toBe(200);
    expect(dig((await score("deny-list-tx", "1.0.0")).body, "score")).toBe(97);
  });
});

describe("finding 3: a dismissed fallback item", () => {
  const FALLBACK = "lib/list.js:3: '.npmrc' [possible: a name in a list, which apm did not see read]";

  test("is listed as dismissed and can be undone", async () => {
    expect((await putPublish(reg, alice, { name: "deny-list-fb", version: "1.0.0", license: "MIT", main: "index.js" }, { files: { "index.js": DENY } })).status).toBe(201);
    // a confirmed signal that also carries possible evidence to fall back to, as the scorer writes one
    await reg.query(
      `UPDATE versions SET score = jsonb_set(score, '{signals}', (
         SELECT jsonb_agg(CASE WHEN s->>'id' = 'credential-mention' THEN s || jsonb_build_object('fallback', jsonb_build_array($3::text)) ELSE s END)
         FROM jsonb_array_elements(score->'signals') s))
       WHERE package = $1 AND version = $2`,
      ["deny-list-fb", "1.0.0", FALLBACK],
    );
    const item = { ...(await credentialItem("deny-list-fb", "1.0.0")), file: "lib/list.js", line: 3 };

    expect((await dismiss(admin, item, { code: totp(adminSecret), reason: "Only a list." })).status).toBe(200);
    const after = await score("deny-list-fb", "1.0.0");

    // the confirmed item still counts; the fallback item is in the history
    expect(dig(after.body, "score")).toBe(97);
    expect(dig(after.body, "dismissed", 0, "file")).toBe("lib/list.js");
    expect(dig(after.body, "dismissed", 0, "reason")).toBe("Only a list.");
    expect((await restore(admin, item, { code: totp(adminSecret), reason: "Undoing a test dismissal." })).status).toBe(200);
    expect(dig((await score("deny-list-fb", "1.0.0")).body, "dismissed")).toEqual([]);
    expect(await liveRows("deny-list-fb")).toBe(0);
  });
});

describe("finding 4: an undo needs a reason", () => {
  test("an undo without a reason is refused, and the log shows both reasons", async () => {
    const item = await credentialItem("deny-list-fb", "1.0.0");

    expect((await dismiss(admin, item, { code: totp(adminSecret), reason: "A deny list." })).status).toBe(200);
    expect((await restore(admin, item, { code: totp(adminSecret) })).status).toBe(400);
    expect((await restore(admin, item, { code: totp(adminSecret), reason: "  " })).status).toBe(400);
    expect(await liveRows("deny-list-fb")).toBe(1);
    expect((await restore(admin, item, { code: totp(adminSecret), reason: "The list is read after all." })).status).toBe(200);
    const undo = (await events("deny-list-fb")).find((e) => e.kind === "evidence-restored" && dig(e.detail, "line") === item.line);

    expect(dig(undo?.detail, "reason")).toBe("The list is read after all.");
    expect(dig(undo?.detail, "dismissal", "reason")).toBe("A deny list.");
    expect(dig(undo?.detail, "dismissal", "by")).toBe("octo-admin");
  });
});
