// The AI review queue for launch: the "AI flags hold installs" switch, read at request time by every verdict path; the
// decision window one second factor opens; bulk dismiss; the public status page's answer; and secrets a model quoted,
// which no view hands out. Reviews are written straight into the database (the reviewer process has its own suite in
// ai-review.test.ts), so each test sets up exactly the flag it needs.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import type { SessionAction } from "../../packages/registry/src/actions.ts";
import { digestLabel, digestOf } from "../../packages/registry/src/digest.ts";
import { dig, enableTotp, getJson, signInWithGitHub, startFakeGitHub, startRegistry, totp, type Browser, type FakeGitHub, type Registry } from "./harness";

const SERVICE_TOKEN = `svc_${randomBytes(24).toString("base64url")}`;
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");
const HOUR = 3_600_000;

// built at run time so no secret-shaped literal sits in the repository
const OPENAI_KEY = ["sk", "proj", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("-");
const MONGO_PASSWORD = ["S3cret", "Passw0rd", "42"].join("");
const SUMMARY = "Hardcodes an OpenAI key and a database password in index.js.";
const ISSUE = "Ships live credentials that anyone installing it can read.";

let reg: Registry;
let gh: FakeGitHub;
let clock = Date.parse("2026-11-18T10:00:00Z");
let alice: string;
let bob: string;
let admin: Browser;
let adminSecret: string;

// ---------- a tar writer (as in ai-review.test.ts) ----------
function tarHeader(path: string, size: number): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string, off: number, len: number): void => h.set(new TextEncoder().encode(s).subarray(0, len), off);

  put(path, 0, 100);
  put("0000644\0", 100, 8);
  put("0000000\0", 108, 8);
  put("0000000\0", 116, 8);
  put(`${size.toString(8).padStart(11, "0")}\0`, 124, 12);
  put("00000000000\0", 136, 12);
  put("        ", 148, 8);
  put("0", 156, 1);
  put("ustar\0", 257, 6);
  put("00", 263, 2);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);

  return h;
}

function tgz(files: Record<string, string>): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const [path, text] of Object.entries(files)) {
    const data = new TextEncoder().encode(text);

    parts.push(tarHeader(`package/${path}`, data.length), data);
    const pad = (512 - (data.length % 512)) % 512;

    if (pad > 0) parts.push(new Uint8Array(pad));
  }

  parts.push(new Uint8Array(1024));

  return Bun.gzipSync(Buffer.concat(parts));
}

async function publish(token: string, name: string, version: string, deps: Record<string, string> = {}): Promise<void> {
  const manifest = { name, version, license: "MIT", main: "index.js", dependencies: deps };
  const bytes = tgz({ "package.json": JSON.stringify(manifest), "index.js": `module.exports = ${JSON.stringify(name)};\n` });

  const body = {
    _id: name,
    name,
    "dist-tags": { latest: version },
    versions: { [version]: manifest },
    _attachments: { [`${name}-${version}.tgz`]: { content_type: "application/octet-stream", data: Buffer.from(bytes).toString("base64"), length: bytes.length } },
  };

  const res = await fetch(`${reg.url}${encodeURIComponent(name)}`, { method: "PUT", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });

  if (res.status !== 201) throw new Error(`publish ${name}@${version}: ${res.status} ${await res.text()}`);
}

/** The digest label a version's review is keyed by. */
async function digestFor(name: string, version: string): Promise<string> {
  const rows = z.array(z.object({ integrity: z.string(), shasum: z.string() })).parse(await reg.query("SELECT integrity, shasum FROM versions WHERE package = $1 AND version = $2", [name, version]));
  const [row] = rows;
  const d = row ? digestOf(row) : null;

  if (!d) throw new Error(`no digest for ${name}@${version}`);

  return digestLabel(d);
}

/** A flag waiting for a person, as the reviewer would have stored it, quoting a key and a connection string. */
async function flag(name: string, version: string, weekly: number | null = null): Promise<string> {
  const digest = await digestFor(name, version);

  const finding = {
    file: "index.js",
    line: 1,
    quote: `apiKey: "${OPENAI_KEY}"`,
    excerpt: `const ai = new OpenAI({ apiKey: "${OPENAI_KEY}" }); mongoose.connect("mongodb://shop:${MONGO_PASSWORD}@db.example.invalid/shop");`,
    issue: `${ISSUE} ${OPENAI_KEY}`,
    severity: "high",
  };

  const result = {
    outcome: "flagged",
    verdict: "suspicious",
    findings: [finding],
    model: "fake-flash",
    reviewedAt: new Date(clock).toISOString(),
    summary: `${SUMMARY} (${OPENAI_KEY})`,
    coverage: { mode: "files", previousVersion: null, filesInScope: 1, filesRead: 1 },
    read: ["index.js"],
    notRead: [],
    attempts: [{ result: "suspicious", kept: 1, dropped: 0, promptTokens: 10, completionTokens: 10, latencyMs: 5 }],
    secondOpinion: null,
  };

  await reg.query(
    `INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, $2, $3, 'flagged', $4::jsonb, $5, 'pending')
     ON CONFLICT (package, version, digest) DO UPDATE SET human_state = 'pending', human_by = NULL, human_at = NULL, human_note = NULL`,
    [name, version, digest, JSON.stringify(result), clock],
  );

  if (weekly !== null) await reg.query("INSERT INTO review_downloads (package, weekly, fetched_at) VALUES ($1, $2, $3) ON CONFLICT (package) DO UPDATE SET weekly = EXCLUDED.weekly", [name, weekly, clock]);

  return digest;
}

const review = (name: string, version: string, token?: string) => getJson(`${reg.url}-/apm/v1/review/${name}/${version}`, token ? { headers: { authorization: `Bearer ${token}` } } : undefined);

const stateOf = async (name: string, version: string): Promise<string | null> => z.string().nullable().parse(dig((await review(name, version)).body, "review", "state") ?? null);

const resolveTree = async (name: string) => {
  const res = await fetch(`${reg.url}-/apm/v1/resolve?name=${name}`);

  return { status: res.status, body: await res.json() };
};

const setSwitch = (b: Browser, hold: boolean, proof: Record<string, string>) => b.json("-/apm/v1/review-admin/switch", { method: "POST", body: { hold, ...proof } });

/** A confirmation the registry issues for one named action from `b`'s session, made with a fresh code. */
async function confirmationFor(b: Browser, action: SessionAction): Promise<string> {
  const r = await b.json("-/apm/v1/factor/confirm", { method: "POST", body: { action, code: totp(adminSecret) } });
  const parsed = z.object({ confirmation: z.string() }).safeParse(r.body);

  if (r.status !== 200 || !parsed.success) throw new Error(`factor/confirm: ${r.status} ${JSON.stringify(r.body)}`);

  return parsed.data.confirmation;
}

beforeAll(async () => {
  gh = startFakeGitHub();
  reg = await startRegistry({ now: () => clock, github: gh, review: { serviceTokenHash: sha256(SERVICE_TOKEN), admins: ["octo-admin"] } });
  alice = await reg.mintToken({ user: "alice", scope: "publish" });
  bob = await reg.mintToken({ user: "bob", scope: "publish" });
  admin = await signInWithGitHub(reg, gh, "octo-admin");
  adminSecret = await enableTotp(admin);
});

afterAll(async () => {
  await reg.stop();
  await gh.stop();
});

describe("AI flags hold installs: the switch", () => {
  test("it changes the verdict paths at request time; confirmed malicious stays refused either way", async () => {
    await publish(alice, "held-dep", "1.0.0");
    await publish(alice, "held-root", "1.0.0", { "held-dep": "^1.0.0" });
    await publish(alice, "evil-dep", "1.0.0");
    clock += 25 * HOUR;
    await flag("held-dep", "1.0.0");

    // the deploy's default: on, so the flag holds, as before
    const q0 = await admin.json("-/apm/v1/review-admin/queue");

    expect(dig(q0.body, "flagsHold", "hold")).toBe(true);
    expect(dig(q0.body, "flagsHold", "source")).toBe("default");
    expect(await stateOf("held-dep", "1.0.0")).toBe("under-review");
    expect(dig((await resolveTree("held-root")).body, "tree", "reviews", "underReview")).toEqual([{ name: "held-dep", version: "1.0.0" }]);

    // a token, a non-admin, no factor, and a code made for the other value all leave it as it is
    expect((await getJson(`${reg.url}-/apm/v1/review-admin/switch`, { method: "POST", headers: { authorization: `Bearer ${bob}`, "content-type": "application/json" }, body: JSON.stringify({ hold: false }) })).status).toBe(403);
    expect((await setSwitch(admin, false, {})).status).toBe(401);
    expect((await setSwitch(admin, false, { confirmation: await confirmationFor(admin, { kind: "review-switch", hold: true }) })).status).toBe(401);
    expect(await stateOf("held-dep", "1.0.0")).toBe("under-review");

    // off: the same rows, no deploy, the next request reads a note
    expect((await setSwitch(admin, false, { code: totp(adminSecret) })).status).toBe(200);
    expect(await stateOf("held-dep", "1.0.0")).toBe("flagged");
    // findings stay withheld from the public either way
    expect(dig((await review("held-dep", "1.0.0")).body, "review", "findings")).toEqual([]);
    const off = await resolveTree("held-root");

    expect(off.status).toBe(200);
    expect(dig(off.body, "tree", "reviews", "underReview")).toEqual([]);
    expect(dig(off.body, "tree", "reviews", "flagged")).toEqual([{ name: "held-dep", version: "1.0.0" }]);
    expect(dig((await getJson(`${reg.url}-/apm/v1/reviews`)).body, "flagsHold")).toBe(false);

    // a person's confirmed-malicious decision is refused by resolve and scan whatever the switch says
    const evil = await flag("evil-dep", "1.0.0");

    await reg.query("UPDATE reviews SET human_state = 'confirmed', human_at = $1 WHERE package = 'evil-dep'", [clock]);
    expect((await resolveTree("evil-dep")).status).toBe(422);
    const scan = await fetch(`${reg.url}-/apm/v1/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: [{ name: "evil-dep", version: "1.0.0" }] }) });

    expect(JSON.stringify(dig(await scan.json(), "advisories"))).toContain("confirmed this version is malicious");

    // on again: the flag holds on the next request
    expect((await setSwitch(admin, true, { code: totp(adminSecret) })).status).toBe(200);
    expect(await stateOf("held-dep", "1.0.0")).toBe("under-review");
    expect(dig((await resolveTree("held-root")).body, "tree", "reviews", "underReview")).toEqual([{ name: "held-dep", version: "1.0.0" }]);
    expect((await resolveTree("evil-dep")).status).toBe(422);
    expect(evil).toStartWith("sha");

    // every change is logged, who and when, next to the decisions
    const q1 = await admin.json("-/apm/v1/review-admin/queue");

    expect(dig(q1.body, "flagsHold", "source")).toBe("set");
    expect(dig(q1.body, "flagsHold", "history")).toEqual([
      { hold: true, by: "octo-admin", at: new Date(clock).toISOString() },
      { hold: false, by: "octo-admin", at: new Date(clock).toISOString() },
    ]);
  });
});

describe("the decision window", () => {
  test("one factor unlocks decisions for this session for 10 minutes; another session, another action or a later time does not", async () => {
    await publish(alice, "window-a", "1.0.0");
    await publish(alice, "window-b", "1.0.0");
    await publish(alice, "window-c", "1.0.0");
    const a = await flag("window-a", "1.0.0");
    const b = await flag("window-b", "1.0.0");
    const c = await flag("window-c", "1.0.0");

    const decide = (who: Browser, name: string, digest: string, extra: Record<string, string> = {}) =>
      who.json("-/apm/v1/review-admin/decide", { method: "POST", body: { name, version: "1.0.0", digest, decision: "dismiss", note: "", ...extra } });

    // locked: a decision without a factor is refused
    expect((await decide(admin, "window-a", a)).status).toBe(401);
    expect(dig((await admin.json("-/apm/v1/review-admin/queue")).body, "unlockedUntil")).toBeNull();

    // a confirmation made for the switch does not open the window (wrong action)
    expect((await admin.json("-/apm/v1/review-admin/unlock", { method: "POST", body: { confirmation: await confirmationFor(admin, { kind: "review-switch", hold: true }) } })).status).toBe(401);

    const opened = await admin.json("-/apm/v1/review-admin/unlock", { method: "POST", body: { code: totp(adminSecret) } });

    expect(opened.status).toBe(200);
    expect(dig(opened.body, "until")).toBe(new Date(clock + 10 * 60_000).toISOString());
    expect(dig((await admin.json("-/apm/v1/review-admin/queue")).body, "unlockedUntil")).toBe(new Date(clock + 10 * 60_000).toISOString());

    // inside the window: no factor per decision
    expect((await decide(admin, "window-a", a)).status).toBe(200);
    expect(await stateOf("window-a", "1.0.0")).toBe("cleared");

    // the window does not cover the switch (wrong action)
    expect((await setSwitch(admin, false, {})).status).toBe(401);

    // another session of the same reviewer has no window (wrong session)
    const other = await signInWithGitHub(reg, gh, "octo-admin");

    expect((await decide(other, "window-b", b)).status).toBe(401);
    expect(dig((await other.json("-/apm/v1/review-admin/queue")).body, "unlockedUntil")).toBeNull();

    // expiry: 10 minutes later the window is gone
    clock += 10 * 60_000;
    expect((await decide(admin, "window-b", b)).status).toBe(401);
    expect(await stateOf("window-b", "1.0.0")).toBe("under-review");

    // a factor sent with one decision still works, as before the window
    expect((await decide(admin, "window-b", b, { code: totp(adminSecret) })).status).toBe(200);

    // locking ends the window at once
    expect((await admin.json("-/apm/v1/review-admin/unlock", { method: "POST", body: { code: totp(adminSecret) } })).status).toBe(200);
    expect((await admin.json("-/apm/v1/review-admin/lock", { method: "POST", body: {} })).status).toBe(200);
    expect((await decide(admin, "window-c", c)).status).toBe(401);
  });

  test("bulk dismiss needs the window, dismisses only open flags and sorts nothing else", async () => {
    await publish(alice, "bulk-a", "1.0.0");
    await publish(alice, "bulk-b", "1.0.0");
    const a = await flag("bulk-a", "1.0.0");
    const b = await flag("bulk-b", "1.0.0");

    const items = [
      { name: "bulk-a", version: "1.0.0", digest: a },
      { name: "bulk-b", version: "1.0.0", digest: b },
    ];

    const bulk = () => admin.json("-/apm/v1/review-admin/dismiss", { method: "POST", body: { items, note: "False positive: checked the diff." } });

    expect((await bulk()).status).toBe(401);
    expect((await admin.json("-/apm/v1/review-admin/unlock", { method: "POST", body: { code: totp(adminSecret) } })).status).toBe(200);
    const done = await bulk();

    expect(done.status).toBe(200);
    expect(dig(done.body, "dismissed")).toBe(2);
    expect(await stateOf("bulk-a", "1.0.0")).toBe("cleared");
    expect(dig((await review("bulk-b", "1.0.0")).body, "review", "note")).toBe("False positive: checked the diff.");
    // already decided: nothing more to dismiss
    expect(dig((await bulk()).body, "dismissed")).toBe(0);
  });
});

describe("the queue, the public status and secrets", () => {
  test("the queue is sorted by weekly downloads, with a one-line summary", async () => {
    await publish(alice, "pop-big", "1.0.0");
    await publish(alice, "pop-small", "1.0.0");
    await flag("pop-small", "1.0.0", 1_000);
    await flag("pop-big", "1.0.0", 207_000_000);
    const q = await admin.json("-/apm/v1/review-admin/queue");
    const pending = dig(q.body, "pending");
    const names = Array.isArray(pending) ? pending.map((p) => dig(p, "name")) : [];

    expect(names.indexOf("pop-big")).toBe(0);
    expect(names.indexOf("pop-small")).toBe(1);
    expect(dig(q.body, "pending", 0, "weeklyDownloads")).toBe(207_000_000);
    expect(dig(q.body, "pending", 0, "summaryLine")).toBe("Hardcodes an OpenAI key and a database password in index.js.");
  });

  test("a quoted key reaches no one unredacted: not the public, the maintainer, the admin queue or Your packages", async () => {
    await publish(alice, "shop", "1.0.0");
    await flag("shop", "1.0.0");
    const secrets = [OPENAI_KEY, MONGO_PASSWORD];
    const owner = await review("shop", "1.0.0", alice);

    expect(dig(owner.body, "viewer")).toBe("maintainer");
    expect(dig(owner.body, "private", "findings", 0, "issue")).toContain(`[redacted, ${OPENAI_KEY.length} chars]`);
    expect(String(dig(owner.body, "private", "findings", 0, "excerpt"))).toContain("mongodb://shop:");

    const alicePackages = await signInWithGitHub(reg, gh, "alice");

    const views = {
      anonymous: await review("shop", "1.0.0"),
      stranger: await review("shop", "1.0.0", bob),
      owner,
      queue: await admin.json("-/apm/v1/review-admin/queue"),
      yourPackages: await alicePackages.json("-/apm/v1/account/packages"),
      status: await getJson(`${reg.url}-/apm/v1/reviews`),
    };

    for (const [who, v] of Object.entries(views)) {
      const text = JSON.stringify(v.body);

      expect(v.status, who).toBe(200);

      for (const s of secrets) expect(text.includes(s), `${who} holds a secret`).toBe(false);
    }

    // the owner sees their own flag on Your packages, with its findings
    const pkgs = dig(views.yourPackages.body, "packages");
    const shop = Array.isArray(pkgs) ? pkgs.find((p) => dig(p, "name") === "shop") : undefined;

    expect(dig(shop, "aiFlags", 0, "version")).toBe("1.0.0");
    expect(dig(shop, "aiFlags", 0, "findings", 0, "line")).toBe(1);
    // the public sees no finding text at all
    expect(dig(views.anonymous.body, "review", "findings")).toEqual([]);
    expect(dig(views.stranger.body, "private")).toBeNull();
  });

  test("the public status has counts and the waiting list, and no finding text", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/reviews`);
    const text = JSON.stringify(r.body);

    expect(r.status).toBe(200);
    expect(Number(dig(r.body, "counts", "waiting"))).toBeGreaterThan(0);
    expect(Number(dig(r.body, "counts", "dismissed"))).toBeGreaterThanOrEqual(4);
    expect(Number(dig(r.body, "counts", "confirmed"))).toBe(1);
    expect(dig(r.body, "waiting", 0, "name")).toBe("pop-big");

    for (const banned of [SUMMARY, ISSUE, "index.js", "apiKey", "mongodb", "fake-flash", "suspicious"]) expect(text.includes(banned), banned).toBe(false);
  });
});
