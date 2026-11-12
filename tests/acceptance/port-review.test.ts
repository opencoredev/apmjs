// Spec (independent review of the Cloudflare port): each test reproduces a race or a silent failure the
// review found, against the Worker build. Races are forced, not hoped for: a second Postgres connection holds
// the lock the request needs, changes rows while the request waits, then lets it go.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { Client } from "pg";
import { z } from "zod";
import {
  addUser,
  deviceLogin,
  dig,
  enableTotp,
  encodePkg,
  getJson,
  pkgTgz,
  putPublish,
  signInWithGitHub,
  startFakeGitHub,
  startRegistry,
  type Browser,
  type FakeGitHub,
  type RawManifest,
  type Registry,
} from "./harness";

const HOUR = 60 * 60 * 1000;
const StatusRows = z.array(z.object({ status: z.string() }));
const PASSWORD = "correct-horse-battery";
let clock = Date.parse("2026-11-01T00:00:00Z");

/** A second connection to the registry's database, inside a transaction the test commits when it is ready. */
async function openTransaction(reg: Registry): Promise<Client> {
  const c = new Client({ connectionString: reg.databaseUrl });
  await c.connect();
  await c.query("BEGIN");

  return c;
}

async function commit(c: Client): Promise<void> {
  try {
    await c.query("COMMIT");
  } finally {
    await c.end();
  }
}

/** Waits until `count` sessions on this registry's database are waiting for a lock someone else holds. */
async function waitForWaiters(reg: Registry, count = 1): Promise<void> {
  const end = Date.now() + 10_000;

  while (Date.now() < end) {
    const [row] = await reg.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()");

    if (Number(dig(row, "n")) >= count) return;
    await Bun.sleep(20);
  }

  throw new Error(`no request was waiting on a lock after 10s (wanted ${count})`);
}

function post(reg: Registry, path: string, token: string, body: Readonly<Record<string, string>>): Promise<{ status: number; body: unknown }> {
  return getJson(`${reg.url}${path}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
}

// ---------- 1. ownership is checked under the package lock ----------
describe("review 1: an owner removed while a change waits for the package lock cannot finish it", () => {
  let reg: Registry;
  let alice: string;
  let bob: string;
  let bobCi: string;
  const pkg = "owner-race";

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await addUser(reg, "alice", PASSWORD);
    bob = await addUser(reg, "bob", PASSWORD);
    await addUser(reg, "carol", PASSWORD);
    expect((await putPublish(reg, alice, { name: pkg, version: "1.0.0", license: "MIT", main: "index.js" })).status).toBe(201);
    await reg.query(`INSERT INTO owners (package, "user") VALUES ($1, 'bob')`, [pkg]);
    expect((await putPublish(reg, bob, { name: pkg, version: "1.0.1", license: "MIT", main: "index.js" })).status).toBe(201);
    // a publish-scope (CI) token yanks without a second factor, so the yank goes straight to the lock
    bobCi = await reg.mintToken({ user: "bob", scope: "publish" });
  });
  afterAll(async () => {
    await reg?.stop();
  });

  /** Holds the package row, sends `request` as bob, removes bob while it waits, then lets it go. */
  async function racedWithRemoval(request: () => Promise<{ status: number; body: unknown }>): Promise<{ status: number; body: unknown }> {
    await reg.query(`INSERT INTO owners (package, "user") VALUES ($1, 'bob') ON CONFLICT DO NOTHING`, [pkg]);
    const holder = await openTransaction(reg);

    try {
      await holder.query("SELECT name FROM packages WHERE name = $1 FOR UPDATE", [pkg]);
      const pending = request();
      await waitForWaiters(reg);
      await holder.query(`DELETE FROM owners WHERE package = $1 AND "user" = 'bob'`, [pkg]);
      await commit(holder);

      return await pending;
    } catch (e) {
      await holder.query("ROLLBACK").catch(() => {});
      await holder.end().catch(() => {});
      throw e;
    }
  }

  const statusOf = async (version: string): Promise<string | null> =>
    StatusRows.parse(await reg.query("SELECT status FROM versions WHERE package = $1 AND version = $2", [pkg, version]))[0]?.status ?? null;

  test("a yank", async () => {
    const r = await racedWithRemoval(() => post(reg, "-/apm/v1/yank", bobCi, { name: pkg, version: "1.0.0" }));

    expect(r.status, JSON.stringify(r.body)).toBe(403);
    expect(await statusOf("1.0.0")).toBe("active");
  });

  test("an owner change", async () => {
    const r = await racedWithRemoval(() => post(reg, "-/apm/v1/owners", bob, { name: pkg, user: "carol", password: PASSWORD }));

    expect(r.status, JSON.stringify(r.body)).toBe(403);
    const owners = (await reg.query(`SELECT "user" FROM owners WHERE package = $1 ORDER BY "user"`, [pkg])).map((o) => dig(o, "user"));
    expect(owners).toEqual(["alice"]);
  });

  test("an incident response", async () => {
    const since = new Date(clock - HOUR).toISOString();
    const r = await racedWithRemoval(() => post(reg, "-/apm/v1/incident", bob, { since, reason: "laptop stolen", password: PASSWORD }));

    // the response itself goes ahead (bob's tokens are revoked), but a package bob no longer owns is not touched
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(await statusOf("1.0.1")).toBe("active");
  });
});

// ---------- 2, 4. staged blobs and the ~safe alias ----------
describe("review 2 and 4: staged uploads and ~safe aliases", () => {
  let gh: FakeGitHub;
  let reg: Registry;
  let b: Browser;
  let stage: string;

  beforeAll(async () => {
    gh = startFakeGitHub();
    reg = await startRegistry({ now: () => clock, github: gh });
    b = await signInWithGitHub(reg, gh, "racer");
    await enableTotp(b);
    stage = (await deviceLogin(b)).token;
  });
  afterAll(async () => {
    await reg?.stop();
    await gh?.stop();
  });

  test("review 2: expiring a staged upload never deletes the blob a replacement upload of the same bytes just wrote", async () => {
    const manifest: RawManifest = { name: "@racer/blob-race", version: "1.0.0", license: "MIT", main: "index.js" };
    expect((await putPublish(reg, stage, manifest)).status).toBe(202);
    const [key] = await reg.blobs.keys();
    expect(key).toMatch(/^sha512\//);
    clock += 25 * HOUR;

    // the replacement upload writes R2, then waits for the staged-insert lock the test holds
    const holder = await openTransaction(reg);
    let replacement: Promise<{ status: number; body: unknown }>;
    let swept: Promise<void>;

    try {
      await holder.query("SELECT pg_advisory_xact_lock($1)", [0x617_06d_5747]);
      replacement = putPublish(reg, stage, manifest);
      await waitForWaiters(reg);
      // the cron expires the first upload meanwhile; give it time to finish if nothing stops it
      swept = reg.sweep();
      await Bun.sleep(750);
    } finally {
      await commit(holder);
    }

    expect((await replacement).status).toBe(202);
    await swept;
    const rows = await reg.query("SELECT status, tarball_key FROM staged WHERE package = $1 ORDER BY staged_at", [manifest.name]);
    expect(rows.map((r) => dig(r, "status"))).toEqual(["expired", "pending"]);
    expect(await reg.blobs.keys()).toContain(String(key));
  });

  test("review 4: per-user answers reached through /~safe/ are private, no-store", async () => {
    for (const path of ["~safe/-/apm/v1/account", "~safe/-/apm/v1/staged"]) {
      const res = await b.fetch(path);

      expect(res.status, path).toBe(200);
      expect(res.headers.get("cache-control"), path).toBe("private, no-store");
      expect(res.headers.get("vary") ?? "", path).toMatch(/Cookie/);
    }

    const who = await fetch(`${reg.url}~safe/-/whoami`, { headers: { authorization: `Bearer ${stage}` } });
    expect(who.status).toBe(200);
    expect(who.headers.get("cache-control")).toBe("private, no-store");
    expect(who.headers.get("vary") ?? "").toMatch(/Authorization/);
  });
});

// ---------- 6, 8. the stored manifest and the stored bytes ----------
describe("review 6 and 8: what a local publish stores is what gets checked", () => {
  let reg: Registry;
  let alice: string;

  beforeAll(async () => {
    reg = await startRegistry({ now: () => clock });
    alice = await reg.mintToken({ user: "alice", scope: "publish" });
  });
  afterAll(async () => {
    await reg?.stop();
  });

  test("review 6: a tarball package.json over 1 MB is refused even when the request's manifest is small", async () => {
    const small: RawManifest = { name: "manifest-cap", version: "1.0.0", license: "MIT", main: "index.js" };
    const tgz = pkgTgz({ ...small, description: "x".repeat(2 * 1024 * 1024) });

    const body = {
      _id: small.name,
      name: small.name,
      "dist-tags": { latest: small.version },
      versions: { [small.version]: small },
      _attachments: { [`${small.name}-${small.version}.tgz`]: { content_type: "application/octet-stream", data: Buffer.from(tgz).toString("base64"), length: tgz.length } },
    };

    const r = await getJson(`${reg.url}${encodePkg(small.name)}`, { method: "PUT", headers: { "content-type": "application/json", authorization: `Bearer ${alice}` }, body: JSON.stringify(body) });

    expect(r.status, JSON.stringify(r.body).slice(0, 300)).toBe(413);
    expect(await reg.query("SELECT 1 FROM versions WHERE package = $1", [small.name])).toEqual([]);
  });

  test("review 8: a local tarball whose stored bytes changed is not served", async () => {
    const manifest: RawManifest = { name: "local-integrity", version: "1.0.0", license: "MIT", main: "index.js" };
    expect((await putPublish(reg, alice, manifest)).status).toBe(201);
    const url = `${reg.url}local-integrity/-/local-integrity-1.0.0.tgz`;
    expect((await fetch(url)).status).toBe(200);
    const [row] = await reg.query("SELECT tarball_key FROM versions WHERE package = $1", [manifest.name]);
    await reg.blobs.put(String(dig(row, "tarball_key")), "CHANGED_AFTER_PUBLISH");

    const res = await fetch(url);
    const text = await res.text();

    expect(text).not.toContain("CHANGED_AFTER_PUBLISH");
    expect(res.status).toBeGreaterThanOrEqual(500);
  });
});

// ---------- 7. analysis failures that may pass are retried ----------
describe("review 7: a transient analysis failure is retried, not recorded as done", () => {
  type Served = { bytes: Uint8Array; status: number; downloads: number };

  const tarballs = new Map<string, Served>();
  let npm: ReturnType<typeof Bun.serve>;
  let reg: Registry;

  const tgzOf = (name: string, files: Record<string, string>): Uint8Array => pkgTgz({ name, version: "1.0.0", license: "MIT", main: "index.js" }, files);

  beforeAll(async () => {
    tarballs.set("flaky-tarball", { bytes: tgzOf("flaky-tarball", { "index.js": "module.exports = 1;\n" }), status: 503, downloads: 0 });
    // over the inline limit (4 MB compressed): scored only on the queue
    tarballs.set("big-tarball", { bytes: tgzOf("big-tarball", { "index.js": "module.exports = 1;\n", "data.txt": randomBytes(4 * 1024 * 1024).toString("base64") }), status: 200, downloads: 0 });
    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const u = new URL(req.url);
        const tar = /^\/([^/]+)\/-\/[^/]+\.tgz$/.exec(u.pathname);
        const served = tarballs.get(tar?.[1] ?? decodeURIComponent(u.pathname.slice(1)));

        if (!served) return Response.json({ error: "Not found" }, { status: 404 });

        if (tar) {
          served.downloads++;

          return served.status === 200 ? new Response(served.bytes) : new Response("upstream busy", { status: served.status });
        }

        const name = decodeURIComponent(u.pathname.slice(1));

        const dist = {
          tarball: `${npm.url.toString()}${name}/-/${name}-1.0.0.tgz`,
          shasum: createHash("sha1").update(served.bytes).digest("hex"),
          integrity: `sha512-${createHash("sha512").update(served.bytes).digest("base64")}`,
        };

        return Response.json({
          name,
          "dist-tags": { latest: "1.0.0" },
          versions: { "1.0.0": { name, version: "1.0.0", main: "index.js", dist } },
          time: { "1.0.0": "2026-10-01T00:00:00Z" },
        });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: npm.url.toString(), upstreamTtlMs: 0 });
  });
  afterAll(async () => {
    await reg?.stop();
    await npm?.stop(true);
  });

  test("an upstream 503 on the tarball asks the queue to retry, and the retry scores it", async () => {
    expect(await reg.analysisJob({ name: "flaky-tarball", version: "1.0.0" })).toBe("retry");
    const flaky = tarballs.get("flaky-tarball");

    if (!flaky) throw new Error("fixture missing");
    expect(flaky.downloads).toBe(1);
    flaky.status = 200;
    expect(await reg.analysisJob({ name: "flaky-tarball", version: "1.0.0" })).toBe("ack");
    const score = await getJson(`${reg.url}-/apm/v1/score/flaky-tarball/1.0.0`);
    expect(score.status, JSON.stringify(score.body)).toBe(200);
  });

  test("a job the queue refused is not reserved, so the next request queues it", async () => {
    const reserved = async (): Promise<number> => (await reg.query("SELECT 1 FROM analysis_jobs WHERE package = 'big-tarball'")).length;
    const first = await getJson(`${reg.url}-/apm/v1/score/big-tarball/1.0.0`, { headers: { "x-apm-test-queue": "fail" } });

    expect(first.status, JSON.stringify(first.body)).toBe(503);
    expect(await reserved()).toBe(0);
    const second = await getJson(`${reg.url}-/apm/v1/score/big-tarball/1.0.0`);
    expect(second.status).toBe(503);
    expect(await reserved()).toBe(1);
  });
});
