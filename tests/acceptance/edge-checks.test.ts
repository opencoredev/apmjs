// APM_INSTALL_CHECKS=edge (edge-checks.ts) in the bundled Worker, in Miniflare against a local npm. A warm tarball
// redirect and install document of a package only npm has make no database statement; a version confirmed the way the
// review routes confirm it (the block list first, then the database) is refused within the view's 4 s; a first
// publish waits out its fence (8 s, outside any transaction, the transaction then checking again who may publish)
// until no view without its name decides an answer, so when npm gains the same name while the publish runs
// (apm refuses a first publish of a name npm already has), no answer to a request made once the name exists in the
// database is npm's; credentialed requests, ~safe and an unreadable list keep the database path; and a download is
// still queued for analysis after its answer.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { putPublish, startRegistry, type Registry } from "./harness";

const BYTES = new Uint8Array(randomBytes(20_000));
const HEX = createHash("sha512").update(BYTES).digest("hex");
const INTEGRITY = `sha512-${createHash("sha512").update(BYTES).digest("base64")}`;
const INSTALL = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";
const LIST_KEY = "state/install-blocklist.json";

/** EDGE_VIEW_MAX_AGE_MS (edge-checks.ts) and a margin for the request itself. */
const VIEW_MS = 4_000;
const WITHIN_MS = VIEW_MS + 750;

/** FIRST_PUBLISH_HOLD_MS, production's publish fence: the test entry holds none unless TEST_PUBLISH_FENCE_MS asks. */
const FENCE_MS = 8_000;

let npm: ReturnType<typeof Bun.serve>;
let reg: Registry;

/** While true, npm has no packument for ec-late (a first publish's check finds none), though it has its 1.0.0 document. */
let lateHidden = true;

const doc = (name: string, version: string) => ({ name, version, dist: { tarball: `${npm.url}${name}/-/${name}-${version}.tgz`, integrity: INTEGRITY } });

beforeAll(async () => {
  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;
      const m = /^\/(ec-[a-z]+)(?:\/(1\.0\.0))?$/.exec(path);

      if (path === "/ec-late" && lateHidden) return Response.json({ error: "Not found" }, { status: 404 });

      if (m?.[1] && m[2]) return Response.json(doc(m[1], m[2]));

      if (m?.[1]) return Response.json({ name: m[1], "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": doc(m[1], "1.0.0") }, time: { "1.0.0": "2026-10-01T00:00:00.000Z" } });

      if (/^\/ec-[a-z]+\/-\/ec-[a-z]+-1\.0\.0\.tgz$/.test(path)) return new Response(BYTES);

      return Response.json({ error: "Not found" }, { status: 404 });
    },
  });
  reg = await startRegistry({ upstream: npm.url.toString(), upstreamTtlMs: 200, env: { APM_INSTALL_CHECKS: "edge", TEST_PUBLISH_FENCE_MS: String(FENCE_MS) } });
  // the cron's first sync: until then the list says it was never synced, and every request takes the database path
  await reg.sweep();
});

afterAll(async () => {
  await reg.stop();
  await npm.stop(true);
});

const tarballOf = (name: string): string => `${reg.url}${name}/-/${name}-1.0.0.tgz`;

const confirmInDatabase = (name: string) =>
  reg.query(`INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, '1.0.0', $2, 'flagged', '{}', 0, 'confirmed')`, [name, `sha512-${HEX}`]);

const BlockList = z.object({ format: z.literal(1), syncedAt: z.number().nullable(), local: z.array(z.object({ name: z.string(), addedAt: z.number() })), confirmed: z.array(z.unknown()) });

/** Puts a confirmation on the block list, as the review routes do before their commit. */
async function confirmOnList(name: string): Promise<void> {
  const list = BlockList.parse(JSON.parse((await reg.blobs.text(LIST_KEY)) ?? "null"));

  await reg.blobs.put(LIST_KEY, JSON.stringify({ ...list, confirmed: [...list.confirmed, { name, version: "1.0.0", digest: `sha512-${HEX}`, addedAt: Date.now() }] }));
}

type Answer = { status: number; location: string | null; timing: string; versions: string[] };

const Versions = z.object({ versions: z.record(z.string(), z.unknown()) });

/** The versions an install document in `text` lists; none for any other body (a tarball, a redirect's empty body). */
function versionsOf(text: string): string[] {
  try {
    const parsed = Versions.safeParse(JSON.parse(text));

    return parsed.success ? Object.keys(parsed.data.versions) : [];
  } catch {
    return [];
  }
}

async function ask(url: string, init: RequestInit = {}): Promise<Answer> {
  // npm's own client by default, which is redirected; Bun's fetch would be streamed (fast-tarball.ts)
  const headers = new Headers(init.headers);

  if (!headers.has("user-agent")) headers.set("user-agent", "npm/10.9.0 node/v24.11.0 linux x64 workspaces/false");
  const res = await fetch(url, { redirect: "manual", ...init, headers });
  const versions = versionsOf(await res.text());

  return { status: res.status, location: res.headers.get("location"), timing: res.headers.get("server-timing") ?? "", versions };
}

const documentOf = (name: string, init: RequestInit = {}) => ask(`${reg.url}${name}`, { ...init, headers: { accept: INSTALL, ...init.headers } });

/** The first answer `get` gives that `done` accepts, asked every 100 ms for up to `ms`; and how long that took. */
async function until(get: () => Promise<Answer>, done: (a: Answer) => boolean, ms: number): Promise<{ answer: Answer; ms: number }> {
  const start = performance.now();
  let answer = await get();

  while (!done(answer) && performance.now() - start < ms) {
    await Bun.sleep(100);
    answer = await get();
  }

  return { answer, ms: performance.now() - start };
}

describe("install checks answered from the edge view", () => {
  test("a warm tarball redirect and install document make no database statement", async () => {
    // the first request may read the list; the second answers from the view
    for (let i = 0; i < 2; i++) {
      const tarball = await ask(tarballOf("ec-plain"));
      const document = await documentOf("ec-plain");

      expect(tarball.status).toBe(302);
      expect(tarball.location).toBe(`${npm.url}ec-plain/-/ec-plain-1.0.0.tgz`);
      expect(document.versions).toEqual(["1.0.0"]);

      if (i === 1) {
        expect(tarball.timing).toContain("edge;");
        expect(tarball.timing).not.toContain("db;");
        expect(document.timing).not.toContain("db;");
      }
    }
  });

  test("a download is still queued for analysis, after its answer", async () => {
    expect((await ask(tarballOf("ec-queued"))).status).toBe(302);
    const deadline = Date.now() + 5_000;
    let rows = 0;

    while (rows === 0 && Date.now() < deadline) {
      rows = (await reg.query("SELECT 1 FROM analysis_jobs WHERE package = 'ec-queued'")).length;
      await Bun.sleep(100);
    }

    expect(rows).toBe(1);
  });

  test("a version confirmed the way the review routes confirm it is refused within the view's age, tarball and document", async () => {
    expect((await ask(tarballOf("ec-bad"))).status).toBe(302);
    expect((await documentOf("ec-bad")).versions).toEqual(["1.0.0"]);
    await confirmOnList("ec-bad");
    await confirmInDatabase("ec-bad");

    const refused = await until(() => ask(tarballOf("ec-bad")), (a) => a.status === 410, WITHIN_MS + 1_000);

    expect(refused.answer.status).toBe(410);
    expect(refused.ms).toBeLessThan(WITHIN_MS);
    // the database path answered it, and the install document leaves the version out
    expect(refused.answer.timing).toContain("db;");
    expect((await documentOf("ec-bad")).versions).toEqual([]);
  });

  test("a first publish is held, and when npm gains the name meanwhile no request made once it exists here gets npm's answer", async () => {
    const name = "ec-late";

    // npm's tarball, from the edge, while the name is npm's alone (npm's packument is not there yet)
    expect((await ask(tarballOf(name))).status).toBe(302);
    const token = await reg.mintToken({ user: "edge-owner", scope: "publish" });
    const started = performance.now();
    let published = false;

    const publish = putPublish(reg, token, { name, version: "9.9.9" }).then((r) => {
      published = true;

      return { ...r, ms: performance.now() - started };
    });

    // npm gains the name once the publish's check has passed: its packument appears too
    setTimeout(() => {
      lateHidden = false;
    }, 1_000);

    type Sample = { exists: boolean; tarball: Answer; document: Answer };

    const samples: Sample[] = [];
    let after = 0;

    // ask until well after the publish returned: whether the name existed is read before each pair of requests
    while (!published || after++ < 15) {
      const exists = (await reg.query("SELECT 1 FROM packages WHERE name = $1", [name])).length > 0;
      const [tarball, document] = await Promise.all([ask(tarballOf(name)), documentOf(name)]);

      samples.push({ exists, tarball, document });
      await Bun.sleep(50);
    }

    const done = await publish;

    expect(done.status).toBe(201);
    // the fence: 8 s from the name going on the list to the transaction
    expect(done.ms).toBeGreaterThanOrEqual(FENCE_MS);

    const afterCommit = samples.filter((s) => s.exists);
    const npms = afterCommit.filter((s) => s.tarball.status === 302 || s.document.versions.includes("1.0.0"));

    expect(afterCommit.length).toBeGreaterThan(10);
    expect(npms).toEqual([]);
    // the registry's own package from then on
    expect((await documentOf(name)).versions).toEqual(["9.9.9"]);
    // while the publish held, the name was npm's, and both answers came from the edge
    expect(samples.some((s) => !s.exists && s.tarball.status === 302)).toBe(true);
    expect(samples.some((s) => !s.exists && s.document.versions.includes("1.0.0") && !s.document.timing.includes("db;"))).toBe(true);
  }, 30_000);

  test("a first publish waits out its fence outside any transaction, and the transaction checks again who may publish", async () => {
    const name = "fence-race";
    const mine = await reg.mintToken({ user: "fence-owner", scope: "publish" });
    const theirs = await reg.mintToken({ user: "fence-other", scope: "publish" });
    const started = performance.now();
    // two first publishes of one name by two people, at once: both find no package and fence the name

    const both = Promise.all([putPublish(reg, mine, { name, version: "1.0.0" }), putPublish(reg, theirs, { name, version: "2.0.0" })]).then((r) => ({
      statuses: r.map((x) => x.status).toSorted(),
      ms: performance.now() - started,
    }));

    // the fence has begun once the name is on the list
    const listed = async () => BlockList.parse(JSON.parse((await reg.blobs.text(LIST_KEY)) ?? "null")).local.some((e) => e.name === name);
    const deadline = Date.now() + 5_000;

    while (!(await listed()) && Date.now() < deadline) await Bun.sleep(50);
    expect(await listed()).toBe(true);
    await Bun.sleep(1_000);

    // while it waits: no package row, and no transaction open on the database (none holds a lock a retry would wait on)
    expect(await reg.query("SELECT 1 FROM packages WHERE name = $1", [name])).toEqual([]);

    const open = z.array(z.object({ n: z.number() })).parse(
      await reg.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()"),
    );

    expect(open).toEqual([{ n: 0 }]);

    const done = await both;

    // one creates the package; the other's transaction finds it under the package's lock and refuses a non-owner
    expect(done.statuses).toEqual([201, 403]);
    // they waited together, not one after the other
    expect(done.ms).toBeGreaterThanOrEqual(FENCE_MS);
    expect(done.ms).toBeLessThan(FENCE_MS + 4_000);
    expect(await reg.query('SELECT "user" FROM owners WHERE package = $1', [name])).toHaveLength(1);
  }, 30_000);

  test("requests with credentials and ~safe keep the database path", async () => {
    const credentialed = await ask(tarballOf("ec-plain"), { headers: { authorization: "Bearer nobody" } });

    expect(credentialed.status).toBe(200);
    expect(credentialed.timing).toContain("db;");
    expect((await documentOf("ec-plain", { headers: { authorization: "Bearer nobody" } })).versions).toEqual(["1.0.0"]);
    // nothing here is scored, so ~safe shows nothing
    expect((await ask(`${reg.url}~safe/ec-plain/-/ec-plain-1.0.0.tgz`)).status).toBe(404);
  });

  test("an unreadable list sends every request to the database path, never open", async () => {
    await reg.blobs.put(LIST_KEY, "{not json");

    try {
      const fallback = await until(() => ask(tarballOf("ec-plain")), (a) => a.timing.includes("db;"), WITHIN_MS + 1_000);

      expect(fallback.answer.timing).toContain("db;");
      expect(fallback.ms).toBeLessThan(WITHIN_MS);
      // the database path answers as before
      expect(fallback.answer.status).toBe(302);
    } finally {
      await reg.sweep();
    }
  });
});
