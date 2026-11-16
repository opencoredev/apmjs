// The install packument of a package only npm has (the abbreviated document npm, pnpm and bun install from) is kept in
// the data center's cache and answers the next requests while it is current, so a repeat install does not read npm's
// packument again. "Current" is checked on every request: a version an apm reviewer confirms malicious, or one they
// clear, shows on the very next request; within the TTL npm is not asked; past it npm is asked whether its packument
// changed (If-None-Match), and its 304 keeps the copy while its 200 replaces it. Runs the bundled Worker in Miniflare,
// whose Cache API works as in production, against a local npm that sends ETags as npm's edge does (weak, compressed).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { z } from "zod";
import { getJson, startRegistry, type Registry } from "./harness";

const TTL = 2_000;
const MINUTE = 60_000;

/** How far the registry's clock is ahead of the wall's: the copy's age is counted on it (KEPT_CHOICES_MAX_AGE_MS). */
let ahead = 0;

/** Weekly downloads npm reports, per package: the AI review looks at new versions of popular ones. */
const downloads = new Map<string, number>();

/** How long npm takes to answer, per package (ms); and packages whose answer npm holds until the test lets it go. */
const delayed = new Map<string, number>();
const gates = new Map<string, { arrived: () => void; release: Promise<void> }>();

/** A hold on npm's answers for one package: `arrived` settles once npm has been asked, `open` lets the answer go. */
type Gate = { readonly arrived: Promise<void>; readonly open: () => void };

/** Holds npm's next answers for `name` until `open` is called. */
function gate(name: string): Gate {
  let open = (): void => undefined;
  let arrived = (): void => undefined;
  const release = new Promise<void>((r) => (open = r));
  const asked = new Promise<void>((r) => (arrived = r));

  gates.set(name, { arrived, release });

  return {
    arrived: asked,
    open: () => {
      gates.delete(name);
      open();
    },
  };
}

const INSTALL = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

/** The versions npm lists now, per package; what npm was asked, per package: plain reads and conditional ones. */
const listed = new Map<string, string[]>();
const asked = new Map<string, { plain: number; conditional: number; notModified: number }>();
let npm: ReturnType<typeof Bun.serve>;
let reg: Registry;

const integrityOf = (name: string, v: string): string => `sha512-${createHash("sha512").update(`${name}@${v}`).digest("base64")}`;

function packument(name: string, versions: readonly string[]): string {
  return JSON.stringify({
    name,
    "dist-tags": { latest: versions.at(-1) },
    versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, exports: { ".": "./index.js" }, dist: { tarball: `${npm.url}${name}/-/${name}-${v}.tgz`, integrity: integrityOf(name, v) } }])),
    time: Object.fromEntries(versions.map((v, i) => [v, `2026-11-0${i + 1}T00:00:00.000Z`])),
  });
}

beforeAll(async () => {
  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const u = new URL(req.url);
      const dl = /^\/downloads\/point\/last-week\/(.+)$/.exec(u.pathname);

      if (dl?.[1]) {
        const n = downloads.get(decodeURIComponent(dl[1]));

        return n === undefined ? new Response("{}", { status: 404 }) : Response.json({ downloads: n, package: dl[1] });
      }

      const name = decodeURIComponent(u.pathname.slice(1));
      const held = gates.get(name);

      if (held) {
        held.arrived();
        await held.release;
      }

      const delay = delayed.get(name);

      if (delay !== undefined) await Bun.sleep(delay);
      const versions = listed.get(name);

      if (!versions) return Response.json({ error: "Not found" }, { status: 404 });
      const text = packument(name, versions);
      const etag = `W/"${createHash("md5").update(text).digest("hex")}"`;
      const count = asked.get(name) ?? { plain: 0, conditional: 0, notModified: 0 };
      asked.set(name, count);
      const sent = req.headers.get("if-none-match");

      if (sent === null) count.plain++;
      else count.conditional++;

      if (sent === etag) {
        count.notModified++;

        return new Response(null, { status: 304, headers: { etag } });
      }

      return new Response(text, { headers: { "content-type": "application/json", etag } });
    },
  });
  reg = await startRegistry({
    now: () => Date.now() + ahead,
    upstream: npm.url.toString(),
    upstreamTtlMs: TTL,
    review: { serviceTokenHash: createHash("sha256").update("install-copy-reviewer").digest("hex"), admins: ["octo-admin"], downloadsUrl: `${npm.url}downloads/point/last-week/` },
  });
});

afterAll(async () => {
  await reg.stop();
  await npm.stop(true);
});

const Install = z.object({ "dist-tags": z.record(z.string(), z.string()), versions: z.record(z.string(), z.looseObject({ dist: z.object({ tarball: z.string(), integrity: z.string() }) })) });

/** The install packument apm serves for `name` now: its versions, and each one's integrity. */
async function install(name: string, headers: Readonly<Record<string, string>> = {}): Promise<{ status: number; versions: string[]; integrity: Record<string, string>; latest: string | undefined }> {
  const res = await getJson(`${reg.url}${name}`, { headers: { accept: INSTALL, ...headers } });
  const doc = Install.safeParse(res.body);

  if (res.status !== 200 || !doc.success) return { status: res.status, versions: [], integrity: {}, latest: undefined };

  return {
    status: res.status,
    versions: Object.keys(doc.data.versions).sort(),
    integrity: Object.fromEntries(Object.entries(doc.data.versions).map(([v, d]) => [v, d.dist.integrity])),
    latest: doc.data["dist-tags"].latest,
  };
}

const counts = (name: string) => asked.get(name) ?? { plain: 0, conditional: 0, notModified: 0 };

const confirm = (name: string, version: string, state: "confirmed" | "dismissed") =>
  reg.query(
    `INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state, human_by, human_at) VALUES ($1, $2, $3, 'flagged', '{}'::jsonb, 0, $4, 'reviewer', 0)
     ON CONFLICT (package, version, digest) DO UPDATE SET human_state = $4`,
    [name, version, `sha512-${createHash("sha512").update(`${name}@${version}`).digest("hex")}`, state],
  );

describe("the install packument's copy", () => {
  test("answers a repeat install without reading npm's packument again, and asks npm only past the TTL", async () => {
    const name = "copy-lib";
    listed.set(name, ["1.0.0", "1.1.0"]);
    const first = await install(name);

    expect(first).toMatchObject({ status: 200, versions: ["1.0.0", "1.1.0"], latest: "1.1.0" });
    expect(first.integrity["1.1.0"]).toBe(integrityOf(name, "1.1.0"));
    // the copy is written after the response
    await Bun.sleep(300);
    expect(await install(name)).toEqual(first);
    expect(counts(name)).toEqual({ plain: 1, conditional: 0, notModified: 0 });

    // past the TTL: one conditional read, npm's 304, and the same answer
    await Bun.sleep(TTL + 200);
    expect(await install(name)).toEqual(first);
    expect(counts(name)).toEqual({ plain: 1, conditional: 1, notModified: 1 });
    // that 304 holds for the TTL in this isolate
    expect(await install(name)).toEqual(first);
    expect(counts(name).conditional).toBe(1);
  }, 30_000);

  test("a version confirmed malicious is gone on the very next request, and back once the flag is dismissed", async () => {
    const name = "copy-blocked";
    listed.set(name, ["1.0.0", "2.0.0"]);
    expect((await install(name)).versions).toEqual(["1.0.0", "2.0.0"]);
    await Bun.sleep(300);

    await confirm(name, "2.0.0", "confirmed");
    const blocked = await install(name);

    expect(blocked.versions).toEqual(["1.0.0"]);
    // latest moves back to the newest version served
    expect(blocked.latest).toBe("1.0.0");
    await Bun.sleep(300);
    expect((await install(name)).versions).toEqual(["1.0.0"]);

    await confirm(name, "2.0.0", "dismissed");
    expect(await install(name)).toMatchObject({ versions: ["1.0.0", "2.0.0"], latest: "2.0.0" });
  }, 30_000);

  test("a version npm publishes shows once the TTL has passed", async () => {
    const name = "copy-new";
    listed.set(name, ["1.0.0"]);
    expect((await install(name)).versions).toEqual(["1.0.0"]);
    await Bun.sleep(300);
    listed.set(name, ["1.0.0", "1.0.1"]);
    // within the TTL npm is trusted as it was
    expect((await install(name)).versions).toEqual(["1.0.0"]);
    await Bun.sleep(TTL + 200);
    // npm's 200 to the conditional read replaces the copy
    expect((await install(name)).versions).toEqual(["1.0.0", "1.0.1"]);
    expect(counts(name)).toMatchObject({ plain: 1, conditional: 1, notModified: 0 });
    await Bun.sleep(300);
    expect((await install(name)).versions).toEqual(["1.0.0", "1.0.1"]);
    expect(counts(name)).toMatchObject({ plain: 1, conditional: 1 });
  }, 30_000);

  test("a package npm removes is 404 past the TTL, not its old copy", async () => {
    const name = "copy-gone";
    listed.set(name, ["1.0.0"]);
    expect((await install(name)).status).toBe(200);
    await Bun.sleep(300);
    listed.delete(name);
    await Bun.sleep(TTL + 200);
    expect((await install(name)).status).toBe(404);
  }, 30_000);

  // review of 7479593, finding 1: copies and 304s kept npm's packument from being read whole for the copy's whole day,
  // and what a whole read runs with it (the AI review's look at new versions) with it, so an enqueue that failed was
  // not tried again; the old path tried at the next read past the TTL
  test("a copy answers for at most an hour from npm's whole read, a 304 does not make it younger, and the read then runs the review", async () => {
    const name = "copy-review";
    listed.set(name, ["1.0.0"]);
    downloads.set(name, 50_000);
    const jobs = async (): Promise<number> => (await reg.query("SELECT 1 FROM review_jobs WHERE package = $1", [name])).length;

    // a fault only this package's job hits: the insert into review_jobs fails
    await reg.query(
      `CREATE FUNCTION apm_test_refuse_copy_job() RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN IF NEW.package = 'copy-review' THEN RAISE EXCEPTION 'test: enqueue refused'; END IF; RETURN NEW; END $$`,
    );
    await reg.query("CREATE TRIGGER apm_test_refuse_copy_job BEFORE INSERT ON review_jobs FOR EACH ROW EXECUTE FUNCTION apm_test_refuse_copy_job()");

    try {
      expect((await install(name)).status).toBe(200);
      // the review's policy runs after the response: it reads the download count, then tries to queue the job

      for (let i = 0; i < 50 && (await reg.query("SELECT 1 FROM review_downloads WHERE package = $1", [name])).length === 0; i++) await Bun.sleep(100);
      await Bun.sleep(500);
      expect(await jobs()).toBe(0);
    } finally {
      await reg.query("DROP TRIGGER apm_test_refuse_copy_job ON review_jobs");
      await reg.query("DROP FUNCTION apm_test_refuse_copy_job()");
    }

    // 40 minutes on: npm's 304 keeps the copy, and nothing is read whole
    ahead += 40 * MINUTE;
    await Bun.sleep(TTL + 200);
    expect((await install(name)).versions).toEqual(["1.0.0"]);
    expect(counts(name)).toEqual({ plain: 1, conditional: 1, notModified: 1 });

    // 65 minutes after the whole read, 25 after the 304: read whole again, and the review is queued
    ahead += 25 * MINUTE;
    await Bun.sleep(TTL + 200);
    expect((await install(name)).versions).toEqual(["1.0.0"]);
    expect(counts(name)).toEqual({ plain: 2, conditional: 1, notModified: 1 });

    for (let i = 0; i < 50 && (await jobs()) === 0; i++) await Bun.sleep(100);
    expect(await jobs()).toBe(1);
  }, 60_000);

  // review of 7479593, finding 2: a request with credentials made the copy that every later request read
  test("a request with credentials neither writes the shared copy nor reads it", async () => {
    const name = "copy-private";
    listed.set(name, ["1.0.0", "1.0.1"]);

    // an Authorization header, even one that names no token: answered, and no copy written
    expect((await install(name, { authorization: "Bearer not-a-token" })).versions).toEqual(["1.0.0", "1.0.1"]);
    await Bun.sleep(300);
    await Bun.sleep(TTL + 200);
    // so past the TTL an anonymous install reads npm whole, not conditionally from a copy
    expect((await install(name)).versions).toEqual(["1.0.0", "1.0.1"]);
    expect(counts(name)).toEqual({ plain: 2, conditional: 0, notModified: 0 });

    // that anonymous install wrote one; a request with a cookie does not read it
    await Bun.sleep(300);
    await Bun.sleep(TTL + 200);
    expect((await install(name, { cookie: "session=abc" })).versions).toEqual(["1.0.0", "1.0.1"]);
    expect(counts(name)).toEqual({ plain: 3, conditional: 0, notModified: 0 });
    // and an anonymous one still does
    await Bun.sleep(TTL + 200);
    expect((await install(name)).versions).toEqual(["1.0.0", "1.0.1"]);
    expect(counts(name)).toMatchObject({ plain: 3, conditional: 1 });
  }, 60_000);

  // re-check of fa220f7, finding 1: an expired copy was made again from the packument this isolate held, without a
  // whole read, and the remade copy was dated as new; the AI review's look did not run and the deadline moved
  test("past the hour, npm's packument is read whole even while this isolate holds it within the TTL, and the copy made of it is not dated younger", async () => {
    const name = "copy-clock";
    listed.set(name, ["1.0.0"]);
    downloads.set(name, 50_000);
    const jobs = async (): Promise<number> => (await reg.query("SELECT 1 FROM review_jobs WHERE package = $1", [name])).length;

    await reg.query(
      `CREATE FUNCTION apm_test_refuse_clock_job() RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN IF NEW.package = 'copy-clock' THEN RAISE EXCEPTION 'test: enqueue refused'; END IF; RETURN NEW; END $$`,
    );
    await reg.query("CREATE TRIGGER apm_test_refuse_clock_job BEFORE INSERT ON review_jobs FOR EACH ROW EXECUTE FUNCTION apm_test_refuse_clock_job()");

    try {
      expect((await install(name)).status).toBe(200);

      for (let i = 0; i < 50 && (await reg.query("SELECT 1 FROM review_downloads WHERE package = $1", [name])).length === 0; i++) await Bun.sleep(100);
      await Bun.sleep(500);
      expect(await jobs()).toBe(0);
    } finally {
      await reg.query("DROP TRIGGER apm_test_refuse_clock_job ON review_jobs");
      await reg.query("DROP FUNCTION apm_test_refuse_clock_job()");
    }

    // 65 minutes on by the registry's clock, at once by the wall's: the copy, this isolate's packument and the shared
    // copy are all within the TTL, and all older than the hour
    ahead += 65 * MINUTE;
    expect((await install(name)).versions).toEqual(["1.0.0"]);
    expect(counts(name)).toEqual({ plain: 2, conditional: 0, notModified: 0 });

    for (let i = 0; i < 50 && (await jobs()) === 0; i++) await Bun.sleep(100);
    expect(await jobs()).toBe(1);

    // the copy made of that read answers at once, and counts from it: an hour and a minute on, read whole again
    await Bun.sleep(300);
    expect((await install(name)).versions).toEqual(["1.0.0"]);
    expect(counts(name).plain).toBe(2);
    ahead += 61 * MINUTE;
    expect((await install(name)).versions).toEqual(["1.0.0"]);
    expect(counts(name).plain).toBe(3);
  }, 60_000);
});

// re-check of fa220f7, finding 2: an upstream TTL longer than the hour kept the install path from reading npm whole
describe("the install packument's copy under a two-hour upstream TTL", () => {
  let longReg: Registry;
  let longAhead = 0;

  beforeAll(async () => {
    longReg = await startRegistry({ now: () => Date.now() + longAhead, upstream: npm.url.toString(), upstreamTtlMs: 2 * 60 * MINUTE });
  });

  afterAll(async () => {
    await longReg.stop();
  });

  test("npm's packument is read whole an hour after the last whole read, though every cache is within its TTL", async () => {
    const name = "copy-long-ttl";
    listed.set(name, ["1.0.0"]);
    const ask = async (): Promise<number> => (await getJson(`${longReg.url}${name}`, { headers: { accept: INSTALL } })).status;

    expect(await ask()).toBe(200);
    await Bun.sleep(300);
    // within the hour the copy answers
    longAhead += 30 * MINUTE;
    expect(await ask()).toBe(200);
    expect(counts(name)).toEqual({ plain: 1, conditional: 0, notModified: 0 });
    // past it npm is read whole, and the copy made of that read answers after
    longAhead += 31 * MINUTE;
    expect(await ask()).toBe(200);
    expect(counts(name)).toEqual({ plain: 2, conditional: 0, notModified: 0 });
    await Bun.sleep(300);
    expect(await ask()).toBe(200);
    expect(counts(name).plain).toBe(2);
  }, 60_000);

  // re-check of 977b103, finding 1: a read time from the future was taken for a whole read, by the shared copies and
  // the isolate's cache alike, so with a long TTL nothing was read whole again
  test("a shared copy whose read time is in the future is not taken for a whole read", async () => {
    const name = "copy-future";
    listed.set(name, ["1.0.0"]);
    const ask = async (): Promise<number> => (await getJson(`${longReg.url}${name}`, { headers: { accept: INSTALL } })).status;

    await longReg.seedUpstreamCache({ url: `${npm.url}${name}`, packument: packument(name, ["1.0.0"]), fetchedAt: Date.now(), readAt: Date.now() + longAhead + 24 * 60 * MINUTE });
    expect(await ask()).toBe(200);
    // npm read whole, the copy dated tomorrow passed over
    expect(counts(name).plain).toBe(1);
    await Bun.sleep(300);
    longAhead += 65 * MINUTE;
    expect(await ask()).toBe(200);
    expect(counts(name).plain).toBe(2);
  }, 60_000);
});

// re-check of 977b103, finding 2: two installs at the hour each read npm's packument whole
describe("the install packument's copy at the hour", () => {
  test("two installs at once in one isolate make one whole read of npm", async () => {
    const name = "copy-burst";
    listed.set(name, ["1.0.0", "1.0.1"]);
    expect((await install(name)).status).toBe(200);
    await Bun.sleep(300);
    delayed.set(name, 400);
    ahead += 61 * MINUTE;

    try {
      const [a, b] = await Promise.all([install(name), install(name)]);

      expect([a.status, b.status]).toEqual([200, 200]);
      expect(a.versions).toEqual(["1.0.0", "1.0.1"]);
      expect(b.versions).toEqual(["1.0.0", "1.0.1"]);
    } finally {
      delayed.delete(name);
    }

    expect(counts(name)).toEqual({ plain: 2, conditional: 0, notModified: 0 });
  }, 60_000);
});

// re-check of 977b103, finding 3: the database taken as down after this request read the confirmed set (by another
// request, while this one waited on npm) did not stop it serving the copy or writing one
describe("the install packument's copy when the database goes down mid-request", () => {
  let linked: Registry;
  const LINK_TTL = 2_000;

  beforeAll(async () => {
    linked = await startRegistry({ upstream: npm.url.toString(), upstreamTtlMs: LINK_TTL, databaseLink: true, env: { APM_DB_DOWN_WINDOW_MS: "1500" } });
    // the cron writes the block list, which the degraded route needs
    await linked.sweep();
  });

  afterAll(async () => {
    await linked.stop();
  });

  const link = () => {
    if (linked.databaseLink === null) throw new Error("no database link");

    return linked.databaseLink;
  };

  const get = (name: string): Promise<Response> => fetch(`${linked.url}${name}`, { headers: { accept: INSTALL } });

  /** Cuts the database, and has another request find it unreachable, so the isolate takes it as down. */
  async function breakerOpens(): Promise<void> {
    link().set("refuse");
    await (await get("breaker-trigger")).arrayBuffer();
  }

  async function backUp(): Promise<void> {
    link().set("up");
    await Bun.sleep(1_600);
  }

  test("a copy is not served once the database is taken as down: the degraded route answers", async () => {
    const name = "copy-mid";
    listed.set(name, ["1.0.0"]);
    await (await get(name)).arrayBuffer();
    await Bun.sleep(300);
    // past the TTL the copy is checked with npm: npm holds that check while the database goes down
    await Bun.sleep(LINK_TTL + 200);
    const held = gate(name);
    const pending = get(name);

    await held.arrived;
    await breakerOpens();
    held.open();
    const res = await pending;

    try {
      expect(res.headers.get("x-apm-degraded")).toBe("database-unavailable");
      await res.arrayBuffer();
    } finally {
      await backUp();
    }
  }, 60_000);

  test("no copy is written by a request that finds the database down after it read npm", async () => {
    const name = "copy-mid-miss";
    listed.set(name, ["1.0.0"]);
    const held = gate(name);
    const pending = get(name);

    await held.arrived;
    await breakerOpens();
    held.open();
    const res = await pending;

    try {
      expect(res.headers.get("x-apm-degraded")).toBe("database-unavailable");
      await res.arrayBuffer();
    } finally {
      await backUp();
    }

    // no copy: past the TTL npm's packument is read whole, not checked against a copy's ETag
    await Bun.sleep(LINK_TTL + 200);
    expect((await get(name)).status).toBe(200);
    expect(counts(name)).toMatchObject({ plain: 2, conditional: 0 });
  }, 60_000);
});
