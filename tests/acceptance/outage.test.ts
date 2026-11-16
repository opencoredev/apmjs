// Installs keep working while Postgres is down, and the block list still holds. The registry Worker runs in workerd
// (Miniflare) with real npm as its upstream and its database behind a link the test cuts (db-link.ts): "hang" accepts
// connections and never answers, "refuse" closes them. Stock npm and bun then install a real npm package through it, a
// version an apm reviewer confirmed malicious is still refused, a package published on apm is refused with a reason
// rather than answered from npm under its name, and every other route says why it cannot answer instead of hanging.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { addUser, dig, getJson, installedVersion, makeSandbox, run, startRegistry, writeConsumer, writePackage, type Registry } from "./harness";

const NPM = "https://registry.npmjs.org/";
const BLOCKLIST_KEY = "state/install-blocklist.json";

/** Installed through the registry during the outage: no dependencies, published years ago. */
const GOOD = { name: "ms", version: "2.1.3" } as const;

/** Marked confirmed malicious for the test (it is not): the registry must refuse it, outage or not. */
const BLOCKED = { name: "ms", version: "2.1.2" } as const;
const LOCAL = "outage-local";

const Blocklist = z.object({
  syncedAt: z.number().nullable(),
  local: z.array(z.object({ name: z.string() })),
  confirmed: z.array(z.object({ name: z.string(), version: z.string(), digest: z.string() })),
});

let reg: Registry;
let work: string;

function link() {
  if (reg.databaseLink === null) throw new Error("the registry was started without a database link");

  return reg.databaseLink;
}

async function blocklist() {
  const text = await reg.blobs.text(BLOCKLIST_KEY);

  return text === null ? null : Blocklist.parse(JSON.parse(text));
}

/** The digest label (digest.ts) of an npm version's tarball, from npm's own document of it. */
async function npmDigest(name: string, version: string): Promise<string> {
  const doc = await getJson(`${NPM}${name}/${version}`);
  const integrity = String(dig(doc.body, "dist", "integrity"));

  return `sha512-${Buffer.from(integrity.slice("sha512-".length), "base64").toString("hex")}`;
}

async function timedGet(path: string, init?: RequestInit): Promise<{ res: Response; ms: number }> {
  const t0 = performance.now();
  const res = await fetch(`${reg.url}${path}`, init);

  return { res, ms: performance.now() - t0 };
}

beforeAll(async () => {
  reg = await startRegistry({ upstream: NPM, databaseLink: true, env: { APM_DB_DOWN_WINDOW_MS: "1500" } });
  work = mkdtempSync(join(tmpdir(), "apm-outage-"));
  const alice = await addUser(reg, "alice");
  const pkg = writePackage(work, { name: LOCAL, version: "1.0.0" }, reg, alice);
  const published = await run(["bun", "publish"], { cwd: pkg, env: makeSandbox(reg, alice).env });

  if (published.code !== 0) throw new Error(`publish failed: ${published.out}`);
  // an apm reviewer's confirmed verdict, written straight to the database: the cron's sync is what carries it to the list
  await reg.query("INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state, human_by, human_at) VALUES ($1, $2, $3, 'flagged', '{}'::jsonb, $4, 'confirmed', 'reviewer', $4)", [
    BLOCKED.name,
    BLOCKED.version,
    await npmDigest(BLOCKED.name, BLOCKED.version),
    Date.now(),
  ]);
}, 120_000);

afterAll(async () => {
  await reg?.stop();
});

describe("the block list in R2", () => {
  test("a first publish puts the package on it before its transaction commits; until the cron syncs it, an outage refuses every install", async () => {
    const before = await blocklist();

    expect(before?.local.map((e) => e.name)).toContain(LOCAL);
    expect(before?.syncedAt).toBeNull();
    link().set("refuse");

    try {
      const { res } = await timedGet(GOOD.name);
      const body = await res.json();

      expect(res.status).toBe(503);
      expect(res.headers.get("x-apm-degraded")).toBe("database-unavailable");
      expect(String(dig(body, "error"))).toContain("block list has not been written from the database yet");
    } finally {
      link().set("up");
    }
  });

  test("the cron's sync writes it from the database: apm's packages and the confirmed versions", async () => {
    // the isolate took the database as down a moment ago; its window is 1.5 s here
    await Bun.sleep(1_600);
    await reg.sweep();
    const list = await blocklist();

    expect(list?.syncedAt).toBeGreaterThan(0);
    expect(list?.local.map((e) => e.name)).toEqual([LOCAL]);
    expect(list?.confirmed.map((c) => `${c.name}@${c.version}`)).toEqual([`${BLOCKED.name}@${BLOCKED.version}`]);
  });
});

describe("a database that answers", () => {
  test("a statement that fails on it is a server error, not an outage: the install route does not answer around it", async () => {
    await reg.query("ALTER TABLE packages RENAME TO packages_renamed_for_test");

    try {
      const res = await fetch(`${reg.url}${GOOD.name}`);

      expect(res.status).toBe(500);
      expect(res.headers.get("x-apm-degraded")).toBeNull();
      await res.arrayBuffer();
    } finally {
      await reg.query("ALTER TABLE packages_renamed_for_test RENAME TO packages");
    }

    // nothing was taken as down: the next request is answered from the database
    const after = await fetch(`${reg.url}${GOOD.name}`);

    expect(after.status).toBe(200);
    expect(after.headers.get("x-apm-degraded")).toBeNull();
    await after.arrayBuffer();
  });
});

for (const mode of ["hang", "refuse"] as const) {
  describe(`while the database ${mode === "hang" ? "accepts connections and never answers" : "refuses connections"}`, () => {
    beforeAll(() => link().set(mode));

    afterAll(async () => {
      link().set("up");
      await Bun.sleep(1_600);
    });

    test("the packument of an npm package is served without scores, and says why", async () => {
      const first = await timedGet(GOOD.name, { headers: { accept: "application/json" } });
      const body = await first.res.json();

      process.stdout.write(`[outage:${mode}] first packument: HTTP ${first.res.status} in ${first.ms.toFixed(0)} ms\n`);
      expect(first.res.status).toBe(200);
      expect(first.res.headers.get("x-apm-degraded")).toBe("database-unavailable");
      expect(first.res.headers.get("x-apm-scores")).toBe("unknown");
      expect(dig(body, "_apmDegraded", "scores")).toBe("unknown");
      expect(dig(body, "versions", GOOD.version, "_apmScore")).toBeUndefined();
      // the confirmed version is not offered at all
      expect(dig(body, "versions", BLOCKED.version)).toBeUndefined();
      expect(String(dig(body, "versions", GOOD.version, "dist", "tarball"))).toStartWith(reg.url);
      // bounded by the connect timeout (3 s), never the client's own
      expect(first.ms).toBeLessThan(6_000);
      const second = await timedGet(GOOD.name, { headers: { accept: "application/vnd.npm.install-v1+json" } });

      process.stdout.write(`[outage:${mode}] next packument: HTTP ${second.res.status} in ${second.ms.toFixed(0)} ms\n`);
      expect(second.res.status).toBe(200);
      // the isolate took the database as down: it does not wait on it again within the window
      expect(second.ms).toBeLessThan(1_500);
      await second.res.arrayBuffer();
    }, 30_000);

    test("npm and bun install a real npm package through the registry", async () => {
      const sb = makeSandbox(reg);
      const npmApp = writeConsumer(work, reg);
      const npm = await run(["npm", "install", "--no-audit", "--no-fund", `${GOOD.name}@${GOOD.version}`], { cwd: npmApp, env: sb.env, timeoutMs: 90_000 });

      process.stdout.write(`[outage:${mode}] npm install ${GOOD.name}@${GOOD.version}: exit ${npm.code}\n`);
      expect(npm.code).toBe(0);
      expect(installedVersion(npmApp, GOOD.name)).toBe(GOOD.version);
      const bunApp = writeConsumer(work, reg);
      const bun = await run(["bun", "add", `${GOOD.name}@${GOOD.version}`], { cwd: bunApp, env: sb.env, timeoutMs: 90_000 });

      process.stdout.write(`[outage:${mode}] bun add ${GOOD.name}@${GOOD.version}: exit ${bun.code}\n`);
      expect(bun.code).toBe(0);
      expect(installedVersion(bunApp, GOOD.name)).toBe(GOOD.version);
    }, 120_000);

    test("a version on the block list is still refused: npm cannot install it and its tarball answers 410", async () => {
      const sb = makeSandbox(reg);
      const app = writeConsumer(work, reg);
      const npm = await run(["npm", "install", "--no-audit", "--no-fund", `${BLOCKED.name}@${BLOCKED.version}`], { cwd: app, env: sb.env, timeoutMs: 90_000 });

      process.stdout.write(`[outage:${mode}] npm install ${BLOCKED.name}@${BLOCKED.version}: exit ${npm.code}\n`);
      expect(npm.code).not.toBe(0);
      expect(installedVersion(app, BLOCKED.name)).toBeNull();
      const tarball = await fetch(`${reg.url}${BLOCKED.name}/-/${BLOCKED.name}-${BLOCKED.version}.tgz`);
      const body = await tarball.json();

      expect(tarball.status).toBe(410);
      expect(dig(body, "confirmed")).toBe(true);
    }, 120_000);

    test("a package published on apm is refused with the reason, never answered from npm under its name", async () => {
      for (const path of [LOCAL, `${LOCAL}/-/${LOCAL}-1.0.0.tgz`]) {
        const { res } = await timedGet(path);
        const body = await res.json();

        expect(res.status).toBe(503);
        expect(res.headers.get("retry-after")).toBe("30");
        expect(String(dig(body, "error"))).toContain("is published on apm");
      }
    });

    test("routes that need the database answer 503 with the reason, at once", async () => {
      for (const path of [`-/apm/v1/packages/${GOOD.name}`, `-/apm/v1/resolve?name=${GOOD.name}`, `~safe/${GOOD.name}`]) {
        const { res, ms } = await timedGet(path);
        const body = await res.json();

        expect(res.status).toBe(503);
        expect(dig(body, "reason")).toBe("database-unavailable");
        expect(ms).toBeLessThan(6_000);
      }
    });

    test("the health check reports the database down and installs working for npm's packages", async () => {
      // an isolate reuses its last answer for 5 s
      await Bun.sleep(5_100);
      const { res } = await timedGet("-/apm/v1/health");
      const body = await res.json();

      process.stdout.write(`[outage:${mode}] health: HTTP ${res.status} ${JSON.stringify(body)}\n`);
      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(dig(body, "status")).toBe("degraded");
      expect(dig(body, "installs")).toBe("npm-only");
      expect(dig(body, "checks", "database", "status")).toBe("down");
      expect(dig(body, "checks", "upstream", "status")).toBe("up");
      expect(dig(body, "checks", "blocklist", "status")).toBe("up");
    }, 15_000);
  });
}

describe("once the database is back", () => {
  test("the registry answers from it again, with scores and apm's own packages", async () => {
    await Bun.sleep(5_200);
    const health = await getJson(`${reg.url}-/apm/v1/health`);

    expect(health.status).toBe(200);
    expect(dig(health.body, "checks", "database", "status")).toBe("up");
    expect(dig(health.body, "installs")).toBe("working");
    const local = await fetch(`${reg.url}${LOCAL}`);

    expect(local.status).toBe(200);
    expect(local.headers.get("x-apm-degraded")).toBeNull();
    await local.arrayBuffer();
    // confirmed malicious, from the database this time
    expect((await fetch(`${reg.url}${BLOCKED.name}/-/${BLOCKED.name}-${BLOCKED.version}.tgz`)).status).toBe(410);
  }, 30_000);
});
