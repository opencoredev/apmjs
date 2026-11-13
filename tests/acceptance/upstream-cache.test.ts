// npm metadata is trusted for one TTL in total, counted from when npm answered, however many cache layers it passed
// through. A packument another isolate left in the shared Cache API near the end of its TTL must not get a fresh TTL in
// this isolate's memory. Runs the bundled Worker in Miniflare, whose Cache API works as in production, against a local npm.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { startRegistry, getJson, type Registry } from "./harness";

const TTL = 10_000;

/** The versions npm lists now, per package, and how often npm was asked for each. */
const listed = new Map<string, string[]>();
const asked = new Map<string, number>();
let npm: ReturnType<typeof Bun.serve>;
let reg: Registry;

function packument(name: string, versions: readonly string[]): string {
  const integrity = `sha512-${Buffer.alloc(64).toString("base64")}`;

  return JSON.stringify({
    name,
    "dist-tags": { latest: versions.at(-1) },
    versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dist: { tarball: `${npm.url}${name}/-/${name}-${v}.tgz`, integrity } }])),
    time: Object.fromEntries(versions.map((v, i) => [v, `2026-11-0${i + 1}T00:00:00.000Z`])),
  });
}

beforeAll(async () => {
  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const name = decodeURIComponent(new URL(req.url).pathname.slice(1));
      const versions = listed.get(name);

      if (!versions) return Response.json({ error: "Not found" }, { status: 404 });
      asked.set(name, (asked.get(name) ?? 0) + 1);

      return new Response(packument(name, versions), { headers: { "content-type": "application/json" } });
    },
  });
  reg = await startRegistry({ upstream: npm.url.toString(), upstreamTtlMs: TTL });
});

afterAll(async () => {
  await reg.stop();
  await npm.stop(true);
});

const Packument = z.object({ versions: z.record(z.string(), z.unknown()) });

/**
 * The versions apm serves for `name` now, in the abbreviated packument installs read. The full one also reads each
 * version's devDependencies under a cache key of its own (upstream.ts, DEV_DEPENDENCIES), which these copies do not
 * seed, so it would ask npm once more.
 */
async function versionsOf(name: string): Promise<string[]> {
  const res = await getJson(`${reg.url}${name}`, { headers: { accept: "application/vnd.npm.install-v1+json" } });
  const doc = Packument.safeParse(res.body);

  return res.status === 200 && doc.success ? Object.keys(doc.data.versions).sort() : [];
}

/** npm's answer for `name`, put in the shared cache as another isolate would have `age` ms ago (null: with no time). */
async function seed(input: { name: string; versions: readonly string[]; age: number | null }): Promise<void> {
  await reg.seedUpstreamCache({ url: `${npm.url}${input.name}`, packument: packument(input.name, input.versions), fetchedAt: input.age === null ? null : Date.now() - input.age });
}

describe("the shared packument cache", () => {
  test("a copy read near the end of its TTL is trusted only for what is left of it", async () => {
    const name = "near-expiry-lib";
    listed.set(name, ["1.0.0", "2.0.0"]);
    // 3 seconds of its 10 left
    await seed({ name, versions: ["1.0.0"], age: TTL - 3_000 });

    expect(await versionsOf(name)).toEqual(["1.0.0"]);
    expect(asked.get(name)).toBeUndefined();

    // past one TTL since npm answered: npm is asked again, though this isolate read the copy only 4 seconds ago
    await Bun.sleep(4_000);
    expect(await versionsOf(name)).toEqual(["1.0.0", "2.0.0"]);
    expect(asked.get(name)).toBe(1);
  });

  test("a copy past its TTL, or with no fetch time, is not used", async () => {
    for (const [name, age] of [
      ["past-ttl-lib", TTL + 1_000],
      ["no-fetch-time-lib", null],
    ] as const) {
      listed.set(name, ["1.0.0", "2.0.0"]);
      await seed({ name, versions: ["1.0.0"], age });

      expect(await versionsOf(name)).toEqual(["1.0.0", "2.0.0"]);
      expect(asked.get(name)).toBe(1);
    }
  });
});
