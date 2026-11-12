// Spec: registry search merges packages published here with the upstream's own /-/v1/search,
// marks every hit's source, keeps npm's wire format, and still answers with local hits (and a
// flag the UI can show) when the upstream is down. A fake upstream stands in for registry.npmjs.org.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, run, getJson, dig, type Registry } from "./harness";

function searchObject(name: string, version: string, description: string) {
  return {
    downloads: { monthly: 4000, weekly: 1000 },
    package: { name, version, description, date: "2025-01-01T00:00:00.000Z", publisher: { username: "someone" }, maintainers: [{ username: "someone" }], links: { npm: `https://www.npmjs.com/package/${name}` } },
    score: { final: 1, detail: { popularity: 1, quality: 1, maintenance: 1 } },
    searchScore: 100,
  };
}

async function publishLocal(reg: Registry, token: string, name: string, version: string): Promise<void> {
  const work = mkdtempSync(join(tmpdir(), "apm-search-"));
  const sb = makeSandbox(reg, token);
  const d = writePackage(work, { name, version, extra: { description: "published to apm" } }, reg, token);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`publish ${name}@${version} failed: ${r.out}`);
}

type Hit = { name: string; version: string; source: unknown };
function hitsOf(body: unknown): Hit[] {
  const objects = dig(body, "objects");
  if (!Array.isArray(objects)) throw new Error(`no objects in ${JSON.stringify(body)}`);
  return objects.map((o: unknown) => ({ name: String(dig(o, "package", "name")), version: String(dig(o, "package", "version")), source: dig(o, "source") }));
}

describe("search merges local packages with the upstream's search", () => {
  let fake: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let upstreamSearches = 0;
  beforeAll(async () => {
    fake = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname !== "/-/v1/search") return Response.json({ error: "Not found" }, { status: 404 });
        upstreamSearches++;
        // npm also has a package with the local name; the local one must win.
        return Response.json({
          objects: [searchObject("widget-cloud", "2.1.0", "A widget from npm"), searchObject("widget-local", "9.9.9", "npm's own widget-local")],
          total: 2,
          time: new Date().toUTCString(),
        });
      },
    });
    reg = await startRegistry({ upstream: fake.url.toString() });
    const alice = await addUser(reg, "alice");
    await publishLocal(reg, alice, "widget-local", "1.0.0");
  });
  afterAll(async () => {
    await reg?.stop();
    fake?.stop(true);
  });

  test("local and upstream results are merged and each is marked by source", async () => {
    const r = await getJson(`${reg.url}-/v1/search?text=widget&size=20`);
    expect(r.status).toBe(200);
    expect(dig(r.body, "upstreamFailed")).toBe(false);
    expect(typeof dig(r.body, "total")).toBe("number");
    const hits = hitsOf(r.body);
    const local = hits.filter((h) => h.name === "widget-local");
    expect(local).toEqual([{ name: "widget-local", version: "1.0.0", source: "local" }]);
    expect(hits.find((h) => h.name === "widget-cloud")).toEqual({ name: "widget-cloud", version: "2.1.0", source: "npm" });
    // Nothing was fetched or scored per search: an unscored upstream hit carries no score.
    const objects = dig(r.body, "objects");
    const cloud = Array.isArray(objects) ? objects.find((o: unknown) => dig(o, "package", "name") === "widget-cloud") : undefined;
    expect(cloud).toBeDefined();
    expect(dig(cloud, "apmScore") ?? null).toBeNull();
  });

  test("the upstream's answer is cached between identical searches", async () => {
    const before = upstreamSearches;
    await getJson(`${reg.url}-/v1/search?text=gadget&size=20`);
    await getJson(`${reg.url}-/v1/search?text=gadget&size=20`);
    expect(upstreamSearches - before).toBe(1);
  });

  test("stock npm search reads the merged answer", async () => {
    const sb = makeSandbox(reg);
    const r = await run(["npm", "search", "--json", "widget"], { cwd: sb.home, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const parsed: unknown = JSON.parse(r.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    const names = Array.isArray(parsed) ? parsed.map((p: unknown) => dig(p, "name")) : [];
    expect(names).toContain("widget-local");
    expect(names).toContain("widget-cloud");
  });
});

describe("search when the upstream is down", () => {
  let broken: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let down = false;
  beforeAll(async () => {
    // npm answers while the local package is published (no first publish goes through while npm can't
    // be asked, scoped or not), then goes down before anyone searches.
    broken = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => (down ? new Response("down", { status: 503 }) : Response.json({ error: "Not found" }, { status: 404 })) });
    reg = await startRegistry({ upstream: broken.url.toString() });
    const alice = await addUser(reg, "alice");
    await publishLocal(reg, alice, "@alice/widget-local", "1.0.0");
    down = true;
  });
  afterAll(async () => {
    await reg?.stop();
    broken?.stop(true);
  });

  test("local results still return with the upstreamFailed flag set", async () => {
    const r = await getJson(`${reg.url}-/v1/search?text=widget`);
    expect(r.status).toBe(200);
    expect(dig(r.body, "upstreamFailed")).toBe(true);
    expect(hitsOf(r.body)).toEqual([{ name: "@alice/widget-local", version: "1.0.0", source: "local" }]);
  });
});
