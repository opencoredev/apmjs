// Spec: the name check reads real npm packuments and never calls a name "available" when npm could not be asked.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { startRegistry, getJson, dig, type Registry } from "./harness";

describe("name check against an upstream registry", () => {
  let fake: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  beforeAll(async () => {
    // Shapes copied from registry.npmjs.org/react: some versions carry `deprecated: false`.
    fake = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const path = new URL(req.url).pathname;
        if (path !== "/odd-shapes") return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
        const base = new URL(req.url).origin;
        const v = (n: string, extra: Record<string, unknown>) => ({ name: "odd-shapes", version: n, dist: { tarball: `${base}/odd-shapes/-/odd-shapes-${n}.tgz`, shasum: "0".repeat(40) }, ...extra });
        return Response.json({
          name: "odd-shapes",
          "dist-tags": { latest: "2.0.0" },
          versions: { "0.1.0": v("0.1.0", { deprecated: false }), "1.0.0": v("1.0.0", { deprecated: "use 2" }), "2.0.0": v("2.0.0", {}), "9.9.9": { broken: true } },
          time: { "0.1.0": "2015-01-01T00:00:00Z", "1.0.0": "2016-01-01T00:00:00Z", "2.0.0": "2017-01-01T00:00:00Z" },
          maintainers: [{ name: "someone" }],
        });
      },
    });
    reg = await startRegistry({ upstream: fake.url.toString() });
  });
  afterAll(async () => {
    await reg?.stop();
    fake?.stop(true);
  });

  test("a packument with deprecated:false and a malformed version still reads as taken", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/names?q=odd-shapes`);
    expect(r.status).toBe(200);
    expect(dig(r.body, "taken")).toBe(true);
    expect(dig(r.body, "available")).toBe(false);
    expect(dig(r.body, "source")).toBe("upstream");
    const p = await getJson(`${reg.url}odd-shapes`);
    expect(p.status).toBe(200);
    expect(dig(p.body, "versions", "1.0.0", "deprecated")).toBe("use 2");
    expect(typeof dig(p.body, "versions", "0.1.0", "deprecated")).not.toBe("string");
    expect(dig(p.body, "versions", "9.9.9")).toBeUndefined();
  });
});

describe("name check when upstream is down", () => {
  let broken: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  beforeAll(async () => {
    broken = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("down", { status: 503 }) });
    reg = await startRegistry({ upstream: broken.url.toString() });
  });
  afterAll(async () => {
    await reg?.stop();
    broken?.stop(true);
  });

  test("an unanswered lookup is reported as unknown, never as available", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/names?q=quite-possibly-free`);
    expect(r.status).toBe(200);
    expect(dig(r.body, "available")).toBe(false);
    expect(dig(r.body, "unknown")).toBe(true);
    expect(dig(r.body, "taken")).toBe(false);
  });
});
