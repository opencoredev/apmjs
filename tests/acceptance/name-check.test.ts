// Spec: the name check reads real npm packuments and never calls a name "available" when npm could not be asked.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { z } from "zod";
import { dig, enableTotp, getJson, putPublish, signInWithGitHub, startFakeGitHub, startRegistry, type Browser, type FakeGitHub, type Registry } from "./harness";

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

// Under the GitHub-scope policy nobody can publish a bare name, so the alternatives are scoped names only.
describe("name check alternatives under the GitHub-scope policy", () => {
  let gh: FakeGitHub;
  let reg: Registry;
  let b: Browser;

  beforeAll(async () => {
    gh = startFakeGitHub();
    reg = await startRegistry({ namePolicy: "scoped", github: gh });
    b = await signInWithGitHub(reg, gh, "scope-owner");
    await enableTotp(b);
    const token = await reg.mintToken({ user: "scope-owner", scope: "publish" });
    const r = await putPublish(reg, token, { name: "@scope-owner/quokka-js", version: "1.0.0", license: "MIT", main: "index.js" });

    expect(r.status, JSON.stringify(r.body)).toBe(201);
  });
  afterAll(async () => {
    await reg?.stop();
    await gh?.stop();
  });

  const Alternatives = z.object({
    scope: z.string().nullable(),
    suggestions: z.array(z.object({ name: z.string(), available: z.boolean(), taken: z.boolean(), checked: z.boolean() })),
  });
  const suggestionsOf = (r: { body: unknown }) => Alternatives.parse(r.body).suggestions;

  const names = (r: { body: unknown }): string[] => suggestionsOf(r).map((x) => x.name);

  test("a visitor is offered @you/ names, unchecked, and no bare names", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/names?q=quokka&part=alternatives`);

    expect(r.status).toBe(200);
    expect(dig(r.body, "scope")).toBeNull();
    expect(names(r)).toContain("@you/use-quokka");
    expect(names(r).every((n) => n.startsWith("@you/"))).toBe(true);
    expect(suggestionsOf(r).every((s) => !s.checked && !s.available)).toBe(true);
  });

  test("a signed-in visitor is offered names under their own scope, checked", async () => {
    const r = await b.json("-/apm/v1/names?q=quokka&part=alternatives");

    expect(r.status).toBe(200);
    expect(dig(r.body, "scope")).toBe("scope-owner");
    expect(names(r).every((n) => n.startsWith("@scope-owner/"))).toBe(true);
    const byName = new Map(suggestionsOf(r).map((s) => [s.name, s]));

    expect(byName.get("@scope-owner/quokka-js")?.taken).toBe(true);
    expect(byName.get("@scope-owner/use-quokka")?.available).toBe(true);
    expect(byName.get("@scope-owner/use-quokka")?.checked).toBe(true);
  });

  test("a visitor is not offered a placeholder the look-alike guard would refuse", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/names?q=hono&part=alternatives`);

    expect(names(r)).toContain("@you/hono");
    expect(names(r)).not.toContain("@you/hono-js");
  });

  test("a scoped name a publish would refuse as a look-alike is not offered as free", async () => {
    const r = await b.json("-/apm/v1/names?q=hono&part=alternatives");
    const byName = new Map(suggestionsOf(r).map((s) => [s.name, s]));

    expect(byName.get("@scope-owner/hono")?.available).toBe(true);
    expect(byName.get("@scope-owner/hono-js")?.available).toBe(false);
  });

  test("a CLI token checks under its own scope too", async () => {
    const token = await reg.mintToken({ user: "scope-owner", scope: "publish" });
    const r = await getJson(`${reg.url}-/apm/v1/names?q=quokka&part=alternatives`, { headers: { authorization: `Bearer ${token}` } });

    expect(dig(r.body, "scope")).toBe("scope-owner");
    expect(names(r)).toContain("@scope-owner/use-quokka");
  });
});
