// A tarball of a package only npm has, through the bundled Worker in Miniflare against a local npm (fast-tarball.ts):
// a request without credentials is sent to npm's own URL once nothing refuses it, one with credentials gets npm's
// bytes through the Worker and is never sent elsewhere, a refusal shows on the very next request (the redirect is
// never kept), and the fast answers carry their Server-Timing to anyone while no other answer does.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { startRegistry, type Registry } from "./harness";

const BYTES = new Uint8Array(randomBytes(40_000));
const HEX = createHash("sha512").update(BYTES).digest("hex");
const INTEGRITY = `sha512-${createHash("sha512").update(BYTES).digest("base64")}`;
const INSTALL = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

// npm's own client, which is redirected; Bun's fetch (this test's default) is streamed (fast-tarball.ts)
const NPM_UA = { "user-agent": "npm/10.9.0 node/v24.11.0 linux x64 workspaces/false" };

let npm: ReturnType<typeof Bun.serve>;
let reg: Registry;
const asked: string[] = [];

/** npm's document for one version of a package npm has, with its tarball on npm. */
const doc = (name: string, version: string) => ({ name, version, dist: { tarball: `${npm.url}${name}/-/${name}-${version}.tgz`, integrity: INTEGRITY } });

beforeAll(async () => {
  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;

      asked.push(path);
      const m = /^\/(dl-[a-z]+)(?:\/(1\.0\.0))?$/.exec(path);

      if (m?.[1] && m[2]) return Response.json(doc(m[1], m[2]));

      if (m?.[1]) return Response.json({ name: m[1], "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": doc(m[1], "1.0.0") }, time: { "1.0.0": "2026-10-01T00:00:00.000Z" } });

      if (/^\/dl-[a-z]+\/-\/dl-[a-z]+-1\.0\.0\.tgz$/.test(path)) return new Response(BYTES, { headers: { "content-type": "application/octet-stream" } });

      return Response.json({ error: "Not found" }, { status: 404 });
    },
  });
  reg = await startRegistry({ upstream: npm.url.toString(), upstreamTtlMs: 10_000 });
});

afterAll(async () => {
  await reg.stop();
  await npm.stop(true);
});

const tarballOf = (name: string): string => `${reg.url}${name}/-/${name}-1.0.0.tgz`;

const confirm = (name: string) =>
  reg.query(`INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, '1.0.0', $2, 'flagged', '{}', 0, 'confirmed')`, [name, `sha512-${HEX}`]);

describe("the fast tarball path through the Worker", () => {
  test("a request without credentials is sent to npm's tarball URL, never kept, and its timing is public", async () => {
    asked.length = 0;
    const res = await fetch(tarballOf("dl-plain"), { headers: NPM_UA, redirect: "manual" });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${npm.url}dl-plain/-/dl-plain-1.0.0.tgz`);
    expect(res.headers.get("cache-control")).toBe("no-store");
    // phases only: the package's own checks, nothing about anyone else
    expect(res.headers.get("server-timing")).toMatch(/^([a-z-]+;dur=[\d.]+;desc="\d+", )*total;dur=[\d.]+$/);
    expect(res.headers.get("server-timing")).toContain("db;");
    // apm opened nothing: the client downloads from npm
    expect(asked.filter((p) => p.endsWith(".tgz"))).toEqual([]);

    // a client that follows it gets npm's bytes, which it checks against the install document's integrity: npm's
    const followed = new Uint8Array(await (await fetch(tarballOf("dl-plain"))).arrayBuffer());
    const document = await (await fetch(`${reg.url}dl-plain`, { headers: { accept: INSTALL } })).json();

    expect(createHash("sha512").update(followed).digest("hex")).toBe(HEX);
    expect(JSON.stringify(document)).toContain(INTEGRITY);
  });

  test("a request with credentials is never sent to npm: it gets the bytes, privately", async () => {
    const credentials: Record<string, string>[] = [{ authorization: "Bearer npm_not_a_real_token" }, { cookie: "s=1" }];

    for (const headers of credentials) {
      const res = await fetch(tarballOf("dl-auth"), { headers, redirect: "manual" });
      const body = new Uint8Array(await res.arrayBuffer());

      expect(res.status).toBe(200);
      expect(res.headers.get("location")).toBeNull();
      expect(res.headers.get("cache-control")).toBe("private, no-store");
      expect(createHash("sha512").update(body).digest("hex")).toBe(HEX);
    }
  });

  test("a version confirmed malicious is 410 on the very next request, with or without credentials", async () => {
    expect((await fetch(tarballOf("dl-bad"), { headers: NPM_UA, redirect: "manual" })).status).toBe(302);
    await confirm("dl-bad");

    const refused = await fetch(tarballOf("dl-bad"), { headers: NPM_UA, redirect: "manual" });

    expect(refused.status).toBe(410);
    expect(refused.headers.get("location")).toBeNull();
    expect((await fetch(tarballOf("dl-bad"), { headers: { authorization: "Bearer x" }, redirect: "manual" })).status).toBe(410);
  });

  test("the install document of a package only npm has carries its timing to anyone", async () => {
    const res = await fetch(`${reg.url}dl-doc`, { headers: { accept: INSTALL } });
    await res.body?.cancel();

    expect(res.status).toBe(200);
    expect(res.headers.get("server-timing")).toMatch(/db;dur=[\d.]+;desc="\d+".*total;dur=[\d.]+$/);
  });

  test("no other answer carries timing without the debug token: a package published here, a missing tarball, the account", async () => {
    await reg.query(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ('dl-mine', 0, 0, '{"latest":"1.0.0"}'::jsonb)`);

    for (const url of [tarballOf("dl-mine"), `${reg.url}dl-plain/-/dl-plain-9.9.9.tgz`, `${reg.url}-/apm/v1/account`]) {
      const res = await fetch(url, { headers: NPM_UA, redirect: "manual" });
      await res.body?.cancel();

      expect(res.status, url).not.toBe(302);
      expect(res.headers.get("server-timing"), url).toBeNull();
    }
  });
});
