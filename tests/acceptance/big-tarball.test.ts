// Upstream tarballs over the 32 MiB analysis cap (MAX_UPSTREAM_TARBALL_BYTES). On 1627c5e the tarball route answered
// 502 "larger than the 32 MiB apm downloads" for every one of them, so `npm install next` failed through apm (next
// 16.4.6 is 43.7 MB). The cap is for analysis memory; serving one now streams the upstream's answer to the client
// unbuffered, after every check that ran before serving, and checks its checksum on the way (verified-stream.ts).
// npm is a local stand-in; no real host is contacted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { dig, getJson, installedVersion, makeSandbox, pkgTgz, run, startRegistry, writeConsumer, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const clock = Date.parse("2026-11-01T00:00:00Z");

/** One package of the stand-in: its one version's tarball, when it was published, and how often its tarball was asked for. */
type Served = { bytes: Uint8Array; publishedAt: number; requests: number; listed?: { sha512: string } };

const ErrorAnswer = z.object({ error: z.string() });

const sha512 = (b: Uint8Array): string => createHash("sha512").update(b).digest("hex");

describe("upstream tarballs over the analysis cap", () => {
  const served = new Map<string, Served>();
  let npm: ReturnType<typeof Bun.serve>;
  let reg: Registry;
  let work: string;

  // 40 MB of random bytes, which gzip does not shrink: each tarball is a real package of about 40 MB
  const filler = new Uint8Array(randomBytes(40 * 1000 * 1000));
  const bigTgz = (name: string): Uint8Array => pkgTgz({ name, version: "1.0.0", license: "MIT", main: "index.js" }, { "index.js": "module.exports = 1;\n", "blob.bin": filler });

  beforeAll(async () => {
    const old = clock - 30 * DAY;

    // plain: served, installed by npm and bun, and later confirmed malicious
    served.set("big", { bytes: bigTgz("big"), publishedAt: old, requests: 0 });
    // has a passing score (copied from small-clean's), so ~safe serves it
    served.set("big-scored", { bytes: bigTgz("big-scored"), publishedAt: old, requests: 0 });
    // published an hour ago: inside ~safe's cooldown
    served.set("big-fresh", { bytes: bigTgz("big-fresh"), publishedAt: clock - 60 * 60 * 1000, requests: 0 });
    // the packument's checksum is not these bytes' (tampered in transit, or on the upstream)
    served.set("big-tampered", { bytes: bigTgz("big-tampered"), publishedAt: old, requests: 0, listed: { sha512: sha512(new Uint8Array([1, 2, 3])) } });
    served.set("small-clean", { bytes: pkgTgz({ name: "small-clean", version: "1.0.0", license: "MIT", main: "index.js" }), publishedAt: old, requests: 0 });

    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const u = new URL(req.url);
        const tar = /^\/([^/]+)\/-\/[^/]+\.tgz$/.exec(u.pathname);
        const name = tar?.[1] ?? decodeURIComponent(u.pathname.slice(1));
        const one = served.get(name);

        if (!one) return Response.json({ error: "Not found" }, { status: 404 });

        if (tar) {
          one.requests++;

          return new Response(one.bytes, { headers: { "content-type": "application/octet-stream", "content-length": String(one.bytes.length) } });
        }

        const hex = one.listed?.sha512 ?? sha512(one.bytes);
        const tarball = `${npm.url.toString()}${name}/-/${name}-1.0.0.tgz`;
        const dist = { tarball, shasum: createHash("sha1").update(one.bytes).digest("hex"), integrity: `sha512-${Buffer.from(hex, "hex").toString("base64")}` };

        return Response.json({
          name,
          "dist-tags": { latest: "1.0.0" },
          versions: { "1.0.0": { name, version: "1.0.0", main: "index.js", license: "MIT", dist } },
          time: { "1.0.0": new Date(one.publishedAt).toISOString() },
        });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: npm.url.toString(), upstreamTtlMs: 0 });
    work = mkdtempSync(join(tmpdir(), "apm-big-"));
  }, 60_000);

  afterAll(async () => {
    await reg?.stop();
    await npm?.stop(true);
  });

  const bytesOf = (name: string): Uint8Array => {
    const one = served.get(name);

    if (!one) throw new Error(`no stand-in package ${name}`);

    return one.bytes;
  };

  /** GET (or HEAD) one tarball through `prefix` ("" or "~safe/"): status, headers and every byte of the body. */
  async function tarball(prefix: string, name: string, method: "GET" | "HEAD" = "GET"): Promise<{ status: number; headers: Headers; body: Uint8Array }> {
    const res = await fetch(`${reg.url}${prefix}${name}/-/${name}-1.0.0.tgz`, { method });

    return { status: res.status, headers: res.headers, body: new Uint8Array(await res.arrayBuffer()) };
  }

  test("a 40 MB tarball is served whole through the registry, with its length, and is not cached", async () => {
    const want = bytesOf("big");

    expect(want.length).toBeGreaterThan(32 * 1024 * 1024);
    const got = await tarball("", "big");

    // on 1627c5e: 502 "Upstream tarball unavailable: the tarball (40.0 MB) is larger than the 32 MiB apm downloads"
    expect(got.status, new TextDecoder().decode(got.body.slice(0, 300))).toBe(200);
    expect(got.headers.get("content-type")).toBe("application/octet-stream");
    // the Worker sends Content-Length (a FixedLengthStream; registry-heap.workerd.test.ts checks it on a GET), but this
    // harness's Bun proxy re-sends a large streamed body chunked, so here the length is checked by HEAD and by the bytes
    expect(got.body.length).toBe(want.length);
    expect(sha512(got.body)).toBe(sha512(want));

    const head = await tarball("", "big", "HEAD");

    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe(String(want.length));
    expect(head.body.length).toBe(0);
    // passed through, never kept: the blob store holds no copy of it
    expect((await reg.blobs.keys()).some((k) => k.endsWith(sha512(want)))).toBe(false);
  }, 120_000);

  test("stock npm and bun install it, and the lockfile's resolved URL stays on the registry", async () => {
    const sb = makeSandbox(reg);

    for (const client of ["npm", "bun"] as const) {
      const app = writeConsumer(work, reg, undefined, { big: "1.0.0" });
      const r = await run([client, "install"], { cwd: app, env: sb.env, timeoutMs: 120_000 });

      // on 1627c5e both failed on the tarball's 502
      expect(r.code, r.out).toBe(0);
      expect(installedVersion(app, "big")).toBe("1.0.0");
      expect(statSync(join(app, "node_modules", "big", "blob.bin")).size).toBe(filler.length);

      if (client === "npm") {
        const lock = z.object({ packages: z.record(z.string(), z.object({ resolved: z.string().optional() }).loose()) }).parse(await Bun.file(join(app, "package-lock.json")).json());

        expect(lock.packages["node_modules/big"]?.resolved).toBe(`${reg.url}big/-/big-1.0.0.tgz`);
      }
    }
  }, 240_000);

  test("~safe serves a 40 MB tarball that passes its policy, whole, to npm too", async () => {
    // a passing score for big-scored's exact bytes: small-clean's analysis, as one made under a higher cap would be
    expect(await reg.analysisJob({ name: "small-clean", version: "1.0.0" })).toBe("ack");

    const rows = await reg.query(
      "INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) SELECT 'big-scored', '1.0.0', $1, scorer, analysis, analyzed_at FROM upstream_analysis WHERE package = 'small-clean' RETURNING package",
      [`sha512-${sha512(bytesOf("big-scored"))}`],
    );

    expect(rows.length).toBe(1);
    const got = await tarball("~safe/", "big-scored");

    // on 1627c5e: 502, the download came before the policy and refused the size
    expect(got.status, new TextDecoder().decode(got.body.slice(0, 300))).toBe(200);
    expect(got.body.length).toBe(bytesOf("big-scored").length);
    expect(sha512(got.body)).toBe(sha512(bytesOf("big-scored")));

    const safe = { ...reg, url: `${reg.url}~safe/` };
    const app = writeConsumer(work, safe, undefined, { "big-scored": "1.0.0" });
    const r = await run(["npm", "install"], { cwd: app, env: makeSandbox(safe).env, timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "big-scored")).toBe("1.0.0");
  }, 240_000);

  test("~safe still refuses a 40 MB version it cannot score, and one inside the cooldown, before sending a byte", async () => {
    // big: over the analysis cap, so recorded too large and never scored; ~safe serves only scored versions
    const unscored = await tarball("~safe/", "big");

    // on 1627c5e: 502 for both, the size refused before the policy was asked
    expect(unscored.status).toBe(404);
    expect(ErrorAnswer.parse(JSON.parse(new TextDecoder().decode(unscored.body))).error).toContain("is not in this view");

    const fresh = await tarball("~safe/", "big-fresh");

    expect(fresh.status).toBe(404);
    expect(ErrorAnswer.parse(JSON.parse(new TextDecoder().decode(fresh.body))).error).toContain("is not in this view");
    expect(served.get("big-fresh")?.requests ?? 0).toBeLessThanOrEqual(1);
  }, 120_000);

  test("a tarball that fails its checksum is cut off before its last bytes, so no client gets all of it", async () => {
    const want = bytesOf("big-tampered");
    const res = await fetch(`${reg.url}big-tampered/-/big-tampered-1.0.0.tgz`);

    // headers go out before the checksum can be known; on 1627c5e this was a 502 for the size
    expect(res.status).toBe(200);
    // every byte that reached the client is counted, whether or not the body then errors (review of 23453ab, finding 3)
    const reader = res.body?.getReader();
    let received = 0;
    let errored = false;

    try {
      for (;;) {
        const chunk = await reader?.read();

        if (chunk === undefined || chunk.done) break;
        received += chunk.value.byteLength;
      }
    } catch {
      errored = true;
    }

    expect(errored).toBe(true);
    expect(received).toBeLessThan(want.length);
  }, 120_000);

  test("once confirmed malicious, a big version is 410 and its bytes are not fetched again", async () => {
    // served first (on 1627c5e: 502)
    expect((await tarball("", "big")).status).toBe(200);
    const digest = `sha512-${sha512(bytesOf("big"))}`;

    await reg.query(
      "INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state, human_by, human_at) VALUES ('big', '1.0.0', $1, 'flagged', '{}'::jsonb, $2, 'confirmed', 'reviewer', $2)",
      [digest, clock],
    );
    const before = served.get("big")?.requests;
    const gone = await tarball("", "big");

    expect(gone.status).toBe(410);
    expect(dig(JSON.parse(new TextDecoder().decode(gone.body)), "confirmed")).toBe(true);
    expect(served.get("big")?.requests).toBe(before);
    expect((await tarball("~safe/", "big")).status).toBe(410);
    expect((await getJson(`${reg.url}big`)).status).toBe(200);
  }, 120_000);
});
