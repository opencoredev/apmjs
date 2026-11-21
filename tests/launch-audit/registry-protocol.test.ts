// Launch-audit check (Registry audit batching, scan rate-limit, upstream protocol routes, /events, and hardening).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { gzipSync } from "node:zlib";
import { z } from "zod";
import { startRegistry, type Registry } from "../acceptance/harness.ts";

let upstreamServer: ReturnType<typeof Bun.serve> | null = null;
let reg: Registry | null = null;

function tarHeader(name: string, size: number): Uint8Array {
  const header = new Uint8Array(512);
  const enc = new TextEncoder();

  header.set(enc.encode(name).subarray(0, 100), 0);
  header.set(enc.encode("0000644\0"), 100);
  header.set(enc.encode("0000000\0"), 108);
  header.set(enc.encode("0000000\0"), 116);
  header.set(enc.encode(`${size.toString(8).padStart(11, "0")}\0`), 124);
  header.set(enc.encode("00000000000\0"), 136);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.set(enc.encode("ustar\0"), 257);
  header.set(enc.encode("00"), 263);

  let sum = 0;

  for (const b of header) sum += b;

  header.set(enc.encode(`${sum.toString(8).padStart(6, "0")}\0 `), 148);

  return header;
}

function tinyTgz(name: string, version: string): Uint8Array {
  const manifest = JSON.stringify({ name, version, main: "index.js", license: "MIT" });
  const body1 = new TextEncoder().encode(manifest);
  const body2 = new TextEncoder().encode("module.exports = 1;\n");
  const pad1 = (512 - (body1.length % 512)) % 512;
  const pad2 = (512 - (body2.length % 512)) % 512;
  const chunks = [tarHeader("package/package.json", body1.length), body1, new Uint8Array(pad1), tarHeader("package/index.js", body2.length), body2, new Uint8Array(pad2), new Uint8Array(1024)];
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const tar = new Uint8Array(total);
  let off = 0;

  for (const c of chunks) {
    tar.set(c, off);
    off += c.length;
  }

  return new Uint8Array(gzipSync(tar));
}

function registry(): Registry {
  if (reg === null) throw new Error("registry not started");

  return reg;
}

beforeAll(async () => {
  const tgz = tinyTgz("up-pkg", "1.2.3");
  const oldTime = new Date(Date.now() - 30 * 86_400_000).toISOString();

  upstreamServer = Bun.serve({
    port: 0,
    fetch(req) {
      const url = new URL(req.url);

      if (url.pathname === "/up-pkg") {
        const origin = url.origin;

        return Response.json({
          name: "up-pkg",
          "dist-tags": { latest: "1.2.3" },
          time: { created: oldTime, modified: oldTime, "1.2.3": oldTime },
          versions: {
            "1.2.3": {
              name: "up-pkg",
              version: "1.2.3",
              main: "index.js",
              license: "MIT",
              dist: { tarball: `${origin}/up-pkg/-/up-pkg-1.2.3.tgz`, shasum: "0".repeat(40) },
            },
          },
        });
      }

      if (url.pathname === "/up-pkg/-/up-pkg-1.2.3.tgz") {
        return new Response(tgz, { headers: { "content-type": "application/octet-stream" } });
      }

      if (url.pathname === "/-/npm/v1/security/advisories/bulk" && req.method === "POST") {
        return Response.json({});
      }

      if ((url.pathname === "/-/npm/v1/security/audits" || url.pathname === "/-/npm/v1/security/audits/quick") && req.method === "POST") {
        return Response.json({ actions: [], advisories: {}, muted: [], metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 } } });
      }

      return new Response("not found", { status: 404 });
    },
  });

  reg = await startRegistry({ upstream: `${upstreamServer.url.toString().replace(/\/$/, "")}/` });
}, 60_000);

afterAll(async () => {
  await reg?.stop();
  upstreamServer?.stop(true);
});

describe("launch audit: registry protocol, performance & hardening", () => {
  test("P0: bulk advisory audit refuses oversized package lists (DoS cap) instead of running unbounded DB queries", async () => {
    const huge: Record<string, string[]> = {};

    for (let i = 0; i < 6000; i++) huge[`pkg-${i}`] = ["1.0.0"];

    const res = await fetch(`${registry().url}-/npm/v1/security/advisories/bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(huge),
    });

    expect([400, 413]).toContain(res.status);
  });

  test("P0: bulk advisory audit batches DB queries (500 names completes without N+1 DB calls)", async () => {
    const body: Record<string, string[]> = {};

    for (let i = 0; i < 500; i++) body[`audit-batch-pkg-${i}`] = ["1.0.0"];

    const t0 = performance.now();

    const res = await fetch(`${registry().url}-/npm/v1/security/advisories/bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

    const elapsed = performance.now() - t0;

    expect(res.status).toBe(200);
    // On N+1 (1000 sequential queries against local Postgres), 500 packages takes much longer than batched 2 queries;
    // also assert via pg_stat_database or source-level absence of sequential getPackage+advisoriesFor per name.
    const apmSrc = await Bun.file("packages/registry/src/apm.ts").text();
    const collectStart = apmSrc.indexOf("const collectAdvisories");
    const collectSlice = apmSrc.slice(collectStart, collectStart + 1600);

    expect(collectSlice).not.toContain("yield* store.getPackage(name)");
    expect(elapsed).toBeLessThan(2000);
  });

  test("P1: npm upstream protocol serves /<pkg>/<version>, /-/package/<pkg>/dist-tags, and /-/npm/v1/security/audits", async () => {
    const byVer = await fetch(`${registry().url}up-pkg/1.2.3`);
    const byTag = await fetch(`${registry().url}up-pkg/latest`);
    const tags = await fetch(`${registry().url}-/package/up-pkg/dist-tags`);

    const audits = await fetch(`${registry().url}-/npm/v1/security/audits`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "app", version: "1.0.0", requires: { "up-pkg": "1.2.3" }, dependencies: { "up-pkg": { version: "1.2.3" } } }),
    });

    const quick = await fetch(`${registry().url}-/npm/v1/security/audits/quick`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "app", version: "1.0.0", requires: { "up-pkg": "1.2.3" }, dependencies: { "up-pkg": { version: "1.2.3" } } }),
    });

    expect(byVer.status).toBe(200);
    expect(byTag.status).toBe(200);
    expect(tags.status).toBe(200);
    expect(audits.status).toBe(200);
    expect(quick.status).toBe(200);
  });

  test("P1: GET /-/apm/v1/packages/<upstream>/events returns 200 with empty events list (matching HTTP API docs)", async () => {
    // Ensure upstream package is seen
    const pkgRes = await fetch(`${registry().url}up-pkg`);

    expect(pkgRes.status).toBe(200);

    const eventsRes = await fetch(`${registry().url}-/apm/v1/packages/up-pkg/events`);

    expect(eventsRes.status).toBe(200);

    const parsed = z.object({ events: z.array(z.unknown()) }).parse(await eventsRes.json());

    expect(parsed.events).toEqual([]);
  });

  test("P1: anonymous POST /-/apm/v1/scan caps queue enqueues per request (cannot flood maxConcurrency:1 queue with 200 jobs)", async () => {
    const apmSrc = await Bun.file("packages/registry/src/apm.ts").text();
    const scanStart = apmSrc.indexOf("const scanResponse");
    const scanSlice = apmSrc.slice(scanStart, scanStart + 4500);

    // Anonymous scan must cap queued analyses (like anonymous resolve's ANONYMOUS_QUEUED_DEPENDENCIES) or rate-limit scan
    expect(scanSlice).toMatch(/ANONYMOUS_QUEUED|scan.*limit|anonymous.*queue/i);
  });

  test("P2: resolve rate limit normalizes IPv6 addresses to /64 and cron isolates step errors", async () => {
    const limitSrc = await Bun.file("packages/registry/src/resolve-limit.ts").text();
    const workerSrc = await Bun.file("packages/registry/src/worker.ts").text();

    // IPv6 /64 normalization in clientAddress
    expect(limitSrc).toMatch(/\/64|ipv6|split\(":"\)/i);

    // Cron Effect.all must isolate failures per step so one failing step does not abort recoverAnalyses
    const cronStart = workerSrc.indexOf("matureRevocations");
    const cronSlice = workerSrc.slice(Math.max(0, cronStart - 400), cronStart + 800);

    expect(cronSlice).not.toMatch(/Effect\.all\(\s*\[\s*matureRevocations/);
  });
});
