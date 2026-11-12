// A revoked version's files through the site's edge cache and proxy.ts, against a real local server standing in for
// the registry. REGISTRY is fixed when lib/registry-url.ts first loads (another test file may load it first), so the
// fetch spy only moves REGISTRY's origin onto this server; the requests and answers are real.
import { afterAll, afterEach, beforeAll, describe, expect, setSystemTime, spyOn, test } from "bun:test";
import { NextRequest } from "next/server";
import { z } from "zod";
import { proxy } from "../proxy";
import { POLICIES } from "./edge-cache";
import { fileStatus } from "./package-status";
import { fetchJson } from "./registry-fetch";
import { fileApiPath, REGISTRY, servableKey } from "./registry-url";

const FileDoc = z.object({ kind: z.literal("text"), text: z.string() });

/** The registry's answer status per path and query; 200 when unset. */
const answers = new Map<string, number>();
const seen: { method: string; path: string }[] = [];
let server: ReturnType<typeof Bun.serve>;
const realFetch = globalThis.fetch;

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const u = new URL(req.url);
      const path = `${u.pathname}${u.search}`;
      seen.push({ method: req.method, path });
      const status = answers.get(path) ?? 200;

      if (status !== 200) return Response.json({ error: `answered ${status}` }, { status });

      return Response.json({ name: "x", version: "1.0.0", path: "index.js", size: 5, kind: "text", text: "hello" });
    },
  });
  const base = `http://127.0.0.1:${server.port}/`;

  const moved = (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> => {
    const url = input instanceof Request ? input.url : input.toString();

    return realFetch(url.startsWith(REGISTRY) ? `${base}${url.slice(REGISTRY.length)}` : url, init);
  };

  spyOn(globalThis, "fetch").mockImplementation(Object.assign(moved, { preconnect: realFetch.preconnect }));
});

afterEach(() => {
  setSystemTime();
});

afterAll(() => {
  void server.stop(true);
});

const T0 = Date.parse("2026-11-12T12:00:00Z");

function fileOf(name: string) {
  const target = { name, version: "1.0.0", path: "index.js" };
  const path = `/${fileApiPath(target)}`;
  const reads = (method: string) => seen.filter((s) => s.method === method && s.path === path).length;

  return {
    target,
    view: () => fetchJson({ url: `${REGISTRY}${fileApiPath(target)}`, schema: FileDoc, cache: POLICIES.versionFile, servable: servableKey(target) }),
    answer: (status: number) => answers.set(path, status),
    reads,
  };
}

const viewOf = (name: string) => proxy(new NextRequest(`https://apmjs.dev/package/${name}/v/1.0.0/file/index.js`));

describe("a cached file of a version that gets revoked", () => {
  test("the next view after the revoke does not show the cached file", async () => {
    const f = fileOf("revoke-after-cache");
    setSystemTime(T0);
    expect(await f.view()).toEqual({ kind: "ok", value: { kind: "text", text: "hello" } });

    f.answer(410);
    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    expect(await f.view()).toEqual({ kind: "unavailable", reason: { kind: "status", status: 410 } });
    // the bytes were dropped as well: a restore is read again, not served from before
    f.answer(200);
    expect((await f.view()).kind).toBe("ok");
    expect(f.reads("GET")).toBe(2);
  });

  test("proxy.ts's cached yes does not outlive the revoke", async () => {
    const f = fileOf("revoke-after-exists");
    setSystemTime(T0);
    expect(await fileStatus(f.target)).toBe("ok");
    expect((await f.view()).kind).toBe("ok");

    f.answer(410);
    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    expect(await fileStatus(f.target)).toBe("refused");
    expect((await f.view()).kind).toBe("unavailable");
  });

  test("the bytes stay cached: within a few seconds nothing is asked, after that only a HEAD", async () => {
    const f = fileOf("cached-and-allowed");
    setSystemTime(T0);
    await f.view();
    setSystemTime(T0 + 1_000);
    expect((await f.view()).kind).toBe("ok");
    expect([f.reads("GET"), f.reads("HEAD")]).toEqual([1, 0]);

    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    expect((await f.view()).kind).toBe("ok");
    expect([f.reads("GET"), f.reads("HEAD")]).toEqual([1, 1]);
  });

  test("a file the version does not have is still a 404 while the version's permission is fresh", async () => {
    const shown = fileOf("permission-fresh");
    setSystemTime(T0);
    expect((await shown.view()).kind).toBe("ok");
    const target = { name: "permission-fresh", version: "1.0.0", path: "nope.js" };
    answers.set(`/${fileApiPath(target)}`, 404);

    expect(await fileStatus(target)).toBe("missing");
  });

  test("a registry that can't confirm the version is not answered from the cache", async () => {
    const f = fileOf("cached-registry-down");
    setSystemTime(T0);
    await f.view();
    f.answer(503);
    setSystemTime(T0 + POLICIES.servable.freshMs + 1_000);
    expect(await f.view()).toEqual({ kind: "unavailable", reason: { kind: "status", status: 503 } });
  });

  test("the permission to serve is kept for a few seconds at most, with no stale window", () => {
    expect(POLICIES.servable.freshMs).toBeLessThanOrEqual(5_000);
    expect(POLICIES.servable.staleMs).toBe(0);
  });
});

describe("proxy.ts on a file view the registry refuses", () => {
  test("a revoked version (410) and an unreadable file (422) reach the page, which explains them", async () => {
    for (const [name, status] of [
      ["refused-revoked", 410],
      ["refused-unreadable", 422],
    ] as const) {
      fileOf(name).answer(status);
      const res = await viewOf(name);

      expect(res.status).not.toBe(503);
      expect(res.headers.get("x-middleware-next")).toBe("1");
    }
  });

  test("a missing file is still the not-found page", async () => {
    fileOf("refused-missing").answer(404);
    const res = await viewOf("refused-missing");

    expect(res.status).toBe(404);
  });

  test("a registry that fails is still the 503 page", async () => {
    for (const [name, status] of [
      ["failing-500", 500],
      ["failing-503", 503],
    ] as const) {
      fileOf(name).answer(status);
      const res = await viewOf(name);

      expect(res.status).toBe(503);
      expect(await res.text()).toContain("registry");
    }
  });
});
