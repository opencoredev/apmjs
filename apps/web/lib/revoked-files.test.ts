// A revoked version's files through the site's file reads and proxy.ts, against a real local server standing in for
// the registry. REGISTRY is fixed when lib/registry-url.ts first loads (another test file may load it first), so the
// fetch spy only moves REGISTRY's origin onto this server; the requests and answers are real. The site keeps no copy
// of a file, so every view is the registry's answer at that moment.
import { afterAll, beforeAll, describe, expect, mock, spyOn, test } from "bun:test";
import { NextRequest } from "next/server";
import { proxy } from "../proxy";
import { fileStatus } from "./package-status";
import { fileApiPath, REGISTRY } from "./registry-url";

// lib/registry.ts is the server entry point; outside Next its marker import would throw
void mock.module("server-only", () => ({}));

const { getFile } = await import("./registry");

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

afterAll(() => {
  void server.stop(true);
  mock.restore();
});

const SHOWN = { kind: "ok", value: { name: "x", version: "1.0.0", path: "index.js", size: 5, kind: "text", text: "hello" } } as const;
const GONE = { kind: "unavailable", reason: { kind: "status", status: 410 } } as const;

function fileOf(name: string) {
  const target = { name, version: "1.0.0", path: "index.js" };
  const path = `/${fileApiPath(target)}`;
  const reads = (method: string) => seen.filter((s) => s.method === method && s.path === path).length;

  return {
    target,
    view: () => getFile(target),
    answer: (status: number) => answers.set(path, status),
    reads,
  };
}

const viewOf = (name: string) => proxy(new NextRequest(`https://apmjs.dev/package/${name}/v/1.0.0/file/index.js`));

describe("a file of a version that gets revoked", () => {
  test("the view right after the revoke does not show the file", async () => {
    const f = fileOf("revoke-after-view");
    expect(await f.view()).toEqual(SHOWN);

    f.answer(410);
    expect(await f.view()).toEqual(GONE);
    // a restore shows it again on the next view
    f.answer(200);
    expect(await f.view()).toEqual(SHOWN);
    expect(f.reads("GET")).toBe(3);
  });

  test("proxy.ts's cached 'this file exists' lets the page through, and the page's own read is refused", async () => {
    const f = fileOf("revoke-after-exists");
    expect(await fileStatus(f.target)).toBe("ok");
    expect(await f.view()).toEqual(SHOWN);

    f.answer(410);
    const res = await viewOf("revoke-after-exists");
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(await f.view()).toEqual(GONE);
  });

  test("every view asks the registry with one GET; a path known to exist sends no HEAD", async () => {
    const f = fileOf("every-view-asks");
    expect(await fileStatus(f.target)).toBe("ok");
    expect(f.reads("HEAD")).toBe(1);

    for (let i = 0; i < 3; i++) {
      expect(await fileStatus(f.target)).toBe("ok");
      expect(await f.view()).toEqual(SHOWN);
    }

    expect([f.reads("GET"), f.reads("HEAD")]).toEqual([3, 1]);
  });

  test("a file the version does not have is a 404", async () => {
    const target = { name: "no-such-file", version: "1.0.0", path: "nope.js" };
    answers.set(`/${fileApiPath(target)}`, 404);

    expect(await fileStatus(target)).toBe("missing");
    expect(await getFile(target)).toEqual({ kind: "missing" });
  });

  test("a registry that can't be read shows no file, however recently it was shown", async () => {
    const f = fileOf("registry-down");
    expect(await f.view()).toEqual(SHOWN);
    f.answer(503);
    expect(await f.view()).toEqual({ kind: "unavailable", reason: { kind: "status", status: 503 } });
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
