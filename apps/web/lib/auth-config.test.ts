// The sign-in options through the edge cache, against a local server standing in for the registry.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { cachedAuthConfig } from "./auth-config";

let seen: { path: string; cookie: string | null }[] = [];
let server: ReturnType<typeof Bun.serve>;
let registry = "";

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url);

      seen.push({ path: url.pathname + url.search, cookie: req.headers.get("cookie") });

      return Response.json({ providers: { github: true, vercel: false }, passkeys: true });
    },
  });
  registry = `http://127.0.0.1:${server.port}/`;
});

afterAll(() => {
  server.stop(true);
});

const ask = (path: string, init: RequestInit = {}) => cachedAuthConfig(new Request(`https://apm.example${path}`, init), { registry, dev: false });

test("the sign-in options are read from the registry once, without the visitor's cookie, and kept", async () => {
  seen = [];
  const first = await ask("/-/apm/v1/auth/config", { headers: { cookie: "session=x" } });
  const second = await ask("/-/apm/v1/auth/config");

  expect(await first?.json()).toEqual({ providers: { github: true, vercel: false }, passkeys: true });
  expect(await second?.json()).toEqual({ providers: { github: true, vercel: false }, passkeys: true });
  expect(second?.headers.get("cache-control")).toBe("private, no-store");
  expect(second?.headers.get("x-frame-options")).toBe("DENY");
  expect(seen).toEqual([{ path: "/-/apm/v1/auth/config", cookie: null }]);
});

test("any other request is left to the registry proxy", async () => {
  expect(await ask("/-/apm/v1/auth/config?x=1")).toBeNull();
  expect(await ask("/-/apm/v1/auth/config", { method: "POST", body: "{}" })).toBeNull();
  expect(await ask("/-/apm/v1/account")).toBeNull();
});
