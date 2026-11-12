// Forwards to a real local server standing in for the registry.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { forwardToRegistry } from "./registry-proxy";

type Seen = { method: string; path: string; headers: Record<string, string>; body: string };

let seen: Seen[] = [];
let server: ReturnType<typeof Bun.serve>;
let registry = "";

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url);

      seen.push({ method: req.method, path: url.pathname + url.search, headers: Object.fromEntries(req.headers), body: await req.text() });

      if (url.pathname === "/api/auth/callback/github") {
        const headers = new Headers({ location: "https://apm.example/account" });

        headers.append("set-cookie", "a=1; Path=/; HttpOnly");
        headers.append("set-cookie", "b=2; Path=/; HttpOnly");

        return new Response(null, { status: 302, headers });
      }

      return Response.json({ ok: true }, { headers: { vary: "Accept-Encoding" } });
    },
  });
  registry = `http://127.0.0.1:${server.port}/`;
});

afterAll(() => {
  server.stop(true);
});

function forward(path: string, init: RequestInit = {}): Promise<Response> {
  const request = new Request(`https://apm.example${path}`, init);

  return forwardToRegistry(request, { registry, headers: new Headers(request.headers), dev: false });
}

describe("forwardToRegistry", () => {
  test("every answer is private, no-store, varies on Cookie and has the security headers", async () => {
    const res = await forward("/-/apm/v1/account", { headers: { cookie: "session=x" } });

    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("vary")).toBe("Accept-Encoding, Cookie");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(seen.at(-1)?.headers.cookie).toBe("session=x");
  });

  test("redirects and every Set-Cookie pass through unfollowed", async () => {
    const res = await forward("/api/auth/callback/github?code=c&state=s");

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://apm.example/account");
    expect(res.headers.getSetCookie()).toEqual(["a=1; Path=/; HttpOnly", "b=2; Path=/; HttpOnly"]);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(seen.at(-1)?.path).toBe("/api/auth/callback/github?code=c&state=s");
  });

  test("POST bodies are forwarded with the origin and the site's host", async () => {
    await forward("/-/apm/v1/staged/abc/approve", { method: "POST", headers: { "content-type": "application/json", origin: "https://apm.example", host: "apm.example", "x-forwarded-proto": "https" }, body: JSON.stringify({ ok: 1 }) });
    const last = seen.at(-1);

    expect(last?.method).toBe("POST");
    expect(last?.body).toBe('{"ok":1}');
    expect(last?.headers.origin).toBe("https://apm.example");
    expect(last?.headers["x-forwarded-host"]).toBe("apm.example");
    expect(last?.headers["x-forwarded-proto"]).toBe("https");
  });

  test("dot segments can't climb out of the two prefixes", async () => {
    const before = seen.length;

    for (const path of ["/-/apm/v1/%2e%2e/%2e%2e/%2e%2e/left-pad", "/api/auth/%2E%2E/%2E%2E/-/whoami", "/-/apm/v1/..%2f..%2f..%2fleft-pad"]) {
      const res = await forward(path);

      if (res.status === 404) continue;
      // Anything forwarded must still be under a prefix.
      expect(seen.at(-1)?.path.startsWith("/-/apm/v1/") || seen.at(-1)?.path.startsWith("/api/auth/")).toBe(true);
    }

    expect(seen.slice(before).every((s) => s.path.startsWith("/-/apm/v1/") || s.path.startsWith("/api/auth/"))).toBe(true);
  });

  test("an unreachable registry is a 502 with the same headers", async () => {
    const closed = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("") });
    const url = `http://127.0.0.1:${closed.port}/`;

    await closed.stop(true);
    const res = await forwardToRegistry(new Request("https://apm.example/-/apm/v1/account"), { registry: url, headers: new Headers(), dev: false });

    expect(res.status).toBe(502);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });
});
