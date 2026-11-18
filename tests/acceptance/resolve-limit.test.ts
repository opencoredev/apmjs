// Spec: GET /-/apm/v1/resolve is limited per address (packages/registry/src/resolve-limit.ts), on the Worker with
// Miniflare's rate limiting binding standing in for Cloudflare's. Over the limit an address gets a 429 that says when
// to ask again and is never cached; another address and every other route are not counted. Miniflare gives every
// request an address, so a request with none (the website's service binding) is covered by
// packages/registry/test/resolve-limit.test.ts.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { RESOLVE_LIMIT_PER_MINUTE } from "../../packages/registry/src/resolve-limit.ts";
import { startRegistry, type Registry } from "./harness";

const LIMIT = 3;

describe("the resolve limit", () => {
  let reg: Registry;

  beforeAll(async () => {
    reg = await startRegistry({ resolveRateLimit: { limit: LIMIT, period: 60 } });
  });

  afterAll(async () => {
    await reg?.stop();
  });

  const resolve = (address: string, path = "-/apm/v1/resolve?name=nothing-here&range=*"): Promise<Response> => fetch(`${reg.url}${path}`, { headers: { "cf-connecting-ip": address } });

  test("an address over the limit gets a 429 with Retry-After; others still resolve", async () => {
    const first: number[] = [];

    for (let i = 0; i < LIMIT; i++) {
      const r = await resolve("203.0.113.7");
      await r.body?.cancel();
      first.push(r.status);
    }

    expect(first.every((s) => s !== 429)).toBe(true);

    const over = await resolve("203.0.113.7");

    expect(over.status).toBe(429);
    expect(over.headers.get("retry-after")).toBe("60");
    expect(over.headers.get("cache-control")).toContain("no-store");
    expect(await over.json()).toEqual({ error: `Too many resolves from this address: at most ${RESOLVE_LIMIT_PER_MINUTE} a minute. Wait a minute and try again.` });

    // the /~safe alias is the same route, so it is counted against the same address
    const safe = await resolve("203.0.113.7", "~safe/-/apm/v1/resolve?name=nothing-here&range=*");
    await safe.body?.cancel();
    expect(safe.status).toBe(429);

    const other = await resolve("198.51.100.20");
    await other.body?.cancel();
    expect(other.status).not.toBe(429);
  });

  // review of eecb224, finding 3: CI behind one NAT shares an address, so a caller apm verified is not counted
  test("a live token is not counted; a forged token or a cookie naming no session still is", async () => {
    const token = await reg.mintToken({ user: "ci-bot", scope: "publish" });
    const address = "203.0.113.50";
    const ask = (headers: Record<string, string>) => fetch(`${reg.url}-/apm/v1/resolve?name=nothing-here&range=*`, { headers: { "cf-connecting-ip": address, ...headers } });

    for (let i = 0; i < LIMIT + 3; i++) {
      const r = await ask({ authorization: `Bearer ${token}` });
      await r.body?.cancel();
      expect(r.status).not.toBe(429);
    }

    // the same address without a verified caller: counted, whatever credentials it sends
    const statuses: number[] = [];

    const unverified: readonly Record<string, string>[] = [{}, { authorization: "Bearer not-a-token" }, { cookie: "better-auth.session_token=forged" }, { cookie: "theme=dark" }];

    for (const headers of unverified) {
      const r = await ask(headers);
      await r.body?.cancel();
      statuses.push(r.status);
    }

    // LIMIT of them pass, then the address is over its limit
    expect(statuses.slice(0, LIMIT).every((s) => s !== 429)).toBe(true);
    expect(statuses[LIMIT]).toBe(429);

    // and the token still resolves
    const after = await ask({ authorization: `Bearer ${token}` });
    await after.body?.cancel();
    expect(after.status).not.toBe(429);
  });

  test("other routes are never counted", async () => {
    for (let i = 0; i < LIMIT + 2; i++) {
      const r = await resolve("192.0.2.44", "-/apm/v1/packages/nothing-here");
      await r.body?.cancel();
      expect(r.status).not.toBe(429);
    }

    const r = await resolve("192.0.2.44");
    await r.body?.cancel();
    expect(r.status).not.toBe(429);
  });
});

// review of 56229cf, finding 2: credentials answered before the router could check them were never counted
describe("credentials the router never verified", () => {
  let reg: Registry;

  beforeAll(async () => {
    reg = await startRegistry({ resolveRateLimit: { limit: LIMIT, period: 60 }, databaseLink: true });
  });

  afterAll(async () => {
    await reg?.stop();
  });

  const ask = async (address: string, headers: Record<string, string>, method = "GET"): Promise<number> => {
    const r = await fetch(`${reg.url}-/apm/v1/resolve?name=nothing-here&range=*`, { method, headers: { "cf-connecting-ip": address, ...headers } });
    await r.body?.cancel();

    return r.status;
  };

  test("a forged token answered 503 in a database outage still counts", async () => {
    const link = reg.databaseLink;

    if (link === null) throw new Error("the registry was started without a database link");
    link.set("refuse");
    const during: number[] = [];

    try {
      for (let i = 0; i < LIMIT; i++) during.push(await ask("192.0.2.70", { authorization: "Bearer forged" }));
    } finally {
      link.set("up");
    }

    expect(during).toEqual(Array.from({ length: LIMIT }, () => 503));
    expect(await ask("192.0.2.70", {})).toBe(429);
  }, 30_000);

  test("a credentialed HEAD, answered 405, counts, and over the limit is answered 429", async () => {
    const statuses: number[] = [];

    for (let i = 0; i <= LIMIT; i++) statuses.push(await ask("192.0.2.71", { authorization: "junk" }, "HEAD"));

    expect(statuses).toEqual([...Array.from({ length: LIMIT }, () => 405), 429]);
  });
});

// review of 0126b2b, finding 2: whether the caller is verified is decided where the router checks the credentials, not
// by whether the GET handler ran, so every early answer is counted by what was verified
describe("early answers to credentialed resolves", () => {
  let reg: Registry;

  beforeAll(async () => {
    reg = await startRegistry({ resolveRateLimit: { limit: LIMIT, period: 60 } });
  });

  afterAll(async () => {
    await reg?.stop();
  });

  const ask = async (address: string, headers: Record<string, string>, method = "GET"): Promise<number> => {
    const r = await fetch(`${reg.url}-/apm/v1/resolve?name=nothing-here&range=*`, { method, headers: { "cf-connecting-ip": address, ...headers } });
    await r.body?.cancel();

    return r.status;
  };

  test("a live token's HEAD, answered 405, uses none of the address's quota", async () => {
    const token = await reg.mintToken({ user: "head-bot", scope: "publish" });
    const heads: number[] = [];

    for (let i = 0; i <= LIMIT; i++) heads.push(await ask("192.0.2.91", { authorization: `Bearer ${token}` }, "HEAD"));

    expect(heads).toEqual(Array.from({ length: LIMIT + 1 }, () => 405));

    // the address's whole quota is still there
    for (let i = 0; i < LIMIT; i++) expect(await ask("192.0.2.91", {})).not.toBe(429);
  });

  test("methods other than GET and HEAD do no resolve work and are never counted, credentials or not", async () => {
    for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
      for (let i = 0; i <= LIMIT; i++) expect(await ask("192.0.2.92", { authorization: "junk" }, method)).not.toBe(429);
    }

    for (let i = 0; i < LIMIT; i++) expect(await ask("192.0.2.92", {})).not.toBe(429);
  });
});

describe("without the binding", () => {
  let reg: Registry;

  beforeAll(async () => {
    reg = await startRegistry({});
  });

  afterAll(async () => {
    await reg?.stop();
  });

  test("nothing is limited", async () => {
    for (let i = 0; i < 6; i++) {
      const r = await fetch(`${reg.url}-/apm/v1/resolve?name=nothing-here&range=*`, { headers: { "cf-connecting-ip": "203.0.113.9" } });
      await r.body?.cancel();
      expect(r.status).not.toBe(429);
    }
  });
});
