// Review of eecb224, finding 3, the CLI's half: a 429 from /resolve (the registry limits resolves per address for callers
// it cannot verify) made `apm add` throw at once. Now `apm add` and `apm explain` ask again as Retry-After says, at most
// RATE_LIMIT_RETRY.tries times within one RATE_LIMIT_RETRY.maxMs deadline from the first ask, say so, and end with a
// message that says what to do. The registry is a local stub whose answers each test sets.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Api, RATE_LIMIT_RETRY, retryAfterMs } from "../src/api.ts";

const CLI = join(import.meta.dir, "..", "src", "main.ts");

/**
 * What the stub answers /resolve with, ask by ask: a 429 with this Retry-After, a 404, or a 202 (still being analysed,
 * ask again at once). The last one repeats.
 */
type Answer = { kind: "limited"; retryAfter: string } | { kind: "missing" } | { kind: "pending" };

let script: Answer[] = [];
let asked = 0;
let server: ReturnType<typeof Bun.serve> | null = null;

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req): Response {
      if (new URL(req.url).pathname !== "/-/apm/v1/resolve") return Response.json({ error: "not here" }, { status: 404 });
      const answer = script[Math.min(asked, script.length - 1)] ?? { kind: "missing" };
      asked++;

      if (answer.kind === "missing") return Response.json({ error: "No package named limited-pkg." }, { status: 404 });

      if (answer.kind === "pending") {
        const pending = [{ name: "limited-pkg", version: "1.0.0" }];

        return Response.json({ error: "limited-pkg@1.0.0 is still being analysed", name: "limited-pkg", range: "latest", version: "1.0.0", pending, pendingCount: 1, retryAfter: 0, skipped: [] }, { status: 202 });
      }

      return Response.json(
        { error: "Too many resolves from this address: at most 60 a minute. Wait a minute and try again." },
        { status: 429, headers: { "retry-after": answer.retryAfter, "cache-control": "no-store" } },
      );
    },
  });
});

afterAll(() => {
  server?.stop(true);
});

beforeEach(() => {
  asked = 0;
});

async function apm(args: string[], extraEnv: Readonly<Record<string, string>> = {}): Promise<{ code: number; out: string; ms: number }> {
  const home = mkdtempSync(join(tmpdir(), "apm-limited-"));
  const cwd = mkdtempSync(join(tmpdir(), "apm-limited-app-"));

  writeFileSync(join(cwd, "package.json"), JSON.stringify({ name: "app", version: "1.0.0" }));
  const t0 = performance.now();

  const p = Bun.spawn(["bun", CLI, ...args], {
    cwd,
    env: { PATH: process.env.PATH ?? "", HOME: home, NO_COLOR: "1", APM_REGISTRY: server?.url.href ?? "", ...extraEnv },
    stdout: "pipe",
    stderr: "pipe",
  });

  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);

  return { code, out: out + err, ms: performance.now() - t0 };
}

describe("a rate-limited resolve", () => {
  test("apm add asks again as Retry-After says, at most 3 times, then says what to do", async () => {
    script = [{ kind: "limited", retryAfter: "1" }];
    const r = await apm(["add", "limited-pkg"]);

    expect(asked).toBe(RATE_LIMIT_RETRY.tries);
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("asking again in 1s (try 2 of 3)");
    expect(r.out).toContain("asking again in 1s (try 3 of 3)");
    expect(r.out).toContain("apm asked 3 times; nothing was installed. Sign in (apm login)");
    // two waits of a second each
    expect(r.ms).toBeGreaterThanOrEqual(1900);
    expect(r.ms).toBeLessThan(20_000);
  }, 30_000);

  test("a wait past the 60 s budget is not waited: one ask, and the message at once", async () => {
    script = [{ kind: "limited", retryAfter: "120" }];
    const r = await apm(["add", "limited-pkg"]);

    expect(asked).toBe(1);
    expect(r.out).toContain("apm asked 1 time; nothing was installed");
    expect(r.ms).toBeLessThan(10_000);
  }, 30_000);

  test("once the limit lets it through, the registry's real answer is what apm reports", async () => {
    script = [{ kind: "limited", retryAfter: "1" }, { kind: "missing" }];
    const r = await apm(["add", "limited-pkg"]);

    expect(asked).toBe(2);
    expect(r.out).toContain("No package named limited-pkg.");
    expect(r.out).not.toContain("apm asked");
  }, 30_000);

  test("apm explain asks again the same way and reports the limit, not a bare HTTP 429", async () => {
    script = [{ kind: "limited", retryAfter: "1" }];
    const r = await apm(["explain", "limited-pkg"]);

    expect(asked).toBe(RATE_LIMIT_RETRY.tries);
    expect(r.out).toContain("asking again in 1s (try 2 of 3)");
    expect(r.out).toContain("the registry limits resolves from this address");
    expect(r.out).toContain("apm asked 3 times");
    expect(r.out).not.toContain("HTTP 429");
  }, 30_000);
});

// review of 54a3b4f, finding 3: only the waits counted against the budget, so slow 429s pushed the last ask past 60 s
describe("the retry deadline", () => {
  test("covers the asks as well as the waits: no ask starts past it", async () => {
    const started = performance.now();
    const starts: number[] = [];

    // each 429 takes a second to come back and asks for a second's wait; the budget is 3 s, not 60, to keep this short
    const slow = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(): Promise<Response> {
        starts.push(performance.now() - started);
        await Bun.sleep(1000);

        return Response.json({ error: "limited" }, { status: 429, headers: { "retry-after": "1" } });
      },
    });

    try {
      const api = new Api({ registry: slow.url.href, token: null, userconfig: "/unused", withheld: null });
      const waits: number[] = [];
      const out = await api.rawRetryingRateLimit("-/apm/v1/resolve?name=x", (w) => waits.push(w.waitMs), { tries: 3, maxMs: 3000 });

      // ask (1 s), wait (1 s), ask (1 s): a second wait would end past 3 s, so there is no third ask
      expect(out.status).toBe(429);
      expect(out.tries).toBe(2);
      expect(waits).toEqual([1000]);
      expect(starts.length).toBe(2);
      expect(starts.every((ms) => ms < 3000)).toBe(true);
      expect(performance.now() - started).toBeLessThan(3500);
    } finally {
      slow.stop(true);
    }
  }, 15_000);
});

// review of 226c936, finding 4: a retry kept its own 60 s timeout, so one still running could carry the total past the
// deadline
describe("a retry still running at the deadline", () => {
  test("is stopped there, and the 429 before it is the answer", async () => {
    let asks = 0;
    const started = performance.now();

    // the first 429 comes at once and asks for a second's wait; the retry takes two seconds; the budget is 1.5 s
    const slow = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(): Promise<Response> {
        asks++;

        if (asks > 1) await Bun.sleep(2000);

        return Response.json({ error: "limited" }, { status: 429, headers: { "retry-after": "1" } });
      },
    });

    try {
      const api = new Api({ registry: slow.url.href, token: null, userconfig: "/unused", withheld: null });
      const out = await api.rawRetryingRateLimit("-/apm/v1/resolve?name=x", () => {}, { tries: 3, maxMs: 1500 });

      expect(out.status).toBe(429);
      expect(out.tries).toBe(2);
      expect(asks).toBe(2);
      expect(performance.now() - started).toBeLessThan(1750);
    } finally {
      slow.stop(true);
    }
  }, 15_000);
});

// the same pattern one level up: apm add's wait for a pending analysis, and the rate-limit retries inside it, each had a
// budget of their own, so a 429 late in the pending wait could stretch it by up to 60 s more
describe("a 429 while apm add waits for a pending analysis", () => {
  test("is retried only inside what is left of that wait", async () => {
    // pending, then limited: with 1.5 s of pending wait, the second ask comes at about 1 s, leaving no room for a
    // 1 s Retry-After
    script = [{ kind: "pending" }, { kind: "limited", retryAfter: "1" }];
    const r = await apm(["add", "limited-pkg"], { APM_PENDING_WAIT_MS: "1500" });

    expect(asked).toBe(2);
    expect(r.out).toContain("apm asked 1 time; nothing was installed");
    expect(r.code).not.toBe(0);
  }, 30_000);
});

describe("retryAfterMs", () => {
  test("reads whole seconds and HTTP dates; nothing for anything else", () => {
    const now = Date.parse("2026-11-18T12:00:00Z");

    expect(retryAfterMs("60", now)).toBe(60_000);
    expect(retryAfterMs(" 0 ", now)).toBe(0);
    expect(retryAfterMs("Wed, 18 Nov 2026 12:00:30 GMT", now)).toBe(30_000);
    expect(retryAfterMs("Wed, 18 Nov 2026 11:00:00 GMT", now)).toBe(0);
    expect(retryAfterMs(null, now)).toBeNull();
    expect(retryAfterMs("", now)).toBeNull();
    expect(retryAfterMs("soon", now)).toBeNull();
  });
});
