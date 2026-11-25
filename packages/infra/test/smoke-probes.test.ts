// The smoke check's verdict probes (smoke-probes.ts) against an injected fetch: a read is bounded in time and size, a
// packument passes only as the view asked for and for the package asked about, with a valid version left and latest
// listed, and explain is asked again only for a transient answer.
import { describe, expect, test } from "bun:test";
import { BODY_CAP, boundedGet, largeExplain, LARGE, NPM_CLIENT, OSSF_LISTED, ossfListed, type Fetch, type ProbeDeps } from "../smoke-probes.ts";
import { z } from "zod";

const REGISTRY = "https://registry.test/";
const WEB = "https://web.test/";
const FULL = "application/json";
const INSTALL = "application/vnd.npm.install-v1+json";

type ExplainBody = { verdict: string; name: string; range: string; version: string | null; score: { score: number; grade: string } | null; reasons: string[]; notes: { kind: string; text: string }[] };

type PackumentBody = { name: string; versions: Record<string, { version: string }>; "dist-tags": Record<string, string> };

type Body = ExplainBody | PackumentBody | { error: string } | { other: number };

const answer = (body: Body, status = 200, type = FULL): Response => new Response(JSON.stringify(body), { status, headers: { "content-type": `${type}; charset=utf-8` } });

const explained = (over: Partial<ExplainBody> = {}): ExplainBody => ({ verdict: "install", name: LARGE.name, range: LARGE.version, version: LARGE.version, score: { score: 98, grade: "A" }, reasons: [], notes: [], ...over });

const refusedExplain: ExplainBody = { verdict: "do-not-install", name: OSSF_LISTED.name, range: OSSF_LISTED.version, version: OSSF_LISTED.version, score: null, reasons: [`Advisory: https://osv.dev/vulnerability/${OSSF_LISTED.id}`], notes: [] };

const packument = (over: Partial<PackumentBody> = {}): PackumentBody => ({ name: OSSF_LISTED.name, versions: { "9.0.0": { version: "9.0.0" } }, "dist-tags": { latest: "9.0.0" }, ...over });

/** A registry and website that answer as a healthy stage does, with `over` changing what a route answers. */
function stage(over: { explain?: () => Response; packument?: (accept: string) => Response; tarball?: (userAgent: string | undefined) => Response } = {}) {
  const calls: string[] = [];
  const tarballs: { userAgent: string | undefined; redirect: string }[] = [];
  const sleeps: number[] = [];

  const fetch: Fetch = async (url, init) => {
    calls.push(url);

    if (url.includes("api/explain")) return over.explain?.() ?? answer(url.includes(OSSF_LISTED.name) ? refusedExplain : explained());

    if (url.endsWith(".tgz")) {
      tarballs.push({ userAgent: init.headers["user-agent"], redirect: init.redirect });

      if (over.tarball) return over.tarball(init.headers["user-agent"]);
    }

    if (url.endsWith(".tgz")) return answer({ error: `known malicious: the OSSF malicious-packages feed lists ${OSSF_LISTED.name}@${OSSF_LISTED.version} (${OSSF_LISTED.id})` }, 403);
    const accept = init.headers.accept ?? FULL;

    return over.packument?.(accept) ?? answer(packument(), 200, accept);
  };

  const deps: ProbeDeps = { fetch, registry: REGISTRY, web: WEB, sleep: async (ms) => void sleeps.push(ms) };

  return { deps, calls, sleeps, tarballs };
}

const stalled = (): Fetch => async () => new Response(new ReadableStream({ start: (c) => c.enqueue(new TextEncoder().encode('{"a":')) }), { headers: { "content-type": FULL } });

describe("boundedGet", () => {
  test("a body that stops arriving ends the read at the deadline", async () => {
    const t0 = Date.now();
    const got = await boundedGet(stalled(), REGISTRY, { timeoutMs: 100, schema: z.object({ a: z.number() }) });

    expect(got.status).toBeNull();
    expect(got.text).toContain("no answer within 100 ms");
    expect(Date.now() - t0).toBeLessThan(2_000);
  });

  test("a body over the cap fails, read no further than the cap", async () => {
    let pulled = 0;
    const chunk = new Uint8Array(256 * 1024).fill(32);
    const endless: Fetch = async () => new Response(new ReadableStream({ pull: (c) => void (pulled++, c.enqueue(chunk)) }), { headers: { "content-type": FULL } });
    const got = await boundedGet(endless, REGISTRY, { timeoutMs: 5_000, schema: z.object({}) });

    expect(got.status).toBeNull();
    expect(got.text).toContain(`over ${BODY_CAP} bytes`);
    expect(pulled * chunk.length).toBeLessThan(BODY_CAP + 4 * chunk.length);
  });

  test("an answer that is not the schema has no data, its status and media type kept", async () => {
    const got = await boundedGet(async () => answer({ other: 1 }, 200, INSTALL), REGISTRY, { timeoutMs: 1_000, schema: z.object({ name: z.string() }) });

    expect(got).toMatchObject({ status: 200, media: INSTALL, data: null });
  });
});

describe("ossfListed", () => {
  test("a healthy stage passes every check", async () => {
    const checks = await ossfListed(stage().deps);

    expect(checks.map((c) => c.ok)).toEqual([true, true, true, true, true]);
  });

  test("the tarball is asked for as the default client and as npm, following no redirect", async () => {
    const s = stage();

    await ossfListed(s.deps);
    expect(s.tarballs).toEqual([
      { userAgent: undefined, redirect: "manual" },
      { userAgent: NPM_CLIENT, redirect: "manual" },
    ]);
  });

  test("a redirect of npm's tarball request to npm fails that check, and only that one", async () => {
    const redirected = (userAgent: string | undefined) =>
      userAgent === NPM_CLIENT
        ? new Response(null, { status: 302, headers: { location: `https://registry.npmjs.org/${OSSF_LISTED.name}/-/${OSSF_LISTED.name}-${OSSF_LISTED.version}.tgz` } })
        : answer({ error: `known malicious (${OSSF_LISTED.id})` }, 403);
    const checks = await ossfListed(stage({ tarball: redirected }).deps);

    expect(checks.slice(1, 3).map((c) => c.ok)).toEqual([true, false]);
    expect(checks[2]?.detail).toContain("HTTP 302");
  });

  test("a 403 that does not cite the advisory fails", async () => {
    const checks = await ossfListed(stage({ tarball: () => answer({ error: "forbidden" }, 403) }).deps);

    expect(checks.slice(1, 3).map((c) => c.ok)).toEqual([false, false]);
  });

  const packumentChecks = async (over: (accept: string) => Response) => (await ossfListed(stage({ packument: over }).deps)).slice(3).map((c) => c.ok);

  test("a packument of another package fails", async () => {
    expect(await packumentChecks((accept) => answer(packument({ name: "other" }), 200, accept))).toEqual([false, false]);
  });

  test("the full view answered for the install view fails that view", async () => {
    expect(await packumentChecks(() => answer(packument(), 200, FULL))).toEqual([true, false]);
  });

  test("a latest whose key and document version disagree fails, though a valid older version is left", async () => {
    const body = packument({ versions: { "9.0.0": { version: "9.0.0" }, "9.1.0": { version: "9.0.5" } }, "dist-tags": { latest: "9.1.0" } });

    expect(await packumentChecks((accept) => answer(body, 200, accept))).toEqual([false, false]);
  });

  test("an empty versions list fails", async () => {
    expect(await packumentChecks((accept) => answer(packument({ versions: {}, "dist-tags": {} }), 200, accept))).toEqual([false, false]);
  });

  test("only invalid versions left, a latest it does not list, or the listed version still there, fails", async () => {
    const wrong = [
      packument({ versions: { "not-a-version": { version: "not-a-version" } }, "dist-tags": { latest: "not-a-version" } }),
      packument({ "dist-tags": { latest: "9.9.9" } }),
      packument({ versions: { "9.0.0": { version: "9.0.0" }, [OSSF_LISTED.version]: { version: OSSF_LISTED.version } } }),
    ];

    for (const body of wrong) expect(await packumentChecks((accept) => answer(body, 200, accept))).toEqual([false, false]);
  });
});

describe("largeExplain", () => {
  test("a transient answer is asked again, and the second answer passes", async () => {
    let n = 0;
    const s = stage({ explain: () => (n++ === 0 ? answer({ error: "unavailable" }, 503) : answer(explained())) });
    const check = await largeExplain(s.deps);

    expect(check.ok).toBe(true);
    expect(check.detail).toContain("2 attempts");
    expect(s.sleeps).toEqual([5_000]);
  });

  test("a dropped connection is asked again, and the second answer passes", async () => {
    let n = 0;

    const s = stage({
      explain: () => {
        if (n++ === 0) throw new TypeError("The socket connection was closed unexpectedly");

        return answer(explained());
      },
    });

    const check = await largeExplain(s.deps);

    expect(check.ok).toBe(true);
    expect(check.detail).toContain("2 attempts");
    expect(s.sleeps).toEqual([5_000]);
  });

  test("an answer over the cap is not asked again", async () => {
    const chunk = new Uint8Array(256 * 1024).fill(32);
    const s = stage({ explain: () => new Response(new ReadableStream({ pull: (c) => c.enqueue(chunk) }), { headers: { "content-type": FULL } }) });

    expect((await largeExplain(s.deps)).ok).toBe(false);
    expect(s.calls.length).toBe(1);
  });

  test("a version still being analysed is transient too", async () => {
    let n = 0;
    const pending = explained({ score: null, notes: [{ kind: "not-scored", text: "apm is still analysing next@16.4.6: it has no score yet" }] });
    const s = stage({ explain: () => answer(n++ === 0 ? pending : explained()) });

    expect((await largeExplain(s.deps)).ok).toBe(true);
    expect(s.sleeps.length).toBe(1);
  });

  test("a verdict that is not transient fails at once, without asking again", async () => {
    const s = stage({ explain: () => answer(explained({ verdict: "review-first" })) });
    const check = await largeExplain(s.deps);

    expect(check.ok).toBe(false);
    expect(s.calls.length).toBe(1);
    expect(s.sleeps).toEqual([]);
  });

  test("a transient answer every time fails after three attempts", async () => {
    const s = stage({ explain: () => answer({ error: "slow down" }, 429) });

    expect((await largeExplain(s.deps)).ok).toBe(false);
    expect(s.calls.length).toBe(3);
  });

  test("an answer about another version fails", async () => {
    expect((await largeExplain(stage({ explain: () => answer(explained({ version: "16.4.7" })) }).deps)).ok).toBe(false);
  });
});
