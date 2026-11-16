// The smoke check's build identity (smoke-identity.ts): before its behavioural checks it waits, for a bounded time,
// until the registry and the website each answer uncached with this run's build several times in a row, and after
// them it asks again with no waiting; an old version that answers every behavioural check still fails it. deploy.ts
// hands it the build and the workers.dev subdomain it resolved.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { BUILD_HEADER, confirmBuild, parseSmokeArgs, smokeTargets } from "../smoke-identity.ts";

const NEW = "0b5e1f2c-aaaa-4bbb-8ccc-000000000002";
const OLD = "0b5e1f2c-aaaa-4bbb-8ccc-000000000001";

let server: ReturnType<typeof Bun.serve>;
let base: string;

/** What build each answer reports, in turn; the last one repeats. */
let answers: (string | null)[];
let seen: { url: string; cacheControl: string | null }[];

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      seen.push({ url: req.url, cacheControl: req.headers.get("cache-control") });
      const build = answers.length > 1 ? answers.shift() : answers[0];

      return new Response(null, { status: 204, headers: build === null || build === undefined ? {} : { [BUILD_HEADER]: build } });
    },
  });
  base = `http://127.0.0.1:${server.port}/-/ping`;
});

afterAll(async () => {
  await server.stop(true);
});

beforeEach(() => {
  answers = [NEW];
  seen = [];
});

describe("the smoke check's build identity", () => {
  test("an old version answering is a failure once the wait is over, whatever else it gets right", async () => {
    answers = [OLD];
    const r = await confirmBuild({ name: "registry", url: base, expected: NEW, consecutive: 3, deadlineMs: 300, intervalMs: 50 });

    expect(r.ok).toBe(false);
    expect(r.detail).toContain(`answered build ${OLD}`);
    expect(r.detail).toContain(NEW);
  });

  test("it waits for the new version to take over, then needs it several times in a row", async () => {
    answers = [OLD, NEW, OLD, NEW, NEW, NEW];
    const r = await confirmBuild({ name: "registry", url: base, expected: NEW, consecutive: 3, deadlineMs: 5_000, intervalMs: 10 });

    expect(r.ok).toBe(true);
    expect(seen.length).toBe(6);
  });

  test("every request asks past any cache: a fresh query string each time and no-cache", async () => {
    await confirmBuild({ name: "registry", url: base, expected: NEW, consecutive: 3, deadlineMs: 1_000, intervalMs: 10 });
    const urls = seen.map((s) => s.url);

    expect(new Set(urls).size).toBe(urls.length);
    expect(seen.every((s) => s.cacheControl === "no-cache")).toBe(true);
  });

  test("after the checks there is no waiting: one old answer fails", async () => {
    answers = [NEW, OLD, NEW];
    const r = await confirmBuild({ name: "website", url: base, expected: NEW, consecutive: 3, deadlineMs: 0, intervalMs: 10 });

    expect(r.ok).toBe(false);
  });

  test("an answer without the header is not the build", async () => {
    answers = [null];
    const r = await confirmBuild({ name: "website", url: base, expected: NEW, consecutive: 1, deadlineMs: 0 });

    expect(r.ok).toBe(false);
    expect(r.detail).toContain("no build");
  });

  test("deploy.ts's build and subdomain choose what it checks", () => {
    expect(parseSmokeArgs(["--stage", "staging", "--build", NEW, "--subdomain", "acct"])).toEqual({ stage: "staging", build: NEW, subdomain: "acct" });
    expect(smokeTargets("staging", "acct")).toEqual({
      registry: "https://apmjs-registry-staging.acct.workers.dev/",
      web: "https://apmjs-web-staging.acct.workers.dev/",
      docs: "https://apmjs-docs-staging.acct.workers.dev/",
    });
    expect(smokeTargets("production", "acct").registry).toBe("https://registry.apmjs.dev/");
    // run by hand without them: no identity check, and the old fallback subdomain
    expect(parseSmokeArgs(["--stage", "production"]).build).toBeNull();
  });
});
