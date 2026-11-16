// The registry's build identity, on the registry Worker as the acceptance tests run it: GET /-/ping answers with the
// version's build id (APM_BUILD, stamped by deploy.ts) in x-apm-build, never cached, so the smoke check can tell which
// version served it. No other answer carries it, and a version without APM_BUILD sends none.
import { describe, expect, test } from "bun:test";
import { startRegistry } from "../../../tests/acceptance/harness.ts";
import { BUILD_HEADER } from "../src/worker.ts";

const BUILD = "0b5e1f2c-aaaa-4bbb-8ccc-000000000001";

describe("the build header", () => {
  test("/-/ping says which build answered and is not to be cached; nothing else says it", async () => {
    const reg = await startRegistry({ legacyAuth: false, env: { APM_BUILD: BUILD } });

    try {
      const ping = await fetch(`${reg.url}-/ping?check=1`);
      const other = await fetch(`${reg.url}-/whoami`);

      expect(ping.status).toBe(200);
      expect(ping.headers.get(BUILD_HEADER)).toBe(BUILD);
      expect(ping.headers.get("cache-control")).toBe("no-store");
      expect(await ping.json()).toEqual({});
      expect(other.headers.get(BUILD_HEADER)).toBeNull();
    } finally {
      await reg.stop();
    }
  }, 120_000);

  test("a version without APM_BUILD sends none", async () => {
    const reg = await startRegistry({ legacyAuth: false });

    try {
      expect((await fetch(`${reg.url}-/ping`)).headers.get(BUILD_HEADER)).toBeNull();
    } finally {
      await reg.stop();
    }
  }, 120_000);
});
