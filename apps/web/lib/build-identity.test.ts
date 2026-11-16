// The website's build identity (GET /api/build): the version's build id (APM_BUILD, stamped by deploy.ts) in
// x-apm-build, never cached, so the smoke check can tell which version served it.
import { describe, expect, test } from "bun:test";
import { BUILD_HEADER, buildIdentity } from "./build-identity";

describe("the website's build identity", () => {
  test("it says which build answered, and is not to be cached", () => {
    const res = buildIdentity({ APM_BUILD: "0b5e1f2c-aaaa-4bbb-8ccc-000000000001" });

    expect(res.status).toBe(204);
    expect(res.headers.get(BUILD_HEADER)).toBe("0b5e1f2c-aaaa-4bbb-8ccc-000000000001");
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  test("outside Cloudflare, or on an unstamped version, it says nothing", () => {
    expect(buildIdentity(null).headers.get(BUILD_HEADER)).toBeNull();
    expect(buildIdentity({}).headers.get(BUILD_HEADER)).toBeNull();
  });
});
