// /package/<name>/v/<version>, the version link the CLI and the registry printed, redirects through proxy.ts to the
// version's page, /package/<name>?v=<version>. The redirect is answered before any registry read.
import { describe, expect, test } from "bun:test";
import { NextRequest } from "next/server";
import { proxy } from "../proxy";
import { parseVersionRoute } from "./package-route";

async function redirectOf(path: string): Promise<{ status: number; location: string | null }> {
  const res = await proxy(new NextRequest(`https://apmjs.dev${path}`));

  return { status: res.status, location: res.headers.get("location") };
}

describe("/package/<name>/v/<version>", () => {
  test("redirects to the version's page", async () => {
    expect(await redirectOf("/package/express/v/5.3.0")).toEqual({ status: 308, location: "https://apmjs.dev/package/express?v=5.3.0" });
  });

  test("keeps a scoped name readable, whether or not the @ came encoded", async () => {
    expect(await redirectOf("/package/@types/node/v/22.0.0")).toEqual({ status: 308, location: "https://apmjs.dev/package/@types/node?v=22.0.0" });
    expect(await redirectOf("/package/%40types/node/v/22.0.0")).toEqual({ status: 308, location: "https://apmjs.dev/package/@types/node?v=22.0.0" });
  });

  test("decodes the version once and encodes it for the query", async () => {
    expect((await redirectOf("/package/x/v/1.0.0-beta.1%2Bbuild.5")).location).toBe("https://apmjs.dev/package/x?v=1.0.0-beta.1%2Bbuild.5");
    expect((await redirectOf("/package/x/v/1.0.0+build.5")).location).toBe("https://apmjs.dev/package/x?v=1.0.0%2Bbuild.5");
    expect((await redirectOf("/package/@acme/tool/v/2.0.0%2Fx")).location).toBe("https://apmjs.dev/package/@acme/tool?v=2.0.0%2Fx");
  });

  test("a trailing slash names the same version", async () => {
    expect((await redirectOf("/package/express/v/5.3.0/")).location).toBe("https://apmjs.dev/package/express?v=5.3.0");
  });

  test("keeps the rest of the query, and the path's version wins over a v already there", async () => {
    expect((await redirectOf("/package/zod/v/4.1.0?format=md")).location).toBe("https://apmjs.dev/package/zod?format=md&v=4.1.0");
    expect((await redirectOf("/package/zod/v/4.1.0?v=3.0.0")).location).toBe("https://apmjs.dev/package/zod?v=4.1.0");
  });

  test("a package named v", async () => {
    expect((await redirectOf("/package/v/v/1.0.0")).location).toBe("https://apmjs.dev/package/v?v=1.0.0");
  });
});

describe("parseVersionRoute", () => {
  test("reads the name and the version", () => {
    expect(parseVersionRoute(["express", "v", "5.3.0"])).toEqual({ name: "express", version: "5.3.0" });
    expect(parseVersionRoute(["%40acme", "tool", "v", "1.0.0%2B1"])).toEqual({ name: "@acme/tool", version: "1.0.0+1" });
  });

  test("names nothing for other package paths", () => {
    expect(parseVersionRoute(["express"])).toBeNull();
    expect(parseVersionRoute(["@acme", "tool"])).toBeNull();
    expect(parseVersionRoute(["v", "1.0.0"])).toBeNull();
    expect(parseVersionRoute(["zod", "v", "4.1.0", "file", "index.js"])).toBeNull();
    expect(parseVersionRoute(["zod", "x", "4.1.0"])).toBeNull();
    expect(parseVersionRoute(["zod", "v", ""])).toBeNull();
    expect(parseVersionRoute(["zod", "v", "%E0%A4%A"])).toBeNull();
    // the scoped package @acme/v at a path with no version, not "@acme" at 1.0.0
    expect(parseVersionRoute(["@acme", "v", "1.0.0"])).toBeNull();
  });
});
