// The GET table's lookup. tests/acceptance/route-compat.test.ts compares every URL form with the dispatch before the
// table; these are the cases that lookup decides on its own.
import { describe, expect, test } from "bun:test";
import { getRouteOf, routeKey } from "../src/routes.ts";

describe("routeKey", () => {
  test("drops empty segments and decodes each one, keeping a decoded slash inside its segment", () => {
    expect(routeKey("/pkg/1.0.0/")).toBe("/pkg/1.0.0");
    expect(routeKey("//pkg//1.0.0")).toBe("/pkg/1.0.0");
    expect(routeKey("/%40scope/name")).toBe("/@scope/name");
    expect(routeKey("/@scope%2fname")).toBe("/@scope%2Fname");
    // a segment that does not decode is read as is; a percent sign in a segment is written back, so %2F is a slash
    expect(routeKey("/pkg/%zz")).toBe("/pkg/%25zz");
    expect(routeKey("/@scope%252Fname")).toBe("/@scope%252Fname");
  });
});

describe("getRouteOf", () => {
  test("finds a route by any spelling its module reads", () => {
    expect(getRouteOf("/pkg/")).toBe("packument");
    expect(getRouteOf("/~safe/pkg/1.0.0/")).toBe("version");
    expect(getRouteOf("/-/package/pkg/dist-tags/latest")).toBe("dist-tags");
    expect(getRouteOf("/-/apm/v1/packages/%40scope/name")).toBe("package");
    expect(getRouteOf("/~safe/-/apm/v1/packages/%40scope%2Fname/")).toBe("package");
    expect(getRouteOf("/@scope%2fname/-/name-1.0.0.tgz")).toBe("tarball");
    expect(getRouteOf("/@scope/name/-/name-1.0.0.tgz")).toBe("tarball");
    // a scope alone names no package: the protocol route answers it as the root
    expect(getRouteOf("/%40scope/")).toBe("root");
    expect(getRouteOf("/@scope%2Fname")).toBe("packument");
  });

  test("reads a path under /api/auth/ against Better Auth's routes alone", () => {
    expect(getRouteOf("/api/auth/get-session")).toBe("auth get-session");
    // the registry's table would read this as package "api", version "auth"
    expect(getRouteOf("/api/auth/sign-in/social")).toBeNull();
    // under /~safe/ it is no Better Auth path: the router sends it to the package routes, as it always has
    expect(getRouteOf("/~safe/api/auth/sign-in/social")).toBe("version");
  });

  test("refuses a path no module answers a GET on", () => {
    expect(getRouteOf("/-/apm/v1/revoke")).toBeNull();
    expect(getRouteOf("/pkg/-rev/1-abc")).toBeNull();
    expect(getRouteOf("/-/apm/v1/review/pkg/1.0.0/request")).toBeNull();
  });
});
