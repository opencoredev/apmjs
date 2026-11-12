import { describe, expect, test } from "bun:test";
import { contentSecurityPolicy, PRIVATE_HEADERS, securityHeaders } from "./security-headers";

describe("security headers", () => {
  test("production CSP forbids framing and plugins and has no eval", () => {
    const csp = contentSecurityPolicy(false);

    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("ws:");
  });

  test("every page gets the full set", () => {
    const keys = securityHeaders(false).map((h) => h.key);

    expect(keys).toEqual(["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]);
  });

  test("per-user responses are never stored by a shared cache", () => {
    expect(PRIVATE_HEADERS).toEqual([
      { key: "Cache-Control", value: "private, no-store" },
      { key: "Vary", value: "Cookie" },
    ]);
  });
});
