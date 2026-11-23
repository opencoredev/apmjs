import { describe, expect, test } from "bun:test";
import nextConfig from "../next.config";
import { contentSecurityPolicy, PRIVATE_HEADERS, REFERRER_POLICY, securityHeaders } from "./security-headers";

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

  test("every page sends its origin alone as the referrer, with no per-route override", async () => {
    expect(REFERRER_POLICY).toBe("strict-origin");
    expect(securityHeaders(false).find((h) => h.key === "Referrer-Policy")?.value).toBe("strict-origin");

    const rules = (await nextConfig.headers?.()) ?? [];
    const referrer = rules.filter((r) => r.headers.some((h) => h.key === "Referrer-Policy"));

    // a document keeps the policy it loaded with, so the policy has to be the same on every route
    expect(referrer.map((r) => r.source)).toEqual(["/:path*"]);
  });

  test("per-user responses are never stored by a shared cache", () => {
    expect(PRIVATE_HEADERS).toEqual([
      { key: "Cache-Control", value: "private, no-store" },
      { key: "Vary", value: "Cookie" },
    ]);
  });
});
