// The files Cloudflare's asset layer serves without the Worker get their headers from _headers files, not from
// next.config.ts: the website's /_next/static/* (public/_headers) and every docs page and file (apps/docs, which is
// assets only). Each must carry every security header the Worker sends (review of de5c7b7, finding 3: only nosniff
// was left, so a built SVG could be framed), each exactly once, and the content-named files the immutable cache policy.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { headerRules, headersFor } from "../scripts/headers-file";
import { securityHeaders } from "./security-headers";

const WEB_HEADERS = join(import.meta.dir, "..", "public", "_headers");
const DOCS_HEADERS = join(import.meta.dir, "..", "..", "docs", "public", "_headers");

/** Each path checked, and whether it is a content-named file a browser may keep for a year. */
const PATHS = [
  { site: "the website", file: WEB_HEADERS, path: "/_next/static/chunks/app.js", immutable: true },
  { site: "the docs site", file: DOCS_HEADERS, path: "/", immutable: false },
  { site: "the docs site", file: DOCS_HEADERS, path: "/guides/ci/", immutable: false },
  { site: "the docs site", file: DOCS_HEADERS, path: "/logo.svg", immutable: false },
  { site: "the docs site", file: DOCS_HEADERS, path: "/_astro/page.CdE12.js", immutable: true },
];

describe("static file headers", () => {
  for (const { site, file, path, immutable } of PATHS) {
    test(`${site}'s ${path} carries every security header the Worker sends, each once${immutable ? ", and is kept for a year" : ""}`, () => {
      const got = headersFor(headerRules(file), path);

      for (const h of securityHeaders(false)) expect(got.get(h.key.toLowerCase()), h.key).toBe(h.value);
      expect(got.get("x-frame-options")).toBe("DENY");
      expect(got.get("referrer-policy")).toBe("strict-origin");
      expect(got.get("content-security-policy")).toContain("frame-ancestors 'none'");
      expect(got.get("cache-control")).toBe(immutable ? "public, max-age=31536000, immutable" : undefined);
    });
  }

  test("the docs' HTML gets the CSP from the /* rule, and /_astro/* sets only its cache policy", () => {
    const docs = headerRules(DOCS_HEADERS);

    expect(docs.map((r) => r.pattern)).toEqual(["/*", "/_astro/*"]);
    expect(docs[0]?.headers.map(([name]) => name)).toEqual(securityHeaders(false).map((h) => h.key.toLowerCase()));
    expect(docs[1]?.headers).toEqual([["cache-control", "public, max-age=31536000, immutable"]]);
  });
});
