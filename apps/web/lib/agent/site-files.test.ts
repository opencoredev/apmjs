// llms.txt, llms-full.txt, the sitemap, the Markdown route, the OpenAPI document, the agent card and the SEO helpers.
import { describe, expect, test } from "bun:test";
import { agentCard } from "./agent-card";
import { LLMS_TXT, llmsFull } from "./llms";
import { markdownApiPath, markdownRoute } from "./md-route";
import { openApiDocument } from "./openapi";
import { clip, jsonLdText, packageJsonLd, packageMetadata, websiteJsonLd } from "./seo";
import { POPULAR_PACKAGES } from "./site";
import { MAX_RECENT, sitemapEntries } from "./sitemap";

describe("llms.txt", () => {
  test("follows the llmstxt.org shape: an H1, a summary quote, then sections of links", () => {
    const lines = LLMS_TXT.split("\n");

    expect(lines[0]).toBe("# apm");
    expect(lines[2]?.startsWith("> apm is a package registry in front of npm.")).toBe(true);
    expect(LLMS_TXT).toContain("## For agents");
    expect(LLMS_TXT).toContain("## Docs");
    expect(LLMS_TXT).toContain("## Optional");
  });

  test("links the MCP server, the verdict endpoint, the Markdown view, OpenAPI, the main pages and the full docs", () => {
    for (const url of ["https://apmjs.dev/mcp", "https://apmjs.dev/api/explain?package=zod", "https://apmjs.dev/package/zod.md", "https://apmjs.dev/openapi.json", "https://apmjs.dev/docs", "https://apmjs.dev/compare", "https://apmjs.dev/llms-full.txt"]) {
      expect(LLMS_TXT).toContain(`](${url})`);
    }
  });

  test("names every MCP tool and never calls a version safe", () => {
    for (const tool of ["search_packages", "check_package", "check_name", "explain_install", "get_file_excerpt"]) expect(LLMS_TXT).toContain(tool);
    expect(LLMS_TXT).toContain('apm never calls a version "safe"');
  });
});

describe("llms-full.txt", () => {
  test("llms.txt first, then each doc under its own title with its source, its own H1 dropped", () => {
    const full = llmsFull([
      { title: "The score", path: "docs/SCORE.md", text: "# Score\n\nPoints are lost for…\n" },
      { title: "Architecture", path: "docs/ARCHITECTURE.md", text: "Intro without a title" },
    ]);

    expect(full.startsWith("# apm\n")).toBe(true);
    expect(full).toContain("<!-- source: docs/SCORE.md -->\n\n# The score\n\nPoints are lost for…");
    expect(full).not.toContain("# Score\n");
    expect(full).toContain("# Architecture\n\nIntro without a title");
    expect(full.endsWith("\n")).toBe(true);
  });
});

describe("sitemap", () => {
  const now = new Date("2026-11-12T00:00:00Z");

  test("the home, docs and compare pages, then every popular package", () => {
    const urls = sitemapEntries({ recent: [], now }).map((e) => e.url);

    expect(urls.slice(0, 3)).toEqual(["https://apmjs.dev/", "https://apmjs.dev/docs", "https://apmjs.dev/compare"]);
    expect(urls).toHaveLength(3 + POPULAR_PACKAGES.length);
    expect(urls).toContain("https://apmjs.dev/package/react");
  });

  test("recent packages once each, a popular one not repeated, scoped names as two segments", () => {
    const entries = sitemapEntries({
      recent: [
        { package: "@acme/tool", at: "2026-11-11T10:00:00Z" },
        { package: "react", at: "2026-11-11T09:00:00Z" },
        { package: "@acme/tool", at: "2026-11-10T00:00:00Z" },
        { package: "odd", at: "not a date" },
      ],
      now,
    });

    const recent = entries.slice(3 + POPULAR_PACKAGES.length);

    expect(recent.map((e) => e.url)).toEqual(["https://apmjs.dev/package/@acme/tool", "https://apmjs.dev/package/odd"]);
    expect(recent[0]?.lastModified).toEqual(new Date("2026-11-11T10:00:00Z"));
    expect(recent[1]?.lastModified).toBeUndefined();
  });

  test("at most MAX_RECENT recent packages", () => {
    const many = Array.from({ length: MAX_RECENT + 50 }, (_, i) => ({ package: `p${i}`, at: "2026-11-11T00:00:00Z" }));

    expect(sitemapEntries({ recent: many, now })).toHaveLength(3 + POPULAR_PACKAGES.length + MAX_RECENT);
  });
});

describe("markdownRoute", () => {
  const route = (path: string) => {
    const url = new URL(path, "https://apmjs.dev");

    return markdownRoute({ pathname: url.pathname, searchParams: url.searchParams });
  };

  test(".md suffix and ?format=md ask for the Markdown view", () => {
    expect(route("/package/zod.md")).toEqual({ name: "zod", version: null });
    expect(route("/package/@scope/name.md?v=1.2.0")).toEqual({ name: "@scope/name", version: "1.2.0" });
    expect(route("/package/zod?format=md")).toEqual({ name: "zod", version: null });
    expect(route("/package/%40scope/name.md")).toEqual({ name: "@scope/name", version: null });
  });

  test("the HTML page, a file of a version and other paths do not", () => {
    expect(route("/package/zod")).toBeNull();
    expect(route("/package/zod/v/4.1.0/file/README.md")).toBeNull();
    expect(route("/package/zod/v/4.1.0/file/README.md?format=md")).toBeNull();
    expect(route("/package/.md")).toBeNull();
    expect(route("/docs.md")).toBeNull();
  });

  test("markdownApiPath encodes each name part", () => {
    expect(markdownApiPath({ name: "@scope/name", version: "1.0.0-beta+1" })).toBe("/api/package-md/%40scope/name?v=1.0.0-beta%2B1");
  });
});

describe("openapi.json and the agent card", () => {
  const doc = openApiDocument();

  test("documents the score, names, search, review, file and resolve routes and the agent routes", () => {
    const paths = Object.keys(doc.paths);

    for (const p of ["/-/apm/v1/score/{name}", "/-/apm/v1/score/{name}/{version}", "/-/apm/v1/names", "/-/v1/search", "/-/apm/v1/review/{name}/{version}", "/-/apm/v1/file/{name}/{version}", "/-/apm/v1/resolve", "/api/explain", "/package/{name}.md", "/mcp"]) {
      expect(paths).toContain(p);
    }

    expect(doc.openapi).toBe("3.1.0");
  });

  test("every $ref points at a schema the document defines", () => {
    const text = JSON.stringify(doc);
    const schemas = Object.keys(doc.components.schemas);

    for (const m of text.matchAll(/"#\/components\/schemas\/([^"]+)"/g)) expect(schemas).toContain(m[1]);
  });

  test("the agent card names the MCP endpoint and one skill per tool", () => {
    const card = agentCard();

    expect(card.endpoints).toMatchObject({ mcp: { url: "https://apmjs.dev/mcp", transport: "streamable-http" }, openapi: "https://apmjs.dev/openapi.json" });
    expect(card.skills).toHaveLength(5);
  });
});

describe("SEO helpers", () => {
  test("package metadata: a title with the score, a clipped description, canonical, OG image and the Markdown alternate", () => {
    const m = packageMetadata({ name: "@acme/tool", description: "A tool. ".repeat(40), latest: "1.0.0", score: { score: 88, grade: "B" } });

    expect(m.title).toBe("@acme/tool 1.0.0: score 88/100 (B) · apm");
    expect(String(m.description).length).toBeLessThanOrEqual(158);
    expect(m.alternates).toEqual({ canonical: "/package/@acme/tool", types: { "text/markdown": "/package/@acme/tool.md" } });
    expect(m.openGraph?.images).toEqual([{ url: "/og/@acme/tool", width: 1200, height: 630, alt: "@acme/tool on apm: apm security score 88/100 (grade B)" }]);
    expect(m.twitter).toMatchObject({ card: "summary_large_image" });
  });

  test("clip cuts at a word and adds an ellipsis", () => {
    expect(clip("short")).toBe("short");
    expect(clip("one two three four five six", 16)).toBe("one two three…");
  });

  test("JSON-LD: WebSite with a SearchAction; SoftwareSourceCode; '<' can't close the script", () => {
    expect(websiteJsonLd()).toMatchObject({ "@type": "WebSite", potentialAction: { "@type": "SearchAction", target: { urlTemplate: "https://apmjs.dev/?q={search_term_string}" } } });
    const ld = packageJsonLd({ name: "x", description: "</script><script>alert(1)</script>", latest: "1.0.0", score: { score: 90, grade: "A" }, license: "MIT", repository: "https://github.com/a/x", homepage: null, maintainers: ["a"] });

    expect(ld).toMatchObject({ "@type": "SoftwareSourceCode", version: "1.0.0", license: "MIT", codeRepository: "https://github.com/a/x", programmingLanguage: "JavaScript" });
    expect(jsonLdText(ld)).not.toContain("</script>");
  });
});
