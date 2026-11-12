// A package's homepage, repository and issues links come from its manifest, which the publisher writes. Only
// plain http(s) URLs become links; the readme fallback order lives in readme-source.ts.
import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { PackageLinks } from "../components/package-links";
import { packageLinks, repositoryUrl, safeHttpUrl } from "./package-links";
import { readmeSource } from "./readme-source";

describe("link sanitizing", () => {
  test("keeps http and https URLs", () => {
    expect(safeHttpUrl("https://react.dev/")).toBe("https://react.dev/");
    expect(safeHttpUrl("  http://example.com/docs  ")).toBe("http://example.com/docs");
  });

  test("drops every other scheme, credentials, relative and junk values", () => {
    for (const bad of ["javascript:alert(1)", " JavaScript:alert(1)", "java\tscript:alert(1)", "data:text/html,<script>alert(1)</script>", "vbscript:x", "file:///etc/passwd", "ftp://x.example/", "//evil.example/x", "/docs", "react.dev", "https://user:pass@evil.example/", "https://token@evil.example/", "", null, undefined, `https://x.example/${"a".repeat(2100)}`]) {
      expect(safeHttpUrl(bad), String(bad)).toBeNull();
    }
  });

  test("repository fields open on GitHub however npm spelled them, other hosts only over http(s)", () => {
    expect(repositoryUrl({ url: "git+https://github.com/facebook/react.git", directory: "packages/react" })).toBe("https://github.com/facebook/react/tree/HEAD/packages/react");
    expect(repositoryUrl({ url: "github:colinhacks/zod", directory: null })).toBe("https://github.com/colinhacks/zod");
    expect(repositoryUrl({ url: "git+https://gitlab.com/acme/tool.git", directory: null })).toBe("https://gitlab.com/acme/tool");
    expect(repositoryUrl({ url: "git@gitlab.com:acme/tool.git", directory: null })).toBeNull();
    expect(repositoryUrl({ url: "javascript:alert(1)", directory: null })).toBeNull();
    expect(repositoryUrl(null)).toBeNull();
  });
});

describe("packageLinks", () => {
  test("react's homepage, repository and issues, in that order", () => {
    const links = packageLinks({
      homepage: "https://react.dev/",
      repository: { url: "git+https://github.com/facebook/react.git", directory: "packages/react" },
      bugs: "https://github.com/facebook/react/issues",
    });

    expect(links.map((l) => [l.label, l.display])).toEqual([
      ["Homepage", "react.dev"],
      ["Repository", "github.com/facebook/react"],
      ["Issues", "github.com/facebook/react/issues"],
    ]);
    // the repository link still opens the package's folder
    expect(links[1]?.href).toBe("https://github.com/facebook/react/tree/HEAD/packages/react");
  });

  test("a homepage that only repeats the repository is dropped, and unsafe ones never appear", () => {
    const links = packageLinks({ homepage: "https://github.com/colinhacks/zod#readme", repository: { url: "github:colinhacks/zod", directory: null }, bugs: "javascript:alert(1)" });
    expect(links.map((l) => l.kind)).toEqual(["repository"]);
    expect(packageLinks({ homepage: null, repository: null, bugs: null })).toEqual([]);
  });

  test("renders plain links with the external rel, and nothing for an unsafe value", () => {
    const html = renderToStaticMarkup(createElement(PackageLinks, { links: packageLinks({ homepage: "https://react.dev/", repository: null, bugs: "javascript:alert(1)" }) }));
    expect(html).toContain('href="https://react.dev/"');
    expect(html).toContain('rel="nofollow noopener noreferrer ugc"');
    expect(html).not.toContain("javascript");
    expect(html).not.toContain("target=");
  });
});

describe("readme fallback order", () => {
  const tarball = { kind: "ok" as const, value: { kind: "text" as const, path: "README.md", size: 7, text: "# react" } };

  test("the packument's readme wins when it has one", () => {
    expect(readmeSource({ packument: "# from npm", version: "19.0.0", tarball })).toEqual({ kind: "packument", text: "# from npm" });
  });

  test("an empty, blank or placeholder packument readme falls back to the tarball's README", () => {
    for (const packument of ["", "  \n", "ERROR: No README data found!"]) {
      expect(readmeSource({ packument, version: "19.0.0", tarball })).toEqual({ kind: "tarball", text: "# react", path: "README.md", version: "19.0.0" });
    }
  });

  test("no README anywhere is none; a registry that did not answer is unknown, not none", () => {
    expect(readmeSource({ packument: "", version: "1.0.0", tarball: { kind: "missing" } })).toEqual({ kind: "none" });
    expect(readmeSource({ packument: "", version: null, tarball: null })).toEqual({ kind: "none" });
    expect(readmeSource({ packument: "", version: "1.0.0", tarball: { kind: "ok", value: { kind: "text", path: "README", size: 2, text: " \n" } } })).toEqual({ kind: "none" });
    expect(readmeSource({ packument: "", version: "1.0.0", tarball: { kind: "unavailable", reason: { kind: "timeout" } } })).toEqual({ kind: "unknown" });
  });

  test("a README too large or not text is named, not rendered", () => {
    expect(readmeSource({ packument: "", version: "1.0.0", tarball: { kind: "ok", value: { kind: "too-large", path: "README.md", size: 2_000_000, limit: 1_048_576 } } })).toEqual({
      kind: "unreadable",
      path: "README.md",
      version: "1.0.0",
      size: 2_000_000,
      reason: "too-large",
    });
  });
});
