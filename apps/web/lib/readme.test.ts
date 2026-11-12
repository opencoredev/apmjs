// Readmes are publisher-written. These render hostile and ordinary ones to HTML with react-dom/server, the
// same elements the package page gets, and check what survives.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { cutReadme, EXTERNAL_REL, renderReadme } from "./readme";
import { githubRepo, type GithubRepo } from "./repository";

const zod: GithubRepo = { owner: "colinhacks", repo: "zod", directory: "" };
const html = (markdown: string, repo: GithubRepo | null = zod): string => renderToStaticMarkup(renderReadme(markdown, repo));

describe("sanitizing", () => {
  test("a script tag is removed with its contents", () => {
    const out = html("Hello\n\n<script>alert(document.cookie)</script>\n\n<p>after<script src=https://evil.example/x.js></script></p>");

    expect(out).not.toContain("<script");
    expect(out).not.toContain("alert");
    expect(out).not.toContain("evil.example");
    expect(out).toContain("after");
  });

  test("an onerror attribute is removed and the image stays", () => {
    const out = html('<img src="https://img.example/a.png" onerror="alert(1)" onload="alert(2)" alt="a">');

    expect(out).not.toMatch(/onerror|onload|alert/i);
    expect(out).toContain('src="https://img.example/a.png"');
  });

  test("a javascript: link keeps its text and loses its href, however it is spelled", () => {
    const out = html('[click](javascript:alert(1))\n\n<a href="java&#x09;script:alert(2)">tab</a> <a href=" JavaScript:alert(3)">space</a>');

    expect(out).not.toMatch(/javascript/i);
    expect(out).toContain("<a>click</a>");
    expect(out).toContain("<a>tab</a>");
    expect(out).toContain("<a>space</a>");
  });

  test("data: and vbscript: links and data: images are dropped", () => {
    const out = html('[d](data:text/html,<script>alert(1)</script>) [v](vbscript:msgbox)\n\n![x](data:image/png;base64,AAAA)\n\n<img src="data:image/svg+xml,<svg onload=alert(1)>">');

    expect(out).not.toMatch(/data:|vbscript|alert/i);
    expect(out).not.toContain("<img");
    expect(out).toContain("<a>d</a>");
  });

  test("an SVG with a script is removed whole", () => {
    const out = html('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(2)</script><circle r="4"/></svg>\n\nok');

    expect(out).not.toMatch(/<svg|<script|<circle|onload|alert/i);
    expect(out).toContain("ok");
  });

  test("iframes, styles and forms do not survive", () => {
    const out = html('<iframe src="https://evil.example"></iframe><style>body{display:none}</style><div style="position:fixed" onclick="x()">text</div>');

    expect(out).not.toMatch(/iframe|<style|style=|onclick|evil\.example/i);
    expect(out).toContain("text");
  });

  test("a raw HTML <a> loses target and gets the external rel", () => {
    const out = html('<a href="https://example.com/" target="_blank" rel="opener">site</a>');

    expect(out).not.toContain("target");
    expect(out).not.toContain('rel="opener"');
    expect(out).toContain(`<a href="https://example.com/" rel="${EXTERNAL_REL}">site</a>`);
  });

  test("every external link gets rel nofollow noopener noreferrer ugc; in-page links don't", () => {
    const out = html("[docs](https://zod.dev/api) <https://github.com/colinhacks/zod> [mail](mailto:a@b.example) [top](#install)");

    expect(EXTERNAL_REL).toBe("nofollow noopener noreferrer ugc");
    expect(out).toContain(`<a href="https://zod.dev/api" rel="${EXTERNAL_REL}">docs</a>`);
    expect(out).toContain(`<a href="https://github.com/colinhacks/zod" rel="${EXTERNAL_REL}">`);
    expect(out).toContain(`<a href="mailto:a@b.example" rel="${EXTERNAL_REL}">mail</a>`);
    expect(out).toContain('<a href="#user-content-install">top</a>');
  });
});

describe("relative URLs", () => {
  test("a relative image loads from the repository's raw files, over https", () => {
    const out = html('![logo](logo.svg)\n\n<img src="./docs/shot.png">\n\n<img src="http://cdn.example/b.png">');

    expect(out).toContain('src="https://raw.githubusercontent.com/colinhacks/zod/HEAD/logo.svg"');
    expect(out).toContain('src="https://raw.githubusercontent.com/colinhacks/zod/HEAD/docs/shot.png"');
    expect(out).toContain('src="https://cdn.example/b.png"');
    expect(out).toContain('loading="lazy"');
  });

  test("relative links open the file on GitHub, inside the package's folder", () => {
    const repo = githubRepo({ url: "git+https://github.com/honojs/hono.git", directory: "packages/core" });
    const out = html("[guide](docs/guide.md) [root](/LICENSE) [up](../shared/x.md)", repo);

    expect(out).toContain('href="https://github.com/honojs/hono/blob/HEAD/packages/core/docs/guide.md"');
    expect(out).toContain('href="https://github.com/honojs/hono/blob/HEAD/LICENSE"');
    expect(out).toContain('href="https://github.com/honojs/hono/blob/HEAD/packages/shared/x.md"');
  });

  test("a relative path can't climb out of the repository", () => {
    const out = html("[x](../../../../other/repo) ![y](../../../../other/repo/a.png)");

    expect(out).not.toContain("other/repo");
    expect(out).not.toContain("<img");
  });

  test("without a GitHub repository, relative links and images are dropped", () => {
    const out = html("![logo](logo.svg) [guide](docs/guide.md) [site](https://example.com/)", null);

    expect(out).not.toContain("<img");
    expect(out).not.toContain("docs/guide.md");
    expect(out).toContain("<a>guide</a>");
    expect(out).toContain('href="https://example.com/"');
  });

  test("protocol-relative and backslash URLs are read as another host, not as repository paths", () => {
    const out = html('<img src="//cdn.example/a.png"> <img src="\\\\cdn.example/b.png">');

    expect(out).toContain('src="https://cdn.example/a.png"');
    expect(out).not.toContain("raw.githubusercontent.com");
  });

  test("picture sources are resolved the same way, and unsafe candidates dropped", () => {
    const out = html('<picture><source media="(prefers-color-scheme: dark)" srcset="dark.png 2x, http://cdn.example/d.png 1x, data:image/png;base64 3x"><img src="light.png"></picture>');

    expect(out).toContain('srcSet="https://raw.githubusercontent.com/colinhacks/zod/HEAD/dark.png 2x, https://cdn.example/d.png 1x"');
    expect(out).not.toContain("data:");
  });
});

describe("headings", () => {
  test("a heading id that clashes with the page's anchors is prefixed", () => {
    const out = html('<h2 id="readme">Raw</h2>\n\n## Versions\n\n<a name="score">x</a>');

    expect(out).toContain('id="user-content-readme"');
    expect(out).toContain('id="user-content-versions"');
    expect(out).toContain('name="user-content-score"');
    expect(out).not.toMatch(/(id|name)="(readme|versions|score)"/);
  });

  test("headings sit under the page's h2 and keep their level as a class", () => {
    const out = html("# Zod\n\n## Install\n\n###### Small");

    expect(out).toContain('<h3 id="user-content-zod" class="readme-h1">Zod</h3>');
    expect(out).toContain('<h4 id="user-content-install" class="readme-h2">Install</h4>');
    expect(out).toContain('<h6 id="user-content-small" class="readme-h6">Small</h6>');
  });
});

describe("Markdown", () => {
  test("code blocks, tables and lists render", () => {
    const out = html("```ts\nconst a = 1;\n```\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- one\n- [x] done");

    expect(out).toContain('<pre><code class="language-ts">const a = 1;\n</code></pre>');
    expect(out).toContain("<table>");
    expect(out).toContain("<td>1</td>");
    expect(out).toContain("<li>one</li>");
    expect(out).toContain('type="checkbox"');
  });
});

describe("repository", () => {
  test("reads the ways npm writes a GitHub repository", () => {
    for (const url of ["git+https://github.com/colinhacks/zod.git", "https://github.com/colinhacks/zod", "git@github.com:colinhacks/zod.git", "github:colinhacks/zod", "colinhacks/zod", "git://github.com/colinhacks/zod.git"]) {
      expect(githubRepo({ url, directory: null })).toEqual(zod);
    }
  });

  test("other hosts and folders outside the repo are not used", () => {
    expect(githubRepo({ url: "https://gitlab.com/a/b", directory: null })).toBeNull();
    expect(githubRepo({ url: "https://github.com/a/b", directory: "../x" })).toBeNull();
    expect(githubRepo(null)).toBeNull();
  });
});

describe("cutReadme", () => {
  test("cuts at a paragraph break near the limit", () => {
    const text = `${"a".repeat(80)}\n\n${"b".repeat(40)}`;

    expect(cutReadme(text, 100)).toBe("a".repeat(80));
    expect(cutReadme("short", 100)).toBe("short");
  });
});
