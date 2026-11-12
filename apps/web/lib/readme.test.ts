// Readmes are publisher-written. These render hostile and ordinary ones to HTML with react-dom/server, the
// same elements the package page gets, and check what survives.
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { jsxs } from "react/jsx-runtime";
import { renderToStaticMarkup } from "react-dom/server";
import { cutReadme, EXTERNAL_REL, MAX_DEPTH, MAX_NODES, measureSource, parseSrcSet, readmeTree, renderReadme } from "./readme";
import { githubRepo, type GithubRepo } from "./repository";

const zod: GithubRepo = { owner: "colinhacks", repo: "zod", directory: "" };

/** A repository whose directory throws when read, standing in for any bug inside the pipeline. */
function poisoned(): GithubRepo {
  return Object.defineProperty({ owner: "o", repo: "r", directory: "" }, "directory", {
    get() {
      throw new Error("boom");
    },
  });
}

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

  test("finding 2: a comma inside a srcset URL stays in that URL", () => {
    const out = html('<picture><source srcset="https://images.example.invalid/a,b.png 1x"><img src="a.png"></picture>');

    expect(out).toContain('srcSet="https://images.example.invalid/a,b.png 1x"');
    expect(parseSrcSet("https://images.example.invalid/a,b.png 1x, b.png 2x")).toEqual([
      { url: "https://images.example.invalid/a,b.png", descriptors: ["1x"] },
      { url: "b.png", descriptors: ["2x"] },
    ]);
  });

  test("finding 2: a data: candidate is dropped whole, not split into a repository URL", () => {
    const out = html('<picture><source srcset="data:image/png;base64,AAAA 1x, ok.png 2x"><img src="a.png"></picture>');

    expect(out).toContain('srcSet="https://raw.githubusercontent.com/colinhacks/zod/HEAD/ok.png 2x"');
    expect(out).not.toContain("AAAA");
    expect(out).not.toContain("base64");
  });

  test("finding 2: srcset follows the grammar: trailing commas, no descriptor, bad descriptors dropped", () => {
    expect(parseSrcSet(" a.png,, b.png 300w ,c.png")).toEqual([
      { url: "a.png", descriptors: [] },
      { url: "b.png", descriptors: ["300w"] },
      { url: "c.png", descriptors: [] },
    ]);

    const out = html('<picture><source srcset="a.png 0x, b.png 2q, c.png 1x 2x, d.png 1.5x, e.png 640w"><img src="a.png"></picture>');
    const base = "https://raw.githubusercontent.com/colinhacks/zod/HEAD";

    expect(out).toContain(`srcSet="${base}/d.png 1.5x, ${base}/e.png 640w"`);
  });

  test("finding 3: a # or ? in the package folder is part of the path", () => {
    for (const directory of ["packages/a#b", "packages/a?b"]) {
      const repo = githubRepo({ url: "https://github.com/o/r", directory });
      const encoded = directory.replace("#", "%23").replace("?", "%3F");
      const out = html("[docs](guide.md) ![logo](logo.png) [up](../x.md) [out](../../../../y.md)", repo);

      expect(out).toContain(`href="https://github.com/o/r/blob/HEAD/${encoded}/guide.md"`);
      expect(out).toContain(`src="https://raw.githubusercontent.com/o/r/HEAD/${encoded}/logo.png"`);
      expect(out).toContain('href="https://github.com/o/r/blob/HEAD/packages/x.md"');
      expect(out).not.toContain("y.md\"");
    }
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

  test("finding 4: a link to an id that was already prefixed follows it to its sanitized id", () => {
    const out = html('[toc](#user-content-foo)\n\n<h2 id="user-content-foo">Foo</h2>');

    expect(out).toContain('id="user-content-user-content-foo"');
    expect(out).toContain('<a href="#user-content-user-content-foo">toc</a>');
  });

  test("finding 4: links by slug, by prefixed slug, by name and to footnotes all reach their target", () => {
    const out = html('[a](#install) [b](#user-content-install) [c](#anchor) [d](#missing)\n\n## Install\n\n<a name="anchor">x</a>\n\nNote[^1]\n\n[^1]: the note');

    expect(out).toContain('<a href="#user-content-install">a</a>');
    expect(out).toContain('<a href="#user-content-install">b</a>');
    expect(out).toContain('<a href="#user-content-anchor">c</a>');
    expect(out).toContain('<a href="#user-content-missing">d</a>');
    expect(out).toMatch(/href="#user-content-fn-1"[^>]*>1</);
    expect(out).toContain('id="user-content-fn-1"');
  });

  test("headings sit under the page's h2 and keep their level as a class", () => {
    const out = html("# Zod\n\n## Install\n\n###### Small");

    expect(out).toContain('<h3 id="user-content-zod" class="readme-h1">Zod</h3>');
    expect(out).toContain('<h4 id="user-content-install" class="readme-h2">Install</h4>');
    expect(out).toContain('<h6 id="user-content-small" class="readme-h6">Small</h6>');
  });
});

describe("finding 1: nesting limits", () => {
  let logged: string[] = [];

  const quiet = () => {
    logged = [];

    return spyOn(console, "error").mockImplementation((line: string) => void logged.push(line));
  };

  afterEach(() => {
    logged = [];
  });

  test("the source check counts HTML depth, blockquotes, list markers and indentation", () => {
    expect(measureSource(`${"<div>".repeat(40)}x`).depth).toBe(40);
    expect(measureSource("<p>a<p>b<br><img src=x><li>c<br/>").depth).toBe(0);
    expect(measureSource("<div/>".repeat(30)).depth).toBe(30);
    expect(measureSource(`${"<div>".repeat(5)}${"</div>".repeat(5)}<div>`).depth).toBe(5);
    expect(measureSource(`${"> ".repeat(30)}x`).depth).toBe(30);
    expect(measureSource(Array.from({ length: 20 }, (_, i) => `${"  ".repeat(i)}- a`).join("\n")).depth).toBe(20);
    expect(measureSource(`<div>\n${"> ".repeat(10)}- x`).depth).toBe(12);
  });

  test("past the limit the escaped source is shown with a note, and one structured line is logged", () => {
    const spy = quiet();
    const source = `${"<div>".repeat(MAX_DEPTH + 1)}<script>x</script>`;
    const out = html(source);

    spy.mockRestore();
    expect(out).toContain('<div class="readme-fallback">');
    expect(out).toContain("nests too deeply");
    expect(out).toContain("&lt;div&gt;&lt;script&gt;x&lt;/script&gt;");
    expect(out).not.toContain("<script");
    expect(logged).toHaveLength(1);
    expect(JSON.parse(logged[0] ?? "")).toMatchObject({ event: "readme_fallback", reason: "too_deep", chars: source.length });
  });

  test("the inputs that overflowed workerd fall back before any parser sees them", () => {
    expect(readmeTree(`${"<div>".repeat(2500)}x`, zod)).toMatchObject({ kind: "fallback", reason: "too_deep" });
    expect(readmeTree(`${"> ".repeat(5000)}x`, zod)).toMatchObject({ kind: "fallback", reason: "too_deep" });
  });

  test("too many nodes falls back", () => {
    const spy = quiet();
    const out = html("<br>".repeat(MAX_NODES + 1));

    spy.mockRestore();
    expect(out).toContain("too large to render");
  });

  test("nesting the source check can't see is caught on the sanitized tree", () => {
    const spy = quiet();
    // Emphasis inside emphasis has no HTML tags or line markers, so only the tree check sees its depth.
    const result = readmeTree(`${"*a _b ".repeat(250)}x${" b_ a*".repeat(250)}`, zod);

    spy.mockRestore();
    expect(result).toMatchObject({ kind: "fallback", reason: "too_deep" });
  });

  test("a renderer failure shows the source and the rest of the page still renders", () => {
    const spy = quiet();

    const out = renderToStaticMarkup(
      jsxs("main", { children: [renderReadme("# Hi", { owner: "o", repo: "r", directory: "" }), renderReadme("[x](y)", poisoned())] }),
    );

    spy.mockRestore();
    expect(out).toContain("<h3");
    expect(out).toContain("could not be rendered");
    expect(out).toContain("<pre>[x](y)</pre>");
    expect(JSON.parse(logged[0] ?? "")).toMatchObject({ event: "readme_fallback", reason: "render_failed" });
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
