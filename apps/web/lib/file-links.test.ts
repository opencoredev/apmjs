// Evidence links: which citations become links, where each one opens, and how the file view lays out lines.
import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { FindingList } from "../components/finding-list";
import { citeEvidence, scriptLine } from "./evidence";
import { CHUNK_LINES, chunkLines, displayLines } from "./file-lines";
import { fileHref, packagePath, parsePackageRoute, scoreHref } from "./package-route";
import { signInIntro } from "../components/sign-in-panel";

describe("fileHref", () => {
  test("opens a file of a version at a line, named in the query too so a large file opens as an excerpt there", () => {
    expect(fileHref({ name: "zod", version: "4.1.0", path: "lib/setup.js", line: 4 })).toBe("/package/zod/v/4.1.0/file/lib/setup.js?line=4#L4");
  });

  test("keeps a scope as its own segment and encodes each path segment", () => {
    expect(fileHref({ name: "@acme/tool", version: "1.0.0-beta.1", path: "dist/a b#c.js", line: 12 })).toBe("/package/%40acme/tool/v/1.0.0-beta.1/file/dist/a%20b%23c.js?line=12#L12");
  });

  test("opens package.json at a script anchor, or at the top", () => {
    expect(fileHref({ name: "puppeteer", version: "24.0.0", path: "package.json", anchor: "scripts.postinstall" })).toBe("/package/puppeteer/v/24.0.0/file/package.json#scripts.postinstall");
    expect(fileHref({ name: "x", version: "1.0.0", path: "binding.gyp" })).toBe("/package/x/v/1.0.0/file/binding.gyp");
  });

  test("refuses paths a browser would rewrite before sending", () => {
    for (const path of ["../package.json", "lib/../x.js", "./x.js", "/abs.js", "lib//x.js", "lib/."]) expect(fileHref({ name: "x", version: "1.0.0", path, line: 1 })).toBeNull();
  });

  test("round-trips through the route parser", () => {
    const href = fileHref({ name: "@acme/tool", version: "2.0.0", path: "dist/a b#c.js", line: 3 }) ?? "";
    const segs = href.split("?")[0]?.slice("/package/".length).split("/") ?? [];
    expect(parsePackageRoute(segs)).toEqual({ kind: "file", name: "@acme/tool", version: "2.0.0", path: "dist/a b#c.js" });
  });
});

describe("parsePackageRoute", () => {
  test("reads package pages, scoped and not", () => {
    expect(parsePackageRoute(["zod"])).toEqual({ kind: "package", name: "zod" });
    expect(parsePackageRoute(["%40acme", "tool"])).toEqual({ kind: "package", name: "@acme/tool" });
    expect(parsePackageRoute(["v"])).toEqual({ kind: "package", name: "v" });
  });

  test("reads a file route, even for a package named v", () => {
    expect(parsePackageRoute(["v", "v", "1.0.0", "file", "index.js"])).toEqual({ kind: "file", name: "v", version: "1.0.0", path: "index.js" });
  });

  test("names nothing for other shapes and bad encodings", () => {
    expect(parsePackageRoute(["zod", "extra"])).toBeNull();
    expect(parsePackageRoute(["zod", "v", "1.0.0", "file"])).toBeNull();
    expect(parsePackageRoute(["zod", "v", "1.0.0", "blob", "x.js"])).toBeNull();
    expect(parsePackageRoute(["%E0%A4%A"])).toBeNull();
    expect(parsePackageRoute([])).toBeNull();
  });

  test("the package and score paths", () => {
    expect(packagePath("@acme/tool")).toBe("/package/%40acme/tool");
    expect(scoreHref("zod", "4.1.0")).toBe("/package/zod?v=4.1.0#score");
  });
});

describe("citeEvidence", () => {
  test("a file and line, with the snippet left as text", () => {
    expect(citeEvidence("credential-access", "lib/setup.js:4: require('fs').readFileSync(home + '/.npmrc')")).toEqual({
      cite: "lib/setup.js:4",
      citation: { path: "lib/setup.js", line: 4, anchor: null },
      rest: ": require('fs').readFileSync(home + '/.npmrc')",
    });
  });

  test("an install script opens package.json at that script", () => {
    expect(citeEvidence("install-script", "package.json scripts.postinstall: node install.mjs")).toEqual({
      cite: "package.json scripts.postinstall",
      citation: { path: "package.json", line: null, anchor: "scripts.postinstall" },
      rest: ": node install.mjs",
    });
    expect(citeEvidence("shell-exec", "package.json scripts.build (run by scripts.postinstall): sh x.sh")?.citation.anchor).toBe("scripts.build");
  });

  test("a whole file, and a binary's bare path", () => {
    expect(citeEvidence("install-script", "binding.gyp: node-gyp build runs at install")?.citation).toEqual({ path: "binding.gyp", line: null, anchor: null });
    expect(citeEvidence("binary", "prebuilds/linux-x64/addon.node")).toEqual({ cite: "prebuilds/linux-x64/addon.node", citation: { path: "prebuilds/linux-x64/addon.node", line: null, anchor: null }, rest: "" });
  });

  test("evidence that names no file stays text", () => {
    expect(citeEvidence("no-license", "package.json has no license field")).toBeNull();
    expect(citeEvidence("incomplete", "not analyzed: dist/huge.js (40.0 MB, too large)")).toBeNull();
    expect(citeEvidence("risky-dependency", "left-pad@1.0.0 scores 20/100")).toBeNull();
    expect(citeEvidence("recent", "published 3h ago")).toBeNull();
  });
});

describe("scriptLine", () => {
  const pj = '{\n  "name": "x",\n  "scripts": {\n    "test": "bun test",\n    "postinstall": "node install.mjs"\n  },\n  "postinstall": "not a script"\n}\n';

  test("finds the script's line inside the scripts object", () => {
    expect(scriptLine(pj, "scripts.postinstall")).toBe(5);
    expect(scriptLine(pj, "scripts.test")).toBe(4);
  });

  test("null for a script that isn't there", () => {
    expect(scriptLine(pj, "scripts.preinstall")).toBeNull();
    expect(scriptLine("{}", "scripts.postinstall")).toBeNull();
  });
});

describe("file view lines", () => {
  test("numbers lines the way the scorer does, without a phantom last line", () => {
    expect(displayLines("a\r\nb\nc\n")).toEqual(["a", "b", "c"]);
    expect(displayLines("")).toEqual([""]);
    expect(displayLines("a\n\n")).toEqual(["a", ""]);
  });

  test("shows hidden and reordering characters as markers", () => {
    expect(displayLines("x\u202Ey\u2066z\u0000\rw\u2028")).toEqual(["x⟨U+202E⟩y⟨U+2066⟩z␀␍w⟨U+2028⟩"]);
  });

  test("blocks of 200 lines, each drawing every row", () => {
    const lines = Array.from({ length: 450 }, (_, i) => (i === 199 ? "" : `line ${i + 1}`));
    const chunks = chunkLines(lines);
    expect(chunks.map((c) => [c.start, c.count])).toEqual([
      [1, CHUNK_LINES],
      [201, CHUNK_LINES],
      [401, 50],
    ]);
    // the block's text ends in "\n", so an empty last line still gets its row
    expect(chunks[0]?.text.endsWith("line 199\n\n")).toBe(true);
    expect(chunks[2]?.numbers.split("\n")).toHaveLength(50);
  });
});

describe("sign-in copy", () => {
  test("mentions Vercel only when its button is shown", () => {
    expect(signInIntro(["github"])).not.toContain("Vercel");
    expect(signInIntro([])).not.toContain("Vercel");
    expect(signInIntro(["github", "vercel"])).toContain("sign in with Vercel");
  });
});

describe("AI review findings", () => {
  test("each finding's file:line links to that line of the reviewed version", () => {
    const html = renderToStaticMarkup(
      createElement(FindingList, {
        name: "@acme/tool",
        version: "1.2.3",
        findings: [
          { file: "lib/run.js", line: 7, excerpt: "<script>alert(1)</script>", issue: "Spawns a shell.", severity: "high" },
          { file: "../escape.js", line: 1, excerpt: "x", issue: "Unlinkable path.", severity: "low" },
        ],
      }),
    );

    expect(html).toContain('href="/package/%40acme/tool/v/1.2.3/file/lib/run.js?line=7#L7"');
    expect(html).toContain(">lib/run.js:7</a>");
    // a path a browser would rewrite stays text, and the excerpt is escaped, never HTML
    expect(html).not.toContain("escape.js#L1");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});
