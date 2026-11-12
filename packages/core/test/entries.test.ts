// Score 15: one entry-point collector for the publish check and the scorer.
import { describe, expect, test } from "bun:test";
import { entryPoints, missingEntries, targetFiles } from "../src/entries.ts";
import { analyze, type TarEntry, findingsOf } from "../src/index.ts";

const files = (...paths: string[]) => paths.map((path) => ({ path }));

describe("entryPoints", () => {
  test("lists bin, main, module, browser, every exports condition, then types", () => {
    const manifest = {
      bin: { cli: "./bin/cli.js" },
      main: "index.js",
      module: "./esm/index.mjs",
      browser: { "./server.js": "./browser.js", fs: false },
      exports: { ".": { import: "./esm/index.mjs", require: ["./index.js", "./fallback.js"] }, "./feature": null },
      types: "index.d.ts",
    };

    expect(entryPoints(manifest).map((e) => `${e.field} ${e.path}`)).toEqual([
      "bin.cli ./bin/cli.js",
      "main index.js",
      "module ./esm/index.mjs",
      'browser["./server.js"] ./browser.js',
      'exports["."]["import"] ./esm/index.mjs',
      'exports["."]["require"][0] ./index.js',
      'exports["."]["require"][1] ./fallback.js',
      "types index.d.ts",
    ]);
  });

  test("lists imports targets after exports, and does not require them to exist", () => {
    const manifest = { main: "index.js", imports: { "#dep": { node: "./dep-node.js", default: "dep-polyfill" }, "#internal/*": "./src/internal/*.js" } };

    expect(entryPoints(manifest).map((e) => `${e.field} ${e.path}`)).toEqual(["main index.js", 'imports["#dep"]["node"] ./dep-node.js', 'imports["#dep"]["default"] dep-polyfill', 'imports["#internal/*"] ./src/internal/*.js']);
    expect(missingEntries(manifest, files("index.js"))).toEqual([]);
  });

  test("fields of the wrong shape are ignored, not thrown on", () => {
    expect(entryPoints({ main: 3, bin: [1], exports: 7, module: { x: 1 } })).toEqual([]);
  });
});

describe("missingEntries", () => {
  test("a missing exports or module target is reported", () => {
    const missing = missingEntries({ main: "index.js", module: "./esm/index.mjs", exports: { ".": { import: "./dist/index.mjs", require: "./index.js" } } }, files("index.js"));

    expect(missing.map((m) => m.path)).toEqual(["./esm/index.mjs", "./dist/index.mjs"]);
  });

  test("patterns, folder mappings, browser remaps and non-relative exports are not checked", () => {
    const manifest = { exports: { "./features/*": "./src/features/*.js", "./legacy/": "./legacy/", "./x": "x.js" }, browser: { "./a.js": "./missing-browser.js" } };

    expect(missingEntries(manifest, files("index.js"))).toEqual([]);
  });

  test("main keeps node's extension and index lookup", () => {
    expect(missingEntries({ main: "lib" }, files("lib/index.js"))).toEqual([]);
    expect(missingEntries({ main: "./server" }, files("server.js"))).toEqual([]);
  });
});

describe("targetFiles", () => {
  const paths = ["docs/payload.txt", "docs/a/b.txt", "docs/x.md", "a/q/x/q.js", "a/q/x/r.js", "lib/x.js", "index.js"];

  test("a pattern names every file it matches, a * matching across folders", () => {
    expect(targetFiles("./docs/*.txt", paths)).toEqual({ kind: "files", files: ["docs/payload.txt", "docs/a/b.txt"] });
  });

  test("every * in a target stands for the same text", () => {
    expect(targetFiles("./a/*/x/*.js", paths)).toEqual({ kind: "files", files: ["a/q/x/q.js"] });
  });

  test("a folder mapping names every file under it; anything else is one path", () => {
    expect(targetFiles("./lib/", paths)).toEqual({ kind: "files", files: ["lib/x.js"] });
    expect(targetFiles("./index.js", paths)).toEqual({ kind: "path", path: "./index.js" });
  });
});

describe("files an exports pattern exposes are read as code", () => {
  const entry = (path: string, text: string): TarEntry => {
    const data = new TextEncoder().encode(text);

    return { path, size: data.length, mode: 0o644, data };
  };

  type ExportMap = Record<string, string | Record<string, string | Record<string, string>>>;

  const analyzeWith = (exports: ExportMap, more: Record<string, string>) => {
    const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", exports };

    return analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry("index.js", "module.exports = 1;"), ...Object.entries(more).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] });
  };

  test("a .txt file behind a conditional wildcard is read as JavaScript", () => {
    const a = analyzeWith({ "./*": { node: { require: "./docs/*.txt" }, default: "./index.js" } }, { "docs/payload.txt": "require('child_process');" });

    expect(findingsOf(a).find((s) => s.id === "shell-exec")?.confidence).toBe("confirmed");
  });

  test("an imports pattern exposes its files too", () => {
    const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", imports: { "#x/*": "./vendor/*.dat" } };
    const a = analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry("index.js", "module.exports = 1;"), entry("vendor/a.dat", "fetch('https://example.invalid');")], publisher: "a", previousPublishers: [] });

    expect(findingsOf(a).find((s) => s.id === "network")?.confidence).toBe("confirmed");
  });

  test("a README behind ./* is not JavaScript, so its install instructions are not a shell call", () => {
    const a = analyzeWith({ "./*": "./*" }, { "README.md": "# probe\n\nInstall with `curl -fsSL https://example.invalid/install | sh`.\n" });

    expect(findingsOf(a).map((s) => s.id)).not.toContain("shell-exec");
  });
});
