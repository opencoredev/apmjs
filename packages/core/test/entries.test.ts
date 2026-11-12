// Score 15: one entry-point collector for the publish check and the scorer.
import { describe, expect, test } from "bun:test";
import { entryPoints, missingEntries } from "../src/entries.ts";

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
