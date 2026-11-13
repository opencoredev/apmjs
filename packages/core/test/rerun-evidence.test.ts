// A run that reads less says why before anything else it found. Only five evidence lines are shown, and a smaller
// re-run of a big package also carries parser-limit warnings and skipped files: with six parser-depth warnings ahead
// of it, the reason ("... so this one read at most 4 MB") was cut from the shown evidence entirely.
import { expect, test } from "bun:test";
import { analyze, type TarEntry } from "../src/index.ts";

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

const BECAUSE = "2 earlier analyses of this version were stopped by the platform before they stored anything, so this one read at most 4 MB";

test("the reason a run read less is the first incomplete evidence, ahead of 6 parser-limit warnings and skipped files", () => {
  const manifest = { name: "big-pkg", version: "1.0.0", license: "MIT", main: "index.js" };
  // nesting past the reader's stack: each such file is a parser-limit warning ("ran out of stack")
  const deep = `${"(".repeat(5_000)}0${")".repeat(5_000)};\n`;
  const plugin = `module.exports = ${JSON.stringify("x".repeat(200_000))};\n`;
  const requires = [...Array.from({ length: 6 }, (_, i) => `require("./deep/d${i}.js");`), ...Array.from({ length: 12 }, (_, i) => `require("./plugins/p${i}.js");`)];

  const files = [
    entry("package.json", JSON.stringify(manifest)),
    entry("index.js", requires.join("\n")),
    ...Array.from({ length: 6 }, (_, i) => entry(`deep/d${i}.js`, deep)),
    ...Array.from({ length: 12 }, (_, i) => entry(`plugins/p${i}.js`, plugin)),
  ];

  const a = analyze({ name: manifest.name, manifest, files, publisher: "a", previousPublishers: [], maxScannedBytes: 1_000_000, incompleteBecause: [BECAUSE] });
  const incomplete = a.signals.find((s) => s.id === "incomplete");
  const all = [...(incomplete?.evidence ?? []), ...(incomplete?.more ?? [])];

  // the fixture really has what pushed the reason out: 6 parser-limit warnings and skipped files
  expect(all.filter((e) => e.includes("ran out of stack")).length).toBe(6);
  expect(all.some((e) => e.startsWith("not analyzed: plugins/"))).toBe(true);
  expect(incomplete?.evidence.length).toBe(5);
  // on 3549541 the reason came after the skipped files, and here after all six parser warnings: not shown at all
  expect(incomplete?.evidence[0]).toBe(BECAUSE);
});
